"""LAN asset discovery and open-port / weak-service checks.

Safety boundaries (hard-coded, cannot be turned off by configuration):
* only private addresses (RFC 1918: 10/8, 172.16/12, 192.168/16), link-local 169.254/16 and
  loopback 127/8 may be scanned;
* a single scan is capped in size (default 1024 addresses, hard maximum 4096) so a large range
  cannot be targeted by mistake;
* only TCP connect probes and reading the banner a service sends on its own; no login attempts,
  password guessing or exploitation.
"""

from __future__ import annotations

import errno
import ipaddress
import re
import socket
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Set

from ..models import Finding, HostInfo, Severity, Status
from ..runner import CommandRunner
from .services import DISCOVERY_PORTS, RULES, assess_ssh_banner, default_ports, parse_http_server

CATEGORY = "network"

ALLOWED_NETWORKS = [
    ipaddress.ip_network(n)
    for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "127.0.0.0/8")
]
HARD_MAX_HOSTS = 4096

OPEN, CLOSED, FILTERED = "open", "closed", "filtered"


class TargetError(ValueError):
    """Invalid target (not private, too large, or malformed)."""


def parse_targets(specs: Iterable[str]) -> List[ipaddress.IPv4Network]:
    nets: List[ipaddress.IPv4Network] = []
    for spec in specs:
        for part in re.split(r"[,\s]+", spec.strip()):
            if not part:
                continue
            try:
                net = ipaddress.ip_network(part, strict=False)
            except ValueError as exc:
                raise TargetError(
                    f"Unrecognized target {part!r}: use an IP or CIDR, e.g. 192.168.1.0/24"
                ) from exc
            if net.version != 4:
                raise TargetError(f"{part}: only IPv4 targets are supported")
            nets.append(net)  # type: ignore[arg-type]
    if not nets:
        raise TargetError("No scan target given")
    return nets


def validate_targets(nets: Sequence[ipaddress.IPv4Network], max_hosts: int = 1024) -> None:
    max_hosts = min(max_hosts, HARD_MAX_HOSTS)
    total = 0
    for net in nets:
        if not any(net.subnet_of(allowed) for allowed in ALLOWED_NETWORKS):  # type: ignore[arg-type]
            raise TargetError(
                f"{net} is not a private/local address. homeguard only audits your own home network and "
                "does not scan public addresses or third-party assets."
            )
        total += net.num_addresses
    if total > max_hosts:
        raise TargetError(
            f"The targets cover {total} addresses, above the limit of {max_hosts}. A home network is usually "
            "one /24 (256 addresses); narrow the range or adjust network.max_hosts (hard maximum 4096)."
        )


def iter_hosts(net: ipaddress.IPv4Network) -> List[str]:
    if net.num_addresses <= 2:
        return [str(ip) for ip in net]
    return [str(ip) for ip in net.hosts()]


def probe_port(ip: str, port: int, timeout: float) -> str:
    """TCP connect probe: open / closed (host up, port refused) / filtered (no answer)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            rc = s.connect_ex((ip, port))
    except OSError:
        return FILTERED
    if rc == 0:
        return OPEN
    if rc == errno.ECONNREFUSED:
        return CLOSED
    return FILTERED


def grab_banner(ip: str, port: int, mode: str, timeout: float = 1.5) -> str:
    """Read a service banner. passive: only receive what the server sends; http: send one HEAD request."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            if mode == "http":
                s.sendall(f"HEAD / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: homeguard-audit\r\n\r\n".encode())
            data = s.recv(1024)
    except OSError:
        return ""
    text = data.decode("utf-8", errors="replace")
    if mode == "http":
        status = text.splitlines()[0] if text else ""
        server = parse_http_server(text)
        return f"{status} | Server: {server}" if server else status
    return text.strip().splitlines()[0][:200] if text.strip() else ""


_ARP_RE = re.compile(r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]{11,17})")


def parse_arp(output: str) -> Dict[str, str]:
    """Parse `arp -an` output into IP -> MAC."""
    table = {}
    for line in output.splitlines():
        m = _ARP_RE.search(line)
        if m and m.group(2).lower() != "ff:ff:ff:ff:ff:ff":
            table[m.group(1)] = m.group(2).lower()
    return table


def reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (OSError, UnicodeError):
        return ""


ProbeFn = Callable[[str, int, float], str]
BannerFn = Callable[[str, int, str], str]


@dataclass
class NetworkOptions:
    timeout: float = 0.6
    workers: int = 128
    max_hosts: int = 1024
    extra_ports: List[int] = field(default_factory=list)
    ports: Optional[List[int]] = None  # overrides the default port list when set
    resolve_names: bool = True
    grab_banners: bool = True


def scan_hosts(
    nets: Sequence[ipaddress.IPv4Network],
    opts: NetworkOptions,
    arp: Optional[Dict[str, str]] = None,
    probe: ProbeFn = probe_port,
    banner: BannerFn = grab_banner,
    resolver: Callable[[str], str] = reverse_dns,
    arp_refresh: Optional[Callable[[], Dict[str, str]]] = None,
) -> List[HostInfo]:
    arp = dict(arp or {})
    candidates: List[str] = []
    seen: Set[str] = set()
    for net in nets:
        for ip in iter_hosts(net):
            if ip not in seen:
                seen.add(ip)
                candidates.append(ip)
    in_scope = set(candidates)
    ports = sorted(set(opts.ports)) if opts.ports else default_ports(opts.extra_ports)
    disc_ports = [p for p in DISCOVERY_PORTS if p in ports] or ports[:5]
    workers = max(1, min(opts.workers, 256))

    results: Dict[str, Dict[int, str]] = {}

    def run_probes(pairs: List[tuple]) -> None:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            for (ip, port), state in zip(pairs, pool.map(lambda p: probe(p[0], p[1], opts.timeout), pairs)):
                results.setdefault(ip, {})[port] = state

    # Phase 1: a few ports decide whether a host is up (open or refused both mean "up")
    run_probes([(ip, p) for ip in candidates for p in disc_ports])
    if arp_refresh:
        # Probing triggers ARP resolution, so hosts that filter every TCP port still show up in the ARP table
        arp.update({ip: mac for ip, mac in arp_refresh().items() if ip in in_scope})
    alive = [
        ip for ip in candidates if ip in arp or any(s in (OPEN, CLOSED) for s in results.get(ip, {}).values())
    ]
    # Phase 2: full port list on live hosts only
    run_probes([(ip, p) for ip in alive for p in ports if p not in results.get(ip, {})])

    hosts: List[HostInfo] = []
    for ip in alive:
        open_ports = {p: "" for p, s in sorted(results.get(ip, {}).items()) if s == OPEN}
        hosts.append(HostInfo(ip=ip, mac=arp.get(ip, ""), open_ports=open_ports))

    # Phase 3: banners and reverse DNS
    with ThreadPoolExecutor(max_workers=min(workers, 32)) as pool:
        if opts.grab_banners:
            jobs = [
                (h, p, pool.submit(banner, h.ip, p, RULES[p].banner))
                for h in hosts
                for p in h.open_ports
                if p in RULES and RULES[p].banner
            ]
            for h, p, fut in jobs:
                h.open_ports[p] = fut.result() or ""
        if opts.resolve_names:
            name_jobs = [(h, pool.submit(resolver, h.ip)) for h in hosts]
            for h, fut in name_jobs:
                h.hostname = fut.result() or ""
    assert all(h.ip in in_scope for h in hosts)  # defensive: results never leave the authorized scope
    return hosts


def evaluate_hosts(hosts: Sequence[HostInfo], scanned: str) -> List[Finding]:
    findings: List[Finding] = []
    for h in hosts:
        label = h.ip + (f" ({h.hostname})" if h.hostname else "")
        for port, ban in sorted(h.open_ports.items()):
            rule = RULES.get(port)
            if port == 22:
                ssh = assess_ssh_banner(ban)
                if ssh:
                    sev, detail, fix, refs = ssh
                    findings.append(
                        Finding(
                            check_id="network.ssh_version",
                            category=CATEGORY,
                            title=f"SSH version has known risks (port {port})",
                            status=Status.FAIL if sev.rank >= Severity.HIGH.rank else Status.WARN,
                            severity=sev,
                            target=label,
                            detail=detail,
                            remediation=fix,
                            evidence=ban,
                            references=refs,
                        )
                    )
            if rule is None:
                findings.append(
                    Finding(
                        check_id=f"network.port.{port}",
                        category=CATEGORY,
                        title=f"Open port {port}",
                        status=Status.INFO,
                        severity=Severity.INFO,
                        target=label,
                        detail="A custom port from your configuration is open.",
                        evidence=ban,
                    )
                )
                continue
            if rule.severity == Severity.INFO:
                status = Status.INFO
            elif rule.severity.rank >= Severity.HIGH.rank:
                status = Status.FAIL
            else:
                status = Status.WARN
            findings.append(
                Finding(
                    check_id=f"network.port.{port}",
                    category=CATEGORY,
                    title=f"{rule.name} service open (port {port})",
                    status=status,
                    severity=rule.severity,
                    target=label,
                    detail=rule.risk,
                    remediation=rule.remediation,
                    evidence=ban,
                )
            )
    problems = [f for f in findings if f.is_problem]
    if not hosts:
        findings.append(
            Finding(
                "network.discovery",
                CATEGORY,
                "LAN asset discovery",
                Status.INFO,
                target=scanned,
                detail="No live hosts found (hosts may have a firewall on, or are not in this range).",
            )
        )
    elif not problems:
        findings.append(
            Finding(
                "network.summary",
                CATEGORY,
                "No risky open services found",
                Status.PASS,
                Severity.MEDIUM,
                target=scanned,
                detail=f"Found {len(hosts)} live hosts; none of the checked ports exposes a service that needs action.",
            )
        )
    return findings


def run_network_checks(
    nets: Sequence[ipaddress.IPv4Network],
    opts: Optional[NetworkOptions] = None,
    runner: Optional[CommandRunner] = None,
    probe: ProbeFn = probe_port,
    banner: BannerFn = grab_banner,
    resolver: Callable[[str], str] = reverse_dns,
) -> tuple:
    """Run the LAN checks. Callers must validate targets and obtain consent first (see consent.py)."""
    opts = opts or NetworkOptions()
    validate_targets(nets, opts.max_hosts)
    runner = runner or CommandRunner()

    def read_arp() -> Dict[str, str]:
        table = parse_arp(runner.run(["arp", "-an"]).stdout)
        return {ip: mac for ip, mac in table.items() if any(ipaddress.ip_address(ip) in n for n in nets)}

    hosts = scan_hosts(
        nets, opts, arp=read_arp(), probe=probe, banner=banner, resolver=resolver, arp_refresh=read_arp
    )
    scanned = ", ".join(str(n) for n in nets)
    return hosts, evaluate_hosts(hosts, scanned)
