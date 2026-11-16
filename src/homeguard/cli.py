"""Command-line entry point.

homeguard local                              # macOS local security baseline
homeguard lan 192.168.1.0/24                 # LAN assets and weak services (you must confirm ownership)
homeguard deps ~/code/myproject              # known vulnerabilities in dependencies (OSV)
homeguard all -c homeguard.toml              # run every check enabled in the config file
homeguard list-checks                        # list all checks
"""

from __future__ import annotations

import argparse
import platform
import socket
import sys
from datetime import datetime, timezone
from typing import List, Optional

from . import __version__
from .checks import deps as deps_mod
from .checks import macos, network
from .checks.services import RULES
from .config import Config, ConfigError, load_config
from .consent import ConsentError, confirm_targets
from .models import ScanResult, Severity
from .osv import OSVClient
from .report import write_reports


def _now() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def _err(msg: str) -> None:
    print(f"homeguard: {msg}", file=sys.stderr)


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "-c", "--config", help="config file (default: ./homeguard.toml, then ~/.config/homeguard/config.toml)"
    )
    common.add_argument("-o", "--output-dir", help="report output directory (default: reports/)")
    common.add_argument(
        "-f", "--format", help="comma-separated report formats: md,html,json (default: md,html)"
    )
    common.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low", "none"],
        help="exit with code 1 if any problem at or above this severity exists (default: high)",
    )
    common.add_argument("-q", "--quiet", action="store_true", help="print only the report paths")

    lan_opts = argparse.ArgumentParser(add_help=False)
    lan_opts.add_argument(
        "--i-own-these-targets",
        action="store_true",
        help="declare that the targets are yours or that you are authorized (for non-interactive use)",
    )
    lan_opts.add_argument(
        "--ports", help="comma-separated ports to check (default: built-in risky port list)"
    )
    lan_opts.add_argument("--timeout", type=float, help="per-port connect timeout in seconds (default: 0.6)")
    lan_opts.add_argument("--no-resolve", action="store_true", help="skip reverse DNS lookups")

    deps_opts = argparse.ArgumentParser(add_help=False)
    deps_opts.add_argument(
        "--offline", action="store_true", help="identify dependencies only; do not query OSV"
    )

    p = argparse.ArgumentParser(
        prog="homeguard",
        description="Personal/home security self-audit tool (only for devices and networks you own or are authorized to test)",
    )
    p.add_argument("--version", action="version", version=f"homeguard {__version__}")
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("local", parents=[common], help="macOS local security baseline")
    lan = sub.add_parser(
        "lan", parents=[common, lan_opts], help="LAN asset discovery and open-port / weak-service checks"
    )
    lan.add_argument(
        "targets", nargs="+", help="target IP or CIDR (private ranges only), e.g. 192.168.1.0/24"
    )
    d = sub.add_parser(
        "deps", parents=[common, deps_opts], help="known vulnerabilities in dependencies (OSV)"
    )
    d.add_argument("paths", nargs="+", help="project directories or lock files")
    a = sub.add_parser(
        "all", parents=[common, lan_opts, deps_opts], help="run every check enabled in the config file"
    )
    a.add_argument("--lan", action="append", default=[], metavar="CIDR", help="add a LAN target")
    a.add_argument("--deps", action="append", default=[], metavar="PATH", help="add a dependency path")
    a.add_argument("--no-local", action="store_true", help="skip the local baseline checks")
    sub.add_parser("list-checks", help="list all checks")
    return p


def list_checks() -> None:
    print("Local security baseline (macOS):")
    for name, _ in macos.CHECKS:
        print(f"  - {name}")
    print("\nLAN service risk rules:")
    for port, r in sorted(RULES.items()):
        print(f"  - {port:>5}  {r.name:<28} {r.severity.label}")
    print(
        "\nDependency lock files: requirements*.txt, Pipfile.lock, poetry.lock, uv.lock, package-lock.json, Cargo.lock, go.mod"
    )


def _apply_common(cfg: Config, args: argparse.Namespace) -> None:
    if args.output_dir:
        cfg.output_dir = args.output_dir
    if args.format:
        cfg.formats = [f.strip() for f in args.format.split(",") if f.strip()]
    if args.fail_on:
        cfg.fail_on = args.fail_on
    if getattr(args, "timeout", None):
        cfg.timeout = args.timeout
    if getattr(args, "no_resolve", False):
        cfg.resolve_names = False
    if getattr(args, "offline", False):
        cfg.offline = True


def run(argv: Optional[List[str]] = None, runner=None, osv_client=None, probe=None, input_fn=input) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "list-checks":
        list_checks()
        return 0
    try:
        cfg = load_config(args.config)
    except ConfigError as exc:
        _err(str(exc))
        return 2
    _apply_common(cfg, args)

    do_local = args.command == "local" or (args.command == "all" and cfg.local_enabled and not args.no_local)
    lan_targets: List[str] = []
    dep_paths: List[str] = []
    if args.command == "lan":
        lan_targets = args.targets
    elif args.command == "deps":
        dep_paths = args.paths
    elif args.command == "all":
        lan_targets = (cfg.targets if cfg.network_enabled else []) + args.lan
        dep_paths = (cfg.deps_paths if cfg.deps_enabled else []) + args.deps

    result = ScanResult(
        tool_version=__version__,
        started_at=_now(),
        hostname=socket.gethostname(),
        platform=f"{platform.system()} {platform.release()} {platform.machine()}",
    )
    log = (lambda *_: None) if args.quiet else (lambda m: print(m, file=sys.stderr))

    # finish all validation and authorization before any scanning starts
    nets = []
    ports: Optional[List[int]] = None
    if getattr(args, "ports", None):
        try:
            ports = [int(x) for x in args.ports.split(",") if x.strip()]
        except ValueError:
            ports = []
        if not ports or any(not 0 < p < 65536 for p in ports):
            _err("--ports must be comma-separated port numbers 1-65535, e.g. 22,80,443")
            return 2
    if lan_targets:
        try:
            nets = network.parse_targets(lan_targets)
            network.validate_targets(nets, cfg.max_hosts)
            result.authorization = confirm_targets(
                nets, cfg.authorized_networks, assume_yes=args.i_own_these_targets, input_fn=input_fn
            )
        except (network.TargetError, ConsentError) as exc:
            _err(str(exc))
            return 2

    if not (do_local or nets or dep_paths):
        _err("No checks enabled. Enable them in the config file or pass --lan / --deps.")
        return 2

    if do_local:
        log("> Local security baseline...")
        result.scopes.append("local")
        result.findings += macos.run_local_checks(
            runner, macos.LocalOptions(cfg.min_macos_major, cfg.check_pending_updates)
        )
    if nets:
        log(
            f"> LAN check: {', '.join(str(n) for n in nets)} ({sum(n.num_addresses for n in nets)} addresses)..."
        )
        result.scopes.append("network")
        opts = network.NetworkOptions(
            timeout=cfg.timeout,
            workers=cfg.workers,
            max_hosts=cfg.max_hosts,
            extra_ports=cfg.extra_ports,
            ports=ports,
            resolve_names=cfg.resolve_names,
        )
        kwargs = {"probe": probe} if probe else {}
        hosts, findings = network.run_network_checks(nets, opts, runner=runner, **kwargs)
        result.hosts, result.findings = hosts, result.findings + findings
    if dep_paths:
        log(
            f"> Dependency check: {', '.join(dep_paths)}"
            + (" (offline)" if cfg.offline else " (querying OSV)")
        )
        result.scopes.append("deps")
        client = osv_client or OSVClient(cfg.osv_url)
        result.findings += deps_mod.run_deps_checks(dep_paths, client=client, offline=cfg.offline)
        if not cfg.offline:
            result.notes.append(
                "The dependency check sends only package name, version and ecosystem to OSV (api.osv.dev)."
            )

    result.finished_at = _now()
    try:
        paths = write_reports(result, cfg.output_dir, cfg.formats)
    except ValueError as exc:
        _err(str(exc))
        return 2

    s = result.summary()
    if not args.quiet:
        print(
            f"\nDone: critical {s['critical']} · high {s['high']} · medium {s['medium']} · low {s['low']} · "
            f"passed {s['passed']} · errors {s['errors']}",
            file=sys.stderr,
        )
        for f in result.problems()[:10]:
            print(f"  [{f.severity.label}] {f.title} - {f.target}", file=sys.stderr)
    for p in paths:
        print(p)

    worst = result.max_problem_severity()
    if cfg.fail_on != "none" and worst is not None and worst.rank >= Severity(cfg.fail_on).rank:
        return 1
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    try:
        return run(argv)
    except KeyboardInterrupt:
        _err("cancelled")
        return 130
