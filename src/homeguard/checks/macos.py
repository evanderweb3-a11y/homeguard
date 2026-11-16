"""macOS local security baseline checks.

Every check is read-only: it only calls built-in query commands (it never changes a
setting and never needs sudo). Each check takes a CommandRunner and returns one or more
Findings, so it can be tested with canned command output.
"""

from __future__ import annotations

import platform
import re
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple

from ..models import Finding, Severity, Status
from ..runner import CommandRunner

CATEGORY = "local"
TARGET = "this Mac"
SOCKETFILTERFW = "/usr/libexec/ApplicationFirewall/socketfilterfw"
SOFTWARE_UPDATE_DOMAIN = "/Library/Preferences/com.apple.SoftwareUpdate"
LOGINWINDOW_DOMAIN = "/Library/Preferences/com.apple.loginwindow"
COMMERCE_DOMAIN = "/Library/Preferences/com.apple.commerce"


@dataclass
class LocalOptions:
    min_macos_major: int = 15
    check_pending_updates: bool = False


def _f(
    check_id: str,
    title: str,
    status: Status,
    severity: Severity = Severity.INFO,
    detail: str = "",
    remediation: str = "",
    evidence: str = "",
    references: Optional[List[str]] = None,
) -> Finding:
    return Finding(
        check_id=check_id,
        category=CATEGORY,
        title=title,
        status=status,
        severity=severity,
        target=TARGET,
        detail=detail,
        remediation=remediation,
        evidence=(evidence or "").strip()[:800],
        references=references or [],
    )


def _unknown(check_id: str, title: str, out: str) -> Finding:
    return _f(
        check_id,
        title,
        Status.ERROR,
        Severity.INFO,
        detail="Could not parse the command output; please verify manually.",
        evidence=out,
    )


def defaults_read(runner: CommandRunner, domain: str, key: str) -> Optional[str]:
    """Read a `defaults` value; returns None when the key does not exist."""
    res = runner.run(["defaults", "read", domain, key])
    if not res.ok:
        return None
    return res.stdout.strip()


# ---------------------------------------------------------------- firewall


def check_firewall(runner: CommandRunner, opts: LocalOptions) -> List[Finding]:
    cid, title = "local.firewall", "Application firewall is enabled"
    out = runner.run([SOCKETFILTERFW, "--getglobalstate"]).output
    m = re.search(r"State\s*=\s*(\d)", out)
    low = out.lower()
    if m:
        state = int(m.group(1))
    elif "disabled" in low:
        state = 0
    elif "enabled" in low:
        state = 1
    else:
        return [_unknown(cid, title, out)]
    findings = []
    if state >= 1:
        findings.append(
            _f(
                cid,
                title,
                Status.PASS,
                Severity.HIGH,
                detail="The macOS application firewall is on.",
                evidence=out,
            )
        )
    else:
        findings.append(
            _f(
                cid,
                title,
                Status.FAIL,
                Severity.HIGH,
                detail="The macOS application firewall is off, so any device on the same network can reach "
                "programs listening on this Mac.",
                remediation="System Settings > Network > Firewall > turn on. "
                f"Command line: sudo {SOCKETFILTERFW} --setglobalstate on",
                evidence=out,
                references=["https://support.apple.com/guide/mac-help/mh34041/mac"],
            )
        )

    out = runner.run([SOCKETFILTERFW, "--getstealthmode"]).output
    low = out.lower()
    scid, stitle = "local.firewall_stealth", "Firewall stealth mode"
    if " off" in low or "disabled" in low:
        findings.append(
            _f(
                scid,
                stitle,
                Status.WARN,
                Severity.LOW,
                detail="With stealth mode off, this Mac answers pings and probes of closed ports, "
                "which makes it easier to discover on public Wi-Fi.",
                remediation="System Settings > Network > Firewall > Options > enable stealth mode. "
                f"Command line: sudo {SOCKETFILTERFW} --setstealthmode on",
                evidence=out,
            )
        )
    elif " on" in low or "enabled" in low:
        findings.append(
            _f(scid, stitle, Status.PASS, Severity.LOW, detail="Stealth mode is on.", evidence=out)
        )
    else:
        findings.append(_unknown(scid, stitle, out))
    return findings


# ---------------------------------------------------------------- FileVault


def check_filevault(runner: CommandRunner, opts: LocalOptions) -> List[Finding]:
    cid, title = "local.filevault", "FileVault disk encryption is on"
    out = runner.run(["fdesetup", "status"]).output
    low = out.lower()
    if "filevault is on" in low:
        return [_f(cid, title, Status.PASS, Severity.HIGH, detail="The disk is encrypted.", evidence=out)]
    if "encryption in progress" in low:
        return [_f(cid, title, Status.INFO, Severity.INFO, detail="Encryption is in progress.", evidence=out)]
    if "filevault is off" in low or "decryption in progress" in low:
        return [
            _f(
                cid,
                title,
                Status.FAIL,
                Severity.HIGH,
                detail="The disk is not encrypted. If this Mac is lost or stolen, its data can be read directly.",
                remediation="System Settings > Privacy & Security > FileVault > turn on, "
                "and store the recovery key somewhere safe.",
                evidence=out,
                references=["https://support.apple.com/guide/mac-help/mh11785/mac"],
            )
        ]
    return [_unknown(cid, title, out)]


# ---------------------------------------------------------------- SIP


def check_sip(runner: CommandRunner, opts: LocalOptions) -> List[Finding]:
    cid, title = "local.sip", "System Integrity Protection (SIP) is on"
    out = runner.run(["csrutil", "status"]).output
    low = out.lower()
    if "custom configuration" in low or "unknown" in low:
        return [
            _f(
                cid,
                title,
                Status.WARN,
                Severity.MEDIUM,
                detail="SIP is in a custom configuration with some protections disabled.",
                remediation="Restart into Recovery, run `csrutil enable` in Terminal, then restart.",
                evidence=out,
            )
        ]
    if "status: enabled" in low:
        return [_f(cid, title, Status.PASS, Severity.HIGH, detail="SIP is on.", evidence=out)]
    if "status: disabled" in low:
        return [
            _f(
                cid,
                title,
                Status.FAIL,
                Severity.HIGH,
                detail="SIP is off, so malware can modify protected system files.",
                remediation="Restart into Recovery (Apple silicon: hold the power button > Options), "
                "run `csrutil enable` in Terminal, then restart.",
                evidence=out,
                references=["https://support.apple.com/102149"],
            )
        ]
    return [_unknown(cid, title, out)]


# ---------------------------------------------------------------- Gatekeeper


def check_gatekeeper(runner: CommandRunner, opts: LocalOptions) -> List[Finding]:
    cid, title = "local.gatekeeper", "Gatekeeper is on"
    out = runner.run(["spctl", "--status"]).output
    low = out.lower()
    if "assessments enabled" in low:
        return [
            _f(cid, title, Status.PASS, Severity.MEDIUM, detail="Only notarized apps can run.", evidence=out)
        ]
    if "assessments disabled" in low:
        return [
            _f(
                cid,
                title,
                Status.FAIL,
                Severity.MEDIUM,
                detail="Gatekeeper is off, so apps from any source can run without checks.",
                remediation="Run `sudo spctl --master-enable`, then choose 'App Store and identified "
                "developers' in System Settings > Privacy & Security.",
                evidence=out,
            )
        ]
    return [_unknown(cid, title, out)]


# ---------------------------------------------------------------- automatic updates

_UPDATE_KEYS: List[Tuple[str, str, Severity]] = [
    ("AutomaticCheckEnabled", "Automatically check for macOS updates", Severity.MEDIUM),
    ("AutomaticDownload", "Automatically download macOS updates", Severity.LOW),
    ("CriticalUpdateInstall", "Automatically install security responses and system files", Severity.HIGH),
    ("AutomaticallyInstallMacOSUpdates", "Automatically install macOS updates", Severity.LOW),
]


def check_auto_updates(runner: CommandRunner, opts: LocalOptions) -> List[Finding]:
    findings = []
    remediation = (
        "System Settings > General > Software Update > (i) next to Automatic Updates, turn the switch on."
    )
    for key, title, sev in _UPDATE_KEYS:
        cid = f"local.update.{key}"
        val = defaults_read(runner, SOFTWARE_UPDATE_DOMAIN, key)
        if val is None:
            findings.append(
                _f(
                    cid,
                    title,
                    Status.INFO,
                    Severity.INFO,
                    detail="Not set explicitly; the system default (on) applies.",
                )
            )
        elif val in ("1", "true", "YES"):
            findings.append(_f(cid, title, Status.PASS, sev, detail="On.", evidence=f"{key} = {val}"))
        else:
            status = Status.FAIL if sev.rank >= Severity.HIGH.rank else Status.WARN
            findings.append(
                _f(
                    cid,
                    title,
                    status,
                    sev,
                    detail="Off; security patches may not be installed in time.",
                    remediation=remediation,
                    evidence=f"{key} = {val}",
                )
            )

    val = defaults_read(runner, COMMERCE_DOMAIN, "AutoUpdate")
    cid, title = "local.update.appstore", "App Store apps update automatically"
    if val in ("0", "false", "NO"):
        findings.append(
            _f(
                cid,
                title,
                Status.WARN,
                Severity.LOW,
                detail="App Store apps are not updated automatically.",
                remediation="System Settings > General > Software Update > (i) > turn on "
                "'Install application updates from the App Store'.",
                evidence=f"AutoUpdate = {val}",
            )
        )
    elif val is None:
        findings.append(
            _f(
                cid,
                title,
                Status.INFO,
                Severity.INFO,
                detail="Not set explicitly; the system default applies.",
            )
        )
    else:
        findings.append(
            _f(cid, title, Status.PASS, Severity.LOW, detail="On.", evidence=f"AutoUpdate = {val}")
        )
    return findings


def check_pending_updates(runner: CommandRunner, opts: LocalOptions) -> List[Finding]:
    cid, title = "local.update.pending", "No pending system updates"
    if not opts.check_pending_updates:
        return [
            _f(
                cid,
                title,
                Status.SKIP,
                detail="Disabled (slow and needs network). Set local.check_pending_updates = true to enable.",
            )
        ]
    out = runner.run(["softwareupdate", "-l"], timeout=180).output
    if "No new software available" in out:
        return [
            _f(cid, title, Status.PASS, Severity.MEDIUM, detail="The system is up to date.", evidence=out)
        ]
    labels = re.findall(r"^\s*\*\s*Label:\s*(.+)$", out, re.M)
    if labels:
        return [
            _f(
                cid,
                title,
                Status.WARN,
                Severity.MEDIUM,
                detail="Pending updates: " + "; ".join(labels),
                remediation="System Settings > General > Software Update > Update Now.",
                evidence=out,
            )
        ]
    return [_unknown(cid, title, out)]


# ---------------------------------------------------------------- OS version


def check_os_version(runner: CommandRunner, opts: LocalOptions) -> List[Finding]:
    cid, title = "local.os_version", "macOS version still receives security updates"
    out = runner.run(["sw_vers", "-productVersion"]).stdout.strip()
    m = re.match(r"(\d+)", out)
    if not m:
        return [_unknown(cid, title, out)]
    major = int(m.group(1))
    if major < opts.min_macos_major:
        return [
            _f(
                cid,
                title,
                Status.FAIL,
                Severity.HIGH,
                detail=f"This Mac runs macOS {out}, below the configured minimum supported major version "
                f"{opts.min_macos_major}; it may no longer receive security updates.",
                remediation="Upgrade to a macOS version Apple still patches. If the hardware cannot upgrade, "
                "keep less sensitive data on this device.",
                evidence=out,
                references=["https://support.apple.com/100100"],
            )
        ]
    return [_f(cid, title, Status.PASS, Severity.HIGH, detail=f"This Mac runs macOS {out}.", evidence=out)]


# ---------------------------------------------------------------- login and screen lock


def check_screen_lock(runner: CommandRunner, opts: LocalOptions) -> List[Finding]:
    cid, title = "local.screen_lock", "Password required right after screen lock"
    out = runner.run(["sysadminctl", "-screenLock", "status"]).output
    low = out.lower()
    remediation = (
        "System Settings > Lock Screen > set 'Require password after screen saver begins or display is "
        "turned off' to 'Immediately' or at most 5 minutes."
    )
    if "screenlock is off" in low:
        return [
            _f(
                cid,
                title,
                Status.FAIL,
                Severity.MEDIUM,
                detail="Waking the Mac does not require a password.",
                remediation=remediation,
                evidence=out,
            )
        ]
    if "immediate" in low:
        return [
            _f(
                cid,
                title,
                Status.PASS,
                Severity.MEDIUM,
                detail="A password is required immediately.",
                evidence=out,
            )
        ]
    m = re.search(r"delay is (\d+) seconds", low)
    if m:
        delay = int(m.group(1))
        if delay <= 300:
            return [
                _f(
                    cid,
                    title,
                    Status.PASS,
                    Severity.MEDIUM,
                    detail=f"A password is required {delay} seconds after locking.",
                    evidence=out,
                )
            ]
        return [
            _f(
                cid,
                title,
                Status.WARN,
                Severity.LOW,
                detail=f"No password is needed when waking within {delay} seconds of locking.",
                remediation=remediation,
                evidence=out,
            )
        ]
    return [_unknown(cid, title, out)]


def check_login_window(runner: CommandRunner, opts: LocalOptions) -> List[Finding]:
    findings = []
    title = "Automatic login is off"
    user = defaults_read(runner, LOGINWINDOW_DOMAIN, "autoLoginUser")
    if user:
        findings.append(
            _f(
                "local.auto_login",
                title,
                Status.FAIL,
                Severity.HIGH,
                detail=f"The Mac logs in as {user} at startup, so anyone holding it gets straight in.",
                remediation="System Settings > Users & Groups > set 'Automatically log in as' to Off.",
                evidence=f"autoLoginUser = {user}",
            )
        )
    else:
        findings.append(
            _f(
                "local.auto_login",
                title,
                Status.PASS,
                Severity.HIGH,
                detail="A password is required at startup.",
            )
        )

    title = "Guest user is off"
    guest = defaults_read(runner, LOGINWINDOW_DOMAIN, "GuestEnabled")
    if guest in ("1", "true", "YES"):
        findings.append(
            _f(
                "local.guest",
                title,
                Status.WARN,
                Severity.LOW,
                detail="The guest user can log in to this Mac without credentials.",
                remediation="System Settings > Users & Groups > Guest User > turn off "
                "'Allow guests to log in to this computer'.",
                evidence=f"GuestEnabled = {guest}",
            )
        )
    else:
        findings.append(
            _f("local.guest", title, Status.PASS, Severity.LOW, detail="The guest user is disabled.")
        )
    return findings


# ---------------------------------------------------------------- sharing services and listening ports


@dataclass(frozen=True)
class SharingService:
    name: str
    severity: Severity
    remediation: str


_SHARING = "System Settings > General > Sharing > "
_AIRPLAY_FIX = (
    "If you do not stream to this Mac from other devices: System Settings > General > "
    "AirDrop & Handoff > turn off 'AirPlay Receiver'."
)

SHARING_PORTS: Dict[int, SharingService] = {
    22: SharingService(
        "Remote Login (SSH)",
        Severity.MEDIUM,
        _SHARING + "turn off Remote Login. If you need it, allow key-based login only and restrict users.",
    ),
    445: SharingService(
        "File Sharing (SMB)",
        Severity.MEDIUM,
        _SHARING + "turn off File Sharing, or share only the folders you need with strong passwords.",
    ),
    548: SharingService("File Sharing (AFP)", Severity.MEDIUM, _SHARING + "turn off File Sharing."),
    5900: SharingService(
        "Screen Sharing / Remote Management (VNC)",
        Severity.MEDIUM,
        _SHARING + "turn off Screen Sharing and Remote Management.",
    ),
    3283: SharingService(
        "Remote Management (Apple Remote Desktop)", Severity.MEDIUM, _SHARING + "turn off Remote Management."
    ),
    3031: SharingService("Remote Apple Events", Severity.MEDIUM, _SHARING + "turn off Remote Apple Events."),
    631: SharingService("Printer Sharing (CUPS)", Severity.LOW, _SHARING + "turn off Printer Sharing."),
    5000: SharingService("AirPlay Receiver", Severity.INFO, _AIRPLAY_FIX),
    7000: SharingService("AirPlay Receiver", Severity.INFO, _AIRPLAY_FIX),
}

# Built-in Apple listeners that usually need no action (Continuity, Handoff, AirPlay, ...)
BENIGN_PROCESSES = {"rapportd", "ControlCe", "ControlCenter", "sharingd", "identityse", "AirPlayXPCHelper"}


@dataclass
class ListeningSocket:
    proto: str
    address: str
    port: int

    @property
    def exposed(self) -> bool:
        a = self.address.strip("[]").split("%")[0]
        return not (a.startswith("127.") or a in ("::1", "localhost") or a.startswith("fe80::1"))


def parse_netstat(output: str) -> List[ListeningSocket]:
    socks = []
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 6 or not parts[0].startswith("tcp") or "LISTEN" not in parts:
            continue
        local = parts[3]
        if "." not in local:
            continue
        addr, _, port = local.rpartition(".")
        if not port.isdigit():
            continue
        socks.append(ListeningSocket(parts[0], addr, int(port)))
    return socks


def parse_lsof(output: str) -> Dict[int, set]:
    """Return port -> set of process names (only processes visible to the current user)."""
    procs: Dict[int, set] = {}
    for line in output.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 9:
            continue
        name = parts[-2] if parts[-1] == "(LISTEN)" else parts[-1]
        port = name.rpartition(":")[2]
        if port.isdigit():
            procs.setdefault(int(port), set()).add(parts[0])
    return procs


def parse_lsof_sockets(output: str) -> List[ListeningSocket]:
    socks = []
    for line in output.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 9:
            continue
        name = parts[-2] if parts[-1] == "(LISTEN)" else parts[-1]
        addr, _, port = name.rpartition(":")
        if port.isdigit():
            socks.append(ListeningSocket("tcp", addr, int(port)))
    return socks


LIMITED_VISIBILITY_NOTE = (
    "netstat returned no TCP sockets (usually because a non-Apple-signed Python is running and macOS "
    "privacy rules hide other processes' sockets). Fell back to lsof, which only shows the current user's "
    "processes, so root services such as SSH or File Sharing cannot be confirmed. Run homeguard from a "
    "virtualenv created with the system /usr/bin/python3, or check System Settings > General > Sharing manually."
)


def check_listening_ports(runner: CommandRunner, opts: LocalOptions) -> List[Finding]:
    # No `-p tcp`: it returns empty output in some environments; parse_netstat filters tcp lines itself.
    res = runner.run(["netstat", "-an"])
    lsof_out = runner.run(["lsof", "-nP", "-iTCP", "-sTCP:LISTEN"]).stdout
    procs = parse_lsof(lsof_out)
    limited = not any(line.startswith("tcp") for line in res.stdout.splitlines())
    socks = parse_lsof_sockets(lsof_out) if limited else parse_netstat(res.stdout)
    exposed_ports = sorted({s.port for s in socks if s.exposed})
    loopback_ports = sorted({s.port for s in socks if not s.exposed} - set(exposed_ports))

    def describe(port: int) -> str:
        names = ",".join(sorted(procs.get(port, []))) or "unknown process (system or another user)"
        return f"{port} ({names})"

    findings: List[Finding] = []
    sharing_hits = [p for p in exposed_ports if p in SHARING_PORTS]
    for port in sharing_hits:
        svc = SHARING_PORTS[port]
        status = Status.INFO if svc.severity == Severity.INFO else Status.WARN
        findings.append(
            _f(
                f"local.sharing.{port}",
                f"Sharing service open to the LAN: {svc.name}",
                status,
                svc.severity,
                detail=f"Port {port} listens on all interfaces, so devices on the same network can connect.",
                remediation=svc.remediation,
                evidence=describe(port),
            )
        )
    if not sharing_hits and limited:
        findings.append(
            _f(
                "local.sharing",
                "System sharing services (could not be fully verified)",
                Status.INFO,
                Severity.INFO,
                detail=LIMITED_VISIBILITY_NOTE,
            )
        )
    elif not sharing_hits:
        findings.append(
            _f(
                "local.sharing",
                "No system sharing service is open to the LAN",
                Status.PASS,
                Severity.MEDIUM,
                detail="SSH, File Sharing, Screen Sharing and similar ports are not listening externally.",
            )
        )

    others = [p for p in exposed_ports if p not in SHARING_PORTS]
    unexplained = [p for p in others if not (procs.get(p) and procs[p] <= BENIGN_PROCESSES)]
    if unexplained:
        findings.append(
            _f(
                "local.listening_ports",
                "Programs listening on all network interfaces",
                Status.WARN,
                Severity.LOW,
                detail="Other devices on the LAN can reach these ports; make sure you need each service: "
                + ", ".join(describe(p) for p in unexplained),
                remediation="Quit or uninstall programs you do not need, bind development servers to 127.0.0.1, "
                "and turn on the application firewall to block unwanted incoming connections.",
                evidence="\n".join(describe(p) for p in unexplained),
            )
        )
    findings.append(
        _f(
            "local.listening_inventory",
            "Listening port inventory",
            Status.INFO,
            Severity.INFO,
            detail=f"{len(exposed_ports)} ports listen externally, {len(loopback_ports)} on loopback only."
            + (f" ({LIMITED_VISIBILITY_NOTE})" if limited else ""),
            evidence="External: "
            + (", ".join(describe(p) for p in exposed_ports) or "none")
            + "\nLoopback only: "
            + (", ".join(str(p) for p in loopback_ports) or "none"),
        )
    )
    return findings


CheckFn = Callable[[CommandRunner, LocalOptions], List[Finding]]

CHECKS: List[Tuple[str, CheckFn]] = [
    ("Firewall and stealth mode", check_firewall),
    ("FileVault disk encryption", check_filevault),
    ("System Integrity Protection", check_sip),
    ("Gatekeeper", check_gatekeeper),
    ("macOS version", check_os_version),
    ("Automatic update settings", check_auto_updates),
    ("Pending updates (optional)", check_pending_updates),
    ("Screen lock password", check_screen_lock),
    ("Automatic login and guest user", check_login_window),
    ("Sharing services and listening ports", check_listening_ports),
]


def run_local_checks(
    runner: Optional[CommandRunner] = None,
    opts: Optional[LocalOptions] = None,
    system: Optional[str] = None,
) -> List[Finding]:
    runner = runner or CommandRunner()
    opts = opts or LocalOptions()
    system = system or platform.system()
    if system != "Darwin":
        return [
            _f(
                "local.unsupported",
                "Local baseline checks",
                Status.SKIP,
                detail=f"Local baseline checks currently support macOS only (this system is {system}). "
                "LAN and dependency checks still work.",
            )
        ]
    findings: List[Finding] = []
    for name, fn in CHECKS:
        try:
            findings.extend(fn(runner, opts))
        except Exception as exc:  # one failing check must not stop the others
            findings.append(_f(f"local.{fn.__name__}", name, Status.ERROR, detail=f"Check failed: {exc!r}"))
    return findings
