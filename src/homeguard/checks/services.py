"""LAN service risk rules: port -> service name, severity, risk, remediation.

Rules are judged only from "is the port open" and "the banner the service sends on its own".
homeguard never tries to log in, guess passwords, or send any exploit payload.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from ..models import Severity


@dataclass(frozen=True)
class ServiceRule:
    port: int
    name: str
    severity: Severity
    risk: str
    remediation: str
    banner: Optional[str] = None  # None / "passive" (read what the server sends) / "http" (send HEAD /)


_R = ServiceRule
_RULE_LIST = [
    _R(
        21,
        "FTP",
        Severity.MEDIUM,
        "FTP sends credentials and files in clear text; other devices on the network can sniff them.",
        "Turn off FTP and use SFTP or SMB3 instead; on a NAS, disable FTP in its control panel.",
        "passive",
    ),
    _R(
        22,
        "SSH",
        Severity.INFO,
        "SSH remote login; weak passwords can be brute-forced.",
        "Allow key-based login only (PasswordAuthentication no) and keep OpenSSH up to date.",
        "passive",
    ),
    _R(
        23,
        "Telnet",
        Severity.HIGH,
        "Telnet is fully unencrypted and often uses default passwords; it is a top entry point for IoT compromise.",
        "Disable Telnet in the device admin page; if you cannot, isolate the device on a guest/IoT network or "
        "replace it.",
    ),
    _R(
        25,
        "SMTP",
        Severity.LOW,
        "A mail server runs on this device; home networks rarely need one.",
        "Confirm what it is for and turn it off if unused.",
        "passive",
    ),
    _R(
        53,
        "DNS",
        Severity.INFO,
        "DNS service (usually the router).",
        "Make sure DNS is not exposed to the internet (disable WAN-side DNS).",
    ),
    _R(
        80,
        "HTTP",
        Severity.LOW,
        "Plain-HTTP admin page; login passwords can be sniffed by other devices on the network.",
        "Prefer HTTPS administration, change default admin passwords, and disable unneeded web admin pages.",
        "http",
    ),
    _R(
        139,
        "NetBIOS",
        Severity.MEDIUM,
        "Legacy Windows file sharing protocol with a long history of vulnerabilities.",
        "Disable NetBIOS over TCP/IP and SMBv1; keep only SMB3.",
    ),
    _R(
        443,
        "HTTPS",
        Severity.INFO,
        "HTTPS service.",
        "Confirm you need this service and keep firmware updated.",
    ),
    _R(
        445,
        "SMB",
        Severity.MEDIUM,
        "File sharing; SMBv1 or anonymous shares are high risk.",
        "Disable SMBv1 and anonymous access, use strong passwords, and share only the folders you need.",
    ),
    _R(
        548,
        "AFP",
        Severity.LOW,
        "Apple's deprecated legacy file sharing protocol.",
        "Switch to SMB and disable AFP.",
    ),
    _R(
        554,
        "RTSP",
        Severity.MEDIUM,
        "Camera / video stream service; often has no password or a default one, exposing the live feed.",
        "Set a strong camera password, disable unneeded RTSP, isolate cameras on an IoT network, update firmware.",
    ),
    _R(
        1883,
        "MQTT",
        Severity.MEDIUM,
        "IoT message broker; without authentication any device can subscribe to or control your smart home.",
        "Enable username/password and TLS (8883), and allow only this host or trusted devices.",
    ),
    _R(
        2375,
        "Docker API (no TLS)",
        Severity.CRITICAL,
        "Unencrypted, unauthenticated Docker remote API: equivalent to giving the whole LAN root on the host.",
        "Remove tcp://0.0.0.0:2375 now; use the local socket, or port 2376 with mutual TLS.",
    ),
    _R(
        3306,
        "MySQL",
        Severity.HIGH,
        "Database exposed directly on the LAN.",
        "Bind to 127.0.0.1 (bind-address) or firewall it to the app server only; use strong passwords.",
        "passive",
    ),
    _R(
        3389,
        "RDP Remote Desktop",
        Severity.MEDIUM,
        "Remote desktop service with a history of critical flaws (e.g. BlueKeep).",
        "Turn it off when unused; require Network Level Authentication (NLA) and patch promptly.",
    ),
    _R(
        5000,
        "UPnP / AirPlay / NAS admin",
        Severity.INFO,
        "Common for AirPlay receivers or NAS admin pages.",
        "Confirm what it is; for a NAS admin page, change default passwords and enable two-factor login.",
    ),
    _R(
        5432,
        "PostgreSQL",
        Severity.HIGH,
        "Database exposed directly on the LAN.",
        "Set listen_addresses to localhost and restrict sources in pg_hba.conf.",
    ),
    _R(
        5555,
        "Android ADB debugging",
        Severity.HIGH,
        "With network ADB on, any device on the LAN can install apps and get a shell (common on TVs, "
        "set-top boxes and tablets).",
        "Turn it off after debugging: device Settings > Developer options > disable network/USB debugging "
        "(run adb disconnect first).",
    ),
    _R(
        5900,
        "VNC screen sharing",
        Severity.MEDIUM,
        "Remote desktop control; weak passwords let others take over the screen.",
        "Turn it off when unused; use a strong password and only on trusted networks.",
        "passive",
    ),
    _R(
        6379,
        "Redis",
        Severity.HIGH,
        "Redis has no authentication by default; data can be read and written, and files written to gain "
        "host access.",
        "bind 127.0.0.1, enable protected-mode and requirepass/ACLs.",
    ),
    _R(
        7000,
        "AirPlay receiver",
        Severity.INFO,
        "AirPlay receiver on an Apple device or TV.",
        "Turn it off in the device settings if you do not stream to it.",
    ),
    _R(
        8008,
        "HTTP (Chromecast / TV)",
        Severity.INFO,
        "Common cast-control interface on Chromecast and smart TVs.",
        "Keep the device firmware up to date.",
        "http",
    ),
    _R(
        8080,
        "HTTP alternate port",
        Severity.LOW,
        "Common plain-text admin page on routers, NAS boxes and development servers.",
        "Confirm what it is, change default passwords, and turn it off if unused.",
        "http",
    ),
    _R(
        8443,
        "HTTPS alternate port",
        Severity.INFO,
        "Common device admin page.",
        "Change default passwords and keep firmware updated.",
    ),
    _R(
        9100,
        "Printer RAW (JetDirect)",
        Severity.LOW,
        "Any device can send print jobs straight to the printer.",
        "Restrict sources in the printer admin page or disable RAW 9100.",
    ),
    _R(
        9200,
        "Elasticsearch",
        Severity.HIGH,
        "Search database with no authentication by default; data can be read directly.",
        "Enable xpack security and bind to localhost only.",
        "http",
    ),
    _R(
        11211,
        "Memcached",
        Severity.HIGH,
        "Cache service with no authentication; cached data can be read.",
        "Bind to 127.0.0.1 and disable UDP.",
    ),
    _R(
        27017,
        "MongoDB",
        Severity.HIGH,
        "Database exposed directly; older versions have no authentication by default.",
        "Enable authorization and set bindIp to 127.0.0.1.",
    ),
    _R(
        32400,
        "Plex Media Server",
        Severity.INFO,
        "Plex media server.",
        "Keep Plex updated and enable two-factor login on the account.",
    ),
    _R(
        62078,
        "iOS device sync (lockdownd)",
        Severity.INFO,
        "Wi-Fi sync service of an iPhone/iPad; this is normal.",
        "No action needed.",
    ),
]
RULES: Dict[int, ServiceRule] = {r.port: r for r in _RULE_LIST}

# A few common ports used to decide quickly whether a host is online
DISCOVERY_PORTS: List[int] = [80, 443, 22, 445, 8080, 5555, 8008, 62078, 7000, 53, 139, 554]


def default_ports(extra: Optional[List[int]] = None) -> List[int]:
    ports = set(RULES) | set(DISCOVERY_PORTS) | set(extra or [])
    return sorted(p for p in ports if 0 < p < 65536)


_OPENSSH_RE = re.compile(r"OpenSSH[_-](\d+)\.(\d+)(?:p(\d+))?", re.I)


def assess_ssh_banner(banner: str) -> Optional[Tuple[Severity, str, str, List[str]]]:
    """Judge whether an SSH banner names a known risky version. Returns (severity, detail, fix, refs)."""
    m = _OPENSSH_RE.search(banner or "")
    if not m:
        return None
    ver = (int(m.group(1)), int(m.group(2)))
    vtxt = f"{ver[0]}.{ver[1]}" + (f"p{m.group(3)}" if m.group(3) else "")
    distro_note = " (Linux distributions may have backported the fix; check your distribution's advisory.)"
    if (8, 5) <= ver < (9, 8) or ver < (4, 4):
        return (
            Severity.HIGH,
            f"OpenSSH {vtxt} is in the range affected by CVE-2024-6387 (regreSSHion, remote code execution on "
            f"glibc systems).{distro_note}",
            "Upgrade OpenSSH to 9.8p1 or later (or install the distribution's fixed package); as a stopgap, "
            "set LoginGraceTime 0.",
            ["https://osv.dev/vulnerability/CVE-2024-6387"],
        )
    if ver < (9, 8):
        return (
            Severity.MEDIUM,
            f"OpenSSH {vtxt} is old and may lack recent security fixes.{distro_note}",
            "Update the system or firmware to get a current OpenSSH.",
            [],
        )
    return None


def parse_http_server(banner: str) -> str:
    m = re.search(r"^Server:\s*(.+)$", banner or "", re.I | re.M)
    return m.group(1).strip() if m else ""
