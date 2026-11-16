from __future__ import annotations

from collections.abc import Sequence
from typing import Dict, List, Tuple

import pytest

from homeguard.runner import CommandResult


class FakeRunner:
    """Returns canned output by command prefix; unmatched commands return returncode=1."""

    def __init__(self, responses: Dict[Tuple[str, ...], CommandResult]):
        self.responses = responses
        self.calls: List[Tuple[str, ...]] = []

    def run(self, args: Sequence[str], timeout=None) -> CommandResult:
        key = tuple(args)
        self.calls.append(key)
        best = None
        for prefix, res in self.responses.items():
            if key[: len(prefix)] == prefix and (best is None or len(prefix) > len(best[0])):
                best = (prefix, res)
        return best[1] if best else CommandResult(1, "", "The domain/default pair does not exist")


def ok(out: str = "", err: str = "") -> CommandResult:
    return CommandResult(0, out, err)


@pytest.fixture
def fake_runner():
    return FakeRunner


NETSTAT_SAMPLE = """Active Internet connections (including servers)
Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)
tcp4       0      0  *.22                   *.*                    LISTEN
tcp6       0      0  *.22                   *.*                    LISTEN
tcp4       0      0  127.0.0.1.631          *.*                    LISTEN
tcp4       0      0  *.3000                 *.*                    LISTEN
tcp46      0      0  *.62070                *.*                    LISTEN
tcp4       0      0  192.168.1.5.52344      17.57.146.20.5223      ESTABLISHED
udp4       0      0  *.5353                 *.*
"""

LSOF_SAMPLE = """COMMAND     PID USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
rapportd    964 me     11u  IPv4  0xaf043437e3d4e30      0t0  TCP *:62070 (LISTEN)
node       4242 me     20u  IPv4  0xb293f58963b09bc1      0t0  TCP *:3000 (LISTEN)
"""


def healthy_mac_responses():
    from homeguard.checks import macos as m

    return {
        (m.SOCKETFILTERFW, "--getglobalstate"): ok("Firewall is enabled. (State = 1)\n"),
        (m.SOCKETFILTERFW, "--getstealthmode"): ok("Firewall stealth mode is on\n"),
        ("fdesetup", "status"): ok("FileVault is On.\n"),
        ("csrutil", "status"): ok("System Integrity Protection status: enabled.\n"),
        ("spctl", "--status"): ok("assessments enabled\n"),
        ("sw_vers", "-productVersion"): ok("27.2.1\n"),
        ("sysadminctl", "-screenLock", "status"): ok(
            "", "2026-11-16 sysadminctl[1:2] screenLock delay is immediate\n"
        ),
        ("defaults", "read", m.SOFTWARE_UPDATE_DOMAIN): ok("1\n"),
        ("defaults", "read", m.COMMERCE_DOMAIN, "AutoUpdate"): ok("1\n"),
        ("netstat", "-an"): ok("Active Internet connections\ntcp4  0  0  127.0.0.1.631  *.*  LISTEN\n"),
        ("lsof",): ok("COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\n"),
    }
