"""Scan authorization.

Before a LAN scan you must confirm that the targets belong to you (or that you are authorized).
Accepted confirmations, in order:
1. the targets are fully covered by network.authorized_networks in the config file;
2. --i-own-these-targets is passed on the command line;
3. in an interactive terminal, the user types "I confirm" or "yes".
Otherwise the scan is refused. Every confirmation is recorded in the report.
"""

from __future__ import annotations

import ipaddress
import sys
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional, Sequence

CONSENT_STATEMENT = (
    "I confirm that the following scan targets are devices/networks I own, or that I have explicit "
    "authorization from their owner, and I understand that scanning networks without authorization may be illegal."
)
ACCEPTED_ANSWERS = {"i confirm", "yes", "y"}


class ConsentError(RuntimeError):
    """Scan authorization was not given."""


def _now() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def _records(nets: Sequence, method: str) -> List[Dict[str, str]]:
    return [
        {"target": str(n), "method": method, "time": _now(), "statement": CONSENT_STATEMENT} for n in nets
    ]


def confirm_targets(
    nets: Sequence[ipaddress.IPv4Network],
    authorized: Sequence[str] = (),
    assume_yes: bool = False,
    interactive: Optional[bool] = None,
    input_fn: Callable[[str], str] = input,
    output: Callable[[str], None] = lambda s: print(s, file=sys.stderr),
) -> List[Dict[str, str]]:
    auth_nets = [ipaddress.ip_network(a, strict=False) for a in authorized]
    pending = [n for n in nets if not any(n.version == a.version and n.subnet_of(a) for a in auth_nets)]  # type: ignore[arg-type]
    records = _records([n for n in nets if n not in pending], "config.authorized_networks")
    if not pending:
        return records
    targets = ", ".join(str(n) for n in pending)
    if assume_yes:
        return records + _records(pending, "--i-own-these-targets")
    if interactive is None:
        interactive = sys.stdin.isatty()
    if not interactive:
        raise ConsentError(
            f"You must confirm that {targets} belongs to you. In a non-interactive environment, declare it in "
            "network.authorized_networks in the config file, or pass --i-own-these-targets."
        )
    output("\nAuthorization required\n" + CONSENT_STATEMENT + f"\nTargets: {targets}")
    answer = input_fn("Type 'I confirm' or 'yes' to continue; anything else cancels: ").strip().lower()
    if answer not in ACCEPTED_ANSWERS:
        raise ConsentError("Authorization not confirmed; LAN scan cancelled.")
    return records + _records(pending, "interactive")
