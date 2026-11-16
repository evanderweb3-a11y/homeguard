"""Thin wrapper around subprocess so tests can swap in a fake command runner."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import Sequence


@dataclass
class CommandResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""

    @property
    def output(self) -> str:
        return (self.stdout or "") + (self.stderr or "")

    @property
    def ok(self) -> bool:
        return self.returncode == 0


class CommandRunner:
    """Runs read-only system query commands. Never uses a shell and never escalates privileges."""

    def __init__(self, timeout: float = 20.0):
        self.timeout = timeout

    def run(self, args: Sequence[str], timeout: float | None = None) -> CommandResult:
        try:
            proc = subprocess.run(
                list(args),
                capture_output=True,
                text=True,
                stdin=subprocess.DEVNULL,  # keep commands from hanging on a password prompt
                timeout=timeout or self.timeout,
                check=False,
            )
        except FileNotFoundError:
            return CommandResult(127, "", f"command not found: {args[0]}")
        except PermissionError:
            return CommandResult(126, "", f"permission denied: {args[0]}")
        except subprocess.TimeoutExpired:
            return CommandResult(124, "", f"timeout after {timeout or self.timeout}s: {' '.join(args)}")
        return CommandResult(proc.returncode, proc.stdout, proc.stderr)
