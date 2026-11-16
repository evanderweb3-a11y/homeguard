"""Core data model: individual check results (Finding) and a scan summary (ScanResult)."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return _SEV_RANK[self]

    @property
    def label(self) -> str:
        return _SEV_LABEL[self]

    @classmethod
    def parse(cls, value: str) -> Severity:
        v = value.strip().lower()
        aliases = {"moderate": "medium", "important": "high", "none": "info", "unknown": "medium"}
        return cls(aliases.get(v, v))


_SEV_RANK = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}
_SEV_LABEL = {
    Severity.CRITICAL: "Critical",
    Severity.HIGH: "High",
    Severity.MEDIUM: "Medium",
    Severity.LOW: "Low",
    Severity.INFO: "Info",
}


class Status(str, Enum):
    PASS = "pass"  # check passed
    FAIL = "fail"  # problem found, needs fixing
    WARN = "warn"  # risk found, fixing recommended
    INFO = "info"  # informational only (inventory etc.)
    SKIP = "skip"  # not applicable / skipped
    ERROR = "error"  # the check itself failed

    @property
    def label(self) -> str:
        return _STATUS_LABEL[self]


_STATUS_LABEL = {
    Status.PASS: "Pass",
    Status.FAIL: "Fail",
    Status.WARN: "Warning",
    Status.INFO: "Info",
    Status.SKIP: "Skipped",
    Status.ERROR: "Error",
}

CATEGORY_LABELS = {
    "local": "Local security baseline",
    "network": "LAN assets and services",
    "deps": "Known vulnerabilities in dependencies",
}


@dataclass
class Finding:
    check_id: str
    category: str
    title: str
    status: Status
    severity: Severity = Severity.INFO
    target: str = "this Mac"
    detail: str = ""
    remediation: str = ""
    evidence: str = ""
    references: List[str] = field(default_factory=list)

    @property
    def is_problem(self) -> bool:
        return self.status in (Status.FAIL, Status.WARN)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        d["severity"] = self.severity.value
        return d


@dataclass
class HostInfo:
    ip: str
    mac: str = ""
    hostname: str = ""
    open_ports: Dict[int, str] = field(default_factory=dict)  # port -> banner (may be empty)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip": self.ip,
            "mac": self.mac,
            "hostname": self.hostname,
            "open_ports": {str(k): v for k, v in sorted(self.open_ports.items())},
        }


@dataclass
class ScanResult:
    tool_version: str
    started_at: str
    finished_at: str = ""
    hostname: str = ""
    platform: str = ""
    scopes: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    hosts: List[HostInfo] = field(default_factory=list)
    authorization: List[Dict[str, str]] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    def problems(self) -> List[Finding]:
        return sort_findings([f for f in self.findings if f.is_problem])

    def summary(self) -> Dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            if f.is_problem:
                counts[f.severity.value] += 1
        counts["passed"] = sum(1 for f in self.findings if f.status == Status.PASS)
        counts["errors"] = sum(1 for f in self.findings if f.status == Status.ERROR)
        counts["total_checks"] = len(self.findings)
        return counts

    def max_problem_severity(self) -> Severity | None:
        probs = self.problems()
        return probs[0].severity if probs else None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool": "homeguard",
            "tool_version": self.tool_version,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "hostname": self.hostname,
            "platform": self.platform,
            "scopes": self.scopes,
            "summary": self.summary(),
            "authorization": self.authorization,
            "notes": self.notes,
            "hosts": [h.to_dict() for h in self.hosts],
            "findings": [f.to_dict() for f in sort_findings(self.findings)],
        }


_STATUS_ORDER = {
    Status.FAIL: 0,
    Status.WARN: 1,
    Status.ERROR: 2,
    Status.INFO: 3,
    Status.PASS: 4,
    Status.SKIP: 5,
}


def sort_findings(findings: List[Finding]) -> List[Finding]:
    return sorted(
        findings,
        key=lambda f: (_STATUS_ORDER[f.status], -f.severity.rank, f.category, f.target, f.check_id),
    )
