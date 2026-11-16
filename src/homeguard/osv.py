"""Client for the OSV open vulnerability database (https://osv.dev).

Only "package name + version + ecosystem" is sent to OSV; no file paths, host names or other data.
"""

from __future__ import annotations

import json
import math
import urllib.error
import urllib.request
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from . import __version__
from .models import Severity

HttpFn = Callable[[str, str, Optional[bytes]], Tuple[int, bytes]]
BATCH_SIZE = 1000


def urllib_http(method: str, url: str, body: Optional[bytes], timeout: float = 30.0) -> Tuple[int, bytes]:
    req = urllib.request.Request(url, data=body, method=method)
    req.add_header("User-Agent", f"homeguard/{__version__}")
    if body is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed https endpoint
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


class OSVError(RuntimeError):
    pass


class OSVClient:
    def __init__(self, base_url: str = "https://api.osv.dev", http: Optional[HttpFn] = None):
        self.base_url = base_url.rstrip("/")
        self.http = http or urllib_http
        self._cache: Dict[str, Dict[str, Any]] = {}

    def _call(self, method: str, path: str, payload: Optional[dict] = None) -> Dict[str, Any]:
        body = json.dumps(payload).encode() if payload is not None else None
        try:
            status, data = self.http(method, self.base_url + path, body)
        except OSError as exc:
            raise OSVError(f"Cannot reach OSV: {exc}") from exc
        if status != 200:
            raise OSVError(f"OSV returned HTTP {status}: {data[:200]!r}")
        return json.loads(data or b"{}")

    def query_batch(self, queries: Sequence[Dict[str, Any]]) -> List[List[str]]:
        """Batch query; returns one list of vulnerability IDs per query, in order."""
        out: List[List[str]] = []
        for i in range(0, len(queries), BATCH_SIZE):
            chunk = list(queries[i : i + BATCH_SIZE])
            resp = self._call("POST", "/v1/querybatch", {"queries": chunk})
            results = resp.get("results", [])
            if len(results) != len(chunk):
                raise OSVError("OSV returned a different number of results than queries")
            for r in results:
                out.append([v["id"] for v in r.get("vulns", []) or []])
        return out

    def get_vuln(self, vuln_id: str) -> Dict[str, Any]:
        if vuln_id not in self._cache:
            self._cache[vuln_id] = self._call("GET", f"/v1/vulns/{vuln_id}")
        return self._cache[vuln_id]


# ---------------------------------------------------------------- severity

_CVSS3 = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def _roundup(x: float) -> float:
    i = round(x * 100000)
    if i % 10000 == 0:
        return i / 100000.0
    return (math.floor(i / 10000) + 1) / 10.0


def cvss3_base_score(vector: str) -> Optional[float]:
    """Compute the CVSS v3.x base score per the specification. Returns None if the vector cannot be parsed."""
    try:
        parts = dict(p.split(":", 1) for p in vector.split("/") if ":" in p and not p.startswith("CVSS"))
        scope_changed = parts["S"] == "C"
        av = _CVSS3["AV"][parts["AV"]]
        ac = _CVSS3["AC"][parts["AC"]]
        ui = _CVSS3["UI"][parts["UI"]]
        pr = {"N": 0.85, "L": 0.68 if scope_changed else 0.62, "H": 0.5 if scope_changed else 0.27}[
            parts["PR"]
        ]
        c, i, a = (_CVSS3["CIA"][parts[k]] for k in ("C", "I", "A"))
    except (KeyError, ValueError):
        return None
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    exploitability = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0
    if scope_changed:
        return _roundup(min(1.08 * (impact + exploitability), 10))
    return _roundup(min(impact + exploitability, 10))


def score_to_severity(score: float) -> Severity:
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0:
        return Severity.LOW
    return Severity.INFO


def vuln_severity(vuln: Dict[str, Any]) -> Tuple[Severity, str]:
    """Return (severity, basis). Prefer the database rating, then a computed CVSS v3 score."""
    db = (vuln.get("database_specific") or {}).get("severity")
    if isinstance(db, str) and db:
        try:
            return Severity.parse(db), f"database rating {db}"
        except ValueError:
            pass
    for sev in vuln.get("severity") or []:
        if str(sev.get("type", "")).startswith("CVSS_V3"):
            score = cvss3_base_score(str(sev.get("score", "")))
            if score is not None:
                return score_to_severity(score), f"CVSS v3 {score}"
    for aff in vuln.get("affected") or []:
        es = (aff.get("ecosystem_specific") or {}).get("severity")
        if isinstance(es, str):
            try:
                return Severity.parse(es), f"ecosystem rating {es}"
            except ValueError:
                pass
    return Severity.MEDIUM, "no rating provided (treated as medium)"


def fixed_versions(vuln: Dict[str, Any], name: str, ecosystem: str) -> List[str]:
    fixed: List[str] = []
    for aff in vuln.get("affected") or []:
        pkg = aff.get("package") or {}
        if (
            pkg.get("name", "").lower() != name.lower()
            or pkg.get("ecosystem", "").lower() != ecosystem.lower()
        ):
            continue
        for rng in aff.get("ranges") or []:
            for ev in rng.get("events") or []:
                if "fixed" in ev and ev["fixed"] not in fixed:
                    fixed.append(ev["fixed"])
    return fixed
