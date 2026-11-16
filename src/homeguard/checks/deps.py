"""Known-vulnerability check for dependencies: parse lock files and batch-query the OSV database.

Supported: requirements*.txt (== pins), Pipfile.lock, poetry.lock, uv.lock,
package-lock.json / npm-shrinkwrap.json, Cargo.lock, go.mod.
"""

from __future__ import annotations

import json
import os
import re
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Tuple

from ..models import Finding, Severity, Status
from ..osv import OSVClient, OSVError, fixed_versions, vuln_severity

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - older Python only
    import tomli as tomllib

CATEGORY = "deps"
SKIP_DIRS = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    ".tox",
    "dist",
    "build",
    "target",
    ".mypy_cache",
}
MAX_FILES = 500


@dataclass(frozen=True)
class Package:
    name: str
    version: str
    ecosystem: str
    source: str


@dataclass
class ParseResult:
    packages: List[Package] = field(default_factory=list)
    unpinned: List[str] = field(default_factory=list)


# ---------------------------------------------------------------- parsers

_REQ_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9._+!-]+)")


def parse_requirements(text: str, source: str) -> ParseResult:
    res = ParseResult()
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "--")) or "://" in line:
            continue
        line = line.split(";", 1)[0].strip()
        m = _REQ_RE.match(line)
        if m:
            res.packages.append(Package(m.group(1), m.group(2), "PyPI", source))
        else:
            res.unpinned.append(line)
    return res


def parse_pipfile_lock(text: str, source: str) -> ParseResult:
    data = json.loads(text)
    res = ParseResult()
    for section in ("default", "develop"):
        for name, meta in (data.get(section) or {}).items():
            ver = str((meta or {}).get("version", ""))
            if ver.startswith("=="):
                res.packages.append(Package(name, ver[2:], "PyPI", source))
            else:
                res.unpinned.append(name)
    return res


def _parse_toml_packages(text: str, source: str, ecosystem: str) -> ParseResult:
    data = tomllib.loads(text)
    res = ParseResult()
    for pkg in data.get("package", []) or []:
        name, ver = pkg.get("name"), pkg.get("version")
        src = pkg.get("source")
        if isinstance(src, dict) and ({"editable", "virtual", "directory", "path"} & set(src)):
            continue  # the local project itself; not queried
        if name and ver:
            res.packages.append(Package(name, str(ver), ecosystem, source))
    return res


def parse_poetry_lock(text: str, source: str) -> ParseResult:
    return _parse_toml_packages(text, source, "PyPI")


def parse_uv_lock(text: str, source: str) -> ParseResult:
    return _parse_toml_packages(text, source, "PyPI")


def parse_cargo_lock(text: str, source: str) -> ParseResult:
    data = tomllib.loads(text)
    res = ParseResult()
    for pkg in data.get("package", []) or []:
        if pkg.get("source", "").startswith("registry+"):
            res.packages.append(Package(pkg["name"], str(pkg["version"]), "crates.io", source))
    return res


def parse_package_lock(text: str, source: str) -> ParseResult:
    data = json.loads(text)
    res = ParseResult()
    seen = set()

    def add(name: str, ver: Optional[str]) -> None:
        if name and ver and (name, ver) not in seen and not ver.startswith(("file:", "link:", "git")):
            seen.add((name, ver))
            res.packages.append(Package(name, ver, "npm", source))

    packages = data.get("packages")
    if isinstance(packages, dict):  # lockfileVersion 2/3
        for path, meta in packages.items():
            if not path or (meta or {}).get("link"):
                continue
            name = meta.get("name") or path.rsplit("node_modules/", 1)[-1]
            add(name, meta.get("version"))
    else:  # lockfileVersion 1

        def walk(deps: Dict) -> None:
            for name, meta in (deps or {}).items():
                add(name, (meta or {}).get("version"))
                walk((meta or {}).get("dependencies") or {})

        walk(data.get("dependencies") or {})
    return res


_GO_REQ_RE = re.compile(r"^\s*(?:require\s+)?([\w.\-/~]+\.[\w.\-/~]+)\s+(v[\w.\-+]+)")


def parse_go_mod(text: str, source: str) -> ParseResult:
    res = ParseResult()
    in_block = False
    for raw in text.splitlines():
        line = raw.split("//", 1)[0].rstrip()
        stripped = line.strip()
        if stripped.startswith("require ("):
            in_block = True
            continue
        if in_block and stripped == ")":
            in_block = False
            continue
        if in_block or stripped.startswith("require "):
            m = _GO_REQ_RE.match(stripped)
            if m:
                res.packages.append(Package(m.group(1), m.group(2).lstrip("v"), "Go", source))
    return res


Parser = Callable[[str, str], ParseResult]


def parser_for(path: Path) -> Optional[Parser]:
    name = path.name
    if name in ("package-lock.json", "npm-shrinkwrap.json"):
        return parse_package_lock
    if name == "Pipfile.lock":
        return parse_pipfile_lock
    if name == "poetry.lock":
        return parse_poetry_lock
    if name == "uv.lock":
        return parse_uv_lock
    if name == "Cargo.lock":
        return parse_cargo_lock
    if name == "go.mod":
        return parse_go_mod
    if re.fullmatch(r"requirements[\w.-]*\.txt", name):
        return parse_requirements
    return None


def discover_lockfiles(paths: Iterable[str]) -> List[Path]:
    found: List[Path] = []
    for p in paths:
        root = Path(os.path.expanduser(p))
        if root.is_file():
            if parser_for(root):
                found.append(root)
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not d.startswith("."))
            for fn in sorted(filenames):
                fp = Path(dirpath) / fn
                if parser_for(fp):
                    found.append(fp)
                    if len(found) >= MAX_FILES:
                        return found
    return found


def collect_packages(paths: Iterable[str]) -> Tuple[List[Package], List[str], List[str]]:
    """Return (packages, unpinned entries, parse errors)."""
    packages: List[Package] = []
    unpinned: List[str] = []
    errors: List[str] = []
    for fp in discover_lockfiles(paths):
        parser = parser_for(fp)
        assert parser is not None
        try:
            res = parser(fp.read_text(encoding="utf-8"), str(fp))
        except Exception as exc:
            errors.append(f"{fp}: {exc}")
            continue
        packages.extend(res.packages)
        unpinned.extend(f"{fp}: {u}" for u in res.unpinned)
    # de-duplicate (keep the first source when a dependency appears in several files)
    uniq: Dict[Tuple[str, str, str], Package] = {}
    for pkg in packages:
        uniq.setdefault((pkg.ecosystem, pkg.name.lower(), pkg.version), pkg)
    return list(uniq.values()), unpinned, errors


# ---------------------------------------------------------------- checks


def run_deps_checks(
    paths: List[str], client: Optional[OSVClient] = None, offline: bool = False
) -> List[Finding]:
    findings: List[Finding] = []
    target = ", ".join(paths)
    packages, unpinned, errors = collect_packages(paths)
    for err in errors:
        findings.append(
            Finding(
                "deps.parse_error",
                CATEGORY,
                "Failed to parse dependency file",
                Status.ERROR,
                target=err.split(":")[0],
                detail=err,
            )
        )
    if unpinned:
        findings.append(
            Finding(
                "deps.unpinned",
                CATEGORY,
                "Unpinned dependencies (cannot be checked precisely)",
                Status.WARN,
                Severity.LOW,
                target=target,
                detail=f"{len(unpinned)} dependencies are not pinned with ==, so installed versions can vary and cannot be matched precisely against the vulnerability database.",
                remediation="Use a lock file (pip-tools / uv lock / poetry lock) or pin versions with == in requirements.",
                evidence="\n".join(unpinned[:50]),
            )
        )
    if not packages:
        findings.append(
            Finding(
                "deps.none",
                CATEGORY,
                "Dependency vulnerability check",
                Status.SKIP,
                target=target,
                detail="No supported dependency lock file found at the given paths.",
            )
        )
        return findings
    if offline:
        findings.append(
            Finding(
                "deps.offline",
                CATEGORY,
                "Dependency vulnerability check",
                Status.SKIP,
                target=target,
                detail=f"Offline mode: found {len(packages)} dependencies but did not query OSV.",
            )
        )
        return findings

    client = client or OSVClient()
    queries = [
        {"package": {"name": p.name, "ecosystem": p.ecosystem}, "version": p.version} for p in packages
    ]
    try:
        ids_per_pkg = client.query_batch(queries)
    except (OSVError, ValueError) as exc:
        findings.append(
            Finding(
                "deps.osv_error",
                CATEGORY,
                "OSV vulnerability query failed",
                Status.ERROR,
                target=target,
                detail=str(exc),
                remediation="Check the network connection and retry, or use --offline to skip.",
            )
        )
        return findings

    # fetch vulnerability details concurrently (each ID requested once)
    def fetch(vid: str) -> Dict:
        try:
            return client.get_vuln(vid)
        except (OSVError, ValueError) as exc:
            return {"id": vid, "summary": f"(failed to fetch details: {exc})"}

    all_ids = sorted({vid for ids in ids_per_pkg for vid in ids})
    with ThreadPoolExecutor(max_workers=8) as pool:
        details = dict(zip(all_ids, pool.map(fetch, all_ids)))

    vuln_count = 0
    for pkg, ids in zip(packages, ids_per_pkg):
        seen: set = set()
        # GHSA records usually carry a severity, so keep them first; merge PYSEC/CVE aliases of the same issue
        for vid in sorted(ids, key=lambda i: (not i.startswith("GHSA-"), i)):
            vuln = details[vid]
            names = {vid, *(vuln.get("aliases") or [])}
            if names & seen:
                continue
            seen |= names
            sev, basis = vuln_severity(vuln)
            fixes = fixed_versions(vuln, pkg.name, pkg.ecosystem)
            aliases = [a for a in vuln.get("aliases") or [] if a != vid]
            summary = vuln.get("summary") or (vuln.get("details") or "")[:240] or "no summary"
            if fixes:
                remediation = f"Upgrade {pkg.name} from {pkg.version} to a fixed version: {', '.join(fixes)} (pick the lowest fix at or above your current major version)."
            else:
                remediation = f"No fixed version yet; follow the {vid} advisory and consider replacing {pkg.name} or applying mitigations."
            vuln_count += 1
            findings.append(
                Finding(
                    check_id=f"deps.osv.{vid}",
                    category=CATEGORY,
                    title=f"{pkg.name} {pkg.version} has known vulnerability {vid}",
                    status=Status.FAIL if sev.rank >= Severity.HIGH.rank else Status.WARN,
                    severity=sev,
                    target=pkg.source,
                    detail=f"[{pkg.ecosystem}] {summary}"
                    + (f" (aliases: {', '.join(aliases)})" if aliases else "")
                    + f"; {basis}",
                    remediation=remediation,
                    references=[f"https://osv.dev/vulnerability/{vid}"],
                )
            )
    if vuln_count == 0:
        findings.append(
            Finding(
                "deps.clean",
                CATEGORY,
                "No known vulnerabilities in dependencies",
                Status.PASS,
                Severity.HIGH,
                target=target,
                detail=f"Checked {len(packages)} dependencies against OSV.",
            )
        )
    else:
        findings.append(
            Finding(
                "deps.inventory",
                CATEGORY,
                "Dependency check statistics",
                Status.INFO,
                target=target,
                detail=f"Checked {len(packages)} dependencies and found {vuln_count} known vulnerability records.",
            )
        )
    return findings
