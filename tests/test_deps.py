from __future__ import annotations

import json

from homeguard.checks import deps as d
from homeguard.models import Severity, Status
from homeguard.osv import (
    OSVClient,
    OSVError,
    cvss3_base_score,
    fixed_versions,
    score_to_severity,
    vuln_severity,
)

VULN = {
    "id": "GHSA-xxxx-yyyy-zzzz",
    "summary": "Demo vulnerability",
    "aliases": ["CVE-2099-0001"],
    "database_specific": {"severity": "HIGH"},
    "affected": [
        {
            "package": {"name": "requests", "ecosystem": "PyPI"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.32.0"}]}],
        }
    ],
}


class FakeOSV(OSVClient):
    def __init__(self, vulns_by_pkg):
        super().__init__(http=self._http)
        self.vulns_by_pkg = vulns_by_pkg
        self.requests = []

    def _http(self, method, url, body):
        self.requests.append((method, url, json.loads(body) if body else None))
        if url.endswith("/v1/querybatch"):
            qs = json.loads(body)["queries"]
            results = [
                {"vulns": [{"id": v} for v in self.vulns_by_pkg.get(q["package"]["name"], [])]} for q in qs
            ]
            return 200, json.dumps({"results": results}).encode()
        if "/v1/vulns/" in url:
            return 200, json.dumps(VULN).encode()
        return 404, b"not found"


def test_parse_requirements():
    text = (
        "requests==2.19.0  # comment\nflask>=2\n-r other.txt\nDjango[argon2]==4.2.1 ; python_version>'3'\n\n"
    )
    res = d.parse_requirements(text, "r.txt")
    assert [(p.name, p.version) for p in res.packages] == [("requests", "2.19.0"), ("Django", "4.2.1")]
    assert res.unpinned == ["flask>=2"]


def test_parse_package_lock_v3_and_v1():
    v3 = {
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "app"},
            "node_modules/lodash": {"version": "4.17.20"},
            "node_modules/a/node_modules/@scope/b": {"version": "1.0.0"},
            "node_modules/local": {"link": True},
        },
    }
    pk = d.parse_package_lock(json.dumps(v3), "p.json").packages
    assert {(p.name, p.version) for p in pk} == {("lodash", "4.17.20"), ("@scope/b", "1.0.0")}
    v1 = {
        "lockfileVersion": 1,
        "dependencies": {"x": {"version": "1.0.0", "dependencies": {"y": {"version": "2.0.0"}}}},
    }
    assert {p.name for p in d.parse_package_lock(json.dumps(v1), "p.json").packages} == {"x", "y"}


def test_parse_toml_locks():
    poetry = '[[package]]\nname = "jinja2"\nversion = "2.10"\n'
    assert d.parse_poetry_lock(poetry, "poetry.lock").packages[0].version == "2.10"
    uv = '[[package]]\nname = "myapp"\nversion = "0.1.0"\nsource = { editable = "." }\n\n[[package]]\nname = "idna"\nversion = "3.6"\n'
    assert [p.name for p in d.parse_uv_lock(uv, "uv.lock").packages] == ["idna"]
    cargo = (
        '[[package]]\nname = "mycrate"\nversion = "0.1.0"\n\n[[package]]\nname = "serde"\nversion = "1.0.0"\n'
        'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
    )
    pk = d.parse_cargo_lock(cargo, "Cargo.lock").packages
    assert [(p.name, p.ecosystem) for p in pk] == [("serde", "crates.io")]


def test_parse_pipfile_lock_and_go_mod():
    pl = {"default": {"urllib3": {"version": "==1.26.0"}}, "develop": {"x": {"version": "*"}}}
    res = d.parse_pipfile_lock(json.dumps(pl), "Pipfile.lock")
    assert res.packages[0].name == "urllib3" and res.unpinned == ["x"]
    gomod = "module example.com/app\n\ngo 1.22\n\nrequire github.com/gin-gonic/gin v1.9.0\nrequire (\n\tgolang.org/x/net v0.17.0 // indirect\n)\n"
    pk = d.parse_go_mod(gomod, "go.mod").packages
    assert [(p.name, p.version) for p in pk] == [
        ("github.com/gin-gonic/gin", "1.9.0"),
        ("golang.org/x/net", "0.17.0"),
    ]


def test_discover_skips_node_modules(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.19.0\n")
    nm = tmp_path / "node_modules" / "x"
    nm.mkdir(parents=True)
    (nm / "package-lock.json").write_text("{}")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "requirements-dev.txt").write_text("pytest==7.0.0\n")
    found = {p.name for p in d.discover_lockfiles([str(tmp_path)])}
    assert found == {"requirements.txt", "requirements-dev.txt"}


def test_run_deps_checks_finds_vuln(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.19.0\nidna==3.7\n")
    client = FakeOSV({"requests": ["GHSA-xxxx-yyyy-zzzz"]})
    fs = d.run_deps_checks([str(tmp_path)], client=client)
    vulns = [f for f in fs if f.check_id.startswith("deps.osv.")]
    assert len(vulns) == 1
    v = vulns[0]
    assert v.status == Status.FAIL and v.severity == Severity.HIGH
    assert "2.32.0" in v.remediation and "CVE-2099-0001" in v.detail
    # only name/version/ecosystem is sent to OSV
    q = client.requests[0][2]["queries"]
    assert q == [
        {"package": {"name": "requests", "ecosystem": "PyPI"}, "version": "2.19.0"},
        {"package": {"name": "idna", "ecosystem": "PyPI"}, "version": "3.7"},
    ]


def test_run_deps_checks_clean_offline_and_error(tmp_path):
    (tmp_path / "requirements.txt").write_text("idna==3.7\n")
    assert any(f.status == Status.PASS for f in d.run_deps_checks([str(tmp_path)], client=FakeOSV({})))
    assert d.run_deps_checks([str(tmp_path)], offline=True)[-1].status == Status.SKIP

    def broken(method, url, body):
        raise OSError("network down")

    fs = d.run_deps_checks([str(tmp_path)], client=OSVClient(http=broken))
    assert fs[-1].status == Status.ERROR
    assert d.run_deps_checks([str(tmp_path / "empty")])[-1].status == Status.SKIP


def test_osv_http_error():
    c = OSVClient(http=lambda m, u, b: (500, b"oops"))
    try:
        c.query_batch([{"package": {"name": "a", "ecosystem": "PyPI"}, "version": "1"}])
    except OSVError as exc:
        assert "500" in str(exc)
    else:
        raise AssertionError("expected OSVError")


def test_cvss3_calculator_known_vectors():
    assert cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8
    assert cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N") == 6.1
    assert cvss3_base_score("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N") == 5.5
    assert cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H") == 10.0
    assert cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N") == 0.0
    assert cvss3_base_score("garbage") is None
    assert score_to_severity(9.8) == Severity.CRITICAL and score_to_severity(5.5) == Severity.MEDIUM


def test_vuln_severity_fallbacks():
    assert vuln_severity({"database_specific": {"severity": "MODERATE"}})[0] == Severity.MEDIUM
    v = {"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}
    assert vuln_severity(v)[0] == Severity.CRITICAL
    assert vuln_severity({})[0] == Severity.MEDIUM
    assert fixed_versions(VULN, "Requests", "pypi") == ["2.32.0"]
    assert fixed_versions(VULN, "other", "PyPI") == []


def test_alias_duplicates_are_merged(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.19.0\n")
    client = FakeOSV({"requests": ["PYSEC-2099-1", "GHSA-xxxx-yyyy-zzzz"]})
    orig = client.http

    def http(method, url, body):
        if url.endswith("/PYSEC-2099-1"):
            return 200, json.dumps({"id": "PYSEC-2099-1", "aliases": ["GHSA-xxxx-yyyy-zzzz"]}).encode()
        return orig(method, url, body)

    client.http = http
    vulns = [
        f for f in d.run_deps_checks([str(tmp_path)], client=client) if f.check_id.startswith("deps.osv.")
    ]
    assert [f.check_id for f in vulns] == ["deps.osv.GHSA-xxxx-yyyy-zzzz"]
