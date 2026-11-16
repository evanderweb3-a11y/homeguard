from __future__ import annotations

import json

import pytest

from homeguard import cli
from homeguard.checks import macos as m
from homeguard.checks import network as n
from homeguard.config import ConfigError, from_dict, load_config
from homeguard.models import Finding, HostInfo, ScanResult, Severity, Status
from homeguard.report import render_html, render_json, render_markdown, write_reports

from conftest import FakeRunner, healthy_mac_responses, ok
from test_deps import FakeOSV


def sample_result():
    r = ScanResult(
        tool_version="0.1.0", started_at="2026-01-01T00:00:00+08:00", hostname="mac", platform="Darwin"
    )
    r.scopes = ["local", "network"]
    r.findings = [
        Finding(
            "local.firewall",
            "local",
            "Application firewall is enabled",
            Status.FAIL,
            Severity.HIGH,
            detail="off <b>x</b>",
            remediation="turn on the firewall",
            evidence="State = 0",
            references=["https://example.com/a"],
        ),
        Finding("local.sip", "local", "SIP", Status.PASS, Severity.HIGH),
        Finding(
            "network.port.23",
            "network",
            "Telnet | service",
            Status.FAIL,
            Severity.CRITICAL,
            target="192.168.1.9",
        ),
    ]
    r.hosts = [HostInfo("192.168.1.9", "aa:bb", "tv.local", {23: "<script>alert(1)</script>"})]
    r.authorization = [
        {"target": "192.168.1.0/24", "method": "interactive", "time": "t", "statement": "I confirm"}
    ]
    return r


def test_markdown_report():
    md = render_markdown(sample_result())
    assert "# homeguard security self-audit report" in md
    assert md.index("Telnet") < md.index("turn on the firewall")  # critical issues come first
    assert "Telnet \\| service" in md  # pipes are escaped in tables
    assert "Scan authorization" in md and "tv.local" in md


def test_html_report_escapes_untrusted_content():
    out = render_html(sample_result())
    assert "<script>alert(1)</script>" not in out
    assert "&lt;script&gt;" in out
    assert "off &lt;b&gt;x&lt;/b&gt;" in out
    assert "prefers-color-scheme" in out


def test_json_report_and_summary():
    data = json.loads(render_json(sample_result()))
    assert (
        data["summary"]["critical"] == 1 and data["summary"]["high"] == 1 and data["summary"]["passed"] == 1
    )
    assert data["findings"][0]["severity"] == "critical"


def test_write_reports(tmp_path):
    paths = write_reports(sample_result(), str(tmp_path), ["md", "html", "json"])
    assert sorted(p.suffix for p in paths) == [".html", ".json", ".md"]
    with pytest.raises(ValueError):
        write_reports(sample_result(), str(tmp_path), ["pdf"])


def test_config_parsing(tmp_path):
    cfg = from_dict(
        {
            "general": {"formats": ["json"]},
            "network": {"enabled": True, "targets": ["192.168.1.0/24"], "timeout": 1},
            "deps": {"enabled": True, "paths": ["~/code"]},
        }
    )
    assert (
        cfg.formats == ["json"]
        and cfg.network_enabled
        and cfg.timeout == 1.0
        and cfg.deps_paths == ["~/code"]
    )
    with pytest.raises(ConfigError):
        from_dict({"network": {"bogus": 1}})
    with pytest.raises(ConfigError):
        from_dict({"local": {"enabled": "yes"}})
    with pytest.raises(ConfigError):
        load_config(str(tmp_path / "missing.toml"))
    p = tmp_path / "c.toml"
    p.write_text("[general]\nfail_on = 'medium'\n")
    assert load_config(str(p)).fail_on == "medium"


def test_example_config_is_valid():
    from pathlib import Path

    cfg = load_config(str(Path(__file__).resolve().parent.parent / "config.example.toml"))
    assert cfg.source


def test_cli_local_end_to_end(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(m.platform, "system", lambda: "Darwin")
    r = healthy_mac_responses()
    r[(m.SOCKETFILTERFW, "--getglobalstate")] = ok("Firewall is disabled. (State = 0)")
    rc = cli.run(["local", "-o", str(tmp_path), "-f", "md,json"], runner=FakeRunner(r))
    assert rc == 1  # a high-severity problem exists
    out = capsys.readouterr().out.strip().splitlines()
    assert len(out) == 2
    data = json.loads(open([p for p in out if p.endswith(".json")][0]).read())
    assert data["summary"]["high"] == 1
    assert cli.run(["local", "-o", str(tmp_path), "--fail-on", "none", "-q"], runner=FakeRunner(r)) == 0


def test_cli_lan_requires_consent_and_refuses_public(tmp_path):
    assert cli.run(["lan", "8.8.8.8", "--i-own-these-targets", "-o", str(tmp_path)]) == 2
    # non-interactive and not confirmed -> refused
    rc = cli.run(["lan", "127.0.0.1", "-o", str(tmp_path)], input_fn=lambda _: "no")
    assert rc == 2


def test_cli_lan_with_flag(tmp_path, capsys):
    runner = FakeRunner({("arp",): ok("")})
    probe = lambda ip, port, t: n.OPEN if port == 5555 else n.CLOSED  # noqa: E731
    rc = cli.run(
        ["lan", "127.0.0.1", "--i-own-these-targets", "--no-resolve", "-o", str(tmp_path), "-f", "json"],
        runner=runner,
        probe=probe,
    )
    assert rc == 1
    path = capsys.readouterr().out.strip()
    data = json.loads(open(path).read())
    assert data["authorization"][0]["method"] == "--i-own-these-targets"
    assert data["hosts"][0]["open_ports"] == {"5555": ""}


def test_cli_bad_ports(tmp_path):
    assert cli.run(["lan", "127.0.0.1", "--ports", "abc", "--i-own-these-targets", "-o", str(tmp_path)]) == 2


def test_cli_deps(tmp_path, capsys):
    (tmp_path / "requirements.txt").write_text("requests==2.19.0\n")
    rc = cli.run(
        ["deps", str(tmp_path), "-o", str(tmp_path / "out"), "-f", "md"],
        osv_client=FakeOSV({"requests": ["GHSA-1"]}),
    )
    assert rc == 1
    md = open(capsys.readouterr().out.strip()).read()
    assert "requests 2.19.0" in md and "2.32.0" in md


def test_cli_all_without_anything_enabled(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert cli.run(["all", "--no-local"]) == 2


def test_list_checks(capsys):
    assert cli.run(["list-checks"]) == 0
    assert "5555" in capsys.readouterr().out
