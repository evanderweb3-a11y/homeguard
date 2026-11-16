from __future__ import annotations

from homeguard.checks import macos as m
from homeguard.models import Severity, Status
from homeguard.runner import CommandResult, CommandRunner

from conftest import LSOF_SAMPLE, NETSTAT_SAMPLE, FakeRunner, healthy_mac_responses, ok


def by_id(findings):
    return {f.check_id: f for f in findings}


def test_healthy_mac_has_no_problems():
    findings = m.run_local_checks(FakeRunner(healthy_mac_responses()), system="Darwin")
    problems = [f for f in findings if f.is_problem or f.status == Status.ERROR]
    assert problems == []
    ids = by_id(findings)
    assert ids["local.firewall"].status == Status.PASS
    assert ids["local.filevault"].status == Status.PASS
    assert ids["local.update.pending"].status == Status.SKIP


def test_insecure_mac_flags_problems():
    r = healthy_mac_responses()
    r[(m.SOCKETFILTERFW, "--getglobalstate")] = ok("Firewall is disabled. (State = 0)\n")
    r[(m.SOCKETFILTERFW, "--getstealthmode")] = ok("Firewall stealth mode is off\n")
    r[("fdesetup", "status")] = ok("FileVault is Off.\n")
    r[("csrutil", "status")] = ok("System Integrity Protection status: disabled.\n")
    r[("spctl", "--status")] = ok("assessments disabled\n")
    r[("sw_vers", "-productVersion")] = ok("12.7.6\n")
    r[("sysadminctl", "-screenLock", "status")] = ok("", "screenLock is off\n")
    r[("defaults", "read", m.SOFTWARE_UPDATE_DOMAIN, "CriticalUpdateInstall")] = ok("0\n")
    r[("defaults", "read", m.LOGINWINDOW_DOMAIN, "autoLoginUser")] = ok("kid\n")
    r[("defaults", "read", m.LOGINWINDOW_DOMAIN, "GuestEnabled")] = ok("1\n")
    ids = by_id(m.run_local_checks(FakeRunner(r), system="Darwin"))
    for cid in [
        "local.firewall",
        "local.filevault",
        "local.sip",
        "local.gatekeeper",
        "local.os_version",
        "local.screen_lock",
        "local.update.CriticalUpdateInstall",
        "local.auto_login",
    ]:
        assert ids[cid].status == Status.FAIL, cid
        assert ids[cid].remediation, cid
    assert ids["local.firewall_stealth"].status == Status.WARN
    assert ids["local.guest"].status == Status.WARN
    assert ids["local.firewall"].severity == Severity.HIGH


def test_firewall_block_all_state_counts_as_enabled():
    r = {
        (m.SOCKETFILTERFW, "--getglobalstate"): ok(
            "Firewall is blocking all non-essential incoming connections. (State = 2)"
        ),
        (m.SOCKETFILTERFW, "--getstealthmode"): ok("Stealth mode enabled"),
    }
    ids = by_id(m.check_firewall(FakeRunner(r), m.LocalOptions()))
    assert ids["local.firewall"].status == Status.PASS
    assert ids["local.firewall_stealth"].status == Status.PASS


def test_unparseable_output_is_error_not_pass():
    f = m.check_filevault(FakeRunner({("fdesetup",): ok("something new")}), m.LocalOptions())[0]
    assert f.status == Status.ERROR


def test_screen_lock_delay():
    r = FakeRunner({("sysadminctl",): ok("", "screenLock delay is 3600 seconds")})
    f = m.check_screen_lock(r, m.LocalOptions())[0]
    assert f.status == Status.WARN and "3600" in f.detail


def test_parse_netstat_and_exposure():
    socks = m.parse_netstat(NETSTAT_SAMPLE)
    ports = {(s.port, s.exposed) for s in socks}
    assert (22, True) in ports and (631, False) in ports and (3000, True) in ports
    assert all(s.port != 52344 for s in socks)  # ESTABLISHED is not listening


def test_listening_ports_flags_sharing_and_unknown_but_not_benign():
    r = FakeRunner({("netstat",): ok(NETSTAT_SAMPLE), ("lsof",): ok(LSOF_SAMPLE)})
    ids = by_id(m.check_listening_ports(r, m.LocalOptions()))
    assert ids["local.sharing.22"].status == Status.WARN
    lp = ids["local.listening_ports"]
    assert "3000 (node)" in lp.detail
    assert "62070" not in lp.detail  # rapportd is a built-in Apple service


def test_listening_ports_limited_visibility_falls_back_to_lsof():
    r = FakeRunner({("netstat",): ok("Active Multipath Internet connections\n"), ("lsof",): ok(LSOF_SAMPLE)})
    ids = by_id(m.check_listening_ports(r, m.LocalOptions()))
    assert ids["local.sharing"].status == Status.INFO  # must not falsely report a pass
    assert "lsof" in ids["local.listening_inventory"].detail
    assert "3000 (node)" in ids["local.listening_ports"].detail


def test_pending_updates_enabled():
    r = FakeRunner(
        {("softwareupdate",): ok("Software Update Tool\n* Label: macOS 27.2.2-27C99\n\tTitle: macOS\n")}
    )
    f = m.check_pending_updates(r, m.LocalOptions(check_pending_updates=True))[0]
    assert f.status == Status.WARN and "27.2.2" in f.detail


def test_non_darwin_is_skipped():
    findings = m.run_local_checks(FakeRunner({}), system="Linux")
    assert len(findings) == 1 and findings[0].status == Status.SKIP


def test_check_exception_becomes_error(monkeypatch):
    def boom(runner, opts):
        raise RuntimeError("x")

    monkeypatch.setattr(m, "CHECKS", [("boom", boom)])
    f = m.run_local_checks(FakeRunner({}), system="Darwin")[0]
    assert f.status == Status.ERROR


def test_command_runner_handles_missing_command():
    res = CommandRunner(timeout=2).run(["definitely-not-a-real-command-xyz"])
    assert res.returncode == 127 and not res.ok
    assert isinstance(res, CommandResult)
