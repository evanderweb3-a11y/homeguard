from __future__ import annotations

import ipaddress
import socket
import threading

import pytest

from homeguard.checks import network as n
from homeguard.checks.services import assess_ssh_banner
from homeguard.consent import ConsentError, confirm_targets
from homeguard.models import HostInfo, Severity, Status

from conftest import FakeRunner, ok


@pytest.mark.parametrize("target", ["8.8.8.8", "1.1.1.0/24", "100.64.0.1", "172.32.0.1", "0.0.0.0/0"])
def test_public_targets_are_refused(target):
    with pytest.raises(n.TargetError):
        n.validate_targets(n.parse_targets([target]))


@pytest.mark.parametrize(
    "target", ["192.168.1.0/24", "10.0.0.5", "172.16.3.0/24", "127.0.0.1", "169.254.1.1"]
)
def test_private_targets_allowed(target):
    n.validate_targets(n.parse_targets([target]))


def test_too_large_network_refused_and_hard_cap():
    with pytest.raises(n.TargetError):
        n.validate_targets(n.parse_targets(["10.0.0.0/16"]))
    with pytest.raises(n.TargetError):
        n.validate_targets(n.parse_targets(["10.0.0.0/18"]), max_hosts=10**9)  # hard maximum 4096


def test_parse_targets_errors():
    with pytest.raises(n.TargetError):
        n.parse_targets(["not-an-ip"])
    with pytest.raises(n.TargetError):
        n.parse_targets(["fe80::1"])
    assert len(n.parse_targets(["192.168.1.1, 192.168.1.2"])) == 2


def test_parse_arp():
    out = (
        "? (192.168.0.1) at 4c:10:d5:c8:c0:d6 on en0 ifscope [ethernet]\n"
        "? (192.168.0.9) at (incomplete) on en0 ifscope [ethernet]\n"
        "? (192.168.0.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]\n"
    )
    assert n.parse_arp(out) == {"192.168.0.1": "4c:10:d5:c8:c0:d6"}


def test_scan_hosts_with_fake_probe():
    open_map = {("192.168.50.2", 5555), ("192.168.50.2", 80), ("192.168.50.3", 23)}
    refused = {("192.168.50.4", 80)}
    calls = []

    def probe(ip, port, timeout):
        calls.append((ip, port))
        if (ip, port) in open_map:
            return n.OPEN
        if (ip, port) in refused:
            return n.CLOSED
        return n.FILTERED

    opts = n.NetworkOptions(resolve_names=False, workers=8)
    hosts = n.scan_hosts(
        [ipaddress.ip_network("192.168.50.0/29")],
        opts,
        arp={"192.168.50.6": "aa:bb:cc:dd:ee:ff"},
        probe=probe,
        banner=lambda ip, p, mode: "HTTP/1.0 200 OK",
        # .3 only has Telnet open (not a discovery port); it is found via the refreshed ARP table. Out-of-scope entries are ignored
        arp_refresh=lambda: {"192.168.50.3": "11:22:33:44:55:66", "10.9.9.9": "00:00:00:00:00:01"},
    )
    by_ip = {h.ip: h for h in hosts}
    assert set(by_ip) == {"192.168.50.2", "192.168.50.3", "192.168.50.4", "192.168.50.6"}
    assert set(by_ip["192.168.50.2"].open_ports) == {80, 5555}
    assert by_ip["192.168.50.2"].open_ports[80] == "HTTP/1.0 200 OK"
    assert by_ip["192.168.50.6"].mac == "aa:bb:cc:dd:ee:ff"
    assert set(by_ip["192.168.50.3"].open_ports) == {23}
    assert all(ipaddress.ip_address(ip) in ipaddress.ip_network("192.168.50.0/29") for ip, _ in calls)
    # offline hosts only get the discovery ports, not a full port scan
    assert sum(1 for ip, _ in calls if ip == "192.168.50.5") == len(n.DISCOVERY_PORTS)


def test_evaluate_hosts_rules():
    hosts = [
        HostInfo(
            "192.168.1.20", open_ports={5555: "", 2375: "", 22: "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13"}
        ),
        HostInfo("192.168.1.21", open_ports={443: ""}),
    ]
    fs = n.evaluate_hosts(hosts, "192.168.1.0/24")
    by = {(f.target.split(" (")[0], f.check_id): f for f in fs}
    assert by[("192.168.1.20", "network.port.2375")].severity == Severity.CRITICAL
    assert by[("192.168.1.20", "network.port.5555")].status == Status.FAIL
    assert by[("192.168.1.20", "network.ssh_version")].severity == Severity.HIGH
    assert by[("192.168.1.21", "network.port.443")].status == Status.INFO


def test_evaluate_no_hosts_and_clean():
    assert n.evaluate_hosts([], "192.168.1.0/24")[0].status == Status.INFO
    fs = n.evaluate_hosts([HostInfo("192.168.1.2", open_ports={443: ""})], "x")
    assert any(f.status == Status.PASS for f in fs)


def test_ssh_banner_assessment():
    assert assess_ssh_banner("SSH-2.0-OpenSSH_9.9") is None
    assert assess_ssh_banner("SSH-2.0-OpenSSH_8.4p1")[0] == Severity.MEDIUM
    assert assess_ssh_banner("SSH-2.0-OpenSSH_9.7p1")[0] == Severity.HIGH
    assert assess_ssh_banner("SSH-2.0-dropbear_2022.83") is None


def test_real_probe_and_banner_on_localhost():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    port = srv.getsockname()[1]

    def serve():
        for _ in range(2):
            try:
                c, _ = srv.accept()
            except OSError:
                return
            c.sendall(b"SSH-2.0-OpenSSH_9.6p1 test\r\n")
            c.close()

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    assert n.probe_port("127.0.0.1", port, 1.0) == n.OPEN
    assert n.grab_banner("127.0.0.1", port, "passive").startswith("SSH-2.0-OpenSSH_9.6p1")
    srv.close()
    assert n.probe_port("127.0.0.1", port, 1.0) in (n.CLOSED, n.FILTERED)


def test_run_network_checks_filters_arp_to_scope():
    runner = FakeRunner(
        {
            ("arp",): ok(
                "? (127.0.0.1) at 00:11:22:33:44:55 on lo0\n? (192.168.9.9) at 00:11:22:33:44:66 on en0\n"
            )
        }
    )
    hosts, findings = n.run_network_checks(
        [ipaddress.ip_network("127.0.0.1/32")],
        n.NetworkOptions(resolve_names=False),
        runner=runner,
        probe=lambda ip, p, t: n.FILTERED,
    )
    assert [h.ip for h in hosts] == ["127.0.0.1"]


# ------------------------------------------------------------ consent

NETS = [ipaddress.ip_network("192.168.1.0/24")]


def test_consent_from_config():
    recs = confirm_targets(NETS, authorized=["192.168.0.0/16"], interactive=False)
    assert recs[0]["method"] == "config.authorized_networks"


def test_consent_flag():
    assert confirm_targets(NETS, assume_yes=True, interactive=False)[0]["method"] == "--i-own-these-targets"


def test_consent_non_interactive_refused():
    with pytest.raises(ConsentError):
        confirm_targets(NETS, interactive=False)


def test_consent_interactive_yes_and_no():
    recs = confirm_targets(NETS, interactive=True, input_fn=lambda _: "I confirm", output=lambda s: None)
    assert recs[0]["method"] == "interactive"
    with pytest.raises(ConsentError):
        confirm_targets(NETS, interactive=True, input_fn=lambda _: "no", output=lambda s: None)
