"""Test del Policy Engine."""

import datetime
import pathlib

from sg_learner import collector, engine
from sg_learner.store import FlowStore, Observation

FIXTURE = pathlib.Path(__file__).parent / "fixtures" / "ovn_acl_log_sample.txt"

VM_MAC = "fa:16:3e:9e:8d:c4"
VM_IP = "10.0.0.23"
T0 = datetime.datetime(2026, 10, 23, 12, 0, tzinfo=datetime.timezone.utc)


def obs(direction="ingress", protocol="tcp", port=22, remote="172.24.4.1",
        verdict="allow", count=10, icmp_type=None, mac=VM_MAC, vm_ip=VM_IP):
    return Observation(
        vm_mac=mac, vm_ip=vm_ip, direction=direction, protocol=protocol,
        service_port=port, icmp_type=icmp_type, remote_ip=remote,
        verdict=verdict, count=count, first_seen=T0, last_seen=T0,
    )


def described(proposal):
    return [(r.describe(), r.connections) for r in proposal.rules]


def test_single_external_source_becomes_host_rule():
    proposal = engine.build_proposal([obs()], VM_MAC)

    assert described(proposal) == [("ingress tcp/22 da 172.24.4.1/32", 10)]
    assert proposal.vm_ip == VM_IP


def test_many_external_sources_become_public_rule():
    observations = [obs(port=443, remote=f"203.0.113.{i}", count=3)
                    for i in range(1, 6)]

    [rule] = engine.build_proposal(observations, VM_MAC).rules

    assert rule.remote_ip_prefix == "0.0.0.0/0"
    assert rule.connections == 15
    assert len(rule.remotes) == 5


def test_below_public_threshold_keeps_single_hosts():
    observations = [obs(port=443, remote=f"203.0.113.{i}")
                    for i in range(1, 5)]

    rules = engine.build_proposal(observations, VM_MAC).rules

    assert [r.remote_ip_prefix for r in rules] == [
        f"203.0.113.{i}/32" for i in range(1, 5)]


def test_traffic_from_other_vm_becomes_remote_group():
    observations = [
        obs(port=5432, remote="10.0.0.40", count=50),
        obs(port=5432, remote="10.0.0.41", count=20),
    ]
    ip_to_group = {"10.0.0.40": "sg-web", "10.0.0.41": "sg-web"}

    [rule] = engine.build_proposal(observations, VM_MAC, ip_to_group).rules

    assert rule.remote_group == "sg-web"
    assert rule.remote_ip_prefix is None
    assert rule.connections == 70
    assert rule.describe() == "ingress tcp/5432 da gruppo sg-web"


def test_vm_and_external_sources_on_same_port():
    observations = [
        obs(port=80, remote="10.0.0.40"),
        obs(port=80, remote="172.24.4.1"),
    ]

    rules = engine.build_proposal(
        observations, VM_MAC, {"10.0.0.40": "sg-app"}).rules

    assert {(r.remote_group, r.remote_ip_prefix) for r in rules} == {
        ("sg-app", None), (None, "172.24.4.1/32")}


def test_dropped_traffic_is_reported_not_allowed():
    proposal = engine.build_proposal(
        [obs(), obs(port=80, verdict="drop", count=3)], VM_MAC)

    assert [r.port for r in proposal.rules] == [22]
    assert [(b.service_port, b.count) for b in proposal.blocked] == [(80, 3)]


def test_dhcp_is_excluded():
    dhcp = obs(direction="egress", protocol="udp", port=67,
               remote="255.255.255.255", vm_ip="0.0.0.0", count=1)

    proposal = engine.build_proposal([dhcp, obs()], VM_MAC)

    assert [r.port for r in proposal.rules] == [22]
    assert [reason for _, reason in proposal.excluded] == [
        "DHCP, gestito da Neutron"]
    assert proposal.vm_ip == VM_IP


def test_egress_rules_and_icmp():
    proposal = engine.build_proposal([
        obs(direction="egress", port=80, remote="169.254.169.254", count=15),
        obs(protocol="icmp", port=None, icmp_type=8, count=4),
    ], VM_MAC)

    assert described(proposal) == [
        ("ingress icmp tipo 8 da 172.24.4.1/32", 4),
        ("egress tcp/80 verso 169.254.169.254/32", 15),
    ]


def test_low_confidence_and_minimum_connections():
    observations = [obs(port=22, count=1), obs(port=443, count=50)]

    marked = engine.build_proposal(observations, VM_MAC).rules
    filtered = engine.build_proposal(observations, VM_MAC,
                                     min_connections=2).rules

    assert {r.port: r.low_confidence for r in marked} == {22: True, 443: False}
    assert [r.port for r in filtered] == [443]


def test_only_observations_of_the_requested_vm():
    other = obs(mac="fa:16:3e:00:00:99", vm_ip="10.0.0.99", port=3306)

    proposal = engine.build_proposal([obs(), other], VM_MAC)

    assert [r.port for r in proposal.rules] == [22]
    assert proposal.total_connections == 10


def test_ipv6_sources():
    observations = [obs(port=443, remote=f"2001:db8::{i}") for i in range(1, 6)]

    [rule] = engine.build_proposal(observations, VM_MAC).rules

    assert (rule.ethertype, rule.remote_ip_prefix) == ("IPv6", "::/0")


def test_neutron_rule_parameters():
    tcp = engine.build_proposal([obs()], VM_MAC).rules[0]
    icmp = engine.build_proposal(
        [obs(protocol="icmp", port=None, icmp_type=8)], VM_MAC).rules[0]
    group = engine.build_proposal(
        [obs(port=5432, remote="10.0.0.40")], VM_MAC,
        {"10.0.0.40": "abc-123"}).rules[0]

    assert tcp.to_neutron() == {
        "direction": "ingress", "ethertype": "IPv4", "protocol": "tcp",
        "port_range_min": 22, "port_range_max": 22,
        "remote_ip_prefix": "172.24.4.1/32",
    }
    assert icmp.to_neutron()["port_range_min"] == 8
    assert group.to_neutron()["remote_group_id"] == "abc-123"


def test_proposal_from_real_log(tmp_path):
    lines = FIXTURE.read_text().splitlines()
    with FlowStore(tmp_path / "db") as store:
        store.record_many(collector.connections(lines))
        [mac] = store.vm_macs()
        proposal = engine.build_proposal(store.observations(), mac)

    assert proposal.rules
    assert all(r.port != 80 or r.direction == "egress"
               for r in proposal.rules), "la porta 80 in ingresso era bloccata"
    assert any(b.service_port == 80 for b in proposal.blocked)
    print(proposal.summary())
