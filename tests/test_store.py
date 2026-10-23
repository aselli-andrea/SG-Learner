"""Test del Flow Store."""

import datetime
import pathlib

import pytest

from sg_learner import collector
from sg_learner.store import FlowStore

FIXTURE = pathlib.Path(__file__).parent / "fixtures" / "ovn_acl_log_sample.txt"

VM_MAC = "fa:16:3e:9e:8d:c4"
OTHER_MAC = "fa:16:3e:00:00:02"
T0 = datetime.datetime(2026, 10, 23, 12, 0, tzinfo=datetime.timezone.utc)


def make_flow(minutes=0, direction=collector.INGRESS, protocol="tcp",
              port=22, remote="172.24.4.1", verdict="allow", mac=VM_MAC,
              vm_ip="10.0.0.37", icmp_type=None):
    """Crea un Flow di prova (come se fosse letto dal log di OVN)."""
    ingress = direction == collector.INGRESS
    return collector.Flow(
        timestamp=T0 + datetime.timedelta(minutes=minutes),
        log_name="neutron-test",
        verdict=verdict,
        direction=direction,
        protocol=protocol,
        src_mac="fa:16:3e:aa:aa:aa" if ingress else mac,
        dst_mac=mac if ingress else "fa:16:3e:aa:aa:aa",
        src_ip=remote if ingress else vm_ip,
        dst_ip=vm_ip if ingress else remote,
        src_port=None if protocol == "icmp" else 40000 + minutes,
        dst_port=None if protocol == "icmp" else port,
        tcp_flags=frozenset({"syn"}) if protocol == "tcp" else frozenset(),
        icmp_type=icmp_type,
    )


@pytest.fixture
def store(tmp_path):
    with FlowStore(tmp_path / "sg-learner.db") as s:
        yield s


def test_same_service_is_aggregated(store):
    store.record_many([make_flow(0), make_flow(5), make_flow(10)])

    [obs] = store.observations()
    assert (obs.direction, obs.protocol, obs.service_port) == (
        "ingress", "tcp", 22)
    assert obs.remote_ip == "172.24.4.1"
    assert obs.vm_ip == "10.0.0.37"
    assert obs.count == 3
    assert obs.first_seen == T0
    assert obs.last_seen == T0 + datetime.timedelta(minutes=10)


def test_different_remote_or_verdict_are_separate(store):
    store.record_many([
        make_flow(0, remote="172.24.4.1"),
        make_flow(1, remote="172.24.4.50"),
        make_flow(2, port=80, verdict="drop"),
    ])

    summary = [(o.service_port, o.remote_ip, o.verdict, o.count)
               for o in store.observations()]
    assert summary == [
        (22, "172.24.4.1", "allow", 1),
        (22, "172.24.4.50", "allow", 1),
        (80, "172.24.4.1", "drop", 1),
    ]


def test_icmp_without_ports(store):
    store.record_many([make_flow(0, protocol="icmp", icmp_type=8),
                       make_flow(1, protocol="icmp", icmp_type=8)])

    [obs] = store.observations()
    assert obs.protocol == "icmp"
    assert obs.service_port is None
    assert obs.icmp_type == 8
    assert obs.count == 2


def test_out_of_order_timestamps(store):
    store.record_many([make_flow(10), make_flow(0)])

    [obs] = store.observations()
    assert obs.first_seen == T0
    assert obs.last_seen == T0 + datetime.timedelta(minutes=10)


def test_filters(store):
    store.record_many([
        make_flow(0),
        make_flow(30, port=80, verdict="drop"),
        make_flow(60, mac=OTHER_MAC, vm_ip="10.0.0.40"),
    ])

    assert store.vm_macs() == [OTHER_MAC, VM_MAC]
    assert len(store.observations(vm_mac=VM_MAC)) == 2
    assert [o.service_port for o in store.observations(verdict="drop")] == [80]
    recent = store.observations(since=T0 + datetime.timedelta(minutes=20))
    assert {o.vm_mac for o in recent} == {VM_MAC, OTHER_MAC}
    assert len(recent) == 2
    assert store.total_connections() == 3
    assert store.total_connections(VM_MAC) == 2


def test_forget_only_one_vm(store):
    store.record_many([make_flow(0), make_flow(1, mac=OTHER_MAC)])

    assert store.forget(VM_MAC) == 1
    assert store.vm_macs() == [OTHER_MAC]


def test_data_survives_reopening(tmp_path):
    path = tmp_path / "sg-learner.db"
    with FlowStore(path) as first:
        first.record(make_flow(0))
        first.set_state("ovn_log_offset", 12345)

    with FlowStore(path) as second:
        assert second.total_connections() == 1
        assert second.get_state("ovn_log_offset") == "12345"
        assert second.get_state("missing", "default") == "default"


def test_real_log_into_store(store):
    lines = FIXTURE.read_text().splitlines()
    flows = list(collector.connections(lines))

    assert store.record_many(flows) == len(flows)
    assert store.total_connections() == len(flows)
    drops = store.observations(verdict="drop")
    assert drops and all(o.service_port == 80 for o in drops)
