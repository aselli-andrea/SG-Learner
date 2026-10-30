"""Test dell'Anomaly Detector."""

import datetime
import io

import pytest

from sg_learner import cli, collector, detector, lifecycle
from sg_learner.store import FlowStore, VmRecord

T0 = datetime.datetime(2026, 10, 26, 12, 0, tzinfo=datetime.timezone.utc)
MAC = "fa:16:3e:00:00:01"


def drop(minutes, remote, port, protocol="tcp", direction="ingress",
         verdict="drop"):
    ingress = direction == collector.INGRESS
    return collector.Flow(
        timestamp=T0 + datetime.timedelta(minutes=minutes),
        log_name="neutron-drop", verdict=verdict, direction=direction,
        protocol=protocol,
        src_mac="fa:16:3e:ff:ff:ff" if ingress else MAC,
        dst_mac=MAC if ingress else "fa:16:3e:ff:ff:ff",
        src_ip=remote if ingress else "10.0.0.10",
        dst_ip="10.0.0.10" if ingress else remote,
        src_port=40000 + minutes, dst_port=port,
        tcp_flags=frozenset({"syn"}),
    )


@pytest.fixture
def store(tmp_path):
    with FlowStore(tmp_path / "sg-learner.db") as s:
        yield s


@pytest.fixture
def vm(store):
    record = VmRecord(
        server_id="srv-web", name="vm-web", project_id="demo",
        port_id="port-web", mac=MAC, ip="10.0.0.10",
        state=lifecycle.ENFORCING, security_groups=["sg-orig"], log_ids=[],
        learned_sg_id="sg-learned",
        proposal={"rules": [], "vm_groups": {}, "summary": "Proposta",
                  "enforced_at": T0.isoformat()},
    )
    store.save_vm(record)
    return record


@pytest.fixture
def det(store):
    return detector.AnomalyDetector(store, candidate_threshold=5,
                                    scan_ports=5)


def test_isolated_attempt_is_an_alert(store, vm, det):
    store.record_many([drop(1, "10.0.0.2", 22), drop(2, "10.0.0.2", 22)])

    [(found_vm, alert)] = det.tick()

    assert found_vm.name == "vm-web"
    assert (alert.kind, alert.service_port, alert.count) == ("alert", 22, 2)
    assert detector.describe(alert) == "ingress tcp/22 da 10.0.0.2"


def test_recurring_flow_becomes_candidate(store, vm, det):
    store.record_many([drop(i, "10.0.0.5", 873) for i in range(6)])

    [(_, alert)] = det.tick()

    assert alert.kind == "candidate"
    assert alert.count == 6


def test_alert_upgraded_to_candidate_when_it_recurs(store, vm, det):
    store.record_many([drop(1, "10.0.0.5", 873)])
    det.tick()
    store.record_many([drop(i, "10.0.0.5", 873) for i in range(2, 8)])

    assert det.tick() == []                       # nessuna anomalia nuova
    [alert] = store.list_alerts()
    assert (alert.kind, alert.count) == ("candidate", 7)


def test_many_ports_from_one_ip_is_a_scan(store, vm, det):
    store.record_many([drop(i, "203.0.113.9", port)
                       for i, port in enumerate((21, 22, 23, 80, 443, 3306))])

    [(_, alert)] = det.tick()

    assert alert.kind == "scan"
    assert alert.ports == 6
    assert "6 porte diverse" in detector.describe(alert)
    assert len(store.list_alerts()) == 1          # niente alert singoli


def test_scan_absorbs_alerts_seen_before_the_threshold(store, vm, det):
    """Caso osservato dal vivo: il detector gira a meta' scansione."""
    store.record_many([drop(1, "10.0.0.2", 21), drop(2, "10.0.0.2", 23)])
    assert [a.kind for _, a in det.tick()] == ["alert", "alert"]

    store.record_many([drop(3 + i, "10.0.0.2", p)
                       for i, p in enumerate((25, 80, 443, 3306))])
    [(_, scan)] = det.tick()

    assert scan.kind == "scan" and scan.ports == 6
    assert store.list_alerts() == [scan]          # restano solo la scan
    assert {a.status for a in store.list_alerts(status="in_scan")} == {
        "in_scan"}
    assert len(store.list_alerts(status="in_scan")) == 2


def test_drops_before_enforcement_are_ignored(store, vm, det):
    store.record_many([drop(-30, "10.0.0.2", 22)])   # prima dell'Enforcer

    assert det.tick() == []


def test_allowed_traffic_and_other_states_are_ignored(store, vm, det):
    store.record_many([drop(1, "172.24.4.1", 22, verdict="allow")])
    assert det.tick() == []

    vm.state = lifecycle.PROPOSED
    store.save_vm(vm)
    store.record_many([drop(2, "10.0.0.2", 22)])
    assert det.tick() == []


def test_accept_adds_rule_and_reapproves(store, vm, det):
    store.record_many([drop(i, "10.0.0.5", 873) for i in range(6)])
    [(_, alert)] = det.tick()

    updated = det.accept(alert.id)

    assert updated.state == lifecycle.APPROVED
    [rule] = updated.proposal["rules"]
    assert (rule["direction"], rule["port"], rule["remote_ip_prefix"]) == (
        "ingress", 873, "10.0.0.5/32")
    assert "aggiunta da anomalia" in updated.proposal["summary"]
    assert store.get_alert(alert.id).status == "accepted"
    assert store.list_alerts() == []              # chiusa


def test_scan_cannot_be_accepted_but_can_be_dismissed(store, vm, det):
    store.record_many([drop(i, "203.0.113.9", 20 + i) for i in range(5)])
    [(_, scan)] = det.tick()

    with pytest.raises(lifecycle.LifecycleError):
        det.accept(scan.id)
    det.dismiss(scan.id)

    assert store.get_alert(scan.id).status == "dismissed"
    with pytest.raises(lifecycle.LifecycleError):
        det.dismiss(scan.id)                      # gia' gestita


def test_dismissed_alert_stays_closed(store, vm, det):
    store.record_many([drop(1, "10.0.0.2", 22)])
    [(_, alert)] = det.tick()
    det.dismiss(alert.id)

    store.record_many([drop(5, "10.0.0.2", 22)])

    assert det.tick() == []
    assert store.list_alerts() == []


def test_dismissed_alert_reopens_after_a_new_enforcement(store, vm, det):
    """Caso visto con tools/demo.sh: una scansione ignorata in una prova
    precedente non deve nascondere la stessa scansione dopo una nuova
    osservazione e applicazione della VM."""
    store.record_many([drop(1, "10.0.0.2", 22)])
    [(_, alert)] = det.tick()
    det.dismiss(alert.id)

    store.forget(MAC)                        # nuovo learn: osservazioni azzerate
    vm.proposal["enforced_at"] = (T0 + datetime.timedelta(hours=1)).isoformat()
    store.save_vm(vm)                        # nuova applicazione
    store.record_many([drop(61, "10.0.0.2", 22)])

    [(_, again)] = det.tick()
    assert again.id == alert.id and again.status == "open"
    assert again.count == 1


def test_cli_alerts(store, vm, det, tmp_path, monkeypatch):
    store.record_many([drop(i, "10.0.0.5", 873) for i in range(6)])
    det.tick()
    conf = tmp_path / "sg-learner.conf"
    conf.write_text(f"[DEFAULT]\ndata_dir = {tmp_path}\n")
    monkeypatch.setattr(cli, "Cloud", lambda conn: None)

    def run(*args):
        out = io.StringIO()
        code = cli.main(["--config-file", str(conf), *args],
                        conn=object(), out=out)
        return code, out.getvalue()

    code, out = run("alerts", "list")
    assert code == 0 and "candidate" in out and "tcp/873" in out

    code, out = run("alerts", "accept", "1")
    assert code == 0 and "accettata" in out

    code, out = run("alerts", "list")
    assert "Nessuna anomalia aperta" in out
