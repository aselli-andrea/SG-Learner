"""Test del ciclo di vita (sg_learner/lifecycle.py), della CLI e
dell'avvio del servizio.

FakeCloud sostituisce cloud.Cloud: trova le VM e registra il logging
attivato, senza OpenStack.

Cosa verificano:
- parse_duration e le transizioni learn, generate, approve, reject;
- la proposta generata solo a fine finestra (tick);
- i comandi della CLI, gli errori e il messaggio senza openrc;
- il servizio che aspetta OpenStack all'avvio (connect_with_retry).
"""

import datetime
import io

import pytest

from sg_learner import cli, collector, lifecycle
from sg_learner.cloud import VmPort
from sg_learner.store import FlowStore

T0 = datetime.datetime(2026, 10, 23, 12, 0, tzinfo=datetime.timezone.utc)

WEB = VmPort(server_id="srv-web", server_name="vm-web", project_id="demo",
             port_id="port-web", mac="fa:16:3e:00:00:01", ip="10.0.0.10",
             security_group_ids=("sg-default",))
APP_IP = "10.0.0.20"


class FakeCloud:
    """Sostituisce cloud.Cloud: registra le chiamate senza OpenStack."""

    def __init__(self):
        self.vms = {"vm-web": WEB, "srv-web": WEB}
        self.logging_calls = []

    def find_vm(self, name_or_id):
        if name_or_id not in self.vms:
            raise LookupError(f"VM non trovata: {name_or_id}")
        return self.vms[name_or_id]

    def enable_logging(self, security_group_ids, project_id, name,
                       event="ALL"):
        self.logging_calls.append((tuple(security_group_ids), event))
        return [f"log-{sg}" for sg in security_group_ids]

    def vm_groups_by_ip(self, exclude_server_id=None):
        return {APP_IP: "vm:vm-app"}, {"vm:vm-app": "srv-app"}


def flow(minutes, remote, port, verdict="allow"):
    """Una connessione TCP in ingresso verso vm-web, `minutes` dopo T0."""
    return collector.Flow(
        timestamp=T0 + datetime.timedelta(minutes=minutes),
        log_name="neutron-log", verdict=verdict,
        direction=collector.INGRESS, protocol="tcp",
        src_mac="fa:16:3e:ff:ff:ff", dst_mac=WEB.mac,
        src_ip=remote, dst_ip=WEB.ip, src_port=40000 + minutes,
        dst_port=port, tcp_flags=frozenset({"syn"}),
    )


@pytest.fixture
def store(tmp_path):
    with FlowStore(tmp_path / "sg-learner.db") as s:
        yield s


@pytest.fixture
def cloud():
    return FakeCloud()


@pytest.fixture
def manager(store, cloud):
    return lifecycle.Lifecycle(store, cloud)


def test_parse_duration():
    assert lifecycle.parse_duration("90s") == 90
    assert lifecycle.parse_duration("30m") == 1800
    assert lifecycle.parse_duration("2h") == 7200
    assert lifecycle.parse_duration("600") == 600
    with pytest.raises(ValueError):
        lifecycle.parse_duration("dieci")
    with pytest.raises(ValueError):
        lifecycle.parse_duration("0")


def test_learn_enables_logging_and_resets_observations(manager, store, cloud):
    store.record(flow(0, "172.24.4.1", 22))   # traffico vecchio

    vm = manager.learn("vm-web", duration=1800, now=T0)

    assert vm.state == lifecycle.LEARNING
    assert vm.learn_until == T0 + datetime.timedelta(minutes=30)
    assert vm.log_ids == ["log-sg-default"]
    assert cloud.logging_calls == [(("sg-default",), "ALL")]
    assert store.observations(vm_mac=WEB.mac) == []
    assert store.get_vm("vm-web").state == lifecycle.LEARNING
    assert store.get_vm("srv-web").name == "vm-web"


def test_tick_generates_proposal_only_after_window(manager, store):
    manager.learn("vm-web", duration=1800, now=T0)
    store.record_many([flow(1, "172.24.4.1", 22),
                       flow(2, APP_IP, 80),
                       flow(3, "172.24.4.1", 3306, verdict="drop")])

    assert manager.tick(now=T0 + datetime.timedelta(minutes=10)) == []

    [vm] = manager.tick(now=T0 + datetime.timedelta(minutes=31))
    assert vm.state == lifecycle.PROPOSED
    rules = {(r["port"], r["remote_ip_prefix"], r["remote_group"])
             for r in vm.proposal["rules"]}
    assert rules == {(22, "172.24.4.1/32", None), (80, None, "vm:vm-app")}
    assert vm.proposal["vm_groups"] == {"vm:vm-app": "srv-app"}
    assert vm.proposal["summary"].startswith("Proposta per vm-web (10.0.0.10)")
    assert "bloccato: ingress tcp/3306" in vm.proposal["summary"]


def test_generate_anticipates_the_proposal(manager):
    manager.learn("vm-web", duration=3600, now=T0)

    vm = manager.generate("vm-web", now=T0 + datetime.timedelta(minutes=5))

    assert vm.state == lifecycle.PROPOSED
    assert vm.proposal["rules"] == []


def test_approve_requires_a_proposal_with_rules(manager, store):
    with pytest.raises(lifecycle.LifecycleError):
        manager.approve("vm-web")              # non ancora seguita

    manager.learn("vm-web", now=T0)
    with pytest.raises(lifecycle.LifecycleError):
        manager.approve("vm-web")              # ancora in osservazione

    manager.generate("vm-web")
    with pytest.raises(lifecycle.LifecycleError):
        manager.approve("vm-web")              # proposta vuota

    manager.learn("vm-web", now=T0)            # riapprendimento
    store.record(flow(1, "172.24.4.1", 22))
    manager.generate("vm-web")
    assert manager.approve("vm-web").state == lifecycle.APPROVED


def test_reject_keeps_original_groups_and_allows_new_learn(manager, store,
                                                          cloud):
    manager.learn("vm-web", now=T0)
    with pytest.raises(lifecycle.LifecycleError):
        manager.reject("vm-web")               # ancora in osservazione

    store.record(flow(1, "172.24.4.1", 22))
    manager.generate("vm-web")
    calls = len(cloud.logging_calls)
    vm = manager.reject("vm-web", now=T0 + datetime.timedelta(minutes=5))

    assert vm.state == lifecycle.REJECTED
    assert vm.security_groups == ["sg-default"]   # gruppi originali
    assert len(cloud.logging_calls) == calls      # Neutron non toccato
    saved = store.get_vm("vm-web")
    assert saved.state == lifecycle.REJECTED
    assert len(saved.proposal["rules"]) == 1      # resta come storico
    assert saved.proposal["rejected_at"].startswith("2026-10-23T12:05")

    with pytest.raises(lifecycle.LifecycleError):
        manager.approve("vm-web")              # rifiutata: non si approva
    with pytest.raises(lifecycle.LifecycleError):
        manager.reject("vm-web")               # gia' rifiutata

    assert manager.learn("vm-web", now=T0).state == lifecycle.LEARNING


def test_learn_unknown_vm(manager):
    with pytest.raises(LookupError):
        manager.learn("non-esiste")


# --- CLI ---------------------------------------------------------------------

@pytest.fixture
def run_cli(tmp_path, cloud, monkeypatch):
    """Esegue il CLI con un database temporaneo e il cloud finto."""
    conf = tmp_path / "sg-learner.conf"
    conf.write_text(f"[DEFAULT]\ndata_dir = {tmp_path}\n")
    monkeypatch.setattr(cli, "Cloud", lambda conn: cloud)

    def run(*args):
        out = io.StringIO()
        code = cli.main(["--config-file", str(conf), *args],
                        conn=object(), out=out)
        return code, out.getvalue()
    return run


def test_cli_full_flow(run_cli, tmp_path):
    code, out = run_cli("learn", "vm-web", "--duration", "30m")
    assert code == 0 and "Osservazione di vm-web (10.0.0.10) avviata" in out

    with FlowStore(tmp_path / "sg-learner.db") as s:
        s.record(flow(1, "172.24.4.1", 22))

    code, out = run_cli("status")
    assert "vm-web" in out and "learning" in out

    code, out = run_cli("proposal", "generate", "vm-web")
    assert code == 0 and "ingress tcp/22 da 172.24.4.1/32" in out

    code, out = run_cli("proposal", "approve", "vm-web")
    assert code == 0 and "approvata" in out

    code, out = run_cli("proposal", "show", "vm-web")
    assert "Stato: approved" in out


def test_cli_reject(run_cli, tmp_path):
    run_cli("learn", "vm-web", "--duration", "30m")
    with FlowStore(tmp_path / "sg-learner.db") as s:
        s.record(flow(1, "172.24.4.1", 22))
    run_cli("proposal", "generate", "vm-web")

    code, out = run_cli("proposal", "reject", "vm-web")
    assert code == 0 and "rifiutata" in out

    code, out = run_cli("proposal", "show", "vm-web")
    assert "Stato: rejected" in out

    code, _ = run_cli("proposal", "approve", "vm-web")
    assert code == 1


def test_cli_reports_errors(run_cli, capsys):
    code, _ = run_cli("proposal", "approve", "vm-web")

    assert code == 1
    assert "non e' seguita" in capsys.readouterr().err


def test_cli_without_openrc_explains_what_to_do(tmp_path, monkeypatch, capsys):
    """Senza `source openrc` la CLI deve stampare un messaggio comprensibile,
    non un traceback di keystoneauth."""
    from keystoneauth1.exceptions.auth_plugins import MissingRequiredOptions
    from sg_learner import cli

    def no_credentials():
        raise MissingRequiredOptions([])
    monkeypatch.setattr(cli.openstack, "connect", no_credentials)
    conf = tmp_path / "sg-learner.conf"
    conf.write_text(f"[DEFAULT]\ndata_dir = {tmp_path}\n")

    assert cli.main(["--config-file", str(conf), "status"]) == 1
    assert "source /opt/stack/devstack/openrc" in capsys.readouterr().err


# --- Avvio del servizio quando OpenStack non e' ancora pronto -----------------

def test_service_retries_until_openstack_is_ready(monkeypatch):
    from sg_learner import service

    calls = {"connect": 0}

    def fake_connect(conf):
        calls["connect"] += 1
        if calls["connect"] < 3:
            raise ConnectionError("Keystone non risponde")
        return "conn"

    monkeypatch.setattr(service, "connect", fake_connect)
    monkeypatch.setattr(service, "self_check", lambda conn, log: None)

    conn = service.connect_with_retry(None, "log", lambda: False,
                                      attempts=5, delay=1,
                                      sleep=lambda s: None)

    assert conn == "conn"
    assert calls["connect"] == 3


def test_service_gives_up_after_all_attempts(monkeypatch):
    from sg_learner import service

    def always_down(conf):
        raise ConnectionError("Keystone non risponde")

    monkeypatch.setattr(service, "connect", always_down)

    with pytest.raises(ConnectionError):
        service.connect_with_retry(None, "log", lambda: False, attempts=3,
                                   delay=1, sleep=lambda s: None)
