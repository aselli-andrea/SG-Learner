"""Test dell'Enforcer con un Neutron finto in memoria."""

import dataclasses
import datetime
import itertools

import pytest

from sg_learner import engine, lifecycle
from sg_learner.cloud import VmPort
from sg_learner.enforcer import Enforcer
from sg_learner.store import ConflictError, FlowStore, Observation, VmRecord

T0 = datetime.datetime(2026, 10, 25, 12, 0, tzinfo=datetime.timezone.utc)


class FakeNeutron:
    """Neutron in memoria: gruppi, regole, porte e network log."""

    def __init__(self):
        self.ids = (f"id-{n}" for n in itertools.count(1))
        self.groups = {"sg-orig": "sg-test"}          # ID -> nome
        self.rules = {}                               # ID -> regola
        self.ports = {"port-web": ["sg-orig"], "port-db": ["sg-orig"]}
        self.vms = {
            "srv-web": VmPort("srv-web", "vm-web", "demo", "port-web",
                              "fa:16:3e:00:00:01", "10.0.0.10", ("sg-orig",)),
            "srv-db": VmPort("srv-db", "vm-db", "demo", "port-db",
                             "fa:16:3e:00:00:02", "10.0.0.20", ("sg-orig",)),
        }
        self.logs = {}
        self.writes = 0

    def find_vm(self, name_or_id):
        return self.vms[name_or_id]

    def port_security_groups(self, port_id):
        return list(self.ports[port_id])

    def set_port_security_groups(self, port_id, sg_ids):
        self.writes += 1
        self.ports[port_id] = list(sg_ids)

    def security_group_names(self, sg_ids):
        return {g: self.groups[g] for g in sg_ids}

    def ensure_security_group(self, name, project_id, description=""):
        for sg_id, sg_name in self.groups.items():
            if sg_name == name:
                return sg_id
        self.writes += 1
        sg_id = next(self.ids)
        self.groups[sg_id] = name
        # Come Neutron: ogni gruppo nuovo permette tutto in uscita...
        for ethertype in ("IPv4", "IPv6"):
            self.rules[next(self.ids)] = {
                "sg": sg_id, "direction": "egress", "ethertype": ethertype,
                "protocol": None, "port_range_min": None,
                "port_range_max": None, "remote_ip_prefix": None,
                "remote_group_id": None}
        # ...e, come cloud.Cloud, il gruppo nuovo viene svuotato subito
        for rule in self.security_group_rules(sg_id):
            self.delete_rule(rule["id"])
        return sg_id

    def security_group_rules(self, sg_id):
        return [{"id": rid, **{k: v for k, v in r.items() if k != "sg"}}
                for rid, r in self.rules.items() if r["sg"] == sg_id]

    def groups_referencing(self, sg_id):
        return {r["sg"] for r in self.rules.values()
                if r["remote_group_id"] == sg_id and r["sg"] != sg_id}

    def create_rule(self, sg_id, project_id, rule):
        self.writes += 1
        full = {"direction": None, "ethertype": None, "protocol": None,
                "port_range_min": None, "port_range_max": None,
                "remote_ip_prefix": None, "remote_group_id": None, **rule}
        self.rules[next(self.ids)] = {"sg": sg_id, **full}

    def delete_rule(self, rule_id):
        self.writes += 1
        self.rules.pop(rule_id, None)

    def enable_logging(self, security_group_ids, project_id, name,
                       event="ALL"):
        ids = []
        for sg_id in security_group_ids:
            log_id = next(self.ids)
            self.logs[log_id] = (sg_id, event)
            ids.append(log_id)
        return ids

    def disable_logging(self, log_ids):
        for log_id in log_ids:
            self.logs.pop(log_id, None)


def obs(port, remote, direction="ingress", protocol="tcp", icmp_type=None,
        mac="fa:16:3e:00:00:01", count=10):
    return Observation(
        vm_mac=mac, vm_ip="10.0.0.10", direction=direction,
        protocol=protocol, service_port=port, icmp_type=icmp_type,
        remote_ip=remote, verdict="allow", count=count,
        first_seen=T0, last_seen=T0)


def approved_vm(store, port, observations, ip_to_group=None,
                vm_groups=None):
    """Salva una VM in stato APPROVED con la proposta delle osservazioni."""
    proposal = engine.build_proposal(observations, port.mac, ip_to_group)
    vm = VmRecord(
        server_id=port.server_id, name=port.server_name,
        project_id=port.project_id, port_id=port.port_id, mac=port.mac,
        ip=port.ip, state=lifecycle.APPROVED,
        security_groups=list(port.security_group_ids), log_ids=[],
        proposal={"rules": [dataclasses.asdict(r) for r in proposal.rules],
                  "vm_groups": vm_groups or {}, "summary": ""},
    )
    store.save_vm(vm)
    return vm


def rules_of(neutron, sg_id):
    return sorted(
        (r["direction"], r["protocol"], r["port_range_min"],
         r["remote_ip_prefix"], r["remote_group_id"])
        for r in neutron.security_group_rules(sg_id))


@pytest.fixture
def store(tmp_path):
    with FlowStore(tmp_path / "sg-learner.db") as s:
        yield s


@pytest.fixture
def neutron():
    return FakeNeutron()


@pytest.fixture
def enforcer(store, neutron):
    return Enforcer(store, neutron)


@pytest.fixture
def web(store, neutron):
    return approved_vm(store, neutron.vms["srv-web"], [
        obs(22, "172.24.4.1"),
        obs(None, "172.24.4.1", protocol="icmp", icmp_type=8),
        obs(80, "169.254.169.254", direction="egress", count=15),
    ])


def test_apply_creates_learned_group_with_only_approved_rules(
        enforcer, neutron, store, web):
    vm = enforcer.apply(store.get_vm("vm-web"))

    assert vm.state == lifecycle.ENFORCING
    assert neutron.groups[vm.learned_sg_id] == "learned-vm-web"
    assert rules_of(neutron, vm.learned_sg_id) == [
        ("egress", "tcp", 80, "169.254.169.254/32", None),
        ("egress", "udp", 67, "0.0.0.0/0", None),     # regola di base DHCP
        ("ingress", "icmp", 8, "172.24.4.1/32", None),
        ("ingress", "tcp", 22, "172.24.4.1/32", None),
    ]   # le regole "tutto permesso in uscita" sono state cancellate
    assert neutron.ports["port-web"] == [vm.learned_sg_id]
    assert vm.security_groups == ["sg-orig"]      # salvati per il rollback
    assert list(neutron.logs.values()) == [(vm.learned_sg_id, "DROP")]
    assert store.get_vm("vm-web").state == lifecycle.ENFORCING


def test_apply_is_idempotent(enforcer, neutron, store, web):
    enforcer.apply(store.get_vm("vm-web"))
    writes = neutron.writes

    enforcer.apply(store.get_vm("vm-web"))

    assert neutron.writes == writes
    assert len(neutron.logs) == 1


def test_reconcile_restores_manual_changes(enforcer, neutron, store, web):
    vm = enforcer.apply(store.get_vm("vm-web"))
    sg_id = vm.learned_sg_id

    # Qualcuno modifica a mano la porta e le regole
    neutron.ports["port-web"].append("sg-orig")
    ssh = next(rid for rid, r in neutron.rules.items()
               if r["sg"] == sg_id and r["port_range_min"] == 22)
    neutron.delete_rule(ssh)
    neutron.create_rule(sg_id, "demo", {
        "direction": "ingress", "ethertype": "IPv4", "protocol": "tcp",
        "port_range_min": 3306, "port_range_max": 3306,
        "remote_ip_prefix": "0.0.0.0/0"})

    enforcer.tick()

    assert neutron.ports["port-web"] == [sg_id]
    ports = [r[2] for r in rules_of(neutron, sg_id)]
    assert 22 in ports and 3306 not in ports


def test_remote_group_makes_peer_a_member(enforcer, neutron, store):
    db_port = neutron.vms["srv-db"]
    approved_vm(store, db_port,
                [obs(5432, "10.0.0.10", mac=db_port.mac)],
                ip_to_group={"10.0.0.10": "vm:vm-web"},
                vm_groups={"vm:vm-web": "srv-web"})

    vm = enforcer.apply(store.get_vm("vm-db"))

    web_group = next(g for g, n in neutron.groups.items()
                     if n == "learned-vm-web")
    # vm-web e' ora membro di learned-vm-web (vuoto), i suoi gruppi restano
    assert neutron.ports["port-web"] == ["sg-orig", web_group]
    assert rules_of(neutron, web_group) == []
    assert rules_of(neutron, vm.learned_sg_id) == [
        ("egress", "tcp", 80, "169.254.169.254/32", None),   # di base
        ("egress", "udp", 67, "0.0.0.0/0", None),            # di base
        ("ingress", "tcp", 5432, None, web_group)]


def test_peer_membership_survives_its_own_enforcement(
        enforcer, neutron, store, web):
    db_port = neutron.vms["srv-db"]
    approved_vm(store, db_port, [obs(5432, "10.0.0.10", mac=db_port.mac)],
                ip_to_group={"10.0.0.10": "vm:vm-web"},
                vm_groups={"vm:vm-web": "srv-web"})
    enforcer.apply(store.get_vm("vm-db"))

    web_vm = enforcer.apply(store.get_vm("vm-web"))

    # learned-vm-web e' sia il gruppo di vm-web sia quello citato da vm-db
    assert neutron.ports["port-web"] == [web_vm.learned_sg_id]
    assert len(rules_of(neutron, web_vm.learned_sg_id)) == 4


def test_rollback_restores_original_groups(enforcer, neutron, store, web):
    enforcer.apply(store.get_vm("vm-web"))

    vm = enforcer.rollback("vm-web")

    assert neutron.ports["port-web"] == ["sg-orig"]
    assert neutron.logs == {}
    assert vm.state == lifecycle.PROPOSED
    assert vm.proposal["rules"]                    # la proposta resta


def test_rollback_keeps_membership_of_other_vms_groups(
        enforcer, neutron, store, web):
    enforcer.apply(store.get_vm("vm-web"))
    # Un'altra VM (vm-app) ha reso vm-web membro del suo gruppo learned
    neutron.ports["port-web"].append(
        neutron.ensure_security_group("learned-vm-app", "demo"))

    enforcer.rollback("vm-web")

    names = [neutron.groups[g] for g in neutron.ports["port-web"]]
    assert names == ["sg-test", "learned-vm-app"]


def test_only_approved_proposals_are_applied(enforcer, store, web):
    web.state = lifecycle.PROPOSED
    store.save_vm(web)

    with pytest.raises(lifecycle.LifecycleError):
        enforcer.apply(store.get_vm("vm-web"))
    assert enforcer.tick() == []


def test_tick_applies_approved_vms(enforcer, store, web):
    [vm] = enforcer.tick()

    assert vm.name == "vm-web"
    assert store.get_vm("vm-web").state == lifecycle.ENFORCING
    assert enforcer.tick() == []                   # gia' applicata


def test_relearn_keeps_original_groups(store, neutron, enforcer, web):
    enforcer.apply(store.get_vm("vm-web"))
    neutron.vms["srv-web"] = dataclasses.replace(
        neutron.vms["srv-web"],
        security_group_ids=tuple(neutron.ports["port-web"]))
    manager = lifecycle.Lifecycle(store, neutron)
    neutron.vm_groups_by_ip = lambda exclude_server_id=None: ({}, {})

    vm = manager.learn("srv-web", now=T0)

    assert vm.state == lifecycle.LEARNING
    assert vm.security_groups == ["sg-orig"]       # non il gruppo learned
    assert vm.learned_sg_id is not None


def test_cli_change_during_reconcile_is_not_lost(enforcer, neutron, store, web):
    """Caso osservato dal vivo: `alerts accept` arriva mentre l'Enforcer
    sta riconciliando la stessa VM."""
    enforcer.apply(store.get_vm("vm-web"))
    service_copy = store.get_vm("vm-web")       # letta dal servizio

    cli_copy = store.get_vm("vm-web")           # la CLI accetta una regola
    ssh = next(r for r in cli_copy.proposal["rules"] if r["port"] == 22)
    cli_copy.proposal["rules"].append(dict(ssh, port=8080))
    cli_copy.state = lifecycle.APPROVED
    store.save_vm(cli_copy)

    enforcer.apply(service_copy)                 # riconciliazione in corso
    assert store.get_vm("vm-web").state == lifecycle.APPROVED  # non sovrascrive

    enforcer.tick()                              # giro successivo
    vm = store.get_vm("vm-web")
    assert vm.state == lifecycle.ENFORCING
    assert 8080 in [r[2] for r in rules_of(neutron, vm.learned_sg_id)]


def test_rollback_keeps_own_group_when_other_vms_reference_it(
        enforcer, neutron, store, web):
    """Caso trovato nella demo a 3 VM: vm-db accetta la 5432 dal gruppo
    learned-vm-web. Il rollback di vm-web non deve togliere vm-web da quel
    gruppo, altrimenti vm-db smetterebbe di accettarla."""
    db_port = neutron.vms["srv-db"]
    approved_vm(store, db_port, [obs(5432, "10.0.0.10", mac=db_port.mac)],
                ip_to_group={"10.0.0.10": "vm:vm-web"},
                vm_groups={"vm:vm-web": "srv-web"})
    enforcer.apply(store.get_vm("vm-db"))
    web_vm = enforcer.apply(store.get_vm("vm-web"))

    enforcer.rollback("vm-web")

    assert neutron.ports["port-web"] == ["sg-orig", web_vm.learned_sg_id]
    assert neutron.logs and all(sg != web_vm.learned_sg_id
                                for sg, _ in neutron.logs.values())


def test_reconcile_without_changes_does_not_save(enforcer, neutron, store, web):
    """Se la riconciliazione non cambia nulla la VM non viene salvata: un
    comando della CLI lanciato nello stesso momento non va in conflitto."""
    enforcer.apply(store.get_vm("vm-web"))
    before = store.get_vm("vm-web").updated_at

    enforcer.tick()

    assert store.get_vm("vm-web").updated_at == before


def test_rollback_retries_when_the_service_saves_meanwhile(
        enforcer, neutron, store, web, monkeypatch):
    enforcer.apply(store.get_vm("vm-web"))
    real_save, calls = store.save_vm, []

    def save_once_in_conflict(vm):
        calls.append(vm.state)
        if len(calls) == 1:
            raise ConflictError("salvata dal servizio nel frattempo")
        return real_save(vm)
    monkeypatch.setattr(store, "save_vm", save_once_in_conflict)

    vm = enforcer.rollback("vm-web")

    assert vm.state == lifecycle.PROPOSED and len(calls) == 2
    assert neutron.ports["port-web"] == ["sg-orig"]
