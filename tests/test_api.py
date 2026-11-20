"""Test dell'API REST con il client di prova di Flask e un Neutron finto."""

import pytest

from sg_learner import api, lifecycle
from sg_learner.store import FlowStore

from tests.test_enforcer import FakeNeutron, obs

ADMIN = {"X-Identity-Status": "Confirmed", "X-Roles": "reader,member,admin"}


class FakeCloud(FakeNeutron):
    """Il Neutron finto dei test dell'Enforcer, con la ricerca per nome e
    la mappa IP -> VM usate dal ciclo di vita."""

    def find_vm(self, name_or_id):
        for port in self.vms.values():
            if name_or_id in (port.server_id, port.server_name):
                return port
        raise LookupError(f"VM non trovata: {name_or_id}")

    def vm_groups_by_ip(self, exclude_server_id=None):
        groups = {f"vm:{p.server_name}": sid for sid, p in self.vms.items()
                  if sid != exclude_server_id}
        ips = {p.ip: f"vm:{p.server_name}" for sid, p in self.vms.items()
               if sid != exclude_server_id}
        return ips, groups


@pytest.fixture
def neutron():
    return FakeCloud()


@pytest.fixture
def client(tmp_path, neutron):
    app = api.create_app(str(tmp_path), lambda: neutron)
    return app.test_client()


@pytest.fixture
def db(tmp_path):
    with FlowStore(tmp_path / api.DB_FILE) as s:
        yield s


def test_requests_without_keystone_identity_are_refused(client):
    assert client.get("/v1/vms").status_code == 401
    # Un utente autenticato ma senza ruolo admin
    member = {"X-Identity-Status": "Confirmed", "X-Roles": "member,reader"}
    response = client.get("/v1/vms", headers=member)
    assert response.status_code == 403
    assert response.get_json() == {"error": "serve il ruolo admin"}


def test_full_cycle_learn_generate_approve(client, db):
    response = client.post("/v1/vms/vm-web/learn", json={"duration": "30m"},
                           headers=ADMIN)
    assert response.status_code == 202
    assert response.get_json()["state"] == lifecycle.LEARNING

    vm = db.get_vm("vm-web")
    assert vm.state == lifecycle.LEARNING

    # SSH dall'host e traffico da vm-db: diventano /32 e remote_group
    from tests.test_lifecycle import flow
    db.record(flow(1, "172.24.4.1", 22))

    response = client.post("/v1/vms/vm-web/proposal/generate", headers=ADMIN)
    assert response.status_code == 200
    body = response.get_json()
    assert body["state"] == lifecycle.PROPOSED
    assert body["proposal"]["rules"][0]["remote_ip_prefix"] == "172.24.4.1/32"

    response = client.post("/v1/vms/vm-web/proposal/approve", headers=ADMIN)
    assert response.status_code == 202
    assert response.get_json()["state"] == lifecycle.APPROVED

    listing = client.get("/v1/vms", headers=ADMIN).get_json()
    assert [(v["name"], v["state"], v["rules"]) for v in listing["vms"]] == \
        [("vm-web", "approved", 1)]


def test_reject_and_errors_become_http_codes(client, db):
    # VM non seguita: 404
    response = client.get("/v1/vms/vm-web", headers=ADMIN)
    assert response.status_code == 404

    client.post("/v1/vms/vm-web/learn", headers=ADMIN)
    # Approvare durante l'osservazione non e' valido: 409
    assert client.post("/v1/vms/vm-web/proposal/approve",
                       headers=ADMIN).status_code == 409
    # Durata non valida: 400
    assert client.post("/v1/vms/vm-web/learn", json={"duration": "dieci"},
                       headers=ADMIN).status_code == 400

    client.post("/v1/vms/vm-web/proposal/generate", headers=ADMIN)
    response = client.post("/v1/vms/vm-web/proposal/reject", headers=ADMIN)
    assert response.status_code == 200
    assert response.get_json()["state"] == lifecycle.REJECTED
    assert db.get_vm("vm-web").proposal["rejected_at"]

    # Rollback solo per una VM applicata: 409
    assert client.post("/v1/vms/vm-web/rollback",
                       headers=ADMIN).status_code == 409


def test_alerts_list_and_dismiss(client, db):
    client.post("/v1/vms/vm-web/learn", headers=ADMIN)
    vm = db.get_vm("vm-web")
    alert, _ = db.upsert_alert(
        vm.server_id, "alert", "ingress", "tcp", 5432, None, "10.0.0.50",
        count=1, first_seen=vm.learn_started, last_seen=vm.learn_started)

    body = client.get("/v1/alerts", headers=ADMIN).get_json()
    assert [(a["id"], a["vm"], a["kind"]) for a in body["alerts"]] == \
        [(alert.id, "vm-web", "alert")]
    assert body["alerts"][0]["description"] == \
        "ingress tcp/5432 da 10.0.0.50"

    response = client.post(f"/v1/alerts/{alert.id}/dismiss", headers=ADMIN)
    assert response.get_json() == {"alert": alert.id, "status": "dismissed"}
    assert client.get("/v1/alerts", headers=ADMIN).get_json() == {"alerts": []}
    every = client.get("/v1/alerts?all=true", headers=ADMIN).get_json()
    assert every["alerts"][0]["status"] == "dismissed"

    # Anomalia gia' gestita: 409
    assert client.post(f"/v1/alerts/{alert.id}/accept",
                       headers=ADMIN).status_code == 409


def test_approved_proposal_is_applied_by_the_enforcer(client, db, neutron):
    from sg_learner.enforcer import Enforcer
    client.post("/v1/vms/vm-web/learn", headers=ADMIN)
    from tests.test_lifecycle import flow
    db.record(flow(1, "172.24.4.1", 22))
    client.post("/v1/vms/vm-web/proposal/generate", headers=ADMIN)
    client.post("/v1/vms/vm-web/proposal/approve", headers=ADMIN)

    # Il giro del servizio: la decisione presa con l'API viene applicata
    Enforcer(db, neutron).tick()
    body = client.get("/v1/vms/vm-web", headers=ADMIN).get_json()
    assert body["state"] == lifecycle.ENFORCING
    assert neutron.ports["port-web"] == [body["learned_security_group"]]

    response = client.post("/v1/vms/vm-web/rollback", headers=ADMIN)
    assert response.status_code == 200
    assert response.get_json()["state"] == lifecycle.PROPOSED
    assert neutron.ports["port-web"] == ["sg-orig"]


def test_keystonemiddleware_rejects_requests_without_token(tmp_path, neutron):
    """La protezione vera: senza X-Auth-Token risponde 401 e non arriva
    all'applicazione, e gli header di identita' inviati dal client
    vengono ignorati."""
    pytest.importorskip("keystonemiddleware")
    import werkzeug.test
    app = api.create_app(str(tmp_path), lambda: neutron)
    protected = api.keystone_protected(app.wsgi_app, {
        "www_authenticate_uri": "http://keystone.example/identity",
        "auth_type": "password",
        "auth_url": "http://keystone.example/identity",
        "username": "sg-learner", "password": "x",
        "project_name": "service", "user_domain_name": "Default",
        "project_domain_name": "Default",
    })
    client = werkzeug.test.Client(protected)
    response = client.get("/v1/vms", headers=ADMIN)   # header falsificati
    assert response.status_code == 401
