"""API REST di SG-Learner (Flask), protetta da Keystone.

Unico punto d'accesso dell'amministratore: la CLI (cli.py) e ogni altro
client chiamano questi endpoint. Usa le stesse classi e lo stesso database
del servizio.
keystonemiddleware verifica il token (401 se manca o non e' valido) e passa
l'identita' negli header X-Identity-Status e X-Roles, togliendo quelli
inviati dal client. L'applicazione accetta solo il ruolo admin (403).

Endpoint (JSON, prefisso /v1):

    GET  /v1/vms                          stato delle VM seguite
    GET  /v1/vms/<vm>                     una VM, con la proposta
    POST /v1/vms/<vm>/learn               avvia l'osservazione {"duration": "30m"}
    POST /v1/vms/<vm>/proposal/generate   genera subito la proposta
    POST /v1/vms/<vm>/proposal/approve    approva la proposta
    POST /v1/vms/<vm>/proposal/reject     rifiuta la proposta
    POST /v1/vms/<vm>/rollback            rimette i gruppi originali
    GET  /v1/alerts[?vm=<vm>&all=true]    anomalie aperte (o tutte)
    POST /v1/alerts/<id>/accept           anomalia -> regola
    POST /v1/alerts/<id>/dismiss          ignora l'anomalia
"""

import argparse
import configparser
import logging
import os
import sys
from wsgiref import simple_server

import flask

from sg_learner import __version__
from sg_learner import detector, engine, lifecycle
from sg_learner.enforcer import Enforcer
from sg_learner.store import ConflictError, FlowStore

LOG = logging.getLogger("sg_learner.api")

DEFAULT_CONFIG = "/etc/sg-learner/sg-learner.conf"
DEFAULT_DATA_DIR = "/opt/stack/data/sg-learner"
DB_FILE = "sg-learner.db"
DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 9797
ADMIN_ROLE = "admin"

# Errori previsti -> codice HTTP (gli stessi che la CLI mostra come messaggio)
_ERRORS = (
    (LookupError, 404),                 # VM o anomalia inesistente
    (lifecycle.LifecycleError, 409),    # operazione non valida nello stato
    (ConflictError, 409),               # modificata nel frattempo: riprovare
    (ValueError, 400),                  # durata non valida
)


def _ts(value):
    """datetime -> testo ISO 8601 per il JSON (None resta None)."""
    return value.isoformat() if value else None


def _vm_json(vm, with_proposal=False):
    """Una VM in JSON; con with_proposal anche la proposta completa."""
    data = {
        "name": vm.name, "id": vm.server_id, "ip": vm.ip, "state": vm.state,
        "learn_until": _ts(vm.learn_until),
        "rules": len(vm.proposal["rules"]) if vm.proposal else None,
        "learned_security_group": vm.learned_sg_id,
        "network_logs": len(vm.log_ids),
    }
    if with_proposal:
        data["proposal"] = vm.proposal
    return data


def _alert_json(alert, names):
    """Un'anomalia in JSON; `names` traduce l'ID della VM nel suo nome."""
    return {
        "id": alert.id, "vm": names.get(alert.server_id, alert.server_id),
        "kind": alert.kind, "count": alert.count, "status": alert.status,
        "description": detector.describe(alert),
        "first_seen": _ts(alert.first_seen), "last_seen": _ts(alert.last_seen),
    }


def create_app(data_dir, cloud_factory, engine_options=None,
               detector_options=None,
               default_duration=lifecycle.DEFAULT_LEARN_DURATION):
    """Crea l'applicazione Flask.

    `cloud_factory` crea il collegamento a OpenStack alla prima richiesta
    che ne ha bisogno: l'API parte anche se Keystone non e' ancora pronto.
    """
    app = flask.Flask("sg_learner.api")
    app.json.sort_keys = False
    state = {"cloud": None}

    def cloud():
        """Collegamento a OpenStack, creato alla prima richiesta."""
        if state["cloud"] is None:
            state["cloud"] = cloud_factory()
        return state["cloud"]

    # Un FlowStore per richiesta: SQLite non condivide una connessione tra
    # thread, e cosi' ogni richiesta vede le ultime modifiche del servizio
    def store():
        """Il FlowStore della richiesta in corso (flask.g)."""
        if "store" not in flask.g:
            flask.g.store = FlowStore(os.path.join(data_dir, DB_FILE))
        return flask.g.store

    @app.teardown_appcontext
    def _close_store(_exc):
        """A fine richiesta chiude il database."""
        db = flask.g.pop("store", None)
        if db is not None:
            db.close()

    def manager():
        """Ciclo di vita (Lifecycle) sul database della richiesta."""
        return lifecycle.Lifecycle(store(), cloud(), engine_options)

    def anomalies():
        """Anomaly Detector sul database della richiesta."""
        return detector.AnomalyDetector(store(), cloud(),
                                        **(detector_options or {}))

    # --- Autorizzazione --------------------------------------------------------

    @app.before_request
    def _require_admin():
        """Prima di ogni richiesta: 401 senza identita' Keystone confermata,
        403 senza ruolo admin. None lascia proseguire la richiesta.
        """
        # Header impostati da keystonemiddleware dopo aver verificato il token
        if flask.request.headers.get("X-Identity-Status") != "Confirmed":
            return _error("token Keystone mancante o non valido", 401)
        roles = flask.request.headers.get("X-Roles", "")
        if ADMIN_ROLE not in [r.strip() for r in roles.split(",")]:
            return _error("serve il ruolo admin", 403)
        return None

    # --- Errori ------------------------------------------------------------------

    def _error(message, code):
        """Risposta di errore in JSON {"error": ...} con il codice."""
        return flask.jsonify(error=message), code

    for exc_class, code in _ERRORS:
        app.register_error_handler(
            exc_class, lambda exc, code=code: _error(str(exc), code))

    # --- VM ------------------------------------------------------------------------

    @app.get("/")
    def root():
        """GET /: nome e versione del servizio."""
        return {"service": "sg-learner", "version": __version__,
                "api": "/v1"}

    @app.get("/v1/vms")
    def list_vms():
        """GET /v1/vms: tutte le VM seguite."""
        return {"vms": [_vm_json(vm) for vm in store().list_vms()]}

    @app.get("/v1/vms/<name>")
    def show_vm(name):
        """GET /v1/vms/<vm>: una VM, con la proposta."""
        return _vm_json(_followed(name), with_proposal=True)

    def _followed(name):
        """La VM seguita, o LookupError (404) se SG-Learner non la conosce."""
        vm = store().get_vm(name)
        if vm is None:
            raise LookupError(f"{name} non e' seguita da SG-Learner")
        return vm

    @app.post("/v1/vms/<name>/learn")
    def learn(name):
        """POST /v1/vms/<vm>/learn: avvia l'osservazione.

        Corpo facoltativo: {"duration": "30m"}.
        """
        body = flask.request.get_json(silent=True) or {}
        duration = lifecycle.parse_duration(
            body.get("duration") or default_duration)
        vm = manager().learn(name, duration)
        return _vm_json(vm), 202

    @app.post("/v1/vms/<name>/proposal/generate")
    def generate(name):
        """POST /v1/vms/<vm>/proposal/generate: genera subito la proposta."""
        return _vm_json(manager().generate(name), with_proposal=True)

    @app.post("/v1/vms/<name>/proposal/approve")
    def approve(name):
        """POST .../proposal/approve: approva (202, applica l'Enforcer)."""
        # L'Enforcer del servizio applica la proposta entro 30 secondi
        return _vm_json(manager().approve(name)), 202

    @app.post("/v1/vms/<name>/proposal/reject")
    def reject(name):
        """POST /v1/vms/<vm>/proposal/reject: rifiuta la proposta."""
        return _vm_json(manager().reject(name))

    @app.post("/v1/vms/<name>/rollback")
    def rollback(name):
        """POST /v1/vms/<vm>/rollback: rimette i gruppi originali."""
        return _vm_json(Enforcer(store(), cloud()).rollback(name))

    # --- Anomalie ----------------------------------------------------------------

    @app.get("/v1/alerts")
    def list_alerts():
        """GET /v1/alerts: anomalie aperte (filtri ?vm=<vm>, ?all=true)."""
        vm_name = flask.request.args.get("vm")
        server_id = _followed(vm_name).server_id if vm_name else None
        everything = flask.request.args.get("all", "").lower() == "true"
        names = {vm.server_id: vm.name for vm in store().list_vms()}
        alerts = store().list_alerts(server_id,
                                     status=None if everything else "open")
        return {"alerts": [_alert_json(a, names) for a in alerts]}

    @app.post("/v1/alerts/<int:alert_id>/accept")
    def accept(alert_id):
        """POST /v1/alerts/<id>/accept: l'anomalia diventa una regola (202)."""
        vm = anomalies().accept(alert_id)
        return {"alert": alert_id, "status": "accepted",
                "vm": _vm_json(vm)}, 202

    @app.post("/v1/alerts/<int:alert_id>/dismiss")
    def dismiss(alert_id):
        """POST /v1/alerts/<id>/dismiss: ignora l'anomalia."""
        anomalies().dismiss(alert_id)
        return {"alert": alert_id, "status": "dismissed"}

    return app


def keystone_protected(app, auth_conf):
    """Mette keystonemiddleware davanti all'applicazione WSGI.

    `auth_conf` sono le opzioni della sezione [keystone_authtoken] del file
    di configurazione, scritte dal plugin DevStack.
    """
    from keystonemiddleware import auth_token
    return auth_token.AuthProtocol(app, dict(auth_conf))


# --- Avvio come servizio ----------------------------------------------------------

def _section(conf, name):
    """Opzioni di una sezione, senza quelle di [DEFAULT]."""
    if not conf.has_section(name):
        return {}
    defaults = conf.defaults()
    return {k: v for k, v in conf.items(name) if k not in defaults}


def main(argv=None):
    """Programma del servizio devstack@sg-learner-api.

    Legge la configurazione (si ferma senza [keystone_authtoken]), crea
    l'applicazione, la mette dietro keystonemiddleware e la serve con
    wsgiref su host e porta della sezione [api].
    """
    parser = argparse.ArgumentParser(description="API REST di SG-Learner")
    parser.add_argument("--config-file", default=DEFAULT_CONFIG)
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    conf = configparser.ConfigParser()
    if not conf.read(args.config_file):
        raise SystemExit(f"File di configurazione non trovato: "
                         f"{args.config_file}")
    auth_conf = _section(conf, "keystone_authtoken")
    if not auth_conf:
        raise SystemExit("Sezione [keystone_authtoken] mancante: l'API non"
                         " parte senza autenticazione Keystone")

    # Import qui, come nel servizio: i test di create_app non ne hanno bisogno
    from sg_learner import cloud as cloud_module
    from sg_learner import service

    app = create_app(
        conf.get("DEFAULT", "data_dir", fallback=DEFAULT_DATA_DIR),
        lambda: cloud_module.Cloud(service.connect(conf)),
        engine.options_from_config(conf),
        detector.options_from_config(conf),
        conf.get("DEFAULT", "learn_duration",
                 fallback=str(lifecycle.DEFAULT_LEARN_DURATION)))
    host = conf.get("api", "host", fallback=DEFAULT_HOST)
    port = conf.getint("api", "port", fallback=DEFAULT_PORT)

    # wsgiref: server WSGI della libreria standard, una richiesta alla volta.
    # Basta per un'API usata dall'amministratore e non aggiunge dipendenze.
    server = simple_server.make_server(
        host, port, keystone_protected(app, auth_conf))
    LOG.info("API di SG-Learner %s in ascolto su %s:%d", __version__,
             host, port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
