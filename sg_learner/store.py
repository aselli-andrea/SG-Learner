"""Flow Store: l'unico accesso al database SQLite di SG-Learner.

Tabelle:

- observations: riepilogo delle connessioni, una riga per VM (MAC),
  direzione, protocollo, porta di servizio, altro capo e verdetto, con
  contatore e prima/ultima volta. Non si salva ogni connessione;
- vms: le VM seguite, il loro stato e la proposta (JSON);
- alerts: le anomalie dell'Anomaly Detector;
- state: chiave/valore, per esempio la posizione nel log di OVN.

Servizio e API usano lo stesso file (la CLI passa dall'API): save_vm evita
che un processo sovrascriva le modifiche dell'altro (controllo su
updated_at).

Collegamenti: scrivono qui CollectionWorker (osservazioni), Lifecycle ed
Enforcer (VM), Anomaly Detector (anomalie); l'API legge e scrive le stesse
tabelle. Nessun altro modulo usa SQLite direttamente.
"""

import contextlib
import dataclasses
import datetime
import json
import sqlite3

SCHEMA_VERSION = 4

# Campi assenti (porte per ICMP, tipo ICMP per TCP/UDP) salvati come -1:
# in SQLite due NULL sono sempre diversi e romperebbero la chiave primaria
_NONE = -1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS observations (
    vm_mac       TEXT    NOT NULL,
    direction    TEXT    NOT NULL,
    protocol     TEXT    NOT NULL,
    service_port INTEGER NOT NULL,
    icmp_type    INTEGER NOT NULL,
    remote_ip    TEXT    NOT NULL,
    verdict      TEXT    NOT NULL,
    vm_ip        TEXT    NOT NULL,
    count        INTEGER NOT NULL,
    first_seen   TEXT    NOT NULL,
    last_seen    TEXT    NOT NULL,
    PRIMARY KEY (vm_mac, direction, protocol, service_port, icmp_type,
                 remote_ip, verdict)
);
CREATE INDEX IF NOT EXISTS observations_by_last_seen
    ON observations (vm_mac, last_seen);
CREATE TABLE IF NOT EXISTS state (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS vms (
    server_id       TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    project_id      TEXT NOT NULL,
    port_id         TEXT NOT NULL,
    mac             TEXT NOT NULL,
    ip              TEXT NOT NULL,
    state           TEXT NOT NULL,
    security_groups TEXT NOT NULL,
    log_ids         TEXT NOT NULL,
    learn_started   TEXT,
    learn_until     TEXT,
    proposal        TEXT,
    updated_at      TEXT NOT NULL,
    learned_sg_id   TEXT,
    enforce_log_ids TEXT NOT NULL DEFAULT '[]'
);
CREATE TABLE IF NOT EXISTS alerts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id    TEXT    NOT NULL,
    kind         TEXT    NOT NULL,
    direction    TEXT    NOT NULL,
    protocol     TEXT    NOT NULL,
    service_port INTEGER NOT NULL,
    icmp_type    INTEGER NOT NULL,
    remote_ip    TEXT    NOT NULL,
    count        INTEGER NOT NULL,
    ports        INTEGER NOT NULL DEFAULT 1,
    first_seen   TEXT    NOT NULL,
    last_seen    TEXT    NOT NULL,
    status       TEXT    NOT NULL DEFAULT 'open',
    UNIQUE (server_id, direction, protocol, service_port, icmp_type,
            remote_ip)
);
"""

# Una connessione nuova crea la riga con count=1; se la riga esiste gia'
# (stessa chiave primaria) si incrementa count e si allargano prima e
# ultima volta
_UPSERT = """
INSERT INTO observations (vm_mac, direction, protocol, service_port,
                          icmp_type, remote_ip, verdict, vm_ip, count,
                          first_seen, last_seen)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
ON CONFLICT (vm_mac, direction, protocol, service_port, icmp_type,
             remote_ip, verdict)
DO UPDATE SET count = count + 1,
              vm_ip = excluded.vm_ip,
              first_seen = MIN(first_seen, excluded.first_seen),
              last_seen = MAX(last_seen, excluded.last_seen)
"""


class ConflictError(Exception):
    """La VM e' stata modificata da un altro processo dopo la lettura."""


@dataclasses.dataclass(frozen=True)
class Observation:
    """Riepilogo delle connessioni osservate per una combinazione di campi."""

    vm_mac: str
    vm_ip: str
    direction: str
    protocol: str
    service_port: int | None
    icmp_type: int | None
    remote_ip: str
    verdict: str
    count: int
    first_seen: datetime.datetime
    last_seen: datetime.datetime


@dataclasses.dataclass
class VmRecord:
    """Una VM seguita da SG-Learner e il suo stato nel ciclo di vita."""

    server_id: str
    name: str
    project_id: str
    port_id: str
    mac: str
    ip: str
    state: str
    security_groups: list
    log_ids: list
    learn_started: datetime.datetime | None = None
    learn_until: datetime.datetime | None = None
    proposal: dict | None = None
    updated_at: datetime.datetime | None = None
    learned_sg_id: str | None = None
    enforce_log_ids: list = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class Alert:
    """Un'anomalia rilevata sul traffico bloccato di una VM applicata."""

    id: int
    server_id: str
    kind: str              # alert, candidate, scan
    direction: str
    protocol: str
    service_port: int | None
    icmp_type: int | None
    remote_ip: str
    count: int
    ports: int             # porte distinte (per kind=scan)
    first_seen: datetime.datetime
    last_seen: datetime.datetime
    status: str            # open, accepted, dismissed, in_scan


def _to_db(value):
    """None -> -1, per i campi che fanno parte della chiave primaria."""
    return _NONE if value is None else value


def _from_db(value):
    """-1 -> None: l'inverso di _to_db."""
    return None if value == _NONE else value


def _ts_to_db(value):
    """datetime -> testo ISO 8601 in UTC."""
    # Sempre in UTC e in formato ISO: cosi' il confronto tra stringhe in
    # SQL (es. last_seen >= ?) equivale al confronto tra istanti
    return value.astimezone(datetime.timezone.utc).isoformat()


def _ts_from_db(value):
    """Testo ISO 8601 -> datetime."""
    return datetime.datetime.fromisoformat(value)


def _opt_ts_to_db(value):
    """Come _ts_to_db, ma None resta None (data facoltativa)."""
    return _ts_to_db(value) if value else None


def _opt_ts_from_db(value):
    """Come _ts_from_db, ma None resta None."""
    return _ts_from_db(value) if value else None


class FlowStore:
    """Accesso al database SQLite di SG-Learner."""

    def __init__(self, path):
        """Apre (o crea) il database: WAL, tabelle mancanti, migrazione."""
        self.path = str(path)
        self._db = sqlite3.connect(self.path)
        self._db.row_factory = sqlite3.Row
        if self.path != ":memory:":
            # WAL: le letture (API) non bloccano le scritture (collector)
            self._db.execute("PRAGMA journal_mode=WAL")
        # CREATE ... IF NOT EXISTS: su un database esistente non cambia nulla
        self._db.executescript(_SCHEMA)
        self._migrate()
        self._db.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
        self._db.commit()

    def _migrate(self):
        """Aggiorna un database creato da una versione precedente."""
        columns = {row["name"] for row in
                   self._db.execute("PRAGMA table_info(vms)")}
        if "learned_sg_id" not in columns:
            self._db.execute("ALTER TABLE vms ADD COLUMN learned_sg_id TEXT")
        if "enforce_log_ids" not in columns:
            self._db.execute("ALTER TABLE vms ADD COLUMN enforce_log_ids"
                             " TEXT NOT NULL DEFAULT '[]'")

    def close(self):
        """Chiude il database."""
        self._db.close()

    def __enter__(self):
        """Uso con `with FlowStore(...) as store:` (si chiude da solo)."""
        return self

    def __exit__(self, *_exc):
        self.close()

    @contextlib.contextmanager
    def _transaction(self):
        """Scritture in blocco: commit se va bene, rollback se c'e' errore."""
        try:
            yield self._db
            self._db.commit()
        except Exception:
            self._db.rollback()
            raise

    # --- Scrittura ---------------------------------------------------------

    def record(self, flow):
        """Registra una connessione (un Flow del collector)."""
        self.record_many([flow])

    def record_many(self, flows):
        """Registra piu' connessioni in un'unica transazione.

        Restituisce il numero di connessioni registrate.
        """
        # Porta di servizio = dst_port del primo pacchetto: in ingresso la
        # porta della VM (22), in uscita quella del servizio remoto (53)
        rows = [
            (f.vm_mac, f.direction, f.protocol, _to_db(f.dst_port),
             _to_db(f.icmp_type), f.remote_ip, f.verdict, f.vm_ip,
             _ts_to_db(f.timestamp), _ts_to_db(f.timestamp))
            for f in flows
        ]
        if rows:
            with self._transaction() as db:
                db.executemany(_UPSERT, rows)
        return len(rows)

    def forget(self, vm_mac, verdict=None):
        """Cancella le osservazioni di una VM (per un nuovo apprendimento).

        Con `verdict` cancella solo quelle con quel verdetto ("drop").
        """
        query, params = "DELETE FROM observations WHERE vm_mac = ?", [vm_mac]
        if verdict is not None:
            query += " AND verdict = ?"
            params.append(verdict)
        with self._transaction() as db:
            cur = db.execute(query, params)
        return cur.rowcount

    def delete_vm(self, server_id):
        """Cancella una VM seguita e le sue anomalie (VM non piu' in Nova)."""
        with self._transaction() as db:
            db.execute("DELETE FROM alerts WHERE server_id = ?", (server_id,))
            cur = db.execute("DELETE FROM vms WHERE server_id = ?",
                             (server_id,))
        return cur.rowcount

    # --- Lettura -------------------------------------------------------------

    def observations(self, vm_mac=None, verdict=None, since=None):
        """Restituisce le osservazioni, filtrate se richiesto.

        `since` limita alle osservazioni viste dopo quell'istante.
        """
        query = "SELECT * FROM observations WHERE 1=1"
        params = []
        if vm_mac is not None:
            query += " AND vm_mac = ?"
            params.append(vm_mac)
        if verdict is not None:
            query += " AND verdict = ?"
            params.append(verdict)
        if since is not None:
            query += " AND last_seen >= ?"
            params.append(_ts_to_db(since))
        query += (" ORDER BY vm_mac, direction, protocol, service_port,"
                  " icmp_type, remote_ip, verdict")
        return [self._row_to_observation(row)
                for row in self._db.execute(query, params)]

    def vm_macs(self):
        """MAC delle porte di VM per cui esistono osservazioni."""
        rows = self._db.execute(
            "SELECT DISTINCT vm_mac FROM observations ORDER BY vm_mac")
        return [row["vm_mac"] for row in rows]

    def total_connections(self, vm_mac=None):
        """Numero totale di connessioni registrate (per VM o in tutto)."""
        query = "SELECT COALESCE(SUM(count), 0) FROM observations"
        params = []
        if vm_mac is not None:
            query += " WHERE vm_mac = ?"
            params.append(vm_mac)
        return self._db.execute(query, params).fetchone()[0]

    @staticmethod
    def _row_to_observation(row):
        """Riga della tabella observations -> Observation."""
        return Observation(
            vm_mac=row["vm_mac"],
            vm_ip=row["vm_ip"],
            direction=row["direction"],
            protocol=row["protocol"],
            service_port=_from_db(row["service_port"]),
            icmp_type=_from_db(row["icmp_type"]),
            remote_ip=row["remote_ip"],
            verdict=row["verdict"],
            count=row["count"],
            first_seen=_ts_from_db(row["first_seen"]),
            last_seen=_ts_from_db(row["last_seen"]),
        )

    # --- VM seguite (ciclo di vita) ------------------------------------------

    def save_vm(self, vm):
        """Inserisce o aggiorna una VM, con il suo updated_at.

        Controllo ottimistico: una VM letta dal database si salva solo se
        updated_at e' ancora quello letto, altrimenti ConflictError (chi
        chiama rilegge e riprova). Cosi' nessun processo cancella le
        modifiche di un altro.
        """
        previous = vm.updated_at
        now = datetime.datetime.now(datetime.timezone.utc)
        # Le liste e la proposta sono salvate come testo JSON
        values = (vm.name, vm.project_id, vm.port_id, vm.mac, vm.ip,
                  vm.state, json.dumps(vm.security_groups),
                  json.dumps(vm.log_ids), _opt_ts_to_db(vm.learn_started),
                  _opt_ts_to_db(vm.learn_until),
                  json.dumps(vm.proposal) if vm.proposal is not None
                  else None,
                  _ts_to_db(now), vm.learned_sg_id,
                  json.dumps(vm.enforce_log_ids))
        with self._transaction() as db:
            if previous is not None:
                # Aggiorna solo se updated_at e' ancora quello letto
                updated = db.execute(
                    "UPDATE vms SET name = ?, project_id = ?, port_id = ?,"
                    " mac = ?, ip = ?, state = ?, security_groups = ?,"
                    " log_ids = ?, learn_started = ?, learn_until = ?,"
                    " proposal = ?, updated_at = ?, learned_sg_id = ?,"
                    " enforce_log_ids = ?"
                    " WHERE server_id = ? AND updated_at = ?",
                    values + (vm.server_id, _ts_to_db(previous))).rowcount
                if updated:
                    vm.updated_at = now
                    return
                # Nessuna riga: VM cambiata (conflitto) o cancellata (sotto)
                if db.execute("SELECT 1 FROM vms WHERE server_id = ?",
                              (vm.server_id,)).fetchone():
                    raise ConflictError(
                        f"{vm.name} e' stata modificata nel frattempo da un"
                        " altro processo: riprovare")
            db.execute(
                "INSERT OR REPLACE INTO vms (name, project_id, port_id, mac,"
                " ip, state, security_groups, log_ids, learn_started,"
                " learn_until, proposal, updated_at, learned_sg_id,"
                " enforce_log_ids, server_id)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                values + (vm.server_id,))
        vm.updated_at = now

    def get_vm(self, name_or_id):
        """Cerca una VM per ID o per nome. Restituisce None se non c'e'."""
        row = self._db.execute(
            "SELECT * FROM vms WHERE server_id = ? OR name = ?"
            " ORDER BY server_id = ? DESC LIMIT 1",
            (name_or_id, name_or_id, name_or_id)).fetchone()
        return self._row_to_vm(row) if row else None

    def list_vms(self, state=None):
        """Le VM seguite, tutte o solo quelle nello stato indicato."""
        query, params = "SELECT * FROM vms", []
        if state is not None:
            query += " WHERE state = ?"
            params.append(state)
        query += " ORDER BY name"
        return [self._row_to_vm(r) for r in self._db.execute(query, params)]

    @staticmethod
    def _row_to_vm(row):
        """Riga della tabella vms -> VmRecord (liste e proposta da JSON)."""
        return VmRecord(
            server_id=row["server_id"], name=row["name"],
            project_id=row["project_id"], port_id=row["port_id"],
            mac=row["mac"], ip=row["ip"], state=row["state"],
            security_groups=json.loads(row["security_groups"]),
            log_ids=json.loads(row["log_ids"]),
            learn_started=_opt_ts_from_db(row["learn_started"]),
            learn_until=_opt_ts_from_db(row["learn_until"]),
            proposal=json.loads(row["proposal"]) if row["proposal"] else None,
            updated_at=_opt_ts_from_db(row["updated_at"]),
            learned_sg_id=row["learned_sg_id"],
            enforce_log_ids=json.loads(row["enforce_log_ids"] or "[]"),
        )

    # --- Anomalie (Anomaly Detector) ------------------------------------------

    def upsert_alert(self, server_id, kind, direction, protocol,
                     service_port, icmp_type, remote_ip, count, first_seen,
                     last_seen, ports=1, reopen_before=None):
        """Inserisce o aggiorna un'anomalia. Restituisce (alert, nuova).

        Un'anomalia chiusa non si riapre, tranne se e' di un periodo di
        applicazione precedente (vista l'ultima volta prima di
        `reopen_before`).
        """
        key = (server_id, direction, protocol, _to_db(service_port),
               _to_db(icmp_type), remote_ip)
        existing = self._db.execute(
            "SELECT * FROM alerts WHERE server_id = ? AND direction = ? AND"
            " protocol = ? AND service_port = ? AND icmp_type = ? AND"
            " remote_ip = ?", key).fetchone()
        reopened = False
        with self._transaction() as db:
            # Nuova, chiusa in un periodo precedente (si riapre) o gia' nota
            if existing is None:
                db.execute(
                    "INSERT INTO alerts (server_id, kind, direction, protocol,"
                    " service_port, icmp_type, remote_ip, count, ports,"
                    " first_seen, last_seen) VALUES"
                    " (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (server_id, kind, direction, protocol,
                     _to_db(service_port), _to_db(icmp_type), remote_ip,
                     count, ports, _ts_to_db(first_seen),
                     _ts_to_db(last_seen)))
            elif (existing["status"] != "open" and reopen_before is not None
                    and _ts_from_db(existing["last_seen"]) < reopen_before):
                db.execute(
                    "UPDATE alerts SET kind = ?, count = ?, ports = ?,"
                    " first_seen = ?, last_seen = ?, status = 'open'"
                    " WHERE id = ?",
                    (kind, count, ports, _ts_to_db(first_seen),
                     _ts_to_db(last_seen), existing["id"]))
                reopened = True
            else:
                db.execute(
                    "UPDATE alerts SET kind = ?, count = ?, ports = ?,"
                    " last_seen = ? WHERE id = ?",
                    # Una chiusa tiene il tipo con cui e' stata gestita
                    (kind if existing["status"] == "open"
                     else existing["kind"], count, ports,
                     _ts_to_db(last_seen), existing["id"]))
        row = self._db.execute(
            "SELECT * FROM alerts WHERE server_id = ? AND direction = ? AND"
            " protocol = ? AND service_port = ? AND icmp_type = ? AND"
            " remote_ip = ?", key).fetchone()
        return self._row_to_alert(row), existing is None or reopened

    def list_alerts(self, server_id=None, status="open"):
        """Le anomalie, filtrate per VM e stato (status=None: tutte)."""
        query, params = "SELECT * FROM alerts WHERE 1=1", []
        if server_id is not None:
            query += " AND server_id = ?"
            params.append(server_id)
        if status is not None:
            query += " AND status = ?"
            params.append(status)
        query += " ORDER BY id"
        return [self._row_to_alert(r) for r in self._db.execute(query, params)]

    def get_alert(self, alert_id):
        """Un'anomalia per ID, o None."""
        row = self._db.execute("SELECT * FROM alerts WHERE id = ?",
                               (alert_id,)).fetchone()
        return self._row_to_alert(row) if row else None

    def set_alert_status(self, alert_id, status):
        """Cambia lo stato di un'anomalia: accepted, dismissed o in_scan."""
        with self._transaction() as db:
            db.execute("UPDATE alerts SET status = ? WHERE id = ?",
                       (status, alert_id))

    @staticmethod
    def _row_to_alert(row):
        """Riga della tabella alerts -> Alert."""
        return Alert(
            id=row["id"], server_id=row["server_id"], kind=row["kind"],
            direction=row["direction"], protocol=row["protocol"],
            service_port=_from_db(row["service_port"]),
            icmp_type=_from_db(row["icmp_type"]),
            remote_ip=row["remote_ip"], count=row["count"],
            ports=row["ports"],
            first_seen=_ts_from_db(row["first_seen"]),
            last_seen=_ts_from_db(row["last_seen"]),
            status=row["status"],
        )

    # --- Stato del servizio ---------------------------------------------------

    def get_state(self, key, default=None):
        """Legge un valore della tabella chiave/valore `state`."""
        row = self._db.execute("SELECT value FROM state WHERE key = ?",
                               (key,)).fetchone()
        return row["value"] if row else default

    def set_state(self, key, value):
        """Scrive un valore della tabella chiave/valore `state`."""
        with self._transaction() as db:
            db.execute(
                "INSERT INTO state (key, value) VALUES (?, ?)"
                " ON CONFLICT (key) DO UPDATE SET value = excluded.value",
                (key, str(value)))
