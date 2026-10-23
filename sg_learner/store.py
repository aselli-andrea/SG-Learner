"""Flow Store: memorizza in SQLite le connessioni osservate.

Il database non salva ogni singola connessione, ma un riepilogo: per ogni
porta di VM (identificata dal MAC) e per ogni combinazione di direzione,
protocollo, porta di servizio, altro capo e verdetto tiene il numero di
connessioni e la prima e l'ultima volta in cui sono state viste.

Esempio di riga:
    vm fa:16:3e:9e:8d:c4 | ingress | tcp | 22 | 172.24.4.1 | allow | 8 conn.

La "porta di servizio" e' sempre la porta di destinazione del pacchetto che
apre la connessione: per il traffico in ingresso e' la porta della VM
(es. 22 per SSH), per quello in uscita la porta del servizio remoto
(es. 80 verso il servizio metadati).

Il database contiene anche:
- la tabella `vms`, con le VM seguite da SG-Learner e il loro stato nel
  ciclo di vita (osservazione, proposta, approvazione, applicazione);
- una piccola tabella chiave/valore usata dal servizio per ricordare il
  proprio stato (ad esempio fin dove ha letto il log di OVN), cosi' da
  riprendere dopo un riavvio.
"""

import contextlib
import dataclasses
import datetime
import json
import sqlite3

SCHEMA_VERSION = 2

# SQLite tratta i NULL come valori sempre diversi tra loro, quindi non
# funzionerebbero nella chiave primaria: i campi assenti (porte per ICMP,
# tipo ICMP per TCP/UDP) vengono salvati come -1.
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
    updated_at      TEXT NOT NULL
);
"""

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


def _to_db(value):
    return _NONE if value is None else value


def _from_db(value):
    return None if value == _NONE else value


def _ts_to_db(value):
    return value.astimezone(datetime.timezone.utc).isoformat()


def _ts_from_db(value):
    return datetime.datetime.fromisoformat(value)


def _opt_ts_to_db(value):
    return _ts_to_db(value) if value else None


def _opt_ts_from_db(value):
    return _ts_from_db(value) if value else None


class FlowStore:
    """Accesso al database SQLite di SG-Learner."""

    def __init__(self, path):
        self.path = str(path)
        self._db = sqlite3.connect(self.path)
        self._db.row_factory = sqlite3.Row
        if self.path != ":memory:":
            # WAL: le letture (API) non bloccano le scritture (collector)
            self._db.execute("PRAGMA journal_mode=WAL")
        self._db.executescript(_SCHEMA)
        self._db.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
        self._db.commit()

    def close(self):
        self._db.close()

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.close()

    @contextlib.contextmanager
    def _transaction(self):
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

    def forget(self, vm_mac):
        """Cancella le osservazioni di una VM (per un nuovo apprendimento)."""
        with self._transaction() as db:
            cur = db.execute("DELETE FROM observations WHERE vm_mac = ?",
                             (vm_mac,))
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
        """Inserisce o aggiorna una VM. Aggiorna anche updated_at."""
        vm.updated_at = datetime.datetime.now(datetime.timezone.utc)
        with self._transaction() as db:
            db.execute(
                "INSERT OR REPLACE INTO vms VALUES"
                " (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (vm.server_id, vm.name, vm.project_id, vm.port_id, vm.mac,
                 vm.ip, vm.state, json.dumps(vm.security_groups),
                 json.dumps(vm.log_ids), _opt_ts_to_db(vm.learn_started),
                 _opt_ts_to_db(vm.learn_until),
                 json.dumps(vm.proposal) if vm.proposal is not None else None,
                 _ts_to_db(vm.updated_at)))

    def get_vm(self, name_or_id):
        """Cerca una VM per ID o per nome. Restituisce None se non c'e'."""
        row = self._db.execute(
            "SELECT * FROM vms WHERE server_id = ? OR name = ?"
            " ORDER BY server_id = ? DESC LIMIT 1",
            (name_or_id, name_or_id, name_or_id)).fetchone()
        return self._row_to_vm(row) if row else None

    def list_vms(self, state=None):
        query, params = "SELECT * FROM vms", []
        if state is not None:
            query += " WHERE state = ?"
            params.append(state)
        query += " ORDER BY name"
        return [self._row_to_vm(r) for r in self._db.execute(query, params)]

    @staticmethod
    def _row_to_vm(row):
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
        )

    # --- Stato del servizio ---------------------------------------------------

    def get_state(self, key, default=None):
        row = self._db.execute("SELECT value FROM state WHERE key = ?",
                               (key,)).fetchone()
        return row["value"] if row else default

    def set_state(self, key, value):
        with self._transaction() as db:
            db.execute(
                "INSERT INTO state (key, value) VALUES (?, ?)"
                " ON CONFLICT (key) DO UPDATE SET value = excluded.value",
                (key, str(value)))
