"""Punto di avvio del servizio SG-Learner (eseguito da systemd).

All'avvio legge la configurazione e verifica l'accesso a OpenStack e al log
di OVN. Poi, in un ciclo continuo:

1. legge le righe nuove del log di ovn-controller (LogFollower);
2. ne estrae le connessioni nuove (Flow Collector);
3. le salva nel database (Flow Store).

A ogni intervallo scrive un riepilogo dell'attivita' e fa avanzare il ciclo
di vita delle VM: per quelle con la finestra di osservazione scaduta genera
la proposta con il Policy Engine; quelle approvate vengono applicate
dall'Enforcer, e quelle gia' applicate vengono riconciliate.
"""

import argparse
import configparser
import datetime
import logging
import os
import signal
import sys
import time

import openstack

from sg_learner import __version__
from sg_learner import collector, engine, lifecycle
from sg_learner.cloud import Cloud
from sg_learner.enforcer import Enforcer
from sg_learner.follower import LogFollower
from sg_learner.store import FlowStore

LOG = logging.getLogger("sg_learner")

DEFAULT_CONFIG = "/etc/sg-learner/sg-learner.conf"
DEFAULT_INTERVAL = 30
DEFAULT_POLL_INTERVAL = 2
DEFAULT_OVN_LOG = "/var/log/ovn/ovn-controller.log"
DEFAULT_DATA_DIR = "/opt/stack/data/sg-learner"
DB_FILE = "sg-learner.db"


def parse_args(argv):
    parser = argparse.ArgumentParser(description="Servizio SG-Learner")
    parser.add_argument("--config-file", default=DEFAULT_CONFIG,
                        help="percorso del file di configurazione")
    parser.add_argument("--debug", action="store_true",
                        help="log dettagliati")
    return parser.parse_args(argv)


def load_config(path):
    conf = configparser.ConfigParser()
    if not conf.read(path):
        raise SystemExit(f"File di configurazione non trovato: {path}")
    if not conf.has_section("openstack"):
        raise SystemExit(f"Sezione [openstack] mancante in {path}")
    return conf


def connect(conf):
    """Connessione a OpenStack con le credenziali dell'utente di servizio."""
    os_conf = conf["openstack"]
    return openstack.connect(
        auth_url=os_conf["auth_url"],
        username=os_conf["username"],
        password=os_conf["password"],
        project_name=os_conf["project_name"],
        user_domain_name=os_conf.get("user_domain_name", "Default"),
        project_domain_name=os_conf.get("project_domain_name", "Default"),
        region_name=os_conf.get("region_name", "RegionOne"),
    )


def self_check(conn, ovn_log):
    """Controlli di avvio: Keystone, Nova, Neutron e log di OVN."""
    conn.authorize()
    LOG.info("Autenticazione su Keystone riuscita")

    servers = list(conn.compute.servers(all_projects=True))
    LOG.info("Nova: %d VM visibili in tutti i progetti", len(servers))

    if conn.network.find_extension("logging"):
        LOG.info("Neutron: estensione Logging API attiva")
    else:
        LOG.warning("Neutron: estensione Logging API NON attiva")

    if os.access(ovn_log, os.R_OK):
        LOG.info("Log OVN leggibile: %s", ovn_log)
    else:
        LOG.warning("Log OVN NON leggibile: %s", ovn_log)


def connect_with_retry(conf, ovn_log, should_stop, attempts=30, delay=10,
                       sleep=time.sleep):
    """Connessione e controlli di avvio, ripetuti se OpenStack non e' pronto.

    Dopo un riavvio della macchina i servizi DevStack ripartono tutti
    insieme, e SG-Learner puo' avviarsi prima di Keystone: invece di
    fermarsi riprova ogni `delay` secondi, per `attempts` volte
    (5 minuti con i valori predefiniti).
    Restituisce la connessione, oppure None se il servizio viene fermato.
    """
    for attempt in range(1, attempts + 1):
        try:
            conn = connect(conf)
            self_check(conn, ovn_log)
            return conn
        except Exception as error:
            if attempt == attempts:
                raise
            LOG.warning("OpenStack non ancora raggiungibile (tentativo %d"
                        " di %d): %s. Nuovo tentativo tra %d s",
                        attempt, attempts, error, delay)
        for _ in range(delay):
            if should_stop():
                return None
            sleep(1)
    return None


class CollectionWorker:
    """Collega LogFollower, Flow Collector e Flow Store."""

    def __init__(self, follower, store, dedup_window=60):
        self.follower = follower
        self.store = store
        self.dedup = collector.ConnectionDeduplicator(dedup_window)
        self.new_connections = 0

    def poll(self):
        """Legge le righe nuove e salva le connessioni. Restituisce quante."""
        lines = self.follower.read_new_lines()
        if not lines:
            return 0
        flows = [f for f in collector.parse_lines(lines)
                 if f.is_connection_start and self.dedup.is_new(f)]
        saved = self.store.record_many(flows)
        self.new_connections += saved
        return saved

    def report(self):
        """Scrive un riepilogo e azzera il contatore del periodo."""
        self.dedup.expire(datetime.datetime.now(datetime.timezone.utc))
        LOG.info("SG-Learner attivo: %d nuove connessioni nell'ultimo"
                 " intervallo, %d in totale su %d porte di VM",
                 self.new_connections, self.store.total_connections(),
                 len(self.store.vm_macs()))
        self.new_connections = 0


def main(argv=None):
    args = parse_args(sys.argv[1:] if argv is None else argv)
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    conf = load_config(args.config_file)
    interval = conf.getint("DEFAULT", "interval", fallback=DEFAULT_INTERVAL)
    poll_interval = conf.getint("DEFAULT", "poll_interval",
                                fallback=DEFAULT_POLL_INTERVAL)
    ovn_log = conf.get("DEFAULT", "ovn_log_file", fallback=DEFAULT_OVN_LOG)
    data_dir = conf.get("DEFAULT", "data_dir", fallback=DEFAULT_DATA_DIR)

    stopping = False

    def _stop(signum, _frame):
        nonlocal stopping
        LOG.info("Ricevuto segnale %s, arresto in corso", signum)
        stopping = True

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    LOG.info("SG-Learner %s in avvio (riepilogo ogni %d s)",
             __version__, interval)
    conn = connect_with_retry(conf, ovn_log, lambda: stopping)
    if conn is None:
        LOG.info("SG-Learner arrestato prima della connessione a OpenStack")
        return 0

    os.makedirs(data_dir, exist_ok=True)
    db_path = os.path.join(data_dir, DB_FILE)
    store = FlowStore(db_path)
    LOG.info("Database: %s", db_path)
    worker = CollectionWorker(LogFollower(ovn_log, store), store)
    cloud = Cloud(conn)
    manager = lifecycle.Lifecycle(store, cloud,
                                  engine.options_from_config(conf))
    enforcer = Enforcer(store, cloud)

    next_report = time.monotonic() + interval
    while not stopping:
        try:
            worker.poll()
        except Exception:
            # Un errore di lettura non deve fermare il servizio
            LOG.exception("Errore durante la lettura del log di OVN")
        if time.monotonic() >= next_report:
            worker.report()
            try:
                for vm in manager.tick():
                    LOG.info("Osservazione di %s terminata: proposta con %d"
                             " regole in attesa di approvazione", vm.name,
                             len(vm.proposal["rules"]))
            except Exception:
                LOG.exception("Errore durante la generazione delle proposte")
            try:
                for vm in enforcer.tick():
                    LOG.info("Proposta di %s applicata: security group %s",
                             vm.name, vm.learned_sg_id)
            except Exception:
                LOG.exception("Errore durante l'applicazione delle proposte")
            next_report += interval
        time.sleep(poll_interval)

    store.close()
    LOG.info("SG-Learner arrestato")
    return 0


if __name__ == "__main__":
    sys.exit(main())
