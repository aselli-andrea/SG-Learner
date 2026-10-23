"""Punto di avvio del servizio SG-Learner (eseguito da systemd).

Versione iniziale: legge la configurazione, verifica l'accesso a OpenStack
e al log di OVN, poi resta attivo segnalando il proprio stato a ogni ciclo.
I componenti (collector, engine, enforcer, detector) verranno aggiunti qui.
"""

import argparse
import configparser
import logging
import os
import signal
import sys
import time

import openstack

from sg_learner import __version__

LOG = logging.getLogger("sg_learner")

DEFAULT_CONFIG = "/etc/sg-learner/sg-learner.conf"
DEFAULT_INTERVAL = 30
DEFAULT_OVN_LOG = "/var/log/ovn/ovn-controller.log"


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


def main(argv=None):
    args = parse_args(sys.argv[1:] if argv is None else argv)
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    conf = load_config(args.config_file)
    interval = conf.getint("DEFAULT", "interval", fallback=DEFAULT_INTERVAL)
    ovn_log = conf.get("DEFAULT", "ovn_log_file", fallback=DEFAULT_OVN_LOG)

    stopping = False

    def _stop(signum, _frame):
        nonlocal stopping
        LOG.info("Ricevuto segnale %s, arresto in corso", signum)
        stopping = True

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    LOG.info("SG-Learner %s in avvio (ciclo ogni %d s)", __version__, interval)
    conn = connect(conf)
    self_check(conn, ovn_log)

    while not stopping:
        LOG.info("SG-Learner attivo")
        for _ in range(interval):
            if stopping:
                break
            time.sleep(1)

    LOG.info("SG-Learner arrestato")
    return 0


if __name__ == "__main__":
    sys.exit(main())
