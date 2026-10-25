"""Comandi per l'amministratore: sg-learner <comando>.

Uso (dopo `source devstack/openrc admin admin`):

    sg-learner learn vm-web --duration 30m   avvia l'osservazione
    sg-learner status                        stato di tutte le VM seguite
    sg-learner proposal generate vm-web      genera subito la proposta
    sg-learner proposal show vm-web          mostra la proposta
    sg-learner proposal approve vm-web       approva la proposta
    sg-learner rollback vm-web               ripristina i gruppi originali

Il CLI usa le credenziali dell'utente che lo esegue (variabili OS_* di
openrc): solo chi ha accesso amministrativo a OpenStack puo' usarlo.
"""

import argparse
import configparser
import datetime
import os
import sys

import openstack

from sg_learner import engine, lifecycle
from sg_learner.cloud import Cloud
from sg_learner.enforcer import Enforcer
from sg_learner.store import FlowStore

DEFAULT_CONFIG = "/etc/sg-learner/sg-learner.conf"
DEFAULT_DATA_DIR = "/opt/stack/data/sg-learner"
DB_FILE = "sg-learner.db"


def _local(ts):
    """Orario nel fuso locale, per la lettura da parte dell'amministratore."""
    return ts.astimezone().strftime("%d/%m %H:%M") if ts else "-"


def print_status(vms, out=sys.stdout):
    if not vms:
        print("Nessuna VM seguita. Usa: sg-learner learn <vm>", file=out)
        return
    now = datetime.datetime.now(datetime.timezone.utc)
    print(f"{'VM':16} {'IP':15} {'STATO':10} {'FINE OSSERVAZIONE':18}"
          " REGOLE", file=out)
    for vm in vms:
        until = _local(vm.learn_until)
        if vm.state == lifecycle.LEARNING and vm.learn_until:
            minutes = max(0, int((vm.learn_until - now).total_seconds() // 60))
            until += f" ({minutes} min)"
        rules = len(vm.proposal["rules"]) if vm.proposal else "-"
        print(f"{vm.name:16} {vm.ip:15} {vm.state:10} {until:18} {rules}",
              file=out)


def build_parser():
    parser = argparse.ArgumentParser(
        prog="sg-learner",
        description="SG-Learner: security group appresi dal traffico reale")
    parser.add_argument("--config-file", default=DEFAULT_CONFIG)
    sub = parser.add_subparsers(dest="command", required=True)

    learn = sub.add_parser("learn", help="avvia l'osservazione di una VM")
    learn.add_argument("vm", help="nome o ID della VM")
    learn.add_argument("--duration", default=None,
                       help="durata dell'osservazione (es. 30m, 2h)")

    sub.add_parser("status", help="stato delle VM seguite")

    rollback = sub.add_parser(
        "rollback", help="ripristina i security group originali")
    rollback.add_argument("vm", help="nome o ID della VM")

    proposal = sub.add_parser("proposal", help="gestione delle proposte")
    proposal_sub = proposal.add_subparsers(dest="action", required=True)
    for action, text in (("generate", "genera subito la proposta"),
                         ("show", "mostra la proposta"),
                         ("approve", "approva la proposta")):
        p = proposal_sub.add_parser(action, help=text)
        p.add_argument("vm", help="nome o ID della VM")
    return parser


def main(argv=None, conn=None, out=sys.stdout):
    args = build_parser().parse_args(argv)

    conf = configparser.ConfigParser()
    conf.read(args.config_file)
    data_dir = conf.get("DEFAULT", "data_dir", fallback=DEFAULT_DATA_DIR)
    default_duration = conf.get("DEFAULT", "learn_duration",
                                fallback=str(lifecycle.DEFAULT_LEARN_DURATION))

    store = FlowStore(os.path.join(data_dir, DB_FILE))
    try:
        cloud = Cloud(conn or openstack.connect())
        manager = lifecycle.Lifecycle(store, cloud,
                                      engine.options_from_config(conf))

        if args.command == "learn":
            duration = lifecycle.parse_duration(
                args.duration or default_duration)
            vm = manager.learn(args.vm, duration)
            print(f"Osservazione di {vm.name} ({vm.ip}) avviata fino alle"
                  f" {_local(vm.learn_until)}. Logging attivo su"
                  f" {len(vm.log_ids)} security group.", file=out)

        elif args.command == "status":
            print_status(manager.status(), out)

        elif args.command == "rollback":
            vm = Enforcer(store, cloud).rollback(args.vm)
            print(f"{vm.name}: ripristinati i security group originali."
                  " La proposta resta disponibile (stato 'proposed').",
                  file=out)

        elif args.action == "generate":
            vm = manager.generate(args.vm)
            print(vm.proposal["summary"], file=out)

        elif args.action == "show":
            vm = manager.get(args.vm)
            if not vm.proposal:
                print(f"{vm.name}: nessuna proposta (stato '{vm.state}')",
                      file=out)
            else:
                print(vm.proposal["summary"], file=out)
                print(f"\nStato: {vm.state}", file=out)

        elif args.action == "approve":
            vm = manager.approve(args.vm)
            print(f"Proposta per {vm.name} approvata: il servizio la"
                  " applichera' entro 30 secondi.", file=out)

    except (lifecycle.LifecycleError, LookupError, ValueError) as error:
        print(f"Errore: {error}", file=sys.stderr)
        return 1
    finally:
        store.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
