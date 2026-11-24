"""CLI dell'amministratore: sg-learner <comando>.

    sg-learner learn <vm> --duration 30m   avvia l'osservazione
    sg-learner status                       stato delle VM seguite
    sg-learner proposal generate|show|approve|reject <vm>
    sg-learner rollback <vm>                rimette i gruppi originali
    sg-learner alerts list [vm] | accept <id> | dismiss <id>

La CLI e' un client dell'API REST (api.py), come il comando `openstack`
lo e' per Nova e Neutron: con le credenziali OS_* di openrc chiede un token
a Keystone, trova l'indirizzo dell'API nel catalogo (servizio sg-learner)
e chiama gli endpoint. Non apre il database e non chiama Neutron.
"""

import argparse
import datetime
import os
import sys
import urllib.parse

import openstack
from keystoneauth1 import exceptions as ks_exceptions
from openstack import exceptions as sdk_exceptions

# Tipo del servizio nel catalogo di Keystone (devstack/plugin.sh)
SERVICE_TYPE = "sg-learner"

OPENRC_HINT = ("credenziali di OpenStack mancanti. Eseguire prima:"
               " source /opt/stack/devstack/openrc admin admin")


class CliError(Exception):
    """Errore da mostrare all'amministratore come "Errore: ..."."""


class ApiClient:
    """Chiamate all'API REST con la sessione autenticata di openstacksdk.

    La sessione aggiunge da sola il token (X-Auth-Token) e trova l'URL
    dell'API nel catalogo di Keystone; `url` lo sostituisce se indicato.
    """

    def __init__(self, conn, url=None):
        self.session = conn.session
        self.region = getattr(conn.config, "region_name", None)
        self.url = url

    def request(self, method, path, body=None):
        """Restituisce (codice HTTP, JSON della risposta)."""
        options = {"endpoint_override": self.url} if self.url else {
            "endpoint_filter": {"service_type": SERVICE_TYPE,
                                "interface": "public",
                                "region_name": self.region}}
        try:
            response = self.session.request(path, method, json=body,
                                            raise_exc=False, **options)
        except ks_exceptions.auth_plugins.MissingRequiredOptions:
            raise CliError(OPENRC_HINT)
        except ks_exceptions.EndpointNotFound:
            raise CliError("API di SG-Learner non trovata nel catalogo di"
                           " Keystone (servizio sg-learner)")
        except ks_exceptions.ConnectFailure:
            raise CliError("API di SG-Learner non raggiungibile: controllare"
                           " 'systemctl status devstack@sg-learner-api'")
        except ks_exceptions.ClientException as error:
            raise CliError(f"richiesta all'API fallita: {error}")
        try:
            data = response.json()
        except ValueError:
            data = {}
        return response.status_code, data


def call(client, method, path, body=None):
    """Una chiamata all'API: il JSON se va bene, altrimenti CliError con il
    messaggio dell'API (404, 409, 400, 401, 403)."""
    code, data = client.request(method, path, body)
    if code >= 400:
        raise CliError(data.get("error") or f"risposta HTTP {code}")
    return data


def _vm_path(name, suffix=""):
    return f"/vms/{urllib.parse.quote(name, safe='')}{suffix}"


def _parse(ts):
    """Testo ISO 8601 dell'API -> datetime (None resta None)."""
    return datetime.datetime.fromisoformat(ts) if ts else None


def _local(ts):
    """Orario nel fuso locale, per la lettura da parte dell'amministratore."""
    return ts.astimezone().strftime("%d/%m %H:%M") if ts else "-"


def print_status(vms, out=sys.stdout):
    """Tabella di `sg-learner status`: una riga per VM seguita."""
    if not vms:
        print("Nessuna VM seguita. Usa: sg-learner learn <vm>", file=out)
        return
    now = datetime.datetime.now(datetime.timezone.utc)
    print(f"{'VM':16} {'IP':15} {'STATO':10} {'FINE OSSERVAZIONE':18}"
          " REGOLE", file=out)
    for vm in vms:
        learn_until = _parse(vm["learn_until"])
        until = _local(learn_until)
        # Durante l'osservazione si mostrano anche i minuti che mancano
        if vm["state"] == "learning" and learn_until:
            minutes = max(0, int((learn_until - now).total_seconds() // 60))
            until += f" ({minutes} min)"
        rules = vm["rules"] if vm["rules"] is not None else "-"
        print(f"{vm['name']:16} {vm['ip'] or '-':15} {vm['state']:10}"
              f" {until:18} {rules}", file=out)


def print_alerts(alerts, out=sys.stdout):
    """Tabella di `sg-learner alerts list`."""
    if not alerts:
        print("Nessuna anomalia aperta.", file=out)
        return
    print(f"{'ID':>4} {'VM':14} {'TIPO':10} {'TENTATIVI':>9} {'ULTIMO':12}"
          " DESCRIZIONE", file=out)
    for a in alerts:
        print(f"{a['id']:>4} {a['vm'][:14]:14} {a['kind']:10}"
              f" {a['count']:>9} {_local(_parse(a['last_seen'])):12}"
              f" {a['description']}", file=out)


def build_parser():
    """Definisce comandi e opzioni della riga di comando (argparse)."""
    parser = argparse.ArgumentParser(
        prog="sg-learner",
        description="SG-Learner: security group appresi dal traffico reale")
    parser.add_argument(
        "--api-url", default=os.environ.get("SG_LEARNER_API_URL"),
        help="URL dell'API (es. http://host:9797/v1); di default lo prende"
             " dal catalogo di Keystone")
    # Un sottocomando per ogni operazione: learn, status, rollback,
    # alerts (list/accept/dismiss) e proposal (generate/show/approve/reject)
    sub = parser.add_subparsers(dest="command", required=True)

    learn = sub.add_parser("learn", help="avvia l'osservazione di una VM")
    learn.add_argument("vm", help="nome o ID della VM")
    learn.add_argument("--duration", default=None,
                       help="durata dell'osservazione (es. 30m, 2h)")

    sub.add_parser("status", help="stato delle VM seguite")

    rollback = sub.add_parser(
        "rollback", help="ripristina i security group originali")
    rollback.add_argument("vm", help="nome o ID della VM")

    alerts = sub.add_parser("alerts", help="anomalie nel traffico bloccato")
    alerts_sub = alerts.add_subparsers(dest="action", required=True)
    alerts_list = alerts_sub.add_parser("list", help="anomalie aperte")
    alerts_list.add_argument("vm", nargs="?", help="solo questa VM")
    alerts_list.add_argument("--all", action="store_true",
                             help="anche quelle gia' gestite")
    for action, text in (("accept", "trasforma l'anomalia in una regola"),
                         ("dismiss", "ignora l'anomalia")):
        p = alerts_sub.add_parser(action, help=text)
        p.add_argument("id", type=int, help="ID dell'anomalia")

    proposal = sub.add_parser("proposal", help="gestione delle proposte")
    proposal_sub = proposal.add_subparsers(dest="action", required=True)
    for action, text in (("generate", "genera subito la proposta"),
                         ("show", "mostra la proposta"),
                         ("approve", "approva la proposta"),
                         ("reject", "rifiuta la proposta")):
        p = proposal_sub.add_parser(action, help=text)
        p.add_argument("vm", help="nome o ID della VM")
    return parser


def run(args, client, out):
    """Esegue il comando chiamando l'API e stampa il risultato."""
    if args.command == "learn":
        body = {"duration": args.duration} if args.duration else None
        vm = call(client, "POST", _vm_path(args.vm, "/learn"), body)
        print(f"Osservazione di {vm['name']} ({vm['ip']}) avviata fino alle"
              f" {_local(_parse(vm['learn_until']))}. Logging attivo su"
              f" {vm['network_logs']} security group.", file=out)

    elif args.command == "status":
        print_status(call(client, "GET", "/vms")["vms"], out)

    elif args.command == "rollback":
        vm = call(client, "POST", _vm_path(args.vm, "/rollback"))
        print(f"{vm['name']}: ripristinati i security group originali."
              " La proposta resta disponibile (stato 'proposed').", file=out)

    elif args.command == "alerts":
        if args.action == "list":
            query = {}
            if args.vm:
                query["vm"] = args.vm
            if args.all:
                query["all"] = "true"
            path = "/alerts" + (f"?{urllib.parse.urlencode(query)}"
                                if query else "")
            print_alerts(call(client, "GET", path)["alerts"], out)
        elif args.action == "accept":
            data = call(client, "POST", f"/alerts/{args.id}/accept")
            print(f"Anomalia {args.id} accettata: la nuova regola per"
                  f" {data['vm']['name']} verra' applicata entro 30"
                  " secondi.", file=out)
        else:
            call(client, "POST", f"/alerts/{args.id}/dismiss")
            print(f"Anomalia {args.id} ignorata.", file=out)

    # Da qui in poi il comando e' "proposal"
    elif args.action == "generate":
        vm = call(client, "POST", _vm_path(args.vm, "/proposal/generate"))
        print(vm["proposal"]["summary"], file=out)

    elif args.action == "show":
        vm = call(client, "GET", _vm_path(args.vm))
        if not vm.get("proposal"):
            print(f"{vm['name']}: nessuna proposta (stato '{vm['state']}')",
                  file=out)
        else:
            print(vm["proposal"]["summary"], file=out)
            print(f"\nStato: {vm['state']}", file=out)

    elif args.action == "approve":
        vm = call(client, "POST", _vm_path(args.vm, "/proposal/approve"))
        print(f"Proposta per {vm['name']} approvata: il servizio la"
              " applichera' entro 30 secondi.", file=out)

    elif args.action == "reject":
        vm = call(client, "POST", _vm_path(args.vm, "/proposal/reject"))
        print(f"Proposta per {vm['name']} rifiutata: la VM resta con i"
              " security group originali. Per una nuova proposta:"
              f" sg-learner learn {vm['name']}", file=out)


def main(argv=None, client=None, out=sys.stdout):
    """Punto di ingresso del comando. Restituisce 0 se va tutto bene.

    client e out servono ai test: un client che parla con l'API di prova
    di Flask e un output da controllare al posto dello schermo.
    """
    args = build_parser().parse_args(argv)
    try:
        if client is None:
            # Credenziali dalle variabili OS_* di openrc: senza openrc si
            # da' un messaggio chiaro invece di un traceback
            try:
                conn = openstack.connect()
            except (ks_exceptions.auth_plugins.MissingRequiredOptions,
                    sdk_exceptions.ConfigException):
                raise CliError(OPENRC_HINT)
            client = ApiClient(conn, args.api_url)
        run(args, client, out)
    # Errori previsti (VM non trovata, stato sbagliato, durata non valida,
    # token o ruolo mancante, API non raggiungibile): messaggio e codice 1
    except CliError as error:
        print(f"Errore: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
