"""Anomaly Detector: analizza il traffico bloccato delle VM applicate.

Dopo l'applicazione, il logging DROP registra ogni connessione bloccata dal
gruppo learned. Il detector le esamina per ogni VM in stato ENFORCING e le
classifica:

- scan: uno stesso IP ha provato almeno `scan_ports` porte diverse. E'
  il comportamento tipico di una scansione (es. nmap): va segnalato con
  priorita' e non diventa mai una regola;
- candidate: lo stesso flusso e' stato bloccato almeno
  `candidate_threshold` volte. Un tentativo che si ripete spesso e' piu'
  probabilmente un servizio legittimo non osservato durante
  l'apprendimento (es. un backup notturno): diventa una regola candidata;
- alert: tentativo bloccato isolato, da conoscere ma non da permettere.

Una scansione viene riconosciuta solo quando le porte provate raggiungono
la soglia: se il detector gira a meta' scansione, le prime porte diventano
alert singoli. Quando poi la scansione viene riconosciuta, questi alert
vengono chiusi (stato `in_scan`) e restano solo nella riga `scan`.

Le anomalie finiscono nella tabella `alerts`. La decisione resta
all'amministratore, con un'asimmetria voluta: SG-Learner non allarga mai
da solo le regole. Accettare una candidata la aggiunge alla proposta e
riporta la VM in APPROVED: l'Enforcer applica la nuova regola al giro
successivo. Cosi' un attaccante non puo' "addestrare" il firewall ad
aprirsi insistendo con i tentativi.
"""

import collections
import dataclasses
import datetime
import logging

from sg_learner import engine, lifecycle

LOG = logging.getLogger(__name__)

ALERT = "alert"
CANDIDATE = "candidate"
SCAN = "scan"
IN_SCAN = "in_scan"     # stato di un alert assorbito da una scansione

DEFAULT_CANDIDATE_THRESHOLD = 5
DEFAULT_SCAN_PORTS = 5


def options_from_config(conf):
    """Parametri del detector dalla sezione [detector] di un ConfigParser."""
    options = {}
    if conf.has_section("detector"):
        for key in ("candidate_threshold", "scan_ports"):
            if conf.has_option("detector", key):
                options[key] = conf.getint("detector", key)
    return options


def describe(alert):
    """Descrizione leggibile di un'anomalia."""
    preposition = "da" if alert.direction == "ingress" else "verso"
    if alert.kind == SCAN:
        return (f"{alert.direction} {preposition} {alert.remote_ip}:"
                f" {alert.ports} porte diverse provate")
    if alert.protocol in ("icmp", "icmp6"):
        what = alert.protocol
    else:
        what = f"{alert.protocol}/{alert.service_port}"
    return f"{alert.direction} {what} {preposition} {alert.remote_ip}"


class AnomalyDetector:
    """Classifica i DROP delle VM applicate e gestisce le decisioni."""

    def __init__(self, store, cloud=None,
                 candidate_threshold=DEFAULT_CANDIDATE_THRESHOLD,
                 scan_ports=DEFAULT_SCAN_PORTS):
        self.store = store
        self.cloud = cloud
        self.candidate_threshold = candidate_threshold
        self.scan_ports = scan_ports

    # --- Analisi ----------------------------------------------------------------

    @staticmethod
    def _since(vm):
        """Da quando contano i DROP: dall'applicazione della proposta."""
        enforced_at = (vm.proposal or {}).get("enforced_at")
        if enforced_at:
            return datetime.datetime.fromisoformat(enforced_at)
        return vm.learn_until

    def analyze(self, vm):
        """Aggiorna le anomalie di una VM. Restituisce quelle nuove."""
        drops = self.store.observations(vm_mac=vm.mac, verdict="drop",
                                        since=self._since(vm))
        new = []

        # Scansioni: un IP che prova molte porte diverse
        by_remote = collections.defaultdict(list)
        for obs in drops:
            by_remote[(obs.direction, obs.remote_ip)].append(obs)
        scanners = set()
        for (direction, remote), items in by_remote.items():
            ports = {(o.protocol, o.service_port) for o in items}
            if len(ports) >= self.scan_ports:
                scanners.add((direction, remote))
                alert, is_new = self.store.upsert_alert(
                    vm.server_id, SCAN, direction, "any", None, None, remote,
                    count=sum(o.count for o in items),
                    first_seen=min(o.first_seen for o in items),
                    last_seen=max(o.last_seen for o in items),
                    ports=len(ports))
                if is_new:
                    new.append(alert)
                self._absorb_into_scan(vm, direction, remote)

        # Singoli flussi bloccati: candidate se ricorrenti, altrimenti alert
        for obs in drops:
            if (obs.direction, obs.remote_ip) in scanners:
                continue
            kind = (CANDIDATE if obs.count >= self.candidate_threshold
                    else ALERT)
            alert, is_new = self.store.upsert_alert(
                vm.server_id, kind, obs.direction, obs.protocol,
                obs.service_port, obs.icmp_type, obs.remote_ip,
                count=obs.count, first_seen=obs.first_seen,
                last_seen=obs.last_seen)
            if is_new:
                new.append(alert)
        return new

    def _absorb_into_scan(self, vm, direction, remote):
        """Chiude gli alert singoli creati prima di riconoscere la scansione."""
        for alert in self.store.list_alerts(vm.server_id):
            if (alert.kind != SCAN and alert.direction == direction
                    and alert.remote_ip == remote):
                self.store.set_alert_status(alert.id, IN_SCAN)

    def tick(self):
        """Analizza tutte le VM applicate. Restituisce (vm, alert) nuovi."""
        found = []
        for vm in self.store.list_vms(state=lifecycle.ENFORCING):
            for alert in self.analyze(vm):
                found.append((vm, alert))
        return found

    # --- Decisioni dell'amministratore ------------------------------------------

    def _open_alert(self, alert_id):
        alert = self.store.get_alert(alert_id)
        if alert is None or alert.status != "open":
            raise lifecycle.LifecycleError(
                f"Anomalia {alert_id} inesistente o gia' gestita")
        return alert

    def dismiss(self, alert_id):
        """Ignora un'anomalia: resta nello storico, chiusa."""
        alert = self._open_alert(alert_id)
        self.store.set_alert_status(alert.id, "dismissed")
        return alert

    def accept(self, alert_id):
        """Trasforma un'anomalia in una regola da applicare.

        La regola viene costruita dal Policy Engine come se il traffico
        fosse stato osservato durante l'apprendimento, aggiunta alla
        proposta, e la VM torna in APPROVED: l'Enforcer la applichera'.
        """
        alert = self._open_alert(alert_id)
        if alert.kind == SCAN:
            raise lifecycle.LifecycleError(
                "Una scansione non puo' diventare una regola: si puo' solo"
                " ignorare")
        vm = self.store.get_vm(alert.server_id)
        if vm is None or vm.state != lifecycle.ENFORCING:
            raise lifecycle.LifecycleError(
                "La VM dell'anomalia non e' piu' in stato 'enforcing'")

        drops = [o for o in self.store.observations(vm_mac=vm.mac,
                                                    verdict="drop")
                 if (o.direction, o.protocol, o.service_port, o.icmp_type,
                     o.remote_ip) == (alert.direction, alert.protocol,
                                      alert.service_port, alert.icmp_type,
                                      alert.remote_ip)]
        allowed = [dataclasses.replace(o, verdict="allow") for o in drops]

        ip_to_group, group_to_server = ({}, {})
        if self.cloud is not None:
            ip_to_group, group_to_server = self.cloud.vm_groups_by_ip(
                exclude_server_id=vm.server_id)
        proposal = engine.build_proposal(allowed, vm.mac, ip_to_group)

        rules = vm.proposal.setdefault("rules", [])
        for rule in proposal.rules:
            as_dict = dataclasses.asdict(rule)
            if not any(_same_rule(as_dict, r) for r in rules):
                rules.append(as_dict)
            if rule.remote_group:
                vm.proposal.setdefault("vm_groups", {})[rule.remote_group] = \
                    group_to_server[rule.remote_group]
        vm.proposal["summary"] += (
            f"\n  + aggiunta da anomalia {alert.id}: {describe(alert)}")
        vm.state = lifecycle.APPROVED
        self.store.save_vm(vm)
        self.store.set_alert_status(alert.id, "accepted")
        LOG.info("%s: anomalia %d accettata, la regola verra' applicata",
                 vm.name, alert.id)
        return vm


def _same_rule(a, b):
    fields = ("direction", "protocol", "port", "icmp_type",
              "remote_ip_prefix", "remote_group")
    return all(a.get(f) == b.get(f) for f in fields)
