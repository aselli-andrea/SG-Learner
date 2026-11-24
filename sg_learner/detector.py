"""Anomaly Detector: classifica il traffico bloccato delle VM applicate.

Algoritmo a soglie, deterministico. Per ogni VM in ENFORCING, sui DROP
successivi all'applicazione (enforced_at):

1. stesso IP remoto con almeno `scan_ports` porte diverse -> scan; gli
   alert singoli gia' creati per quell'IP diventano `in_scan`;
2. ogni altro flusso: almeno `candidate_threshold` tentativi -> candidate
   (forse un servizio legittimo non osservato), altrimenti alert.

SG-Learner non allarga mai le regole da solo: solo l'amministratore
trasforma un'anomalia in regola (accept), e una scan non si accetta mai.
Un'anomalia chiusa si riapre solo in un nuovo periodo di applicazione.

Collegamenti: legge i DROP dal Flow Store (store.py), raccolti dal log DROP
che l'Enforcer attiva sul gruppo appreso. tick lo chiama il servizio ogni
30 secondi; dismiss e accept arrivano dall'API. accept usa il Policy Engine
(engine.py) e riporta la VM in APPROVED: la regola la applica l'Enforcer.
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
                 scan_ports=DEFAULT_SCAN_PORTS, engine_options=None):
        """`cloud` serve solo ad accept (regole verso altre VM); le soglie
        vengono dalla sezione [detector] della configurazione."""
        self.store = store
        self.cloud = cloud
        # Le stesse opzioni del Policy Engine usate per la proposta
        self.engine_options = engine_options or {}
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
        """Aggiorna le anomalie di una VM. Restituisce quelle nuove.

        Due passate sui DROP dopo enforced_at: prima le scansioni (per IP
        remoto), poi i flussi restanti, candidate o alert per soglia.
        """
        since = self._since(vm)
        drops = self.store.observations(vm_mac=vm.mac, verdict="drop",
                                        since=since)
        new = []

        # Passata 1, scansioni: stesso IP, almeno scan_ports porte diverse
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
                    ports=len(ports), reopen_before=since)
                # reopen_before: riapre solo se chiusa in un periodo precedente
                if is_new:
                    new.append(alert)
                self._absorb_into_scan(vm, direction, remote)

        # Passata 2, flussi singoli: candidate se ricorrenti, altrimenti alert
        for obs in drops:
            if (obs.direction, obs.remote_ip) in scanners:
                continue
            kind = (CANDIDATE if obs.count >= self.candidate_threshold
                    else ALERT)
            alert, is_new = self.store.upsert_alert(
                vm.server_id, kind, obs.direction, obs.protocol,
                obs.service_port, obs.icmp_type, obs.remote_ip,
                count=obs.count, first_seen=obs.first_seen,
                last_seen=obs.last_seen, reopen_before=since)
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
        """L'anomalia indicata, solo se esiste ed e' ancora aperta."""
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
        """Trasforma un'anomalia in una regola: la aggiunge alla proposta e
        riporta la VM in APPROVED, cosi' l'Enforcer la applica.
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

        # I DROP che corrispondono esattamente all'anomalia (stessi campi)
        drops = [o for o in self.store.observations(vm_mac=vm.mac,
                                                    verdict="drop")
                 if (o.direction, o.protocol, o.service_port, o.icmp_type,
                     o.remote_ip) == (alert.direction, alert.protocol,
                                      alert.service_port, alert.icmp_type,
                                      alert.remote_ip)]
        # Gli stessi DROP, trattati come traffico permesso: cosi' il Policy
        # Engine costruisce la regola con le stesse logiche della proposta
        allowed = [dataclasses.replace(o, verdict="allow") for o in drops]

        ip_to_group, group_to_server = ({}, {})
        if self.cloud is not None:
            ip_to_group, group_to_server = self.cloud.vm_groups_by_ip(
                exclude_server_id=vm.server_id)
        proposal = engine.build_proposal(allowed, vm.mac, ip_to_group,
                                         **self.engine_options)

        rules = vm.proposal.setdefault("rules", [])
        for rule in proposal.rules:
            as_dict = dataclasses.asdict(rule)
            # Si aggiunge solo se la proposta non ha gia' una regola uguale
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
    """Due regole (dizionari) permettono lo stesso traffico."""
    fields = ("direction", "protocol", "port", "icmp_type",
              "remote_ip_prefix", "remote_group")
    return all(a.get(f) == b.get(f) for f in fields)
