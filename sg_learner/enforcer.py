"""Enforcer: applica su Neutron le proposte approvate e le mantiene.

apply, per una VM approvata:

1. prepara i gruppi `learned-<nome>` delle altre VM citate da remote_group;
2. crea o riusa `learned-<nome>` e ne allinea le regole (approvate piu'
   BASE_RULES): crea le mancanti, cancella le altre;
3. mette sulla porta il gruppo appreso al posto degli originali;
4. attiva il logging DROP e porta la VM in ENFORCING.

Ogni 30 secondi tick ripete apply anche sulle VM gia' applicate
(riconciliazione): e' idempotente, corregge solo le differenze, e
ricrea il log DROP se qualcuno lo ha cancellato. Le VM cancellate da Nova
escono dal database. I gruppi originali non vengono mai modificati:
rollback li rimette.

I gruppi appresi si riconoscono dal segno nella descrizione (cloud.py,
LEARNED_MARK), che li lega alla VM: il nome serve solo all'amministratore.

Collegamenti: legge le VM approvate dal Flow Store (store.py), dove le ha
scritte l'API (approve, alerts accept); agisce su Neutron solo tramite
cloud.py. tick lo chiama il servizio, rollback l'API.
"""

import datetime
import logging

from sg_learner import engine, lifecycle
from sg_learner.cloud import LOG_EVENT_DROP
from sg_learner.store import ConflictError

LOG = logging.getLogger(__name__)

LEARNED_PREFIX = "learned-"
DESCRIPTION = "Generato da SG-Learner dal traffico osservato"

_RULE_FIELDS = ("direction", "ethertype", "protocol", "port_range_min",
                "port_range_max", "remote_ip_prefix", "remote_group_id")


def learned_group_name(vm_name):
    """Nome del gruppo appreso di una VM: "vm-web" -> "learned-vm-web"."""
    return f"{LEARNED_PREFIX}{vm_name}"


def _rule_key(rule):
    """Chiave di confronto tra una regola desiderata e una esistente."""
    return tuple(rule.get(field) for field in _RULE_FIELDS)


class Enforcer:
    """Applica e mantiene i security group appresi."""

    def __init__(self, store, cloud):
        """`store`: il Flow Store; `cloud`: l'accesso a Neutron (cloud.py)."""
        self.store = store
        self.cloud = cloud

    # --- Applicazione ---------------------------------------------------------

    def apply(self, vm):
        """Applica la proposta approvata di una VM. Restituisce la VM."""
        if vm.state not in (lifecycle.APPROVED, lifecycle.ENFORCING):
            raise lifecycle.LifecycleError(
                f"{vm.name} e' nello stato '{vm.state}': si applica solo"
                " una proposta approvata")

        groups = self._prepare_remote_groups(vm)
        sg_id = self.cloud.ensure_learned_group(
            vm.server_id, learned_group_name(vm.name), vm.project_id,
            DESCRIPTION)
        self._sync_rules(vm, sg_id, groups)

        # Porta: il gruppo della VM piu' i learned di cui e' membro (punto 1)
        current = self.cloud.port_security_groups(vm.port_id)
        wanted = [sg_id] + self._memberships(current, exclude=sg_id)
        if sorted(current) != sorted(wanted):
            self.cloud.set_port_security_groups(vm.port_id, wanted)
            LOG.info("%s: security group della porta sostituiti con %s",
                     vm.name, learned_group_name(vm.name))

        changed = vm.learned_sg_id != sg_id
        # Log DROP mai creato, o cancellato a mano: senza, il Detector non
        # vedrebbe piu' niente. Si ricrea
        if vm.enforce_log_ids and self.cloud.missing_logs(vm.enforce_log_ids):
            LOG.warning("%s: log DROP non piu' presente, lo ricreo", vm.name)
            vm.enforce_log_ids = []
        if not vm.enforce_log_ids:
            vm.enforce_log_ids = self.cloud.enable_logging(
                [sg_id], vm.project_id, name=f"sg-learner-{vm.name}-drop",
                event=LOG_EVENT_DROP)
            changed = True

        first_time = vm.state != lifecycle.ENFORCING
        if not (first_time or changed):
            # Nessuna novita': non si salva (niente conflitti con l'API)
            return vm
        if first_time:
            # Da qui in avanti i DROP sono di competenza dell'Anomaly Detector.
            # I DROP vecchi si cancellano: le righe sono aggregate, e un DROP
            # dell'osservazione gonfierebbe i conteggi delle anomalie
            vm.proposal["enforced_at"] = datetime.datetime.now(
                datetime.timezone.utc).isoformat()
            self.store.forget(vm.mac, verdict="drop")
        vm.learned_sg_id = sg_id
        vm.state = lifecycle.ENFORCING
        try:
            self.store.save_vm(vm)
        except ConflictError:
            # VM cambiata nel frattempo (alerts accept): ci pensa il giro dopo
            LOG.info("%s modificata nel frattempo: verra' riallineata al"
                     " prossimo giro", vm.name)
            return None
        if first_time:
            LOG.info("%s: proposta applicata (%d regole)", vm.name,
                     len(vm.proposal["rules"]))
        return vm

    def _memberships(self, sg_ids, exclude=None):
        """Gruppi appresi di altre VM tra quelli indicati (dal segno nella
        descrizione, non dal nome)."""
        return [g for g in self.cloud.learned_groups(sg_ids) if g != exclude]

    def _prepare_remote_groups(self, vm):
        """Gruppo learned di ogni VM citata da remote_group: {nome: ID}."""
        groups = {}
        for group, server_id in (vm.proposal.get("vm_groups") or {}).items():
            remote = self.cloud.find_vm(server_id)
            sg_id = self.cloud.ensure_learned_group(
                remote.server_id, learned_group_name(remote.server_name),
                remote.project_id, DESCRIPTION)
            current = self.cloud.port_security_groups(remote.port_id)
            if sg_id not in current:
                self.cloud.set_port_security_groups(remote.port_id,
                                                    current + [sg_id])
                LOG.info("%s aggiunta al gruppo %s (vuoto finche' non"
                         " viene applicata la sua proposta)",
                         remote.server_name,
                         learned_group_name(remote.server_name))
            groups[group] = sg_id
        return groups

    def _desired_rules(self, vm, groups):
        """Regole che il gruppo learned deve avere, nel formato di Neutron."""
        rules = []
        proposed = [engine.ProposedRule(**rule)
                    for rule in vm.proposal["rules"]]
        for rule in proposed + list(engine.BASE_RULES):
            neutron = {field: None for field in _RULE_FIELDS}
            neutron.update(rule.to_neutron())
            # Nome logico ("vm:vm-web") -> ID reale del gruppo su Neutron
            if neutron.get("remote_group_id"):
                neutron["remote_group_id"] = groups[neutron["remote_group_id"]]
            rules.append(neutron)
        return rules

    def _sync_rules(self, vm, sg_id, groups):
        """Allinea le regole del gruppo: cancella le estranee, crea le mancanti."""
        # Confronto per contenuto (direzione, protocollo, porte, altro capo),
        # non per ID: una regola uguale gia' presente non si tocca
        desired = {_rule_key(r): r for r in self._desired_rules(vm, groups)}
        existing = {_rule_key(r): r for r in
                    self.cloud.security_group_rules(sg_id)}
        for key, rule in existing.items():
            if key not in desired:
                self.cloud.delete_rule(rule["id"])
        for key, rule in desired.items():
            if key not in existing:
                self.cloud.create_rule(
                    sg_id, vm.project_id,
                    {k: v for k, v in rule.items() if v is not None})

    # --- Ciclo periodico e rollback ----------------------------------------------

    def tick(self):
        """Applica le proposte approvate e riconcilia quelle applicate.

        Restituisce le VM appena applicate. Un errore su una VM (es. una VM
        citata da remote_group cancellata) non ferma le altre.
        """
        self.forget_deleted_vms()
        applied = []
        for vm in (self.store.list_vms(state=lifecycle.APPROVED)
                   + self.store.list_vms(state=lifecycle.ENFORCING)):
            approved = vm.state == lifecycle.APPROVED
            try:
                if self.apply(vm) is not None and approved:
                    applied.append(vm)
            except Exception:
                LOG.exception("%s: applicazione non riuscita, si riprova al"
                              " giro dopo", vm.name)
        return applied

    def forget_deleted_vms(self):
        """Toglie dal database le VM che non esistono piu' in Nova.

        Il controllo e' sull'elenco completo dei server: una VM resta se
        esiste, anche quando un'altra operazione su di lei fallisce.
        Restituisce i nomi delle VM tolte.
        """
        alive = self.cloud.server_ids()
        removed = []
        for vm in self.store.list_vms():
            if vm.server_id in alive:
                continue
            # Solo il log DROP del suo gruppo appreso: i log dell'osservazione
            # stanno sui gruppi originali e possono servire ad altre VM
            self.cloud.disable_logging(vm.enforce_log_ids)
            self.store.forget(vm.mac)
            self.store.delete_vm(vm.server_id)
            removed.append(vm.name)
            LOG.info("%s non esiste piu' in Nova: tolta da SG-Learner",
                     vm.name)
        return removed

    def rollback(self, name_or_id):
        """Rimette sulla porta i security group originali.

        La VM torna in stato PROPOSED con la stessa proposta: si puo'
        riapprovare, oppure ripetere l'osservazione con learn.
        """
        # ConflictError: il servizio ha salvato la VM nel frattempo. Si ripete,
        # tanto le operazioni su Neutron sono idempotenti
        for attempt in range(3):
            try:
                return self._rollback(name_or_id)
            except ConflictError:
                if attempt == 2:
                    raise
                LOG.info("%s modificata dal servizio durante il rollback:"
                         " ripeto", name_or_id)
        return None

    def _rollback(self, name_or_id):
        """Un tentativo di rollback: gruppi originali sulla porta, log DROP
        spento, VM in PROPOSED. Solleva ConflictError se la VM cambia nel
        frattempo (rollback lo ripete).
        """
        vm = self.store.get_vm(name_or_id)
        if vm is None or vm.state != lifecycle.ENFORCING:
            raise lifecycle.LifecycleError(
                f"{name_or_id}: il rollback vale solo per una VM con la"
                " proposta applicata")
        # Restano le appartenenze ai learned di altre VM (le loro remote_group)
        current = self.cloud.port_security_groups(vm.port_id)
        memberships = self._memberships(current, exclude=vm.learned_sg_id)
        # Resta anche il proprio learned se altre VM lo citano (es. vm-web
        # accetta la 80 da learned-vm-app). Non allarga: le regole si sommano
        if vm.learned_sg_id and vm.learned_sg_id in current and \
                self.cloud.groups_referencing(vm.learned_sg_id):
            memberships.append(vm.learned_sg_id)
            LOG.info("%s: %s resta sulla porta perche' citato da regole di"
                     " altre VM", vm.name, learned_group_name(vm.name))
        self.cloud.set_port_security_groups(
            vm.port_id, list(dict.fromkeys(vm.security_groups + memberships)))
        self.cloud.disable_logging(vm.enforce_log_ids)
        vm.enforce_log_ids = []
        vm.state = lifecycle.PROPOSED
        self.store.save_vm(vm)
        LOG.info("%s: ripristinati i security group originali", vm.name)
        return vm

