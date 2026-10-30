"""Enforcer: applica su Neutron le proposte approvate e le mantiene.

Per una VM in stato APPROVED:

1. prepara i gruppi delle altre VM citate dalle regole remote_group
   (`learned-<nome>`): se non esistono li crea vuoti e li aggiunge alla
   porta di quella VM. Un gruppo vuoto non cambia cio' che la VM puo'
   fare (le regole dei security group si sommano), ma la rende "membro"
   del gruppo, cosi' la regola remote_group funziona subito;
2. crea (o riusa) il gruppo `learned-<nome>` della VM e ne allinea le
   regole a quelle approvate piu' le regole di base (DHCP e metadata,
   engine.BASE_RULES): crea le mancanti e cancella le altre.
   Ogni gruppo nuovo nasce vuoto: cloud.py cancella subito le regole di
   uscita "tutto permesso" che Neutron vi aggiunge;
3. assegna alla porta della VM solo `learned-<nome>` (piu' i gruppi
   learned di cui e' membro per il punto 1), al posto dei gruppi
   originali, che restano salvati per un eventuale rollback;
4. attiva il logging DROP sul nuovo gruppo: da qui in avanti vengono
   registrate solo le connessioni bloccate, per l'Anomaly Detector;
5. porta la VM in stato ENFORCING.

Per una VM gia' in ENFORCING il ciclo periodico ripete i controlli e
corregge le differenze (riconciliazione): se qualcuno cambia a mano i
gruppi della porta o le regole, vengono ripristinati. Ogni operazione e'
idempotente: ripeterla quando tutto e' in ordine non cambia nulla.
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
    return f"{LEARNED_PREFIX}{vm_name}"


def _rule_key(rule):
    """Chiave di confronto tra una regola desiderata e una esistente."""
    return tuple(rule.get(field) for field in _RULE_FIELDS)


class Enforcer:
    """Applica e mantiene i security group appresi."""

    def __init__(self, store, cloud):
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
        sg_id = self.cloud.ensure_security_group(
            learned_group_name(vm.name), vm.project_id, DESCRIPTION)
        self._sync_rules(vm, sg_id, groups)

        # Restano solo il gruppo della VM e i gruppi learned di altre VM di
        # cui la porta e' membro (punto 1); ogni altro gruppo viene tolto.
        current = self.cloud.port_security_groups(vm.port_id)
        wanted = [sg_id] + self._memberships(current, exclude=sg_id)
        if sorted(current) != sorted(wanted):
            self.cloud.set_port_security_groups(vm.port_id, wanted)
            LOG.info("%s: security group della porta sostituiti con %s",
                     vm.name, learned_group_name(vm.name))

        changed = vm.learned_sg_id != sg_id
        if not vm.enforce_log_ids:
            vm.enforce_log_ids = self.cloud.enable_logging(
                [sg_id], vm.project_id, name=f"sg-learner-{vm.name}-drop",
                event=LOG_EVENT_DROP)
            changed = True

        first_time = vm.state != lifecycle.ENFORCING
        if not (first_time or changed):
            # Riconciliazione senza novita' nel database: non si salva, cosi'
            # un comando della CLI lanciato in questo momento non va in
            # conflitto con il servizio (caso visto con la demo: rollback).
            return vm
        if first_time:
            # Da qui in avanti i DROP sono di competenza dell'Anomaly Detector
            vm.proposal["enforced_at"] = datetime.datetime.now(
                datetime.timezone.utc).isoformat()
        vm.learned_sg_id = sg_id
        vm.state = lifecycle.ENFORCING
        try:
            self.store.save_vm(vm)
        except ConflictError:
            # Mentre parlavamo con Neutron la VM e' stata cambiata (es. con
            # `alerts accept`): non si sovrascrive, il prossimo giro
            # applichera' la versione aggiornata.
            LOG.info("%s modificata nel frattempo: verra' riallineata al"
                     " prossimo giro", vm.name)
            return None
        if first_time:
            LOG.info("%s: proposta applicata (%d regole)", vm.name,
                     len(vm.proposal["rules"]))
        return vm

    def _memberships(self, sg_ids, exclude=None):
        """Gruppi learned di altre VM tra quelli indicati."""
        names = self.cloud.security_group_names(sg_ids)
        return [g for g in sg_ids if g != exclude and
                names.get(g, "").startswith(LEARNED_PREFIX)]

    def _prepare_remote_groups(self, vm):
        """Gruppo learned di ogni VM citata da remote_group: {nome: ID}."""
        groups = {}
        for group, server_id in (vm.proposal.get("vm_groups") or {}).items():
            remote = self.cloud.find_vm(server_id)
            sg_id = self.cloud.ensure_security_group(
                learned_group_name(remote.server_name), remote.project_id,
                DESCRIPTION)
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
        rules = []
        proposed = [engine.ProposedRule(**rule)
                    for rule in vm.proposal["rules"]]
        for rule in proposed + list(engine.BASE_RULES):
            neutron = {field: None for field in _RULE_FIELDS}
            neutron.update(rule.to_neutron())
            if neutron.get("remote_group_id"):
                neutron["remote_group_id"] = groups[neutron["remote_group_id"]]
            rules.append(neutron)
        return rules

    def _sync_rules(self, vm, sg_id, groups):
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

        Restituisce le VM appena applicate.
        """
        applied = []
        for vm in self.store.list_vms(state=lifecycle.APPROVED):
            if self.apply(vm) is not None:
                applied.append(vm)
        for vm in self.store.list_vms(state=lifecycle.ENFORCING):
            self.apply(vm)
        return applied

    def rollback(self, name_or_id):
        """Rimette sulla porta i security group originali.

        La VM torna in stato PROPOSED con la stessa proposta: si puo'
        riapprovare, oppure ripetere l'osservazione con learn.
        """
        # Se il servizio salva la stessa VM proprio in questo momento il
        # salvataggio fallisce (ConflictError): le operazioni su Neutron sono
        # idempotenti, quindi si rilegge la VM e si ripete.
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
        vm = self.store.get_vm(name_or_id)
        if vm is None or vm.state != lifecycle.ENFORCING:
            raise lifecycle.LifecycleError(
                f"{name_or_id}: il rollback vale solo per una VM con la"
                " proposta applicata")
        # Le appartenenze ai gruppi learned di altre VM restano, altrimenti
        # le loro regole remote_group smetterebbero di valere per questa VM
        current = self.cloud.port_security_groups(vm.port_id)
        memberships = self._memberships(current, exclude=vm.learned_sg_id)
        # Anche il gruppo learned della VM resta sulla porta se altre VM lo
        # citano nelle loro regole (es. vm-web accetta la 80 dal gruppo
        # learned-vm-app): togliendolo, il rollback di vm-app romperebbe
        # vm-web. Tenerlo non restringe nulla: le regole si sommano e quelle
        # learned sono un sottoinsieme del traffico gia' permesso dai gruppi
        # originali (piu' DHCP e metadata). Caso trovato nella demo a 3 VM.
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

