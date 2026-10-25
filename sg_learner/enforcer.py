"""Enforcer: applica su Neutron le proposte approvate e le mantiene.

Per una VM in stato APPROVED:

1. prepara i gruppi delle altre VM citate dalle regole remote_group
   (`learned-<nome>`): se non esistono li crea vuoti e li aggiunge alla
   porta di quella VM. Un gruppo vuoto non cambia cio' che la VM puo'
   fare (le regole dei security group si sommano), ma la rende "membro"
   del gruppo, cosi' la regola remote_group funziona subito;
2. crea (o riusa) il gruppo `learned-<nome>` della VM e ne allinea le
   regole a quelle approvate: crea le mancanti e cancella le altre.
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

import logging

from sg_learner import engine, lifecycle
from sg_learner.cloud import LOG_EVENT_DROP

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

        if not vm.enforce_log_ids:
            vm.enforce_log_ids = self.cloud.enable_logging(
                [sg_id], vm.project_id, name=f"sg-learner-{vm.name}-drop",
                event=LOG_EVENT_DROP)

        first_time = vm.state != lifecycle.ENFORCING
        vm.learned_sg_id = sg_id
        vm.state = lifecycle.ENFORCING
        self.store.save_vm(vm)
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
        for rule in vm.proposal["rules"]:
            neutron = {field: None for field in _RULE_FIELDS}
            neutron.update(engine.ProposedRule(**rule).to_neutron())
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
            applied.append(self.apply(vm))
        for vm in self.store.list_vms(state=lifecycle.ENFORCING):
            self.apply(vm)
        return applied

    def rollback(self, name_or_id):
        """Rimette sulla porta i security group originali.

        La VM torna in stato PROPOSED con la stessa proposta: si puo'
        riapprovare, oppure ripetere l'osservazione con learn.
        """
        vm = self.store.get_vm(name_or_id)
        if vm is None or vm.state != lifecycle.ENFORCING:
            raise lifecycle.LifecycleError(
                f"{name_or_id}: il rollback vale solo per una VM con la"
                " proposta applicata")
        # Le appartenenze ai gruppi learned di altre VM restano, altrimenti
        # le loro regole remote_group smetterebbero di valere per questa VM
        current = self.cloud.port_security_groups(vm.port_id)
        memberships = self._memberships(current, exclude=vm.learned_sg_id)
        self.cloud.set_port_security_groups(
            vm.port_id, list(dict.fromkeys(vm.security_groups + memberships)))
        self.cloud.disable_logging(vm.enforce_log_ids)
        vm.enforce_log_ids = []
        vm.state = lifecycle.PROPOSED
        self.store.save_vm(vm)
        LOG.info("%s: ripristinati i security group originali", vm.name)
        return vm

