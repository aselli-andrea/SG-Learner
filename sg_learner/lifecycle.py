"""Ciclo di vita delle VM: osservazione, proposta, approvazione.

Ogni VM seguita da SG-Learner attraversa questi stati:

    LEARNING  --(fine finestra o generate)-->  PROPOSED
    PROPOSED  --(approve)-->                   APPROVED
    APPROVED  --(Enforcer)-->                  ENFORCING
    qualunque --(learn)-->                     LEARNING   (riapprendimento)

- learn: attiva il Packet Logging sui security group della VM, azzera le
  osservazioni precedenti e apre una finestra di osservazione;
- alla fine della finestra il servizio genera la proposta con il Policy
  Engine (tick); l'amministratore puo' anche anticiparla (generate);
- approve: l'amministratore approva la proposta; l'applicazione su Neutron
  e' compito dell'Enforcer.
"""

import dataclasses
import datetime

from sg_learner import engine
from sg_learner.store import VmRecord

LEARNING = "learning"
PROPOSED = "proposed"
APPROVED = "approved"
ENFORCING = "enforcing"

DEFAULT_LEARN_DURATION = 3600  # secondi


class LifecycleError(Exception):
    """Operazione non valida nello stato attuale della VM."""


def _now():
    return datetime.datetime.now(datetime.timezone.utc)


def parse_duration(text):
    """Converte "90s", "30m", "2h", "1d" o "600" in secondi."""
    text = str(text).strip().lower()
    units = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    if text and text[-1] in units:
        value, factor = text[:-1], units[text[-1]]
    else:
        value, factor = text, 1
    try:
        seconds = int(float(value) * factor)
    except ValueError:
        raise ValueError(f"Durata non valida: {text}") from None
    if seconds <= 0:
        raise ValueError(f"La durata deve essere positiva: {text}")
    return seconds


class Lifecycle:
    """Gestisce le transizioni di stato delle VM."""

    def __init__(self, store, cloud, engine_options=None):
        self.store = store
        self.cloud = cloud
        self.engine_options = engine_options or {}

    def get(self, name_or_id):
        """Restituisce la VM seguita, o errore se non lo e'."""
        vm = self.store.get_vm(name_or_id)
        if vm is None:
            raise LifecycleError(
                f"{name_or_id} non e' seguita da SG-Learner:"
                " avviare prima l'osservazione con 'learn'")
        return vm

    def learn(self, name_or_id, duration=DEFAULT_LEARN_DURATION, now=None):
        """Avvia (o riavvia) l'osservazione di una VM."""
        now = now or _now()
        port = self.cloud.find_vm(name_or_id)
        log_ids = self.cloud.enable_logging(
            port.security_group_ids, port.project_id,
            name=f"sg-learner-{port.server_name}")
        self.store.forget(port.mac)
        vm = VmRecord(
            server_id=port.server_id, name=port.server_name,
            project_id=port.project_id, port_id=port.port_id,
            mac=port.mac, ip=port.ip, state=LEARNING,
            security_groups=list(port.security_group_ids),
            log_ids=log_ids, learn_started=now,
            learn_until=now + datetime.timedelta(seconds=duration),
        )
        self.store.save_vm(vm)
        return vm

    def generate(self, name_or_id, now=None):
        """Genera subito la proposta, senza aspettare la fine della finestra."""
        vm = self.get(name_or_id)
        if vm.state != LEARNING:
            raise LifecycleError(
                f"{vm.name} e' nello stato '{vm.state}': la proposta si"
                " genera solo durante l'osservazione")
        return self._propose(vm, now or _now())

    def _propose(self, vm, now):
        ip_to_group, group_to_server = self.cloud.vm_groups_by_ip(
            exclude_server_id=vm.server_id)
        proposal = engine.build_proposal(
            self.store.observations(vm_mac=vm.mac), vm.mac, ip_to_group,
            **self.engine_options)
        vm.proposal = {
            "generated_at": now.isoformat(),
            "total_connections": proposal.total_connections,
            "rules": [dataclasses.asdict(r) for r in proposal.rules],
            "vm_groups": {r.remote_group: group_to_server[r.remote_group]
                          for r in proposal.rules if r.remote_group},
            "summary": proposal.summary().replace(
                f"Proposta per {proposal.vm_ip or vm.mac}",
                f"Proposta per {vm.name} ({vm.ip})", 1),
        }
        vm.state = PROPOSED
        self.store.save_vm(vm)
        return vm

    def approve(self, name_or_id):
        """Approva la proposta: l'Enforcer la applichera'."""
        vm = self.get(name_or_id)
        if vm.state != PROPOSED:
            raise LifecycleError(
                f"{vm.name} e' nello stato '{vm.state}': si approva solo"
                " una proposta in attesa")
        if not vm.proposal or not vm.proposal["rules"]:
            raise LifecycleError(
                f"La proposta per {vm.name} non contiene regole: osservare"
                " la VM piu' a lungo prima di approvare")
        vm.state = APPROVED
        self.store.save_vm(vm)
        return vm

    def tick(self, now=None):
        """Genera le proposte per le VM con la finestra di osservazione
        scaduta. Restituisce le VM aggiornate."""
        now = now or _now()
        return [self._propose(vm, now)
                for vm in self.store.list_vms(state=LEARNING)
                if vm.learn_until and vm.learn_until <= now]

    def status(self):
        return self.store.list_vms()
