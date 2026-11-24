"""Ciclo di vita delle VM: osservazione, proposta, approvazione, rifiuto.

    LEARNING  --(fine finestra o generate)-->  PROPOSED
    PROPOSED  --(approve)-->  APPROVED  --(Enforcer)-->  ENFORCING
    PROPOSED  --(reject)-->   REJECTED
    ENFORCING --(rollback)--> PROPOSED
    ENFORCING --(accept di un'anomalia)-->  APPROVED
    non applicata --(learn)-->  LEARNING   (se applicata: prima rollback)

approve e reject scrivono solo la decisione nel database: su Neutron
agisce l'Enforcer (enforcer.py), al giro successivo del servizio.

Collegamenti: i comandi arrivano dall'API (api.py); tick lo chiama il
servizio (service.py) per le finestre scadute. Per la proposta usa il
Policy Engine (engine.py) sulle osservazioni del Flow Store (store.py).
"""

import dataclasses
import datetime
import logging

from sg_learner import engine
from sg_learner.store import ConflictError, VmRecord

LEARNING = "learning"
PROPOSED = "proposed"
APPROVED = "approved"
ENFORCING = "enforcing"
REJECTED = "rejected"

DEFAULT_LEARN_DURATION = 3600  # secondi

LOG = logging.getLogger(__name__)


class LifecycleError(Exception):
    """Operazione non valida nello stato attuale della VM."""


class NotFoundError(LookupError):
    """VM o anomalia inesistente (l'API risponde 404)."""


class InvalidInputError(ValueError):
    """Dato scritto dall'amministratore non valido (l'API risponde 400)."""


def _now():
    """Ora attuale in UTC."""
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
        raise InvalidInputError(f"Durata non valida: {text}") from None
    if seconds <= 0:
        raise InvalidInputError(f"La durata deve essere positiva: {text}")
    return seconds


class Lifecycle:
    """Gestisce le transizioni di stato delle VM."""

    def __init__(self, store, cloud, engine_options=None):
        """`engine_options`: soglie del Policy Engine dalla sezione [engine]."""
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
        previous = self.store.get_vm(port.server_id)
        # Con la proposta applicata il gruppo appreso resterebbe sulla porta
        # durante la nuova osservazione: il traffico nuovo verrebbe solo
        # bloccato. Prima si torna ai gruppi originali con rollback
        if previous and previous.state in (APPROVED, ENFORCING):
            wait = (" (attendere che l'Enforcer la applichi)"
                    if previous.state == APPROVED else "")
            raise LifecycleError(
                f"{port.server_name} e' nello stato '{previous.state}':"
                f" eseguire prima sg-learner rollback {port.server_name}"
                f"{wait}")
        log_ids = self.cloud.enable_logging(
            port.security_group_ids, port.project_id,
            name=f"sg-learner-{port.server_name}")
        # Le osservazioni vecchie non entrano nella nuova proposta
        self.store.forget(port.mac)
        # VM gia' seguita: restano i gruppi originali (rollback) e il learned
        originals = (previous.security_groups if previous
                     else list(port.security_group_ids))
        vm = VmRecord(
            server_id=port.server_id, name=port.server_name,
            project_id=port.project_id, port_id=port.port_id,
            mac=port.mac, ip=port.ip, state=LEARNING,
            security_groups=originals,
            log_ids=log_ids, learn_started=now,
            learn_until=now + datetime.timedelta(seconds=duration),
            learned_sg_id=previous.learned_sg_id if previous else None,
            enforce_log_ids=previous.enforce_log_ids if previous else [],
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
        """Genera la proposta con il Policy Engine e porta la VM in PROPOSED.

        Usata da generate e da tick. vm_groups dice, per ogni gruppo logico
        "vm:<nome>", quale VM ne fara' parte (serve all'Enforcer).
        """
        # IP delle altre VM -> gruppo: per regole remote_group, non per IP
        ip_to_group, group_to_server = self.cloud.vm_groups_by_ip(
            exclude_server_id=vm.server_id)
        # Solo il traffico della finestra: una riga vista per intero prima di
        # learn_started (pacchetti letti subito dopo forget) non conta
        observations = [o for o in self.store.observations(vm_mac=vm.mac)
                        if not vm.learn_started
                        or o.last_seen >= vm.learn_started]
        proposal = engine.build_proposal(
            observations, vm.mac, ip_to_group, **self.engine_options)
        vm.proposal = {
            "generated_at": now.isoformat(),
            "total_connections": proposal.total_connections,
            "rules": [dataclasses.asdict(r) for r in proposal.rules],
            # Per ogni gruppo citato, la VM che ne fara' parte (Enforcer)
            "vm_groups": {r.remote_group: group_to_server[r.remote_group]
                          for r in proposal.rules if r.remote_group},
            # Nel testo per l'amministratore il MAC diventa nome e IP
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

    def reject(self, name_or_id, now=None):
        """Rifiuta la proposta: la VM resta con i gruppi originali."""
        vm = self.get(name_or_id)
        if vm.state != PROPOSED:
            raise LifecycleError(
                f"{vm.name} e' nello stato '{vm.state}': si rifiuta solo"
                " una proposta in attesa")
        # Niente Neutron: in PROPOSED la porta ha gia' i gruppi originali.
        # La proposta resta salvata come storico
        vm.proposal["rejected_at"] = (now or _now()).isoformat()
        vm.state = REJECTED
        self.store.save_vm(vm)
        return vm

    def tick(self, now=None):
        """Genera le proposte per le VM con la finestra di osservazione
        scaduta. Restituisce le VM aggiornate."""
        now = now or _now()
        proposed = []
        for vm in self.store.list_vms(state=LEARNING):
            if vm.learn_until and vm.learn_until <= now:
                # Un errore su una VM non ferma le altre
                try:
                    proposed.append(self._propose(vm, now))
                except ConflictError:
                    pass        # cambiata dall'API: si riprova al giro dopo
                except Exception:
                    LOG.exception("%s: proposta non generata, si riprova"
                                  " al giro dopo", vm.name)
        return proposed

    def status(self):
        """Tutte le VM seguite, per `sg-learner status`."""
        return self.store.list_vms()
