"""Accesso a OpenStack: tutte le chiamate a Nova e Neutron passano da qui.

Raccogliere le chiamate in un unico modulo ha due vantaggi: il resto del
codice non dipende dai dettagli delle API, e nei test questa classe puo'
essere sostituita da una finta (vedi tests/test_lifecycle.py).

Il Packet Logging di Neutron non e' ancora coperto da openstacksdk, quindi
le chiamate a /log/logs usano direttamente l'API REST tramite la sessione
autenticata di openstacksdk.
"""

import dataclasses
import logging

from openstack import exceptions

LOG = logging.getLogger(__name__)

LOG_EVENT_ALL = "ALL"
LOG_EVENT_DROP = "DROP"


@dataclasses.dataclass(frozen=True)
class VmPort:
    """La porta di rete principale di una VM."""

    server_id: str
    server_name: str
    project_id: str
    port_id: str
    mac: str
    ip: str
    security_group_ids: tuple


class Cloud:
    """Operazioni su OpenStack usate da SG-Learner."""

    def __init__(self, conn):
        self.conn = conn

    # --- Nova e porte ----------------------------------------------------------

    def find_vm(self, name_or_id):
        """Trova una VM (in qualunque progetto) e la sua porta principale."""
        server = self.conn.compute.find_server(
            name_or_id, ignore_missing=True, all_projects=True)
        if server is None:
            raise LookupError(f"VM non trovata: {name_or_id}")
        ports = list(self.conn.network.ports(device_id=server.id))
        if not ports:
            raise LookupError(f"La VM {server.name} non ha porte di rete")
        port = ports[0]
        if len(ports) > 1:
            LOG.warning("La VM %s ha %d porte: uso %s", server.name,
                        len(ports), port.id)
        ip = port.fixed_ips[0]["ip_address"] if port.fixed_ips else ""
        return VmPort(
            server_id=server.id, server_name=server.name,
            project_id=server.project_id, port_id=port.id,
            mac=port.mac_address, ip=ip,
            security_group_ids=tuple(port.security_group_ids or ()),
        )

    def vm_groups_by_ip(self, exclude_server_id=None):
        """Mappa {IP di una VM: "vm:<nome>"} per il traffico tra VM.

        Restituisce anche {"vm:<nome>": server_id}, per ritrovare la VM
        quando la regola verra' applicata.
        """
        names = {s.id: s.name
                 for s in self.conn.compute.servers(all_projects=True)}
        ip_to_group, group_to_server = {}, {}
        for port in self.conn.network.ports():
            server_id = port.device_id
            if (not (port.device_owner or "").startswith("compute:")
                    or server_id == exclude_server_id
                    or server_id not in names):
                continue
            group = f"vm:{names[server_id]}"
            group_to_server[group] = server_id
            for fixed_ip in port.fixed_ips or ():
                ip_to_group[fixed_ip["ip_address"]] = group
        return ip_to_group, group_to_server

    # --- Security group e porte (usati dall'Enforcer) ---------------------------

    def port_security_groups(self, port_id):
        return list(self.conn.network.get_port(port_id).security_group_ids
                    or ())

    def security_group_names(self, sg_ids):
        """{ID: nome} dei security group indicati."""
        return {sg_id: self.conn.network.get_security_group(sg_id).name
                for sg_id in sg_ids}

    def set_port_security_groups(self, port_id, sg_ids):
        self.conn.network.update_port(port_id,
                                      security_group_ids=list(sg_ids))

    def ensure_security_group(self, name, project_id, description=""):
        """Restituisce l'ID del gruppo `name` nel progetto, creandolo se
        non esiste.

        Un gruppo appena creato viene svuotato: Neutron vi aggiunge regole
        "tutto permesso in uscita" (IPv4 e IPv6) che allargherebbero i
        permessi di qualunque porta a cui il gruppo viene assegnato.
        """
        for sg in self.conn.network.security_groups(name=name,
                                                    project_id=project_id):
            return sg.id
        sg = self.conn.network.create_security_group(
            name=name, project_id=project_id, description=description)
        for rule in self.security_group_rules(sg.id):
            self.delete_rule(rule["id"])
        LOG.info("Creato il security group %s (%s), senza regole",
                 name, sg.id)
        return sg.id

    def security_group_rules(self, sg_id):
        """Regole del gruppo, come dizionari con i campi di Neutron."""
        return [{
            "id": rule.id,
            "direction": rule.direction,
            "ethertype": rule.ether_type,
            "protocol": rule.protocol,
            "port_range_min": rule.port_range_min,
            "port_range_max": rule.port_range_max,
            "remote_ip_prefix": rule.remote_ip_prefix,
            "remote_group_id": rule.remote_group_id,
        } for rule in self.conn.network.security_group_rules(
            security_group_id=sg_id)]

    def create_rule(self, sg_id, project_id, rule):
        self.conn.network.create_security_group_rule(
            security_group_id=sg_id, project_id=project_id, **rule)

    def delete_rule(self, rule_id):
        self.conn.network.delete_security_group_rule(rule_id,
                                                     ignore_missing=True)

    # --- Packet Logging di Neutron ---------------------------------------------

    def _request(self, method, path, **kwargs):
        response = self.conn.network.request(path, method, **kwargs)
        exceptions.raise_from_response(response)
        return response.json() if response.content else None

    def network_logs(self):
        return self._request("GET", "/log/logs")["logs"]

    def enable_logging(self, security_group_ids, project_id, name,
                       event=LOG_EVENT_ALL):
        """Attiva il logging sui security group indicati.

        Riusa un log gia' esistente sullo stesso gruppo con lo stesso
        evento. Restituisce gli ID dei log.
        """
        existing = {(log["resource_id"], log["event"]): log["id"]
                    for log in self.network_logs()
                    if log.get("resource_type") == "security_group"}
        log_ids = []
        for sg_id in security_group_ids:
            log_id = existing.get((sg_id, event))
            if log_id is None:
                body = {"log": {
                    "name": name, "resource_type": "security_group",
                    "resource_id": sg_id, "event": event, "enabled": True,
                    "project_id": project_id,
                }}
                log_id = self._request("POST", "/log/logs", json=body)["log"]["id"]
                LOG.info("Logging %s attivato sul security group %s",
                         event, sg_id)
            log_ids.append(log_id)
        return log_ids

    def disable_logging(self, log_ids):
        for log_id in log_ids:
            try:
                self._request("DELETE", f"/log/logs/{log_id}")
            except exceptions.NotFoundException:
                pass
