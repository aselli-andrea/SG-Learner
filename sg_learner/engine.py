"""Policy Engine: dalle osservazioni alla proposta di security group minimo.

Riceve le osservazioni di una VM (dal Flow Store) e propone le sole regole
necessarie a consentire il traffico realmente visto. Non chiama OpenStack:
le informazioni sul cloud (quale IP appartiene a quale altra VM) gli vengono
passate da chi lo usa, cosi' la logica si puo' verificare con i test.

Regole di costruzione della proposta:

1. Solo il traffico consentito (verdict=allow) diventa una regola. I
   tentativi bloccati vengono riportati a parte, come informazione.
2. Il traffico gestito automaticamente da Neutron non diventa una regola:
   DHCP (UDP 67/68) e Neighbor Discovery IPv6 (ICMPv6 133-137).
3. Le connessioni vengono raggruppate per direzione, protocollo e porta
   di servizio (o tipo ICMP).
4. Per ogni gruppo, gli altri capi della comunicazione diventano:
   - remote_group, se sono altre VM del cloud: la regola segue il loro
     security group, anche se cambiano indirizzo;
   - 0.0.0.0/0 (o ::/0), se gli IP esterni distinti sono almeno
     `public_threshold`: e' un servizio pubblico;
   - un /32 (o /128) per ciascun IP esterno, altrimenti.
5. Le regole con poche connessioni (meno di `low_confidence_below`) sono
   marcate come "poco osservate", da controllare con attenzione.
"""

import collections
import dataclasses
import ipaddress

from sg_learner.collector import INGRESS

DEFAULT_PUBLIC_THRESHOLD = 5
DEFAULT_MIN_CONNECTIONS = 1
DEFAULT_LOW_CONFIDENCE_BELOW = 3

# Traffico che Neutron consente sempre, indipendentemente dal security group
_DHCP_PORTS = {67, 68, 546, 547}
_ICMPV6_NEIGHBOR_DISCOVERY = {133, 134, 135, 136, 137}


@dataclasses.dataclass(frozen=True)
class ProposedRule:
    """Una regola di security group proposta all'amministratore."""

    direction: str
    protocol: str
    port: int | None
    icmp_type: int | None
    ethertype: str
    remote_ip_prefix: str | None
    remote_group: str | None
    connections: int
    remotes: tuple
    low_confidence: bool

    def describe(self):
        """Descrizione leggibile, ad esempio "ingress tcp/22 da 0.0.0.0/0"."""
        if self.protocol in ("icmp", "icmp6"):
            what = self.protocol
            if self.icmp_type is not None:
                what += f" tipo {self.icmp_type}"
        else:
            what = f"{self.protocol}/{self.port}"
        peer = self.remote_ip_prefix or f"gruppo {self.remote_group}"
        preposition = "da" if self.direction == INGRESS else "verso"
        return f"{self.direction} {what} {preposition} {peer}"

    def to_neutron(self):
        """Parametri per creare la regola con l'API di Neutron."""
        rule = {
            "direction": self.direction,
            "ethertype": self.ethertype,
            "protocol": self.protocol if self.protocol != "icmp6" else "ipv6-icmp",
        }
        if self.port is not None:
            rule["port_range_min"] = rule["port_range_max"] = self.port
        if self.icmp_type is not None:
            # Per ICMP Neutron usa port_range_min come tipo
            rule["port_range_min"] = self.icmp_type
        if self.remote_group:
            rule["remote_group_id"] = self.remote_group
        else:
            rule["remote_ip_prefix"] = self.remote_ip_prefix
        return rule


@dataclasses.dataclass(frozen=True)
class Proposal:
    """Proposta di security group minimo per una porta di VM."""

    vm_mac: str
    vm_ip: str | None
    rules: tuple
    blocked: tuple      # Observation con verdict=drop
    excluded: tuple     # (Observation, motivo)
    total_connections: int

    def summary(self):
        """Riepilogo testuale, una riga per regola."""
        lines = [f"Proposta per {self.vm_ip or self.vm_mac}"
                 f" ({self.total_connections} connessioni osservate)"]
        for rule in self.rules:
            note = "  [poco osservata]" if rule.low_confidence else ""
            lines.append(f"  + {rule.describe():45} {rule.connections:>6}"
                         f" conn.{note}")
        for obs in self.blocked:
            preposition = "da" if obs.direction == INGRESS else "verso"
            lines.append(f"  ! bloccato: {obs.direction} {obs.protocol}"
                         f"/{obs.service_port} {preposition} {obs.remote_ip}"
                         f" ({obs.count} tentativi)")
        for obs, reason in self.excluded:
            lines.append(f"  - escluso: {obs.direction} {obs.protocol}"
                         f"/{obs.service_port} ({reason})")
        return "\n".join(lines)


def _exclusion_reason(obs):
    if obs.protocol == "udp" and obs.service_port in _DHCP_PORTS:
        return "DHCP, gestito da Neutron"
    if obs.protocol == "icmp6" and obs.icmp_type in _ICMPV6_NEIGHBOR_DISCOVERY:
        return "Neighbor Discovery IPv6, gestito da Neutron"
    return None


def _host_prefix(ip):
    address = ipaddress.ip_address(ip)
    return f"{address}/{address.max_prefixlen}"


def _ethertype(ip):
    return "IPv6" if ipaddress.ip_address(ip).version == 6 else "IPv4"


def build_proposal(observations, vm_mac, ip_to_group=None,
                   public_threshold=DEFAULT_PUBLIC_THRESHOLD,
                   min_connections=DEFAULT_MIN_CONNECTIONS,
                   low_confidence_below=DEFAULT_LOW_CONFIDENCE_BELOW):
    """Costruisce la proposta per la porta di VM con MAC `vm_mac`.

    `ip_to_group`: dizionario {IP di un'altra VM: suo security group},
    usato per trasformare il traffico tra VM in regole remote_group.
    """
    ip_to_group = ip_to_group or {}
    mine = [o for o in observations if o.vm_mac == vm_mac]

    blocked, excluded = [], []
    groups = collections.defaultdict(list)
    for obs in mine:
        reason = _exclusion_reason(obs)
        if reason:
            excluded.append((obs, reason))
        elif obs.verdict != "allow":
            blocked.append(obs)
        else:
            key = (obs.direction, obs.protocol, obs.service_port,
                   obs.icmp_type, _ethertype(obs.remote_ip))
            groups[key].append(obs)

    rules = []
    for (direction, protocol, port, icmp_type, ethertype), obs_list in \
            groups.items():
        rules.extend(_rules_for_group(
            direction, protocol, port, icmp_type, ethertype, obs_list,
            ip_to_group, public_threshold, min_connections,
            low_confidence_below))

    rules.sort(key=lambda r: (r.direction != INGRESS, r.protocol,
                              r.port if r.port is not None else -1,
                              r.remote_group or "", r.remote_ip_prefix or ""))
    vm_ip = next((o.vm_ip for o in mine if o.vm_ip != "0.0.0.0"), None)
    return Proposal(
        vm_mac=vm_mac,
        vm_ip=vm_ip,
        rules=tuple(rules),
        blocked=tuple(blocked),
        excluded=tuple(excluded),
        total_connections=sum(o.count for o in mine),
    )


def _rules_for_group(direction, protocol, port, icmp_type, ethertype,
                     obs_list, ip_to_group, public_threshold,
                     min_connections, low_confidence_below):
    def make(prefix, group, members):
        count = sum(o.count for o in members)
        return ProposedRule(
            direction=direction, protocol=protocol, port=port,
            icmp_type=icmp_type, ethertype=ethertype,
            remote_ip_prefix=prefix, remote_group=group,
            connections=count,
            remotes=tuple(sorted({o.remote_ip for o in members})),
            low_confidence=count < low_confidence_below,
        )

    by_group = collections.defaultdict(list)
    external = []
    for obs in obs_list:
        group = ip_to_group.get(obs.remote_ip)
        if group:
            by_group[group].append(obs)
        else:
            external.append(obs)

    rules = [make(None, group, members)
             for group, members in by_group.items()]

    external_ips = {o.remote_ip for o in external}
    if len(external_ips) >= public_threshold:
        any_prefix = "::/0" if ethertype == "IPv6" else "0.0.0.0/0"
        rules.append(make(any_prefix, None, external))
    else:
        for ip in sorted(external_ips):
            members = [o for o in external if o.remote_ip == ip]
            rules.append(make(_host_prefix(ip), None, members))

    return [r for r in rules if r.connections >= min_connections]
