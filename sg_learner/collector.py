"""Flow Collector: interpreta le righe ACL log scritte da ovn-controller.

Con il Packet Logging di Neutron su ML2/OVN, ovn-controller scrive una riga
per ogni pacchetto che attraversa un security group sotto logging, ad esempio:

    2026-10-23T12:14:19.200Z|00140|acl_log(ovn_pinctrl0)|INFO|
    name="neutron-<id-network-log>", verdict=allow, severity=info,
    direction=to-lport: tcp,vlan_tci=0x0000,dl_src=...,dl_dst=...,
    nw_src=172.24.4.1,nw_dst=10.0.0.37,...,tp_src=41168,tp_dst=22,
    tcp_flags=syn

Questo modulo trasforma ogni riga in un oggetto Flow e riconosce l'inizio
delle connessioni. OVN logga tutti i pacchetti (syn, ack, fin...), mentre a
SG-Learner interessa contare le connessioni:

- TCP: conta solo il pacchetto syn senza ack;
- ICMP: conta solo la echo request (tipo 8, o 128 per ICMPv6);
- UDP: ogni datagramma puo' aprire un flusso;
- le ritrasmissioni e i pacchetti ripetuti vengono scartati dal
  ConnectionDeduplicator, che raggruppa per 5-tupla in una finestra di tempo.
"""

import dataclasses
import datetime
import logging
import re

LOG = logging.getLogger(__name__)

INGRESS = "ingress"
EGRESS = "egress"

# "to-lport": il pacchetto va verso la porta della VM (ingresso);
# "from-lport": il pacchetto esce dalla porta della VM (uscita).
_DIRECTIONS = {"to-lport": INGRESS, "from-lport": EGRESS}

# Tipi ICMP che aprono una "connessione": echo request IPv4 e IPv6
_ICMP_ECHO_REQUEST = {"icmp": 8, "icmp6": 128}

_LINE_RE = re.compile(
    r"^(?P<timestamp>\S+)\|\d+\|acl_log\([^)]*\)\|\w+\|(?P<body>.*)$"
)
_NAME_RE = re.compile(r'name="(?P<name>[^"]*)"')


@dataclasses.dataclass(frozen=True)
class Flow:
    """Un pacchetto registrato dall'ACL log di OVN."""

    timestamp: datetime.datetime
    log_name: str
    verdict: str
    direction: str
    protocol: str
    src_mac: str
    dst_mac: str
    src_ip: str
    dst_ip: str
    src_port: int | None = None
    dst_port: int | None = None
    tcp_flags: frozenset = frozenset()
    icmp_type: int | None = None
    icmp_code: int | None = None

    @property
    def network_log_id(self):
        """ID del network log di Neutron (il nome OVN e' "neutron-<id>")."""
        return self.log_name.removeprefix("neutron-")

    @property
    def vm_mac(self):
        """MAC della porta della VM a cui si riferisce il pacchetto."""
        return self.dst_mac if self.direction == INGRESS else self.src_mac

    @property
    def vm_ip(self):
        """IP della VM a cui si riferisce il pacchetto."""
        return self.dst_ip if self.direction == INGRESS else self.src_ip

    @property
    def remote_ip(self):
        """IP dell'altro capo della comunicazione."""
        return self.src_ip if self.direction == INGRESS else self.dst_ip

    @property
    def is_connection_start(self):
        """True se il pacchetto apre una nuova connessione."""
        if self.protocol == "tcp":
            return "syn" in self.tcp_flags and "ack" not in self.tcp_flags
        if self.protocol in _ICMP_ECHO_REQUEST:
            return self.icmp_type == _ICMP_ECHO_REQUEST[self.protocol]
        if self.protocol == "udp":
            return True
        return False

    @property
    def connection_key(self):
        """Identifica una connessione, per riconoscere le ritrasmissioni."""
        if self.protocol in _ICMP_ECHO_REQUEST:
            return (self.direction, self.protocol, self.src_ip, self.dst_ip,
                    self.icmp_type)
        return (self.direction, self.protocol, self.src_ip, self.src_port,
                self.dst_ip, self.dst_port)


def _parse_timestamp(value):
    # Formato di OVS: 2026-10-23T12:14:19.200Z (sempre UTC)
    return datetime.datetime.strptime(
        value, "%Y-%m-%dT%H:%M:%S.%fZ"
    ).replace(tzinfo=datetime.timezone.utc)


def _parse_fields(text):
    """Converte "a=1,b=2,c" in un dizionario; le chiavi senza valore -> None."""
    fields = {}
    for item in text.split(","):
        item = item.strip()
        if not item:
            continue
        key, sep, value = item.partition("=")
        fields[key.strip()] = value.strip() if sep else None
    return fields


def _int_or_none(value):
    return int(value) if value not in (None, "") else None


def _parse_tcp_flags(value):
    if not value or value == "0":
        return frozenset()
    return frozenset(value.split("|"))


def _normalize_protocol(packet_type):
    # OVS usa "tcp6", "udp6" per IPv6: il protocollo di trasporto e' lo stesso
    return {"tcp6": "tcp", "udp6": "udp"}.get(packet_type, packet_type)


def parse_line(line):
    """Interpreta una riga del log di ovn-controller.

    Restituisce un Flow, oppure None se la riga non e' un ACL log valido.
    """
    match = _LINE_RE.match(line.strip())
    if not match:
        return None

    body = match.group("body")
    header, sep, packet = body.partition(": ")
    if not sep:
        LOG.debug("Riga acl_log senza descrizione del pacchetto: %s", line)
        return None

    name_match = _NAME_RE.search(header)
    header_fields = _parse_fields(_NAME_RE.sub("", header))
    direction = _DIRECTIONS.get(header_fields.get("direction"))
    verdict = header_fields.get("verdict")
    if not name_match or not direction or not verdict:
        LOG.debug("Intestazione acl_log non riconosciuta: %s", line)
        return None

    packet_type, _, rest = packet.partition(",")
    fields = _parse_fields(rest)
    src_ip = fields.get("nw_src") or fields.get("ipv6_src")
    dst_ip = fields.get("nw_dst") or fields.get("ipv6_dst")
    if not src_ip or not dst_ip:
        LOG.debug("Pacchetto senza indirizzi IP: %s", line)
        return None

    try:
        return Flow(
            timestamp=_parse_timestamp(match.group("timestamp")),
            log_name=name_match.group("name"),
            verdict=verdict,
            direction=direction,
            protocol=_normalize_protocol(packet_type.strip()),
            src_mac=fields.get("dl_src", ""),
            dst_mac=fields.get("dl_dst", ""),
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=_int_or_none(fields.get("tp_src")),
            dst_port=_int_or_none(fields.get("tp_dst")),
            tcp_flags=_parse_tcp_flags(fields.get("tcp_flags")),
            icmp_type=_int_or_none(fields.get("icmp_type")),
            icmp_code=_int_or_none(fields.get("icmp_code")),
        )
    except ValueError:
        LOG.debug("Valori non validi nella riga acl_log: %s", line)
        return None


def parse_lines(lines):
    """Restituisce i Flow di tutte le righe acl_log valide, in ordine."""
    for line in lines:
        flow = parse_line(line)
        if flow is not None:
            yield flow


class ConnectionDeduplicator:
    """Scarta le ritrasmissioni dello stesso tentativo di connessione.

    Un pacchetto con la stessa connection_key di uno visto meno di
    `window` secondi prima viene considerato una ripetizione.
    """

    def __init__(self, window=60):
        self.window = datetime.timedelta(seconds=window)
        self._last_seen = {}

    def is_new(self, flow):
        key = flow.connection_key
        previous = self._last_seen.get(key)
        self._last_seen[key] = flow.timestamp
        return previous is None or flow.timestamp - previous > self.window

    def expire(self, now):
        """Dimentica le connessioni non viste da piu' di `window`."""
        limit = now - self.window
        self._last_seen = {
            key: seen for key, seen in self._last_seen.items() if seen >= limit
        }


def connections(lines, window=60):
    """Restituisce solo i Flow che aprono una nuova connessione."""
    dedup = ConnectionDeduplicator(window)
    for flow in parse_lines(lines):
        if flow.is_connection_start and dedup.is_new(flow):
            yield flow
