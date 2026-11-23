"""Flow Collector: dalle righe del log di OVN alle connessioni.

Con il Packet Logging di Neutron, ovn-controller scrive una riga `acl_log`
per ogni pacchetto (esempi in tests/fixtures/ovn_acl_log_sample.txt).
parse_line trasforma una riga in un Flow. A SG-Learner pero' interessano
le connessioni, non i pacchetti:

- TCP: conta solo il SYN senza ACK;
- ICMP: conta solo la echo request (tipo 8, o 128 per IPv6);
- UDP: ogni datagramma, tranne le risposte.

ConnectionDeduplicator scarta ritrasmissioni e risposte UDP: senza, ogni
risposta DNS diventerebbe una regola inutile su una porta casuale.
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
            return True     # UDP non ha handshake: decide il deduplicator
        return False

    @property
    def connection_key(self):
        """Identifica una connessione, per riconoscere le ritrasmissioni."""
        if self.protocol in _ICMP_ECHO_REQUEST:
            # ICMP non ha porte: si usa il tipo al loro posto
            return (self.direction, self.protocol, self.src_ip, self.dst_ip,
                    self.icmp_type)
        return (self.direction, self.protocol, self.src_ip, self.src_port,
                self.dst_ip, self.dst_port)


def _parse_timestamp(value):
    """Converte l'ora scritta da OVS in un datetime in UTC."""
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
    """Intero, o None se il campo manca o e' vuoto."""
    return int(value) if value not in (None, "") else None


def _parse_tcp_flags(value):
    """Converte "syn|ack" nell'insieme {"syn", "ack"}."""
    if not value or value == "0":
        return frozenset()
    return frozenset(value.split("|"))


def _normalize_protocol(packet_type):
    """Protocollo di trasporto, uguale per IPv4 e IPv6 (tcp6 -> tcp)."""
    # OVS usa "tcp6", "udp6" per IPv6: il protocollo di trasporto e' lo stesso
    return {"tcp6": "tcp", "udp6": "udp"}.get(packet_type, packet_type)


def parse_line(line):
    """Interpreta una riga del log di ovn-controller.

    Restituisce un Flow, oppure None se la riga non e' un ACL log valido.
    """
    match = _LINE_RE.match(line.strip())
    if not match:
        return None

    # Il corpo ha due parti separate da ": ": l'intestazione dell'ACL
    # (nome del log, verdetto, direzione) e la descrizione del pacchetto
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
    # nw_* per IPv4, ipv6_* per IPv6
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


def _udp_endpoints(flow):
    """(IP e porta sorgente, IP e porta destinazione) di un datagramma."""
    return (flow.src_ip, flow.src_port), (flow.dst_ip, flow.dst_port)


class ConnectionDeduplicator:
    """Scarta ritrasmissioni e risposte UDP.

    Ripetizione: stessa connection_key entro `window` secondi. Risposta
    UDP: datagramma con sorgente e destinazione scambiate rispetto a uno
    visto da poco.
    """

    def __init__(self, window=60):
        self.window = datetime.timedelta(seconds=window)
        self._last_seen = {}
        # Datagrammi UDP recenti: (sorgente, destinazione) -> ultimo istante
        self._udp_seen = {}

    def _is_udp_reply(self, flow):
        """True se il datagramma fa la strada inversa di uno visto da poco."""
        src, dst = _udp_endpoints(flow)
        request = self._udp_seen.get((dst, src))
        return (request is not None
                and flow.timestamp - request <= self.window)

    def is_new(self, flow):
        """True se il flusso e' una connessione nuova da contare.

        False per le risposte UDP e per le ripetizioni della stessa
        connection_key entro `window` secondi (ritrasmissioni).
        """
        if flow.protocol == "udp":
            reply = self._is_udp_reply(flow)
            self._udp_seen[_udp_endpoints(flow)] = flow.timestamp
            if reply:
                return False
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
        self._udp_seen = {
            key: seen for key, seen in self._udp_seen.items() if seen >= limit
        }


def connections(lines, window=60):
    """Restituisce solo i Flow che aprono una nuova connessione."""
    dedup = ConnectionDeduplicator(window)
    for flow in parse_lines(lines):
        if flow.is_connection_start and dedup.is_new(flow):
            yield flow
