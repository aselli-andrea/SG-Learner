"""Test del Flow Collector su righe reali del log di ovn-controller."""

import datetime
import pathlib

from sg_learner import collector

FIXTURE = pathlib.Path(__file__).parent / "fixtures" / "ovn_acl_log_sample.txt"

LOG_ID = "c9330f49-2b8c-4286-b101-ec10ab218886"
VM_MAC = "fa:16:3e:9e:8d:c4"

# Righe copiate dal log reale (test del 23/10/2026 su vm-test, 10.0.0.37)
PING_IN = (
    "2026-10-23T12:14:19.198Z|00138|acl_log(ovn_pinctrl0)|INFO|"
    'name="neutron-c9330f49-2b8c-4286-b101-ec10ab218886", verdict=allow, '
    "severity=info, direction=to-lport: icmp,vlan_tci=0x0000,"
    "dl_src=fa:16:3e:01:fe:e4,dl_dst=fa:16:3e:9e:8d:c4,nw_src=172.24.4.1,"
    "nw_dst=10.0.0.37,nw_tos=0,nw_ecn=0,nw_ttl=63,nw_frag=no,icmp_type=8,"
    "icmp_code=0"
)
SSH_SYN = (
    "2026-10-23T12:14:19.200Z|00140|acl_log(ovn_pinctrl0)|INFO|"
    'name="neutron-c9330f49-2b8c-4286-b101-ec10ab218886", verdict=allow, '
    "severity=info, direction=to-lport: tcp,vlan_tci=0x0000,"
    "dl_src=fa:16:3e:01:fe:e4,dl_dst=fa:16:3e:9e:8d:c4,nw_src=172.24.4.1,"
    "nw_dst=10.0.0.37,nw_tos=0,nw_ecn=0,nw_ttl=63,nw_frag=no,tp_src=41168,"
    "tp_dst=22,tcp_flags=syn"
)
SSH_FIN_ACK = (
    "2026-10-23T12:14:19.201Z|00142|acl_log(ovn_pinctrl0)|INFO|"
    'name="neutron-c9330f49-2b8c-4286-b101-ec10ab218886", verdict=allow, '
    "severity=info, direction=to-lport: tcp,vlan_tci=0x0000,"
    "dl_src=fa:16:3e:01:fe:e4,dl_dst=fa:16:3e:9e:8d:c4,nw_src=172.24.4.1,"
    "nw_dst=10.0.0.37,nw_tos=0,nw_ecn=0,nw_ttl=63,nw_frag=no,tp_src=41168,"
    "tp_dst=22,tcp_flags=fin|ack"
)
# Tre syn ritrasmessi dello stesso tentativo (stessa porta sorgente 49540)
HTTP_DROP = [
    f"2026-10-23T{ts}|acl_log(ovn_pinctrl0)|INFO|"
    'name="neutron-c9330f49-2b8c-4286-b101-ec10ab218886", verdict=drop, '
    "severity=info, direction=to-lport: tcp,vlan_tci=0x0000,"
    "dl_src=fa:16:3e:01:fe:e4,dl_dst=fa:16:3e:9e:8d:c4,nw_src=172.24.4.1,"
    "nw_dst=10.0.0.37,nw_tos=0,nw_ecn=0,nw_ttl=63,nw_frag=no,tp_src=49540,"
    "tp_dst=80,tcp_flags=syn"
    for ts in ("12:14:19.202Z|00144", "12:14:20.222Z|00149",
               "12:14:21.246Z|00152")
]
METADATA_SYN_OUT = (
    "2026-10-23T10:29:54.550Z|00131|acl_log(ovn_pinctrl0)|INFO|"
    'name="neutron-c9330f49-2b8c-4286-b101-ec10ab218886", verdict=allow, '
    "severity=info, direction=from-lport: tcp,vlan_tci=0x0000,"
    "dl_src=fa:16:3e:9e:8d:c4,dl_dst=fa:16:3e:5a:e3:fa,nw_src=10.0.0.37,"
    "nw_dst=169.254.169.254,nw_tos=0,nw_ecn=0,nw_ttl=64,nw_frag=no,"
    "tp_src=58508,tp_dst=80,tcp_flags=syn"
)
METADATA_SYNACK_IN = (
    "2026-10-23T10:29:54.550Z|00132|acl_log(ovn_pinctrl0)|INFO|"
    'name="neutron-c9330f49-2b8c-4286-b101-ec10ab218886", verdict=allow, '
    "severity=info, direction=to-lport: tcp,vlan_tci=0x0000,"
    "dl_src=fa:16:3e:5a:e3:fa,dl_dst=fa:16:3e:9e:8d:c4,"
    "nw_src=169.254.169.254,nw_dst=10.0.0.37,nw_tos=0,nw_ecn=0,nw_ttl=64,"
    "nw_frag=no,tp_src=80,tp_dst=58508,tcp_flags=syn|ack"
)


# --- Interpretazione delle singole righe -----------------------------------

def test_parse_tcp_syn_ingress():
    flow = collector.parse_line(SSH_SYN)

    assert flow.verdict == "allow"
    assert flow.direction == collector.INGRESS
    assert flow.protocol == "tcp"
    assert (flow.src_ip, flow.src_port) == ("172.24.4.1", 41168)
    assert (flow.dst_ip, flow.dst_port) == ("10.0.0.37", 22)
    assert flow.tcp_flags == {"syn"}
    assert flow.network_log_id == LOG_ID
    assert flow.timestamp == datetime.datetime(
        2026, 10, 23, 12, 14, 19, 200000, tzinfo=datetime.timezone.utc)


def test_vm_side_for_ingress_and_egress():
    ingress = collector.parse_line(SSH_SYN)
    egress = collector.parse_line(METADATA_SYN_OUT)

    assert (ingress.vm_mac, ingress.vm_ip) == (VM_MAC, "10.0.0.37")
    assert ingress.remote_ip == "172.24.4.1"
    assert egress.direction == collector.EGRESS
    assert (egress.vm_mac, egress.vm_ip) == (VM_MAC, "10.0.0.37")
    assert egress.remote_ip == "169.254.169.254"


def test_parse_icmp_echo_request():
    flow = collector.parse_line(PING_IN)

    assert flow.protocol == "icmp"
    assert (flow.icmp_type, flow.icmp_code) == (8, 0)
    assert flow.src_port is None and flow.dst_port is None
    assert flow.is_connection_start


def test_parse_drop_verdict():
    flow = collector.parse_line(HTTP_DROP[0])

    assert flow.verdict == "drop"
    assert flow.dst_port == 80


def test_multiple_tcp_flags():
    flow = collector.parse_line(SSH_FIN_ACK)

    assert flow.tcp_flags == {"fin", "ack"}


def test_non_acl_lines_are_ignored():
    assert collector.parse_line("") is None
    assert collector.parse_line(
        "2026-10-23T12:00:00.000Z|00001|vlog|INFO|opened log file") is None
    assert collector.parse_line("riga qualsiasi") is None


# --- Riconoscimento dell'inizio delle connessioni --------------------------

def test_only_syn_without_ack_starts_a_tcp_connection():
    assert collector.parse_line(SSH_SYN).is_connection_start
    assert collector.parse_line(METADATA_SYN_OUT).is_connection_start
    assert not collector.parse_line(SSH_FIN_ACK).is_connection_start
    assert not collector.parse_line(METADATA_SYNACK_IN).is_connection_start


def test_retransmitted_syn_counts_once():
    result = list(collector.connections(HTTP_DROP))

    assert len(result) == 1
    assert result[0].dst_port == 80
    assert result[0].verdict == "drop"


def test_same_connection_after_window_counts_again():
    first = collector.parse_line(SSH_SYN)
    later = collector.Flow(**{
        **first.__dict__,
        "timestamp": first.timestamp + datetime.timedelta(seconds=120),
    })
    dedup = collector.ConnectionDeduplicator(window=60)

    assert dedup.is_new(first)
    assert dedup.is_new(later)


def test_connections_from_a_mixed_stream():
    lines = [PING_IN, SSH_SYN, SSH_FIN_ACK, *HTTP_DROP,
             METADATA_SYN_OUT, METADATA_SYNACK_IN, "riga qualsiasi"]

    summary = sorted(
        (f.direction, f.protocol, f.dst_port, f.verdict)
        for f in collector.connections(lines)
    )

    assert summary == [
        ("egress", "tcp", 80, "allow"),      # VM -> servizio metadati
        ("ingress", "icmp", None, "allow"),  # ping dall'host
        ("ingress", "tcp", 22, "allow"),     # SSH dall'host
        ("ingress", "tcp", 80, "drop"),      # HTTP bloccato
    ]


# --- File di log reale ------------------------------------------------------

def test_every_line_of_the_real_log_is_parsed():
    lines = FIXTURE.read_text().splitlines()
    flows = list(collector.parse_lines(lines))

    assert lines, "il file di esempio e' vuoto"
    assert len(flows) == len(lines)
    assert all(f.verdict in ("allow", "drop") for f in flows)
    assert all(f.network_log_id == LOG_ID for f in flows)


def test_real_log_retransmissions_are_merged():
    lines = FIXTURE.read_text().splitlines()
    syn_drops_port_80 = [
        f for f in collector.parse_lines(lines)
        if f.verdict == "drop" and f.dst_port == 80 and f.is_connection_start
    ]
    attempts = {f.src_port for f in syn_drops_port_80}
    merged = [
        f for f in collector.connections(lines)
        if f.verdict == "drop" and f.dst_port == 80
    ]

    assert syn_drops_port_80, "nessun drop sulla porta 80 nel file di esempio"
    assert len(merged) == len(attempts) < len(syn_drops_port_80)
