"""Analysis correctness: counts, durations, TCP attempt tracking, DNS statistics."""

from __future__ import annotations

import pytest
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import ARP
from scapy.packet import Raw

from conftest import CLIENT, CLIENT6, RESOLVER, SERVER, SERVER6, START, TrafficBuilder, eth
from netsentry.analyzer import TrafficAnalyzer
from netsentry.models import Outcome


def mixed_traffic() -> TrafficBuilder:
    traffic = TrafficBuilder()
    traffic.connect(CLIENT, SERVER, 40000, 443, t=0.0)  # 2 TCP packets
    traffic.udp(CLIENT, SERVER, 5000, 123, t=1.0)  # 1 UDP
    traffic.dns_query(CLIENT, "example.com", t=2.0)  # 1 UDP/DNS
    traffic.dns_response(CLIENT, "example.com", t=2.1)  # 1 UDP/DNS
    traffic.ping(CLIENT, SERVER, t=3.0, reply=True)  # 2 ICMP
    traffic.connect(CLIENT6, SERVER6, 40001, 22, t=4.0)  # 2 TCP over IPv6
    traffic.ping(CLIENT6, SERVER6, t=5.0)  # 1 ICMPv6
    traffic.add(eth() / ARP(psrc=CLIENT, pdst=SERVER), t=10.0)  # 1 non-IP
    return traffic


def test_packet_and_protocol_counts(analyze):
    result = analyze(mixed_traffic())
    traffic = result.traffic
    assert traffic.total_packets == 11
    assert traffic.ip_packets == 10
    assert traffic.network_counts == {"IPv4": 7, "IPv6": 3, "ARP": 1}
    assert traffic.transport_counts == {"TCP": 4, "UDP": 3, "ICMP": 2, "ICMPv6": 1}
    assert traffic.application_counts == {"DNS": 2}


def test_unique_addresses_and_ports(analyze):
    traffic = analyze(mixed_traffic()).traffic
    assert set(traffic.source_counts) == {CLIENT, SERVER, RESOLVER, CLIENT6, SERVER6}
    assert traffic.source_counts[CLIENT] == 4
    assert traffic.destination_counts[SERVER] == 3
    assert traffic.destination_port_counts[("TCP", 443)] == 1
    assert traffic.destination_port_counts[("TCP", 40000)] == 1  # the SYN-ACK's destination
    assert traffic.destination_port_counts[("UDP", 53)] == 1
    # Ports that started flows are counted separately from reply ports.
    assert traffic.flows_initiated_by_port[("TCP", 443)] == 1
    assert ("TCP", 40000) not in traffic.flows_initiated_by_port


def test_duration_and_rate(analyze):
    traffic = analyze(mixed_traffic()).traffic
    assert traffic.first_timestamp == pytest.approx(START)
    assert traffic.duration_seconds == pytest.approx(10.0)
    assert traffic.packets_per_second == pytest.approx(11 / 10.0)


def test_zero_duration_capture_has_no_rate(analyze):
    traffic = TrafficBuilder()
    for port in range(3):
        traffic.udp(CLIENT, SERVER, 5000 + port, 9, t=0.0)  # identical timestamps
    result = analyze(traffic)
    assert result.traffic.duration_seconds == 0.0
    assert result.traffic.packets_per_second is None  # never divides by zero


def test_single_packet_has_unknown_duration(analyze):
    traffic = TrafficBuilder()
    traffic.udp(CLIENT, SERVER, 5000, 9, t=0.0)
    result = analyze(traffic)
    assert result.traffic.duration_seconds is None and result.traffic.packets_per_second is None
    assert any("duration is unknown" in note for note in result.limitations)


def test_short_capture_does_not_report_a_rate(analyze):
    traffic = TrafficBuilder()
    traffic.udp(CLIENT, SERVER, 5000, 9, t=0.0)
    traffic.udp(CLIENT, SERVER, 5000, 9, t=0.4)
    result = analyze(traffic)
    assert result.traffic.duration_seconds == pytest.approx(0.4)
    assert result.traffic.packets_per_second is None


def test_out_of_order_capture_uses_min_and_max_times(analyze):
    traffic = TrafficBuilder()
    traffic.udp(CLIENT, SERVER, 5000, 9, t=5.0)
    traffic.udp(CLIENT, SERVER, 5000, 9, t=1.0)
    traffic.udp(CLIENT, SERVER, 5000, 9, t=3.0)
    result = analyze(traffic)
    assert result.traffic.duration_seconds == pytest.approx(4.0)
    assert result.parse.frames_out_of_order == 2
    assert any("earlier than a previous frame" in w for w in result.warnings)


def test_empty_capture_produces_a_warning(analyze):
    result = analyze(TrafficBuilder())
    assert result.traffic.total_packets == 0
    assert "The capture is valid but contains no packets." in result.warnings


# -- TCP connection attempts ---------------------------------------------------------


def test_syn_retransmissions_are_one_attempt(analyze):
    traffic = TrafficBuilder()
    for delay in (0, 1, 3, 7):  # Linux-style exponential back-off, same port and ISN
        traffic.syn(CLIENT, SERVER, 40000, 80, t=delay, seq=1234)
    result = analyze(traffic)
    assert result.tcp.syn_only == 4
    assert result.tcp.connection_attempts == 1
    assert result.tcp.retransmitted_syns == 3
    attempt = result.index.connection_attempts[0]
    assert attempt.syn_packets == 4 and attempt.outcome is Outcome.NO_REPLY_OBSERVED
    assert attempt.first_seen == pytest.approx(START) and attempt.last_seen == pytest.approx(
        START + 7
    )


def test_new_isn_on_same_ports_is_a_new_attempt(analyze):
    traffic = TrafficBuilder()
    traffic.syn(CLIENT, SERVER, 40000, 80, t=0, seq=1)
    traffic.syn(CLIENT, SERVER, 40000, 80, t=60, seq=999_999)
    assert analyze(traffic).tcp.connection_attempts == 2


def test_outcomes_accepted_refused_and_unknown(analyze):
    traffic = TrafficBuilder()
    traffic.connect(CLIENT, SERVER, 40000, 80, t=0, outcome="accept")
    traffic.connect(CLIENT, SERVER, 40001, 81, t=1, outcome="refuse")
    traffic.connect(CLIENT, SERVER, 40002, 82, t=2, outcome="none")
    result = analyze(traffic)
    outcomes = {a.server_port: a.outcome for a in result.index.connection_attempts}
    assert outcomes == {80: Outcome.ACCEPTED, 81: Outcome.REFUSED, 82: Outcome.NO_REPLY_OBSERVED}
    assert (result.tcp.accepted, result.tcp.refused, result.tcp.no_reply_observed) == (1, 1, 1)


def test_syn_ack_with_wrong_acknowledgement_does_not_match(analyze):
    traffic = TrafficBuilder()
    traffic.syn(CLIENT, SERVER, 40000, 80, t=0, seq=1000)
    traffic.tcp(SERVER, CLIENT, 80, 40000, "SA", t=0.1, seq=1, ack=5555)  # not ISN+1
    result = analyze(traffic)
    assert result.index.connection_attempts[0].outcome is Outcome.NO_REPLY_OBSERVED
    assert result.tcp.unmatched_syn_acks == 1


def test_sequence_number_wraparound(analyze):
    traffic = TrafficBuilder()
    traffic.syn(CLIENT, SERVER, 40000, 80, t=0, seq=2**32 - 1)
    traffic.tcp(SERVER, CLIENT, 80, 40000, "SA", t=0.1, seq=1, ack=0)  # (2**32 - 1) + 1 wraps to 0
    assert analyze(traffic).index.connection_attempts[0].outcome is Outcome.ACCEPTED


def test_reset_after_accept_is_not_a_refusal(analyze):
    traffic = TrafficBuilder()
    traffic.connect(CLIENT, SERVER, 40000, 80, t=0, outcome="accept")
    traffic.tcp(SERVER, CLIENT, 80, 40000, "R", t=5, seq=5001)
    result = analyze(traffic)
    assert result.index.connection_attempts[0].outcome is Outcome.ACCEPTED
    assert result.tcp.resets_after_accept == 1 and result.tcp.rst == 1


def test_client_reset_is_not_a_refusal(analyze):
    traffic = TrafficBuilder()
    traffic.syn(CLIENT, SERVER, 40000, 80, t=0)
    traffic.tcp(CLIENT, SERVER, 40000, 80, "R", t=1)  # the client aborts its own attempt
    assert analyze(traffic).index.connection_attempts[0].outcome is Outcome.NO_REPLY_OBSERVED


def test_syn_ack_without_syn_is_counted_and_noted(analyze):
    traffic = TrafficBuilder()
    traffic.syn_ack(SERVER, CLIENT, 80, 40000, t=0)
    result = analyze(traffic)
    assert result.tcp.unmatched_syn_acks == 1 and result.tcp.connection_attempts == 0
    assert any("no matching SYN" in note for note in result.limitations)


def test_tcp_flag_statistics(analyze):
    traffic = TrafficBuilder()
    traffic.connect(CLIENT, SERVER, 40000, 80, t=0)
    traffic.tcp(CLIENT, SERVER, 40000, 80, "FA", t=1)
    tcp = analyze(traffic).tcp
    assert tcp.flag_counts == {"SYN": 2, "ACK": 2, "FIN": 1}
    assert (tcp.syn_only, tcp.syn_ack, tcp.fin, tcp.rst) == (1, 1, 1, 0)


# -- UDP / ICMP contacts -------------------------------------------------------------


def test_udp_flow_initiator_and_reply(analyze):
    traffic = TrafficBuilder()
    traffic.udp(CLIENT, SERVER, 5000, 9999, t=0)
    traffic.udp(SERVER, CLIENT, 9999, 5000, t=0.1)  # reply on the same flow
    traffic.udp(CLIENT, SERVER, 5001, 9998, t=1)  # unanswered
    contacts = analyze(traffic).index.contacts
    summary = {(c.source, c.port, c.answered) for c in contacts}
    assert summary == {(CLIENT, 9999, True), (CLIENT, 9998, False)}  # the reply is not a contact


def test_multicast_destinations_are_not_contacts(analyze):
    traffic = TrafficBuilder()
    traffic.udp(CLIENT, "239.255.255.250", 5000, 1900, t=0)
    traffic.udp(CLIENT, "255.255.255.255", 68, 67, t=1)
    assert analyze(traffic).index.contacts == []


def test_icmp_echo_contacts(analyze):
    traffic = TrafficBuilder()
    traffic.ping(CLIENT, SERVER, t=0, reply=True)
    traffic.ping(CLIENT6, SERVER6, t=1, reply=False)
    contacts = {(c.transport, c.port, c.answered) for c in analyze(traffic).index.contacts}
    assert contacts == {("ICMP", None, True), ("ICMPv6", None, False)}


# -- DNS -------------------------------------------------------------------------------


def test_dns_statistics_and_duplicate_handling(analyze):
    traffic = TrafficBuilder()
    traffic.dns_query(CLIENT, "a.example", t=0, txid=1)
    traffic.dns_query(CLIENT, "a.example", t=0.001, txid=1)  # duplicated packet
    traffic.dns_response(CLIENT, "a.example", t=0.01, txid=1, rcode=0)
    traffic.dns_query(CLIENT, "b.example", t=1, txid=2, qtype="AAAA")
    traffic.dns_response(CLIENT, "b.example", t=1.01, txid=2, rcode=3)
    result = analyze(traffic)
    dns = result.dns
    assert (dns.messages, dns.queries, dns.responses) == (5, 3, 2)
    assert dns.query_names == {"a.example": 2, "b.example": 1}
    assert dns.query_types == {1: 2, 28: 1}
    assert dns.response_codes == {0: 1, 3: 1}
    # Detection events count the duplicated query once.
    assert len(result.index.dns_queries) == 2
    assert [r.rcode for r in result.index.dns_responses] == [0, 3]
    assert result.index.dns_responses[0].client == CLIENT


def test_undecodable_dns_is_counted_and_noted(analyze):
    traffic = TrafficBuilder()
    traffic.add(
        eth() / IP(src=CLIENT, dst=RESOLVER) / UDP(sport=5000, dport=53) / Raw(b"\xff" * 5), t=0
    )
    result = analyze(traffic)
    assert result.dns.malformed == 1
    assert any("did not decode as DNS" in note for note in result.limitations)


# -- limitations ---------------------------------------------------------------------


def test_one_directional_capture_is_noted(analyze):
    traffic = TrafficBuilder()
    for host in range(12):
        traffic.syn(CLIENT, f"198.51.100.{host + 1}", 40000 + host, 443, t=host)
    result = analyze(traffic)
    assert any("one direction only" in note for note in result.limitations)


def test_fragments_are_counted_and_noted(analyze):
    traffic = TrafficBuilder()
    traffic.add(eth() / IP(src=CLIENT, dst=SERVER, proto=17, frag=50) / Raw(b"x" * 16), t=0)
    result = analyze(traffic)
    assert result.traffic.ip_fragments == 1
    assert result.traffic.transport_counts == {"IP fragment (no transport header)": 1}
    assert any("does not reassemble" in note for note in result.limitations)


def test_analyzer_accepts_records_directly():
    """The analyser works on PacketRecords, so it can be tested without files."""
    from netsentry.models import CaptureInfo, PacketRecord, ParseStats

    analyzer = TrafficAnalyzer()
    analyzer.add(
        PacketRecord(
            index=1,
            timestamp=None,
            captured_length=60,
            original_length=None,
            link_type=1,
            network="IPv4",
            src_ip=CLIENT,
            dst_ip=SERVER,
            ip_protocol=6,
            transport=None,
        )
    )
    result = analyzer.finish(CaptureInfo("x.pcap", 1, "0" * 64, "pcap"), ParseStats())
    assert result.traffic.undecoded_transport == 1
    assert result.traffic.transport_counts == {"TCP (header not decodable)": 1}
    assert result.traffic.bytes_on_wire == 60
