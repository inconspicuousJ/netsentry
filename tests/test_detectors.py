"""Detection rules: trigger, threshold edges, benign look-alikes and de-duplication."""

from __future__ import annotations

import dataclasses
import json
from collections import Counter

import pytest
from scapy.layers.inet import ICMP, IP, UDP
from scapy.packet import Raw

from conftest import (
    CLIENT,
    CLIENT6,
    RESOLVER,
    SERVER,
    SERVER6,
    TrafficBuilder,
    eth,
    rule_findings,
    rule_suppressed,
)
from netsentry import detectors as d
from netsentry.config import DetectionConfig, DnsSettings, HighVolumeSettings
from netsentry.models import Confidence, Severity, TrafficIndex

PUBLIC_HOST = "93.184.216.34"  # a globally routable address (no traffic is ever sent)


def scan(
    traffic: TrafficBuilder,
    source: str,
    target: str,
    ports,
    *,
    start: float = 0.0,
    step: float = 0.1,
    outcome: str = "refuse",
    transport: str = "tcp",
) -> None:
    for i, port in enumerate(ports):
        if transport == "udp":
            traffic.udp(source, target, 50000 + i, port, t=start + i * step)
        else:
            traffic.connect(source, target, 50000 + i, port, t=start + i * step, outcome=outcome)


def config_with(**sections) -> DetectionConfig:
    return dataclasses.replace(DetectionConfig(), **sections)


# -- sliding windows -------------------------------------------------------------------


def test_window_helpers_include_events_exactly_one_window_apart():
    # Events exactly window_seconds apart are in the same window ...
    assert d.best_window_distinct([(0.0, "a"), (60.0, "b")], 60.0)[0] == 2
    assert d.best_window_count([0.0, 60.0], 60.0)[0] == 2
    # ... and events even slightly further apart are not.
    assert d.best_window_distinct([(0.0, "a"), (60.001, "b")], 60.0)[0] == 1
    assert d.best_window_count([0.0, 60.001], 60.0)[0] == 1
    assert d.best_window_distinct([], 60.0)[0] == 0
    assert d.best_window_count([], 60.0)[0] == 0


def test_window_distinct_counts_repeated_keys_once():
    events = [(0.0, 1), (1.0, 1), (2.0, 2), (100.0, 3)]
    distinct, start, end = d.best_window_distinct(events, 10.0)
    assert (distinct, start, end) == (2, 0, 2)


# -- NS-SCAN-001 port scan -----------------------------------------------------------------


def test_port_scan_detected_at_threshold(builder, detect):
    scan(builder, CLIENT, SERVER, range(1, 21))  # exactly 20 ports, all refused
    _, report = detect(builder)
    [finding] = rule_findings(report, d.PORT_SCAN)
    assert finding.severity is Severity.MEDIUM
    assert finding.confidence is Confidence.MEDIUM
    assert finding.subject == {"source": CLIENT}
    target = finding.evidence["targets"][0]
    assert target["destination"] == SERVER
    assert target["distinct_ports_in_window"] == 20
    assert target["refused_or_negative"] == 20 and target["answered_positively"] == 0
    assert target["ports_sample"][:3] == ["TCP/1", "TCP/2", "TCP/3"]


def test_port_scan_not_detected_below_threshold(builder, detect):
    scan(builder, CLIENT, SERVER, range(1, 20))  # 19 ports
    _, report = detect(builder)
    assert rule_findings(report, d.PORT_SCAN) == []


def test_port_scan_respects_time_window(builder, detect):
    scan(builder, CLIENT, SERVER, range(1, 21), step=4.0)  # 20 ports over 76 s
    _, report = detect(builder)
    assert rule_findings(report, d.PORT_SCAN) == []

    wider = config_with(
        port_scan=dataclasses.replace(DetectionConfig().port_scan, window_seconds=120.0)
    )
    _, report = detect(builder, wider)
    assert len(rule_findings(report, d.PORT_SCAN)) == 1


def test_large_scan_of_closed_ports_has_high_confidence(builder, detect):
    scan(builder, CLIENT, SERVER, range(1, 41))
    _, report = detect(builder)
    assert rule_findings(report, d.PORT_SCAN)[0].confidence is Confidence.HIGH


def test_scan_without_visible_replies_has_low_confidence(builder, detect):
    scan(builder, CLIENT, SERVER, range(1, 41), outcome="none")
    _, report = detect(builder)
    [finding] = rule_findings(report, d.PORT_SCAN)
    assert finding.confidence is Confidence.LOW
    assert finding.evidence["targets"][0]["reply_traffic_visible"] is False


def test_client_using_many_open_services_is_suppressed(builder, detect):
    scan(builder, CLIENT, SERVER, range(1, 25), outcome="accept")
    _, report = detect(builder)
    assert rule_findings(report, d.PORT_SCAN) == []
    [suppressed] = rule_suppressed(report, d.PORT_SCAN)
    assert suppressed.subject == {"source": CLIENT, "destination": SERVER}
    assert "accepted the connection" in suppressed.reason


def test_retransmissions_do_not_add_distinct_ports(builder, detect):
    scan(builder, CLIENT, SERVER, range(1, 20))  # 19 ports
    for i in range(10):
        builder.syn(CLIENT, SERVER, 50000, 1, t=5 + i)  # retransmissions/duplicates to port 1
    _, report = detect(builder)
    assert rule_findings(report, d.PORT_SCAN) == []


def test_ipv6_port_scan(builder, detect):
    scan(builder, CLIENT6, SERVER6, range(1000, 1025))
    _, report = detect(builder)
    [finding] = rule_findings(report, d.PORT_SCAN)
    assert finding.subject == {"source": CLIENT6}


def test_udp_port_scan(builder, detect):
    scan(builder, CLIENT, SERVER, range(1, 21), transport="udp")
    _, report = detect(builder)
    [finding] = rule_findings(report, d.PORT_SCAN)
    assert finding.evidence["targets"][0]["ports_sample"][0] == "UDP/1"


def test_traceroute_is_not_a_port_scan(builder, detect):
    """Classic UDP traceroute probes one new port per hop from 33434 upward."""
    port = 33434
    for hop in range(1, 31):
        for probe in range(3):
            t = hop * 0.1 + probe * 0.01
            builder.add(
                eth()
                / IP(src=CLIENT, dst=SERVER, ttl=hop)
                / UDP(sport=44000, dport=port)
                / Raw(b"\x00" * 32),
                t,
            )
            router = f"192.0.2.{200 + hop}" if hop < 30 else SERVER
            reply = ICMP(type=11) if hop < 30 else ICMP(type=3, code=3)
            builder.add(eth() / IP(src=router, dst=CLIENT) / reply, t + 0.005)
            port += 1
    _, report = detect(builder)
    assert rule_findings(report, d.PORT_SCAN) == []
    assert "traceroute" in rule_suppressed(report, d.PORT_SCAN)[0].reason


def test_scan_of_several_hosts_is_a_single_finding(builder, detect):
    for host in range(3):
        scan(builder, CLIENT, f"198.51.100.{host + 1}", range(1, 21), start=host * 10)
    _, report = detect(builder)
    [finding] = rule_findings(report, d.PORT_SCAN)
    assert finding.evidence["hosts_flagged"] == 3
    assert len(finding.evidence["targets"]) == 3


# -- NS-SCAN-002 host sweep ------------------------------------------------------------------


def sweep(traffic: TrafficBuilder, count: int, port: int = 445, outcome: str = "none") -> None:
    for host in range(count):
        traffic.connect(
            CLIENT, f"198.51.100.{host + 1}", 40000 + host, port, t=host * 0.5, outcome=outcome
        )


def test_host_sweep_detected_at_threshold(builder, detect):
    sweep(builder, 30)
    _, report = detect(builder)
    [finding] = rule_findings(report, d.HOST_SWEEP)
    service = finding.evidence["services"][0]
    assert service["service"] == "TCP/445" and service["distinct_hosts_in_window"] == 30
    assert finding.confidence is Confidence.LOW  # no replies visible at all


def test_host_sweep_not_detected_below_threshold(builder, detect):
    sweep(builder, 29)
    _, report = detect(builder)
    assert rule_findings(report, d.HOST_SWEEP) == []


def test_browsing_many_sites_is_suppressed(builder, detect):
    sweep(builder, 40, port=443, outcome="accept")
    _, report = detect(builder)
    assert rule_findings(report, d.HOST_SWEEP) == []
    assert rule_suppressed(report, d.HOST_SWEEP)[0].subject["service"] == "TCP/443"


def test_ping_sweep(builder, detect):
    for host in range(30):
        builder.ping(CLIENT, f"198.51.100.{host + 1}", t=host * 0.2)
    _, report = detect(builder)
    [finding] = rule_findings(report, d.HOST_SWEEP)
    assert finding.evidence["services"][0]["service"] == "ICMP echo"


# -- NS-CONN-001 repeated connection attempts ------------------------------------------------


def repeated(
    traffic: TrafficBuilder,
    count: int,
    port: int = 22,
    outcome: str = "refuse",
    retransmits: int = 0,
    step: float = 1.0,
) -> None:
    for i in range(count):
        traffic.connect(CLIENT, SERVER, 41000 + i, port, t=i * step, outcome=outcome, seq=100 + i)
        for r in range(retransmits):
            traffic.syn(CLIENT, SERVER, 41000 + i, port, t=i * step + 0.1 * (r + 1), seq=100 + i)


def test_repeated_attempts_to_ssh_detected(builder, detect):
    repeated(builder, 10)
    _, report = detect(builder)
    [finding] = rule_findings(report, d.REPEATED_CONNECTIONS)
    assert finding.severity is Severity.MEDIUM  # SSH is a sensitive service port
    assert finding.confidence is Confidence.MEDIUM
    assert finding.subject == {"source": CLIENT, "destination": SERVER, "port": 22}
    assert finding.evidence["attempts_in_window"] == 10
    assert finding.evidence["refused_rst_observed"] == 10


def test_repeated_attempts_below_threshold(builder, detect):
    repeated(builder, 9)
    _, report = detect(builder)
    assert rule_findings(report, d.REPEATED_CONNECTIONS) == []


def test_one_connection_with_many_retransmissions_is_not_repeated(builder, detect):
    for i in range(12):
        builder.syn(CLIENT, SERVER, 41000, 22, t=i, seq=777)
    _, report = detect(builder)
    assert rule_findings(report, d.REPEATED_CONNECTIONS) == []


def test_retransmissions_are_reported_but_not_counted(builder, detect):
    repeated(builder, 10, outcome="none", retransmits=2)
    _, report = detect(builder)
    evidence = rule_findings(report, d.REPEATED_CONNECTIONS)[0].evidence
    assert evidence["attempts_in_window"] == 10
    assert evidence["syn_packets_in_window"] == 30
    assert evidence["retransmitted_syns_excluded"] == 20
    assert evidence["no_reply_observed"] == 10


def test_accepted_connections_to_ordinary_port_are_suppressed(builder, detect):
    repeated(builder, 15, port=8080, outcome="accept")
    _, report = detect(builder)
    assert rule_findings(report, d.REPEATED_CONNECTIONS) == []
    assert len(rule_suppressed(report, d.REPEATED_CONNECTIONS)) == 1


def test_accepted_connections_to_sensitive_port_are_reported(builder, detect):
    repeated(builder, 15, port=3389, outcome="accept")
    _, report = detect(builder)
    assert rule_findings(report, d.REPEATED_CONNECTIONS)[0].severity is Severity.MEDIUM


def test_database_connection_pool_is_not_flagged(builder, detect):
    repeated(builder, 30, port=3306, outcome="accept")  # an app opening a connection per request
    _, report = detect(builder)
    assert rule_findings(report, d.REPEATED_CONNECTIONS) == []

    refused = TrafficBuilder()
    repeated(refused, 10, port=3306, outcome="refuse")  # database down: still worth a LOW look
    _, report = detect(refused)
    assert rule_findings(report, d.REPEATED_CONNECTIONS)[0].severity is Severity.LOW


def test_unanswered_attempts_to_ordinary_port_are_low(builder, detect):
    repeated(builder, 10, port=8080, outcome="none")
    _, report = detect(builder)
    [finding] = rule_findings(report, d.REPEATED_CONNECTIONS)
    assert (finding.severity, finding.confidence) == (Severity.LOW, Confidence.LOW)


def test_repeated_attempts_outside_window(builder, detect):
    repeated(builder, 10, step=7.0)  # 10 attempts over 63 s
    _, report = detect(builder)
    assert rule_findings(report, d.REPEATED_CONNECTIONS) == []


# -- NS-CONN-002 refused connections -----------------------------------------------------------


def refused_spread(traffic: TrafficBuilder, count: int, outcome: str = "refuse") -> None:
    """Refused attempts spread across hosts/ports so no scan or repeat rule applies."""
    for i in range(count):
        traffic.connect(
            CLIENT, f"198.51.100.{i % 5 + 1}", 42000 + i, 8000 + i // 5, t=i, outcome=outcome
        )


def test_refused_connections_detected(builder, detect):
    refused_spread(builder, 10)
    _, report = detect(builder)
    [finding] = rule_findings(report, d.FAILED_CONNECTIONS)
    assert finding.severity is Severity.LOW
    assert finding.evidence["refused_rst_observed"] == 10
    assert finding.evidence["distinct_destinations_refused"] == 5
    assert [f.rule_id for f in report.findings] == [d.FAILED_CONNECTIONS]


def test_refused_connections_below_threshold(builder, detect):
    refused_spread(builder, 9)
    _, report = detect(builder)
    assert rule_findings(report, d.FAILED_CONNECTIONS) == []


def test_mostly_successful_client_is_not_flagged(builder, detect):
    refused_spread(builder, 10)
    for i in range(11):
        builder.connect(CLIENT, SERVER, 43000 + i, 443, t=20 + i, outcome="accept")
    _, report = detect(builder)
    assert rule_findings(report, d.FAILED_CONNECTIONS) == []


def test_unanswered_attempts_are_not_counted_as_refused(builder, detect):
    refused_spread(builder, 15, outcome="none")
    _, report = detect(builder)
    assert rule_findings(report, d.FAILED_CONNECTIONS) == []


def test_scan_is_not_reported_twice_as_refused_connections(builder, detect):
    scan(builder, CLIENT, SERVER, range(1, 31))  # 30 refused ports
    _, report = detect(builder)
    assert [f.rule_id for f in report.findings] == [d.PORT_SCAN]
    [suppressed] = rule_suppressed(report, d.FAILED_CONNECTIONS)
    assert "already reported" in suppressed.reason


def test_repeated_endpoint_is_not_reported_twice(builder, detect):
    repeated(builder, 12, port=22, outcome="refuse")
    _, report = detect(builder)
    assert [f.rule_id for f in report.findings] == [d.REPEATED_CONNECTIONS]


# -- NS-PORT-001 unusual ports -----------------------------------------------------------------


def test_watched_port_detected(builder, detect):
    builder.connect(CLIENT, SERVER, 40000, 4444, t=0, outcome="accept")
    _, report = detect(builder)
    [finding] = rule_findings(report, d.UNUSUAL_PORT)
    assert (finding.severity, finding.confidence) == (Severity.LOW, Confidence.LOW)
    assert finding.evidence["port"] == 4444 and "Metasploit" in finding.evidence["reason"]
    assert finding.evidence["accepted_or_answered"] == 1


def test_watched_port_used_as_source_port_is_ignored(builder, detect):
    builder.connect(CLIENT, SERVER, 4444, 443, t=0, outcome="accept")
    _, report = detect(builder)
    assert rule_findings(report, d.UNUSUAL_PORT) == []


def test_inward_service_flagged_only_for_public_destinations(builder, detect):
    builder.connect(CLIENT, PUBLIC_HOST, 40000, 445, t=0, outcome="none")
    builder.connect(CLIENT, SERVER, 40001, 445, t=1, outcome="accept")  # documentation range
    _, report = detect(builder)
    [finding] = rule_findings(report, d.UNUSUAL_PORT)
    assert finding.evidence["category"] == "inward-facing service on a public address"
    assert finding.evidence["example_flows"] == [
        {"source": CLIENT, "destination": PUBLIC_HOST, "flows": 1}
    ]


def test_watched_ports_touched_by_a_scan_are_not_reported_again(builder, detect):
    scan(builder, CLIENT, SERVER, [*range(1, 25), 4444])
    _, report = detect(builder)
    assert rule_findings(report, d.UNUSUAL_PORT) == []
    assert rule_suppressed(report, d.UNUSUAL_PORT)[0].subject == {"transport": "TCP", "port": 4444}


# -- NS-VOL-001 high volume ------------------------------------------------------------------


def test_peak_packets_in_window():
    per_second = Counter({100: 5, 101: 5, 105: 5, 120: 50})
    assert d.peak_packets_in_window(per_second, 10.0) == (50, 120)
    assert d.peak_packets_in_window(per_second, 6.0) == (50, 120)
    assert d.peak_packets_in_window(Counter({100: 5, 101: 5, 105: 5}), 6.0) == (15, 100)
    assert d.peak_packets_in_window(Counter(), 10.0) == (0, None)


def volume_index(packets_by_second: dict[str, dict[int, int]]) -> TrafficIndex:
    index = TrafficIndex()
    for source, seconds in packets_by_second.items():
        index.packets_per_second_by_source[source] = Counter(seconds)
        index.packets_by_source[source] = sum(seconds.values())
        index.destinations_by_source[source] = Counter({SERVER: sum(seconds.values())})
    index.total_ip_packets = sum(index.packets_by_source.values())
    return index


def test_burst_at_default_threshold():
    settings = HighVolumeSettings()
    burst = volume_index({CLIENT: {1000: 10_000}, SERVER: {1000: 10}})
    [finding] = d.detect_high_volume(burst, settings).findings
    assert finding.severity is Severity.LOW and finding.evidence["peak_packets_in_window"] == 10_000

    below = volume_index({CLIENT: {1000: 9_999}, SERVER: {1000: 9_000}})
    assert d.detect_high_volume(below, settings).findings == []


def test_concentration_is_informational():
    index = volume_index({CLIENT: {t: 100 for t in range(1000, 1010)}, SERVER: {1000: 100}})
    [finding] = d.detect_high_volume(index, HighVolumeSettings()).findings
    assert finding.severity is Severity.INFO
    assert finding.evidence["share_of_ip_packets"] == pytest.approx(1000 / 1100, abs=1e-4)


def test_single_source_capture_has_no_concentration_finding():
    index = volume_index({CLIENT: {t: 200 for t in range(1000, 1010)}})
    assert d.detect_high_volume(index, HighVolumeSettings()).findings == []


def test_high_volume_from_packets(builder, detect):
    for i in range(60):
        builder.udp(CLIENT, SERVER, 5000, 9999, t=i * 0.01)
    builder.udp(SERVER, CLIENT, 9999, 5000, t=1)
    settings = HighVolumeSettings(window_seconds=1.0, min_packets_in_window=50)
    _, report = detect(builder, config_with(high_volume=settings))
    [finding] = rule_findings(report, d.HIGH_VOLUME)
    assert finding.subject == {"source": CLIENT} and finding.evidence["packets_sent"] == 60


# -- NS-DNS rules ---------------------------------------------------------------------------------


def low_dns(**changes) -> DetectionConfig:
    return config_with(dns=dataclasses.replace(DnsSettings(), **changes))


def test_dns_query_rate(builder, detect):
    for i in range(20):
        builder.dns_query(CLIENT, f"host{i}.example", t=i * 0.5, txid=i)
    _, report = detect(builder, low_dns(min_queries_in_window=20))
    [finding] = rule_findings(report, d.DNS_QUERY_RATE)
    assert finding.evidence["queries_in_window"] == 20

    _, report = detect(builder, low_dns(min_queries_in_window=21))
    assert rule_findings(report, d.DNS_QUERY_RATE) == []


def test_dns_duplicates_do_not_inflate_rate(builder, detect):
    for i in range(10):
        builder.dns_query(CLIENT, f"host{i}.example", t=i, txid=i)
        builder.dns_query(CLIENT, f"host{i}.example", t=i + 0.001, txid=i)  # duplicate packet
    _, report = detect(builder, low_dns(min_queries_in_window=11))
    assert rule_findings(report, d.DNS_QUERY_RATE) == []


def test_resolver_is_suppressed_for_query_rate(builder, detect):
    for i in range(20):
        builder.dns_query(RESOLVER, f"host{i}.example", t=i * 0.5, txid=i, server="192.0.2.1")
    builder.dns_response(CLIENT, "x.example", t=1)  # RESOLVER answers a client: it is a resolver
    _, report = detect(builder, low_dns(min_queries_in_window=20))
    assert rule_findings(report, d.DNS_QUERY_RATE) == []
    assert rule_suppressed(report, d.DNS_QUERY_RATE)[0].subject == {"source": RESOLVER}


def test_single_long_name_is_info(builder, detect):
    name = "a" * 45 + "." + "b" * 45 + "." + "c" * 20 + ".example"  # 121 bytes
    builder.dns_query(CLIENT, name, t=0)
    _, report = detect(builder)
    [finding] = rule_findings(report, d.DNS_LONG_NAMES)
    assert (finding.severity, finding.confidence) == (Severity.INFO, Confidence.LOW)
    assert finding.evidence["longest_name_bytes"] == len(name)


def test_long_label_alone_triggers(builder, detect):
    builder.dns_query(CLIENT, "x" * 55 + ".example", t=0)
    _, report = detect(builder)
    assert rule_findings(report, d.DNS_LONG_NAMES)[0].evidence["longest_label_bytes"] == 55


def test_normal_length_names_do_not_trigger(builder, detect):
    builder.dns_query(CLIENT, "x" * 49 + ".example", t=0)  # label just under 50, name 57 bytes
    _, report = detect(builder)
    assert rule_findings(report, d.DNS_LONG_NAMES) == []


def test_many_long_names_under_one_domain_resemble_tunnelling(builder, detect):
    for i in range(10):
        builder.dns_query(CLIENT, f"{i:02d}" + "f" * 58 + ".t.tunnel.example", t=i, txid=i)
    _, report = detect(builder)
    [finding] = rule_findings(report, d.DNS_LONG_NAMES)
    assert (finding.severity, finding.confidence) == (Severity.LOW, Confidence.MEDIUM)
    assert finding.evidence["top_parent_domains"][0] == {
        "parent_domain": "tunnel.example",
        "count": 10,
    }


def failures(traffic: TrafficBuilder, total: int, failed: int) -> None:
    for i in range(total):
        name = f"name{i}.example"
        traffic.dns_query(CLIENT, name, t=i, txid=i)
        traffic.dns_response(CLIENT, name, t=i + 0.01, txid=i, rcode=3 if i < failed else 0)


def test_dns_failure_ratio_at_threshold(builder, detect):
    failures(builder, total=20, failed=10)
    _, report = detect(builder)
    [finding] = rule_findings(report, d.DNS_FAILURES)
    assert finding.evidence["failure_ratio"] == 0.5
    assert finding.evidence["response_codes"] == [{"rcode": "NXDOMAIN", "count": 10}]


def test_dns_failures_below_ratio_or_volume(builder, detect):
    failures(builder, total=20, failed=9)
    _, report = detect(builder)
    assert rule_findings(report, d.DNS_FAILURES) == []

    small = TrafficBuilder()
    failures(small, total=19, failed=19)
    _, report = detect(small)
    assert rule_findings(report, d.DNS_FAILURES) == []


def test_repeated_failing_name_is_reported_once(builder, detect):
    for i in range(20):
        builder.dns_query(CLIENT, "dead-c2.example", t=i * 30, txid=i)
        builder.dns_response(CLIENT, "dead-c2.example", t=i * 30 + 0.01, txid=i, rcode=3)
    _, report = detect(builder)
    [finding] = rule_findings(report, d.DNS_REPEATED_UNUSUAL)
    assert finding.evidence["queries"] == 20 and finding.evidence["failed_responses"] == 20
    assert finding.evidence["median_seconds_between_queries"] == pytest.approx(30.0)
    # The same 20 failures must not also produce a failure-ratio finding.
    assert rule_findings(report, d.DNS_FAILURES) == []

    without_specific_rule = config_with(disabled_rules=(d.DNS_REPEATED_UNUSUAL,))
    _, report = detect(builder, without_specific_rule)
    assert len(rule_findings(report, d.DNS_FAILURES)) == 1


def test_repeated_long_name_is_not_also_a_long_name_finding(builder, detect):
    name = "y" * 60 + ".beacon.example"
    for i in range(20):
        builder.dns_query(CLIENT, name, t=i, txid=i)
    _, report = detect(builder)
    assert len(rule_findings(report, d.DNS_REPEATED_UNUSUAL)) == 1
    assert rule_findings(report, d.DNS_LONG_NAMES) == []


def test_repeated_ordinary_name_is_not_flagged(builder, detect):
    for i in range(50):
        builder.dns_query(CLIENT, "www.example.com", t=i, txid=i)
        builder.dns_response(CLIENT, "www.example.com", t=i + 0.01, txid=i, rcode=0)
    _, report = detect(builder)
    assert report.findings == []


# -- NS-CLEAR-001 cleartext ------------------------------------------------------------------


def http_request(traffic: TrafficBuilder, port: int = 80, secret: bytes = b"") -> None:
    traffic.connect(CLIENT, SERVER, 40000, port, t=0)
    traffic.tcp(
        CLIENT,
        SERVER,
        40000,
        port,
        "PA",
        t=0.1,
        seq=1001,
        ack=5001,
        payload=b"GET /index.html HTTP/1.1\r\nHost: example\r\n\r\n" + secret,
    )
    traffic.tcp(
        SERVER,
        CLIENT,
        port,
        40000,
        "PA",
        t=0.2,
        seq=5001,
        ack=1050,
        payload=b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
    )


def test_http_is_informational_cleartext(builder, detect):
    http_request(builder, secret=b"Authorization: Basic dXNlcjpodW50ZXIy")
    _, report = detect(builder)
    [finding] = rule_findings(report, d.CLEARTEXT)
    assert (finding.severity, finding.confidence) == (Severity.INFO, Confidence.HIGH)
    assert finding.evidence["packets_identified"] == 2
    assert finding.evidence["flows"][0] == {
        "client": CLIENT,
        "server": SERVER,
        "server_port": 80,
        "packets": 2,
    }
    assert "dXNlcjpodW50ZXIy" not in json.dumps(finding.evidence)


def test_http_on_non_standard_port_is_identified_by_content(builder, detect):
    http_request(builder, port=8081)
    _, report = detect(builder)
    assert rule_findings(report, d.CLEARTEXT)[0].evidence["flows"][0]["server_port"] == 8081


def test_tls_and_http_lookalikes_are_not_cleartext(builder, detect):
    builder.tcp(CLIENT, SERVER, 40000, 443, "PA", t=0, payload=b"\x16\x03\x01\x02\x00\x01\x00")
    builder.tcp(CLIENT, SERVER, 40001, 80, "PA", t=1, payload=b"GET is not a request line")
    _, report = detect(builder)
    assert rule_findings(report, d.CLEARTEXT) == []


def test_telnet_and_ftp_are_low(builder, detect):
    builder.tcp(SERVER, CLIENT, 23, 40000, "PA", t=0, payload=b"\xff\xfd\x18\xff\xfd\x20")
    builder.tcp(SERVER, CLIENT, 21, 40001, "PA", t=1, payload=b"220 FTP server ready\r\n")
    builder.tcp(SERVER, CLIENT, 2121, 40002, "PA", t=2, payload=b"220 not on port 21\r\n")
    _, report = detect(builder)
    found = {f.evidence["protocol"]: f for f in rule_findings(report, d.CLEARTEXT)}
    assert set(found) == {"FTP", "Telnet"}
    assert found["Telnet"].severity is Severity.LOW
    assert found["FTP"].evidence["flows"][0]["server_port"] == 21


# -- engine -----------------------------------------------------------------------------------


def test_benign_capture_has_no_findings(builder, detect):
    for i in range(5):
        name = f"site{i}.example"
        builder.dns_query(CLIENT, name, t=i, txid=i)
        builder.dns_response(CLIENT, name, t=i + 0.01, txid=i)
        builder.connect(CLIENT, f"198.51.100.{i + 1}", 40000 + i, 443, t=i + 0.1)
    _, report = detect(builder)
    assert report.findings == [] and report.suppressed == []


def test_disabled_rule_is_skipped_and_noted(builder, detect):
    scan(builder, CLIENT, SERVER, range(1, 31))
    config = config_with(disabled_rules=(d.PORT_SCAN,))
    _, report = detect(builder, config)
    assert rule_findings(report, d.PORT_SCAN) == []
    assert any(d.PORT_SCAN in note for note in report.notes)
    # With the scan rule off, the refusals are no longer "explained" and are reported.
    assert len(rule_findings(report, d.FAILED_CONNECTIONS)) == 1


def test_findings_are_sorted_and_serialisable(builder, detect):
    scan(builder, CLIENT, SERVER, range(1, 31))
    http_request(builder)
    builder.dns_query(CLIENT, "z" * 60 + ".example", t=50)
    _, report = detect(builder)
    severities = [f.severity.rank for f in report.findings]
    assert severities == sorted(severities, reverse=True)
    # Severity first (MEDIUM before INFO), then confidence (HIGH before LOW).
    assert [f.rule_id for f in report.findings] == [d.PORT_SCAN, d.CLEARTEXT, d.DNS_LONG_NAMES]
    for finding in report.findings:
        json.dumps(finding.evidence, allow_nan=False)  # evidence must always be valid JSON
        assert finding.limitations == d.RULES[finding.rule_id].limitations


def test_every_rule_is_documented():
    assert len(d.RULES) == 11
    for rule in d.RULES.values():
        assert (
            rule.rule_id.startswith("NS-") and rule.name and rule.description and rule.limitations
        )


def test_validate_rule_ids():
    assert d.validate_rule_ids(["NS-SCAN-001", "NS-NOPE-999"]) == ["NS-NOPE-999"]
