"""Reports: JSON validity and stability, thresholds, safe rendering of hostile data."""

from __future__ import annotations

import json
import re

import pytest
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP

from conftest import CLIENT, SERVER, TrafficBuilder, eth
from netsentry.config import DetectionConfig
from netsentry.detectors import run_detections
from netsentry.models import Severity
from netsentry.reporting import SCHEMA_VERSION, build_report, render_json, render_text

ANSI_ESCAPE = re.compile(r"\x1b\[")


def scenario() -> TrafficBuilder:
    traffic = TrafficBuilder()
    for i, port in enumerate(range(1, 31)):
        traffic.connect(CLIENT, SERVER, 50000 + i, port, t=i * 0.1, outcome="refuse")
    traffic.connect(CLIENT, SERVER, 40000, 80, t=10)
    traffic.tcp(
        CLIENT,
        SERVER,
        40000,
        80,
        "PA",
        t=10.1,
        seq=1001,
        ack=5001,
        payload=b"GET /?token=SECRET-TOKEN-123 HTTP/1.1\r\nHost: x\r\n\r\n",
    )
    traffic.dns_query(CLIENT, "www.example.com", t=11)
    traffic.dns_response(CLIENT, "www.example.com", t=11.01)
    return traffic


@pytest.fixture
def report_for(analyze):
    def _build(traffic: TrafficBuilder, threshold: Severity = Severity.INFO, top: int = 10):
        result = analyze(traffic)
        config = DetectionConfig()
        return build_report(
            result, run_detections(result, config), config, threshold=threshold, top=top
        )

    return _build


def test_json_report_is_valid_and_complete(report_for):
    report = report_for(scenario())
    parsed = json.loads(render_json(report))
    assert parsed["schema_version"] == SCHEMA_VERSION
    for key in (
        "tool",
        "analysis",
        "capture",
        "processing",
        "summary",
        "protocols",
        "top_talkers",
        "tcp",
        "dns",
        "findings_summary",
        "findings",
        "suppressed_candidates",
        "warnings",
        "limitations",
    ):
        assert key in parsed
    assert parsed["tool"]["name"] == "NetSentry"
    assert parsed["summary"]["packets"] == 65
    assert parsed["capture"]["first_packet_time"].endswith("Z")
    assert parsed["analysis"]["generated_at"] != parsed["capture"]["first_packet_time"]
    finding = parsed["findings"][0]
    assert finding["id"] == "F-001" and finding["rule_id"] == "NS-SCAN-001"
    assert finding["severity"] == "MEDIUM" and isinstance(finding["evidence"], dict)
    ports = parsed["top_talkers"]["destination_ports"]
    assert all(
        {"transport", "port", "packets", "flows_initiated", "common_service_hint"} <= set(p)
        for p in ports
    )


def test_json_is_deterministic_apart_from_generation_time(report_for):
    first = json.loads(render_json(report_for(scenario())))
    second = json.loads(render_json(report_for(scenario())))
    for report in (first, second):
        report["analysis"].pop("generated_at")
        report["capture"].pop("file_name")
        report["capture"].pop("sha256")  # file names differ, so the bytes differ
    assert first == second


def test_json_rejects_nan():
    with pytest.raises(ValueError):
        render_json({"value": float("nan")})


def test_threshold_hides_lower_findings_but_counts_them(report_for):
    report = report_for(scenario(), threshold=Severity.MEDIUM)
    assert [f["rule_id"] for f in report["findings"]] == ["NS-SCAN-001"]
    assert report["findings_summary"]["below_threshold"] == 1  # the INFO cleartext finding
    assert report["findings_summary"]["by_severity"] == {
        "HIGH": 0,
        "MEDIUM": 1,
        "LOW": 0,
        "INFO": 1,
    }
    assert report["analysis"]["severity_threshold"] == "MEDIUM"


def test_top_limits_list_lengths(report_for):
    report = report_for(scenario(), top=2)
    assert len(report["top_talkers"]["destination_ports"]) == 2
    assert len(report["top_talkers"]["sources"]) <= 2


def test_reports_never_contain_payload_content(report_for):
    report = report_for(scenario())
    assert "SECRET-TOKEN-123" not in render_json(report)
    assert "SECRET-TOKEN-123" not in render_text(report, verbose=True)


def test_text_report_has_sections_and_no_ansi_codes(report_for):
    text = render_text(report_for(scenario()))
    assert not ANSI_ESCAPE.search(text)
    for heading in (
        "Capture",
        "Protocol distribution",
        "Top talkers",
        "TCP",
        "DNS",
        "Findings",
        "Analysis limitations",
    ):
        assert heading in text
    assert "[MEDIUM] F-001" in text  # severity is written as a word, not only a colour
    assert "Potential port scan from 192.0.2.10" in text


# OSC title change + bell, screen clear, Rich markup, and a right-to-left override.
HOSTILE_NAME = b"\x1b]0;pwned\x07\x1b[2J[red]fake[/red]\xe2\x80\xae.example"


def hostile_capture() -> TrafficBuilder:
    traffic = TrafficBuilder()
    for i in range(20):  # repeated so it shows up in names and in an NS-DNS-004 finding
        dns = DNS(id=i, qd=DNSQR(qname=HOSTILE_NAME))
        traffic.add(eth() / IP(src=CLIENT, dst=SERVER) / UDP(sport=5000 + i, dport=53) / dns, t=i)
        traffic.add(
            eth()
            / IP(src=SERVER, dst=CLIENT)
            / UDP(sport=53, dport=5000 + i)
            / DNS(id=i, qr=1, rcode=3, qd=DNSQR(qname=HOSTILE_NAME)),
            t=i + 0.01,
        )
    return traffic


def test_terminal_control_sequences_in_packet_fields_are_neutralised(report_for):
    report = report_for(hostile_capture())
    for output in (render_text(report, verbose=True), render_json(report)):
        assert "\x1b" not in output and "\x07" not in output
        assert "‮" not in output  # right-to-left override must not reach the terminal
    text = render_text(report, verbose=True)
    assert "\\x1b]0;pwned" in text  # shown as a visible escape instead
    # Valid Rich markup inside packet data is printed literally, never interpreted.
    assert "[red]fake[/red]" in text
    assert any(f["rule_id"] == "NS-DNS-004" for f in report["findings"])


def test_json_report_contains_escaped_name(report_for):
    parsed = json.loads(render_json(report_for(hostile_capture())))
    names = [row["name"] for row in parsed["dns"]["top_query_names"]]
    assert names and names[0].startswith("\\x1b]0;pwned\\x07")


def test_empty_capture_report(report_for):
    report = report_for(TrafficBuilder())
    assert report["summary"]["packets"] == 0 and report["findings"] == []
    text = render_text(report)
    assert "No findings at or above the threshold" in text
    assert "contains no packets" in text
    json.loads(render_json(report))
