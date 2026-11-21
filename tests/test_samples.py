"""Regression test: the demo captures produce exactly the findings they were built for.

The benign capture is a false-positive guard: ordinary browsing, DNS and NTP traffic must
produce no findings and no suppressed candidates.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

from netsentry.analyzer import analyze_capture
from netsentry.detectors import run_detections

GENERATOR = Path(__file__).resolve().parent.parent / "samples" / "generate_samples.py"


@pytest.fixture(scope="module")
def samples():
    spec = importlib.util.spec_from_file_location("generate_samples", GENERATOR)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run(samples, tmp_path: Path, builder_name: str, file_name: str):
    path = tmp_path / file_name
    getattr(samples, builder_name)().write(path)
    result = analyze_capture(path)
    return result, run_detections(result)


def test_benign_sample_is_quiet(samples, tmp_path):
    result, report = run(samples, tmp_path, "build_benign", "benign.pcap")
    assert result.traffic.total_packets > 1000 and result.warnings == []
    assert report.findings == [] and report.suppressed == []


def test_port_scan_sample(samples, tmp_path):
    _, report = run(samples, tmp_path, "build_port_scan", "scan.pcap")
    assert [(f.rule_id, f.severity.value, f.confidence.value) for f in report.findings] == [
        ("NS-SCAN-001", "MEDIUM", "HIGH")
    ]
    assert [s.rule_id for s in report.suppressed] == ["NS-CONN-002"]


def test_mixed_incident_sample_reports_each_planted_pattern_once(samples, tmp_path):
    _, report = run(samples, tmp_path, "build_mixed_incident", "mixed.pcapng")
    assert sorted(f.rule_id for f in report.findings) == sorted(
        [
            "NS-SCAN-001",
            "NS-CONN-001",
            "NS-CLEAR-001",  # Telnet
            "NS-CLEAR-001",  # HTTP
            "NS-DNS-002",
            "NS-DNS-004",
            "NS-PORT-001",
        ]
    )
