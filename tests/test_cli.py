"""Command-line behaviour: exit codes, output files, errors, interrupts, offline operation."""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
from pathlib import Path

import pytest

from conftest import CLIENT, SERVER, TrafficBuilder
from netsentry import cli
from netsentry.cli import ExitCode, main
from netsentry.config import DetectionConfig, load_config

PROJECT_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def scan_capture(write_capture) -> Path:
    traffic = TrafficBuilder()
    for i, port in enumerate(range(1, 31)):
        traffic.connect(CLIENT, SERVER, 50000 + i, port, t=i * 0.1, outcome="refuse")
    return write_capture(traffic)


@pytest.fixture
def benign_capture(write_capture) -> Path:
    traffic = TrafficBuilder()
    traffic.connect(CLIENT, SERVER, 40000, 443, t=0)
    traffic.dns_query(CLIENT, "example.com", t=1)
    traffic.dns_response(CLIENT, "example.com", t=1.01)
    return write_capture(traffic)


# -- help / info ---------------------------------------------------------------------------


def test_help_and_version(capsys):
    assert main(["--help"]) == ExitCode.OK
    assert "analyze" in capsys.readouterr().out
    assert main(["--version"]) == ExitCode.OK
    assert "NetSentry" in capsys.readouterr().out


def test_no_command_prints_help(capsys):
    assert main([]) == ExitCode.USAGE
    assert "usage" in capsys.readouterr().out


def test_info_lists_rules_and_exit_codes(capsys):
    assert main(["info"]) == ExitCode.OK
    out = capsys.readouterr().out
    assert "NS-SCAN-001" in out and "NS-CLEAR-001" in out and "Exit codes" in out


def test_default_config_template_round_trips(capsys, tmp_path):
    assert main(["info", "--default-config"]) == ExitCode.OK
    template = tmp_path / "thresholds.json"
    template.write_text(capsys.readouterr().out)
    assert "port_scan" in json.loads(template.read_text())
    assert load_config(template) == DetectionConfig()  # the template is a valid --config file


# -- analyse ---------------------------------------------------------------------------------


def test_analyze_text_report(scan_capture, capsys):
    assert main(["analyze", str(scan_capture), "--no-color"]) == ExitCode.OK
    out = capsys.readouterr().out
    assert "NetSentry" in out and "Potential port scan" in out and "[MEDIUM]" in out


def test_analyze_json_to_stdout_is_pure_json(scan_capture, capsys):
    assert main(["analyze", str(scan_capture), "--format", "json"]) == ExitCode.OK
    report = json.loads(capsys.readouterr().out)
    assert report["findings"][0]["rule_id"] == "NS-SCAN-001"


def test_threshold_filters_findings(scan_capture, capsys):
    assert main(["analyze", str(scan_capture), "-f", "json", "--threshold", "high"]) == ExitCode.OK
    report = json.loads(capsys.readouterr().out)
    assert report["findings"] == [] and report["findings_summary"]["below_threshold"] == 1


def test_fail_on_sets_exit_code(scan_capture, benign_capture):
    assert main(["analyze", str(scan_capture), "--fail-on", "medium"]) == ExitCode.FINDINGS
    assert main(["analyze", str(scan_capture), "--fail-on", "high"]) == ExitCode.OK
    assert main(["analyze", str(benign_capture), "--fail-on", "info"]) == ExitCode.OK


def test_disable_rule(scan_capture, capsys):
    code = main(
        [
            "analyze",
            str(scan_capture),
            "-f",
            "json",
            "--disable-rule",
            "ns-scan-001",
            "--disable-rule",
            "NS-CONN-002",
        ]
    )
    assert code == ExitCode.OK
    assert json.loads(capsys.readouterr().out)["findings"] == []


@pytest.mark.parametrize(
    "arguments",
    [
        ["--threshold", "critical"],
        ["--top", "0"],
        ["--max-packets", "-1"],
        ["--format", "xml"],
        ["--disable-rule", "NS-NOPE-001"],
    ],
)
def test_invalid_arguments_are_usage_errors(scan_capture, arguments):
    assert main(["analyze", str(scan_capture), *arguments]) == ExitCode.USAGE


def test_invalid_config_files(scan_capture, tmp_path, capsys):
    bad_json = tmp_path / "bad.json"
    bad_json.write_text("{not json")
    assert main(["analyze", str(scan_capture), "--config", str(bad_json)]) == ExitCode.USAGE
    assert "not valid JSON" in capsys.readouterr().err

    unknown = tmp_path / "unknown.json"
    unknown.write_text(json.dumps({"port_scan": {"min_ports": 5}}))
    assert main(["analyze", str(scan_capture), "--config", str(unknown)]) == ExitCode.USAGE
    assert "min_ports" in capsys.readouterr().err


def test_config_changes_thresholds(scan_capture, tmp_path, capsys):
    strict = tmp_path / "strict.json"
    strict.write_text(json.dumps({"port_scan": {"min_distinct_ports": 50}}))
    assert main(["analyze", str(scan_capture), "-f", "json", "-c", str(strict)]) == ExitCode.OK
    report = json.loads(capsys.readouterr().out)
    assert "NS-SCAN-001" not in {f["rule_id"] for f in report["findings"]}
    assert report["analysis"]["configuration"]["port_scan"]["min_distinct_ports"] == 50


# -- input errors ------------------------------------------------------------------------------


@pytest.mark.parametrize("kind", ["missing", "directory", "empty", "text", "truncated-header"])
def test_bad_inputs_give_concise_errors(kind, tmp_path, capsys):
    path = tmp_path / "input.pcap"
    if kind == "directory":
        path.mkdir()
    elif kind == "empty":
        path.write_bytes(b"")
    elif kind == "text":
        path.write_text("hello, I am not a capture")
    elif kind == "truncated-header":
        path.write_bytes(b"\xd4\xc3\xb2\xa1\x02\x00")
    assert main(["analyze", str(path)]) == ExitCode.INPUT_ERROR
    err = capsys.readouterr().err
    assert err.startswith("netsentry: error:")
    assert "Traceback" not in err


# -- output files -------------------------------------------------------------------------------


def test_output_json_is_inferred_from_extension(scan_capture, tmp_path, capsys):
    output = tmp_path / "reports" / "report.json"  # parent directory is created
    assert main(["analyze", str(scan_capture), "--output", str(output)]) == ExitCode.OK
    assert json.loads(output.read_text())["schema_version"] == "1.0"
    assert "Report written to" in capsys.readouterr().err


def test_output_text_file_has_no_ansi(scan_capture, tmp_path):
    output = tmp_path / "report.txt"
    assert main(["analyze", str(scan_capture), "-o", str(output)]) == ExitCode.OK
    text = output.read_text(encoding="utf-8")
    assert "\x1b[" not in text and "Potential port scan" in text


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits")
def test_report_file_is_private(scan_capture, tmp_path):
    output = tmp_path / "report.json"
    assert main(["analyze", str(scan_capture), "-o", str(output)]) == ExitCode.OK
    assert output.stat().st_mode & 0o777 == 0o600


def test_existing_output_is_not_overwritten_without_flag(scan_capture, tmp_path, capsys):
    output = tmp_path / "report.json"
    output.write_text("keep me")
    assert main(["analyze", str(scan_capture), "-o", str(output)]) == ExitCode.OUTPUT_ERROR
    assert output.read_text() == "keep me"
    assert "--overwrite" in capsys.readouterr().err

    assert main(["analyze", str(scan_capture), "-o", str(output), "--overwrite"]) == ExitCode.OK
    assert json.loads(output.read_text())["tool"]["name"] == "NetSentry"
    assert [p.name for p in tmp_path.iterdir() if p.name.startswith(".netsentry-")] == []


def test_output_cannot_replace_the_capture(scan_capture):
    before = scan_capture.read_bytes()
    code = main(["analyze", str(scan_capture), "-o", str(scan_capture), "--overwrite"])
    assert code == ExitCode.OUTPUT_ERROR
    assert scan_capture.read_bytes() == before


def test_output_directory_and_unwritable_paths(scan_capture, tmp_path):
    assert main(["analyze", str(scan_capture), "-o", str(tmp_path)]) == ExitCode.OUTPUT_ERROR
    blocker = tmp_path / "file.txt"
    blocker.write_text("x")
    nested = blocker / "report.json"  # parent is a file, not a directory
    assert main(["analyze", str(scan_capture), "-o", str(nested)]) == ExitCode.OUTPUT_ERROR


def test_write_failure_leaves_no_partial_report(scan_capture, tmp_path, monkeypatch):
    from netsentry import utils

    class FullDisk:
        def __init__(self, descriptor: int, mode: str) -> None:
            os.close(descriptor)

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def write(self, data: bytes) -> int:
            raise OSError(28, "No space left on device")

    monkeypatch.setattr(utils.os, "fdopen", FullDisk)
    output = tmp_path / "report.json"
    assert main(["analyze", str(scan_capture), "-o", str(output)]) == ExitCode.OUTPUT_ERROR
    assert not output.exists()


# -- robustness ---------------------------------------------------------------------------------


def test_keyboard_interrupt_exits_130(scan_capture, monkeypatch, capsys):
    import netsentry.analyzer

    def interrupted(*args, **kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(netsentry.analyzer, "analyze_capture", interrupted)
    assert main(["analyze", str(scan_capture)]) == ExitCode.INTERRUPTED
    assert "Interrupted" in capsys.readouterr().err


def test_unexpected_error_is_concise_unless_debug(scan_capture, monkeypatch, capsys):
    def broken(*args, **kwargs):
        raise RuntimeError("detector exploded")

    monkeypatch.setattr(cli, "run_detections", broken)
    assert main(["analyze", str(scan_capture)]) == ExitCode.INTERNAL_ERROR
    err = capsys.readouterr().err
    assert "unexpected internal error (RuntimeError)" in err and "Traceback" not in err

    assert main(["analyze", str(scan_capture), "--debug"]) == ExitCode.INTERNAL_ERROR
    assert "Traceback" in capsys.readouterr().err


def test_analysis_makes_no_network_connections(scan_capture, tmp_path, monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError("NetSentry attempted network access")

    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket.socket, "sendto", blocked)
    monkeypatch.setattr(socket.socket, "send", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    monkeypatch.setattr(socket, "gethostbyname", blocked)
    output = tmp_path / "offline.json"
    assert main(["analyze", str(scan_capture), "-o", str(output)]) == ExitCode.OK


def test_packet_limit_is_reported(write_capture, capsys):
    traffic = TrafficBuilder()
    for i in range(10):
        traffic.udp(CLIENT, SERVER, 5000 + i, 9999, t=i)
    path = write_capture(traffic)
    assert main(["analyze", str(path), "-f", "json", "--max-packets", "4"]) == ExitCode.OK
    report = json.loads(capsys.readouterr().out)
    assert report["summary"]["packets"] == 4
    assert report["processing"]["stopped_at_packet_limit"] is True
    assert any("packet limit" in warning for warning in report["warnings"])


def test_entry_points_run_as_subprocesses(scan_capture):
    for command in (
        [sys.executable, "main.py", "--version"],
        [sys.executable, "-m", "netsentry", "analyze", str(scan_capture), "-f", "json"],
    ):
        completed = subprocess.run(
            command, cwd=PROJECT_ROOT, capture_output=True, text=True, timeout=120, check=False
        )
        assert completed.returncode == 0, completed.stderr
        assert "NetSentry" in completed.stdout
