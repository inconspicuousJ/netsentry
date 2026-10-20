"""Helpers: escaping of untrusted text, formatting, safe report writing."""

from __future__ import annotations

import os

import pytest

from netsentry.protocols import describe_tcp_flags, identify_cleartext_protocol, service_hint
from netsentry.utils import (
    ReportWriteError,
    escape_bytes,
    format_bytes,
    format_duration,
    format_timestamp,
    sanitize_text,
    truncate,
    write_report_file,
)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("\x1b[31mred", "\\x1b[31mred"),  # ANSI escape
        ("a\r\nb\tc", "a\\x0d\\x0ab\\x09c"),  # line breaks cannot forge new report lines
        ("\x7f\x9b", "\\x7f\\x9b"),  # DEL and the 8-bit CSI control
        ("evil‮txt.exe", "evil\\u202etxt.exe"),  # right-to-left override
        ("zero​width", "zero\\u200bwidth"),
        ("line sep", "line\\u2028sep"),
        ("café 漢字", "café 漢字"),  # ordinary text is untouched
    ],
)
def test_sanitize_text(raw, expected):
    assert sanitize_text(raw) == expected


def test_escape_bytes_is_unambiguous():
    assert escape_bytes(b"ok.example") == "ok.example"
    assert escape_bytes(b"a b\\c\x00\xff") == "a\\x20b\\\\c\\x00\\xff"


def test_truncate_marks_hidden_characters():
    text = truncate("x" * 200, 50)
    assert len(text) <= 50
    kept = text.index("…")
    assert text == "x" * kept + f"…(+{200 - kept} chars)"  # the count is the true number hidden
    assert truncate("short", 50) == "short"
    assert truncate("x" * 51, 50).endswith("chars)")
    assert len(sanitize_text("y" * 300, max_length=40)) <= 40


def test_formatting_helpers():
    assert format_timestamp(0.0) == "1970-01-01T00:00:00.000000Z"
    assert format_timestamp(None) is None
    assert format_timestamp(1e20).startswith("out-of-range")
    assert format_duration(None) == "unknown"
    assert format_duration(0.25) == "250.0 ms"
    assert format_duration(75) == "1 min 15.0 s"
    assert format_duration(3725) == "1 h 02 min 05.0 s"
    assert format_bytes(512) == "512 B"
    assert format_bytes(1536) == "1.5 KiB"


def test_protocol_helpers():
    assert describe_tcp_flags(0x12) == "SYN+ACK"
    assert describe_tcp_flags(0) == "none"
    assert service_hint("TCP", 443) == "HTTPS" and service_hint("TCP", 50000) is None
    assert identify_cleartext_protocol(b"HTTP/1.1 404 Not Found\r\n", 80, 5000) == (
        "HTTP",
        "server_to_client",
    )
    assert identify_cleartext_protocol(b"USER anonymous\r\n", 5000, 21) == (
        "FTP",
        "client_to_server",
    )
    assert identify_cleartext_protocol(b"USER anonymous\r\n", 5000, 2121) is None
    assert identify_cleartext_protocol(b"GET / HTTP/2\r\n", 5000, 80) is None
    assert identify_cleartext_protocol(b"", 5000, 80) is None


def test_write_report_file_creates_and_refuses_to_clobber(tmp_path):
    target = tmp_path / "out" / "report.txt"
    write_report_file(target, "first")
    assert target.read_text() == "first"
    with pytest.raises(ReportWriteError, match="already exists"):
        write_report_file(target, "second")
    assert target.read_text() == "first"
    write_report_file(target, "second", overwrite=True)
    assert target.read_text() == "second"
    assert sorted(p.name for p in target.parent.iterdir()) == ["report.txt"]


def test_write_report_file_rejects_bad_targets(tmp_path):
    with pytest.raises(ReportWriteError, match="directory"):
        write_report_file(tmp_path, "x")
    capture = tmp_path / "capture.pcap"
    capture.write_bytes(b"data")
    with pytest.raises(ReportWriteError, match="input capture"):
        write_report_file(capture, "x", overwrite=True, protected_paths=[capture])
    assert capture.read_bytes() == b"data"


@pytest.mark.skipif(not hasattr(os, "symlink") or os.name != "posix", reason="POSIX symlinks")
def test_write_report_file_does_not_follow_symlinks(tmp_path):
    victim = tmp_path / "victim.txt"
    victim.write_text("important")
    link = tmp_path / "report.txt"
    link.symlink_to(victim)
    with pytest.raises(ReportWriteError, match="already exists"):
        write_report_file(link, "attacker-controlled")
    write_report_file(link, "report", overwrite=True)  # replaces the link itself
    assert victim.read_text() == "important"
    assert not link.is_symlink() and link.read_text() == "report"
