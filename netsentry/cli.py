"""Command-line interface for NetSentry.

Exit codes (also listed by ``netsentry info``):

    0    analysis completed (and, with --fail-on, no finding reached that severity)
    1    analysis completed and --fail-on matched at least one finding
    2    invalid command-line arguments or configuration
    3    the capture file could not be read or is not a supported capture
    4    the report could not be written
    70   unexpected internal error (re-run with --debug for details)
    130  interrupted by the user (Ctrl+C)
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import sys
import traceback
from collections.abc import Sequence
from enum import IntEnum
from pathlib import Path
from typing import Any

from rich import box
from rich.console import Console
from rich.table import Table
from rich.text import Text

from . import TOOL_NAME, __version__
from .config import ConfigError, DetectionConfig, load_config
from .detectors import RULES, run_detections, validate_rule_ids
from .models import Severity
from .reporting import DEFAULT_TOP, build_report, render_json, render_terminal, render_text
from .utils import ReportWriteError, sanitize_text, write_report_file

_SPINNER_MIN_BYTES = 5 * 1024 * 1024  # do not animate for small files
_MAX_TOP = 1000


class ExitCode(IntEnum):
    OK = 0
    FINDINGS = 1
    USAGE = 2
    INPUT_ERROR = 3
    OUTPUT_ERROR = 4
    INTERNAL_ERROR = 70
    INTERRUPTED = 130


DESCRIPTION = (
    f"{TOOL_NAME} {__version__} - offline network traffic analysis and defensive threat "
    "detection for PCAP/PCAPNG capture files. Everything runs locally: no packets are sent, "
    "nothing is uploaded, and no administrator rights are needed."
)

EPILOG = """examples:
  netsentry analyze capture.pcap
  netsentry analyze capture.pcapng --threshold medium
  netsentry analyze capture.pcap --format json
  netsentry analyze capture.pcap --output reports/report.json
  netsentry info --default-config > thresholds.json
  netsentry analyze capture.pcap --config thresholds.json

Only analyse traffic you are authorised to inspect."""


def _severity(value: str) -> Severity:
    try:
        return Severity.parse(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from None


def _top_count(value: str) -> int:
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("must be a whole number") from None
    if not 1 <= number <= _MAX_TOP:
        raise argparse.ArgumentTypeError(f"must be between 1 and {_MAX_TOP}")
    return number


def _packet_limit(value: str) -> int:
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("must be a whole number") from None
    if number < 0:
        raise argparse.ArgumentTypeError("must be 0 (no limit) or a positive number")
    return number


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netsentry",
        description=DESCRIPTION,
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"{TOOL_NAME} {__version__}")
    commands = parser.add_subparsers(dest="command", metavar="COMMAND")

    analyze = commands.add_parser(
        "analyze",
        help="analyse a PCAP/PCAPNG capture file",
        description="Analyse a capture file and report traffic statistics and findings.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    analyze.add_argument("capture", help="path to a .pcap or .pcapng file (optionally gzipped)")
    analyze.add_argument(
        "-f",
        "--format",
        choices=("text", "json"),
        help="report format (default: text, or json when --output ends in .json)",
    )
    analyze.add_argument(
        "-o",
        "--output",
        metavar="PATH",
        help="write the report to PATH instead of the terminal (never overwrites unless "
        "--overwrite is given)",
    )
    analyze.add_argument(
        "--overwrite", action="store_true", help="allow --output to replace an existing file"
    )
    analyze.add_argument(
        "-t",
        "--threshold",
        "--min-severity",
        dest="threshold",
        type=_severity,
        default=Severity.INFO,
        metavar="SEVERITY",
        help="only report findings at or above this severity: info, low, medium, high "
        "(default: info)",
    )
    analyze.add_argument(
        "--fail-on",
        type=_severity,
        metavar="SEVERITY",
        help="exit with code 1 if any finding at or above SEVERITY is detected "
        "(useful in scripts; considers all findings, regardless of --threshold)",
    )
    analyze.add_argument(
        "--top",
        type=_top_count,
        default=DEFAULT_TOP,
        metavar="N",
        help=f"rows to show in top-talker and DNS lists (default: {DEFAULT_TOP})",
    )
    analyze.add_argument(
        "--max-packets",
        type=_packet_limit,
        default=None,
        metavar="N",
        help="stop after N packets to bound run time on huge captures "
        "(default: 1,000,000; 0 = no limit)",
    )
    analyze.add_argument(
        "-c",
        "--config",
        metavar="FILE",
        help="JSON file overriding detection thresholds (see: netsentry info --default-config)",
    )
    analyze.add_argument(
        "--disable-rule",
        action="append",
        default=[],
        metavar="RULE_ID",
        help="disable a detection rule, e.g. NS-DNS-002 (repeatable)",
    )
    analyze.add_argument(
        "-v", "--verbose", action="store_true", help="show every evidence entry in findings"
    )
    analyze.add_argument("--no-color", action="store_true", help="disable coloured output")
    analyze.add_argument(
        "--debug", action="store_true", help="show Python tracebacks for unexpected errors"
    )

    info = commands.add_parser(
        "info",
        help="show version, detection rules, privacy notes and exit codes",
        description="Show information about NetSentry and its detection rules.",
    )
    info.add_argument(
        "--default-config",
        action="store_true",
        help="print the default detection thresholds as JSON (a template for --config)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:  # argparse exits on --help/--version or bad arguments
        return exc.code if isinstance(exc.code, int) else ExitCode.USAGE

    # soft_wrap: let the terminal wrap messages, so long paths stay copyable.
    err = Console(stderr=True, highlight=False, emoji=False, soft_wrap=True)
    try:
        if args.command == "analyze":
            return _run_analyze(args, err)
        if args.command == "info":
            return _run_info(args)
        parser.print_help()
        return ExitCode.USAGE
    except KeyboardInterrupt:
        err.print(Text("\nInterrupted by user; no report was written.", style="yellow"))
        return ExitCode.INTERRUPTED
    except BrokenPipeError:
        # Output was piped into a program that stopped reading (e.g. `| head`).
        _silence_stdout()
        return ExitCode.OK


def _error(err: Console, message: str) -> None:
    err.print(Text.assemble(("netsentry: error: ", "bold red"), sanitize_text(message)))


def _run_analyze(args: argparse.Namespace, err: Console) -> int:
    # Imported here so `netsentry --help` and `info` stay fast (Scapy is large).
    from .analyzer import analyze_capture
    from .capture_loader import DEFAULT_MAX_PACKETS, CaptureError

    try:
        config = load_config(args.config) if args.config else DetectionConfig()
    except ConfigError as exc:
        _error(err, f"invalid configuration: {exc}")
        return ExitCode.USAGE
    disabled = {*config.disabled_rules, *(rule.strip().upper() for rule in args.disable_rule)}
    unknown = validate_rule_ids(disabled)
    if unknown:
        _error(
            err,
            f"unknown rule identifier(s): {', '.join(unknown)} (see `netsentry info` for the list)",
        )
        return ExitCode.USAGE
    config = dataclasses.replace(config, disabled_rules=tuple(sorted(disabled)))

    output = Path(args.output) if args.output else None
    report_format = args.format or (
        "json" if output is not None and output.suffix.lower() == ".json" else "text"
    )
    if output is not None:
        problem = _precheck_output(output, Path(args.capture), args.overwrite)
        if problem:
            _error(err, problem)
            return ExitCode.OUTPUT_ERROR

    max_packets = DEFAULT_MAX_PACKETS if args.max_packets is None else args.max_packets
    try:
        result = _analyze_with_status(analyze_capture, args.capture, max_packets, err)
        detection = run_detections(result, config)
        report = build_report(result, detection, config, threshold=args.threshold, top=args.top)

        if report_format == "json":
            content = render_json(report)
        elif output is not None:
            content = render_text(report, verbose=args.verbose)
        else:
            content = ""

        if output is not None:
            write_report_file(
                output, content, overwrite=args.overwrite, protected_paths=[args.capture]
            )
            summary = report["findings_summary"]
            err.print(
                Text(
                    f"Report written to {sanitize_text(output)} ({report_format}, "
                    f"{summary['reported']} finding(s) reported, "
                    f"{summary['below_threshold']} below threshold).",
                )
            )
        elif report_format == "json":
            sys.stdout.write(content)
            sys.stdout.flush()
        else:
            console = Console(highlight=False, emoji=False, no_color=args.no_color or None)
            render_terminal(console, report, verbose=args.verbose)
    except CaptureError as exc:
        _error(err, str(exc))
        return ExitCode.INPUT_ERROR
    except ReportWriteError as exc:
        _error(err, str(exc))
        return ExitCode.OUTPUT_ERROR
    except (KeyboardInterrupt, BrokenPipeError):
        raise
    except Exception as exc:
        if args.debug:
            traceback.print_exc()
        _error(
            err,
            f"unexpected internal error ({exc.__class__.__name__}). "
            + ("" if args.debug else "Re-run with --debug for details."),
        )
        return ExitCode.INTERNAL_ERROR

    if args.fail_on is not None and any(
        finding.severity.rank >= args.fail_on.rank for finding in detection.findings
    ):
        return ExitCode.FINDINGS
    return ExitCode.OK


def _analyze_with_status(analyze: Any, capture: str, max_packets: int, err: Console) -> Any:
    try:
        large = os.path.getsize(capture) >= _SPINNER_MIN_BYTES
    except OSError:
        large = False  # inspect_capture_file will report the real problem
    if not (large and err.is_terminal):
        return analyze(capture, max_packets=max_packets)
    with err.status("Reading capture...") as status:
        return analyze(
            capture,
            max_packets=max_packets,
            progress=lambda count: status.update(f"Reading capture... {count:,} packets"),
        )


def _precheck_output(output: Path, capture: Path, overwrite: bool) -> str | None:
    """Fail fast, before a long analysis, on outputs that can never be written."""
    if output.is_dir():
        return f"the output path is a directory: {output}"
    try:
        if output.exists() and capture.exists() and os.path.samefile(output, capture):
            return "refusing to write the report over the input capture file"
    except OSError:
        pass
    if output.exists() and not overwrite:
        return f"{output} already exists; choose another name or pass --overwrite"
    return None


def _run_info(args: argparse.Namespace) -> int:
    if args.default_config:
        sys.stdout.write(json.dumps(DetectionConfig().to_dict(), indent=2) + "\n")
        return ExitCode.OK

    console = Console(highlight=False, emoji=False)
    console.print(Text(f"{TOOL_NAME} {__version__}", style="bold"))
    console.print(
        "Offline analysis of existing PCAP and PCAPNG captures (optionally gzip-compressed). "
        "NetSentry summarises traffic and applies explainable detection rules; findings are "
        "leads for investigation, not proof of malicious activity.",
        markup=False,
    )
    console.print()
    console.print(Text("Privacy and safety", style="bold"))
    for line in (
        "Captures are processed locally; nothing is uploaded or sent over the network.",
        "Application payloads are never printed or stored in reports.",
        "Reports still contain IP addresses and DNS names, so store and share them carefully.",
        "Only analyse traffic you are authorised to inspect.",
    ):
        console.print(Text(f"- {line}"))
    console.print()

    table = Table(title="Detection rules", box=box.SIMPLE, title_justify="left")
    table.add_column("Rule")
    table.add_column("Name")
    table.add_column("What it looks for")
    for rule in RULES.values():
        table.add_row(rule.rule_id, rule.name, rule.description)
    console.print(table)
    console.print(
        Text("Thresholds: `netsentry info --default-config` prints them as an editable JSON file.")
    )
    console.print()

    codes = Table(title="Exit codes", box=box.SIMPLE, title_justify="left")
    codes.add_column("Code", justify="right")
    codes.add_column("Meaning")
    for code, meaning in (
        (ExitCode.OK, "analysis completed"),
        (ExitCode.FINDINGS, "--fail-on matched at least one finding"),
        (ExitCode.USAGE, "invalid arguments or configuration"),
        (ExitCode.INPUT_ERROR, "capture missing, unreadable or not a supported format"),
        (ExitCode.OUTPUT_ERROR, "report could not be written"),
        (ExitCode.INTERNAL_ERROR, "unexpected internal error"),
        (ExitCode.INTERRUPTED, "interrupted (Ctrl+C)"),
    ):
        codes.add_row(str(int(code)), meaning)
    console.print(codes)
    return ExitCode.OK


def _silence_stdout() -> None:
    try:
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
    except (OSError, ValueError, AttributeError):
        pass


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
