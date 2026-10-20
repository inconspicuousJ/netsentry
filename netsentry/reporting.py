"""Report generation: one structured report, rendered as JSON or for humans.

:func:`build_report` produces a plain dictionary (the documented JSON schema).
Both renderers work from that dictionary, so the terminal view and the JSON
export can never disagree.

Safety: every string that came from a capture is already escaped by the
loader, and the terminal renderer additionally wraps all dynamic values in
Rich ``Text`` objects (which never interpret ``[markup]``) after passing them
through :func:`sanitize_text`. JSON output uses ``ensure_ascii`` so control
characters are always written as ``\\uXXXX`` escapes.
"""

from __future__ import annotations

import io
import json
import re
from collections import Counter
from typing import Any

from rich import box
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from . import TOOL_NAME, __version__
from .capture_loader import DNS_UNDECODABLE, link_type_name
from .config import DetectionConfig
from .models import AnalysisResult, DetectionReport, Finding, Severity
from .protocols import dns_rcode_name, dns_type_name, service_hint
from .utils import (
    format_bytes,
    format_duration,
    format_timestamp,
    safe_ratio,
    sanitize_text,
    truncate,
    utc_now_iso,
)

SCHEMA_VERSION = "1.0"
DEFAULT_TOP = 10
_DISPLAY_VALUE_LIMIT = 110  # characters per value in the terminal view

SEVERITY_STYLES = {
    "HIGH": "bold red",
    "MEDIUM": "bold yellow",
    "LOW": "cyan",
    "INFO": "blue",
}

_APPLICATION_BASIS = {
    "DNS": "DNS message decoded (port 53)",
    "mDNS": "DNS message decoded (port 5353)",
    DNS_UNDECODABLE: "port 53, failed DNS decoding",
    "HTTP": "HTTP request/status line",
    "FTP": "FTP command/reply on port 21",
    "Telnet": "Telnet negotiation on port 23",
}


# ---------------------------------------------------------------------------
# Structured report
# ---------------------------------------------------------------------------


def build_report(
    result: AnalysisResult,
    detection: DetectionReport,
    config: DetectionConfig,
    *,
    threshold: Severity = Severity.INFO,
    top: int = DEFAULT_TOP,
) -> dict[str, Any]:
    """Assemble the full report as JSON-compatible data."""
    reported = [f for f in detection.findings if f.severity.rank >= threshold.rank]
    by_severity = Counter(f.severity.value for f in detection.findings)
    traffic, parse = result.traffic, result.parse

    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": TOOL_NAME, "version": __version__},
        "analysis": {
            "generated_at": utc_now_iso(),
            "generated_at_note": "Time this report was produced, not a capture timestamp.",
            "severity_threshold": threshold.value,
            "packet_limit": parse.packet_limit,
            "configuration": config.to_dict(),
        },
        "capture": _capture_section(result),
        "processing": {
            "frames_read": parse.frames_read,
            "frames_decoded": parse.frames_decoded,
            "decode_failures": parse.decode_failures,
            "unsupported_link_type_frames": sum(parse.unsupported_link_type_frames.values()),
            "truncated_records": parse.truncated_records,
            "oversized_records": parse.oversized_records,
            "snaplen_limited_frames": parse.snaplen_limited_frames,
            "malformed_network_headers": parse.malformed_network_headers,
            "frames_without_timestamp": parse.frames_without_timestamp,
            "frames_out_of_order": parse.frames_out_of_order,
            "frames_with_epoch_zero_timestamp": parse.frames_with_epoch_zero_timestamp,
            "trailing_bytes_unparsed": parse.trailing_bytes_unparsed,
            "stopped_at_packet_limit": parse.stopped_at_packet_limit,
            "read_error": parse.read_error,
        },
        "summary": {
            "packets": traffic.total_packets,
            "ip_packets": traffic.ip_packets,
            "non_ip_packets": traffic.total_packets - traffic.ip_packets,
            "bytes_on_wire": traffic.bytes_on_wire,
            "bytes_captured": traffic.bytes_captured,
            "packets_per_second": (
                round(traffic.packets_per_second, 3)
                if traffic.packets_per_second is not None
                else None
            ),
            "unique_source_addresses": len(traffic.source_counts),
            "unique_destination_addresses": len(traffic.destination_counts),
            "unique_destination_ports": len(traffic.destination_port_counts),
            "ip_fragments": traffic.ip_fragments,
            "icmp_unreachable_messages": traffic.icmp_unreachable,
        },
        "protocols": _protocol_section(result),
        "top_talkers": _talkers_section(result, top),
        "tcp": _tcp_section(result, top),
        "dns": _dns_section(result, top),
        "findings_summary": {
            "total_detected": len(detection.findings),
            "reported": len(reported),
            "below_threshold": len(detection.findings) - len(reported),
            "by_severity": {s.value: by_severity.get(s.value, 0) for s in reversed(Severity)},
        },
        "findings": [
            _finding_to_dict(finding, number) for number, finding in enumerate(reported, start=1)
        ],
        "suppressed_candidates": [
            {"rule_id": s.rule_id, "subject": s.subject, "reason": s.reason}
            for s in detection.suppressed
        ],
        "detection_notes": list(detection.notes),
        "warnings": list(result.warnings),
        "limitations": list(result.limitations),
    }


def _ranked(counter: Counter[Any], limit: int | None = None) -> list[tuple[Any, int]]:
    """Sort by count (descending) then key, so output order is deterministic."""
    items = sorted(counter.items(), key=lambda item: (-item[1], str(item[0])))
    return items[:limit] if limit is not None else items


def _capture_section(result: AnalysisResult) -> dict[str, Any]:
    capture, traffic, parse = result.capture, result.traffic, result.parse
    return {
        "file_name": capture.file_name,
        "file_size_bytes": capture.file_size,
        "sha256": capture.sha256,
        "format": capture.file_format,
        "gzip_compressed": capture.compressed,
        "timestamp_precision": capture.timestamp_precision,
        "link_types": [
            {"link_type": link, "name": link_type_name(link), "frames": count}
            for link, count in _ranked(parse.link_types)
        ],
        "first_packet_time": format_timestamp(traffic.first_timestamp),
        "last_packet_time": format_timestamp(traffic.last_timestamp),
        "first_packet_epoch": traffic.first_timestamp,
        "last_packet_epoch": traffic.last_timestamp,
        "duration_seconds": (
            round(traffic.duration_seconds, 6) if traffic.duration_seconds is not None else None
        ),
    }


def _protocol_section(result: AnalysisResult) -> dict[str, Any]:
    traffic = result.traffic

    def rows(counter: Counter[str], whole: int) -> list[dict[str, Any]]:
        return [
            {"protocol": name, "packets": count, "share": safe_ratio(count, whole)}
            for name, count in _ranked(counter)
        ]

    return {
        "network": rows(traffic.network_counts, traffic.total_packets),
        "transport": rows(traffic.transport_counts, traffic.ip_packets),
        "application": [
            {
                "protocol": name,
                "packets": count,
                "share": safe_ratio(count, traffic.ip_packets),
                "basis": _APPLICATION_BASIS.get(name, "content"),
            }
            for name, count in _ranked(traffic.application_counts)
        ],
        "note": (
            "Network and transport protocols come from decoded headers. Application protocols "
            "are listed only when identified from content; port-based guesses appear as hints "
            "in top_talkers.destination_ports."
        ),
    }


def _talkers_section(result: AnalysisResult, top: int) -> dict[str, Any]:
    traffic = result.traffic
    return {
        "sources": [
            {"address": address, "packets": count}
            for address, count in _ranked(traffic.source_counts, top)
        ],
        "destinations": [
            {"address": address, "packets": count}
            for address, count in _ranked(traffic.destination_counts, top)
        ],
        "destination_ports": [
            {
                "transport": transport,
                "port": port,
                "packets": count,
                "flows_initiated": traffic.flows_initiated_by_port.get((transport, port), 0),
                "common_service_hint": service_hint(transport, port),
            }
            for (transport, port), count in _ranked(traffic.destination_port_counts, top)
        ],
    }


def _tcp_section(result: AnalysisResult, top: int) -> dict[str, Any]:
    tcp = result.tcp
    return {
        "packets": tcp.packets,
        "flags": {
            name: tcp.flag_counts.get(name, 0)
            for name in ("SYN", "ACK", "FIN", "RST", "PSH", "URG", "ECE", "CWR")
        },
        "syn_without_ack": tcp.syn_only,
        "syn_ack": tcp.syn_ack,
        "rst": tcp.rst,
        "fin": tcp.fin,
        "connection_attempts": {
            "total": tcp.connection_attempts,
            "accepted_syn_ack_observed": tcp.accepted,
            "refused_rst_observed": tcp.refused,
            "no_reply_observed": tcp.no_reply_observed,
            "retransmitted_syns": tcp.retransmitted_syns,
            "unmatched_syn_acks": tcp.unmatched_syn_acks,
            "resets_after_accept": tcp.resets_after_accept,
        },
        "top_rst_sources": [
            {"address": address, "rst_packets": count}
            for address, count in _ranked(tcp.rst_sources, top)
        ],
    }


def _dns_section(result: AnalysisResult, top: int) -> dict[str, Any]:
    dns = result.dns
    return {
        "messages": dns.messages,
        "queries": dns.queries,
        "responses": dns.responses,
        "over_tcp": dns.over_tcp,
        "responses_with_answers": dns.responses_with_answers,
        "undecodable_port_53_packets": dns.malformed,
        "mdns_messages": dns.mdns_messages,
        "unique_query_names": len(dns.query_names),
        "query_types": [
            {"type": dns_type_name(code), "count": count}
            for code, count in _ranked(dns.query_types)
        ],
        "response_codes": [
            {"rcode": dns_rcode_name(code), "count": count}
            for code, count in _ranked(dns.response_codes)
        ],
        "top_query_names": [
            {"name": name, "count": count} for name, count in _ranked(dns.query_names, top)
        ],
    }


def _finding_to_dict(finding: Finding, number: int) -> dict[str, Any]:
    return {
        "id": f"F-{number:03d}",
        "rule_id": finding.rule_id,
        "title": finding.title,
        "severity": finding.severity.value,
        "confidence": finding.confidence.value,
        "summary": finding.summary,
        "evidence": finding.evidence,
        "recommendation": finding.recommendation,
        "limitations": finding.limitations,
        "subject": finding.subject,
        "first_seen": format_timestamp(finding.first_seen),
        "last_seen": format_timestamp(finding.last_seen),
    }


def render_json(report: dict[str, Any]) -> str:
    """Serialise the report. ``allow_nan=False`` guarantees strictly valid JSON."""
    return json.dumps(report, indent=2, ensure_ascii=True, allow_nan=False) + "\n"


# ---------------------------------------------------------------------------
# Human-readable report
# ---------------------------------------------------------------------------


_ISO_TIMESTAMP = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)\.(\d{6})Z$")


def compact_timestamp(value: str) -> str:
    """Shorten an ISO timestamp for display: drop trailing zeros of the fraction.

    ``2025-01-01T10:00:40.000000Z`` -> ``2025-01-01T10:00:40Z``. JSON output keeps
    the full microsecond form; this only affects the human-readable report.
    """
    match = _ISO_TIMESTAMP.match(value)
    if not match:
        return value
    fraction = match.group(2).rstrip("0")
    return f"{match.group(1)}.{fraction}Z" if fraction else f"{match.group(1)}Z"


def _text(value: Any, style: str = "", limit: int | None = _DISPLAY_VALUE_LIMIT) -> Text:
    """Wrap a dynamic value so Rich shows it literally (no markup, no control chars)."""
    if value is None:
        return Text("-", style="dim")
    if isinstance(value, bool):
        value = "yes" if value else "no"
    elif isinstance(value, int):
        value = f"{value:,}"
    elif isinstance(value, str):
        value = compact_timestamp(value)
    elif isinstance(value, float):
        if value.is_integer():
            value = f"{int(value):,}"
        else:
            value = f"{value:.4g}" if abs(value) < 1000 else f"{value:,.1f}"
    return Text(sanitize_text(value, max_length=limit), style=style)


def _section(console: Console, title: str) -> None:
    console.print()
    console.rule(Text(title, style="bold"), align="left", style="dim")


def _share(value: float | None) -> Text:
    return Text("-" if value is None else f"{value * 100:.1f}%")


def render_terminal(console: Console, report: dict[str, Any], *, verbose: bool = False) -> None:
    """Print the report with restrained Rich styling.

    Severity is always written as a word ("MEDIUM"), so the report stays
    readable without colour (for example when saved to a file or with NO_COLOR).
    """
    capture, summary = report["capture"], report["summary"]
    console.print(
        Panel(
            Text.assemble(
                (f"{report['tool']['name']} {report['tool']['version']}", "bold"),
                "  offline network traffic analysis\n",
                ("Findings are leads for investigation, not proof of compromise.", "dim"),
            ),
            box=box.ROUNDED,
            expand=False,
        )
    )

    _section(console, "Capture")
    overview = Table.grid(padding=(0, 2))
    overview.add_column(style="bold")
    overview.add_column()
    link_types = ", ".join(f"{lt['name']} ({lt['frames']:,})" for lt in capture["link_types"])
    file_format = capture["format"].upper() + (" (gzip)" if capture["gzip_compressed"] else "")
    rows: list[tuple[str, Any]] = [
        ("File", capture["file_name"]),
        ("Size", format_bytes(capture["file_size_bytes"])),
        ("SHA-256", capture["sha256"]),
        ("Format", file_format),
        ("Link types", link_types or None),
        ("First packet", capture["first_packet_time"]),
        ("Last packet", capture["last_packet_time"]),
        ("Duration", format_duration(capture["duration_seconds"])),
        ("Packets", f"{summary['packets']:,} ({summary['ip_packets']:,} IP)"),
        ("Data on wire", format_bytes(summary["bytes_on_wire"])),
        (
            "Packet rate",
            f"{summary['packets_per_second']:,.1f} packets/s"
            if summary["packets_per_second"] is not None
            else "not reported (duration unknown or under 1 s)",
        ),
        (
            "Unique",
            f"{summary['unique_source_addresses']:,} sources, "
            f"{summary['unique_destination_addresses']:,} destinations, "
            f"{summary['unique_destination_ports']:,} destination ports",
        ),
    ]
    for label, value in rows:
        overview.add_row(label, _text(value, limit=None))
    console.print(overview)
    _render_processing(console, report["processing"])

    _render_protocols(console, report["protocols"])
    _render_talkers(console, report["top_talkers"])
    _render_tcp(console, report["tcp"])
    if report["dns"]["messages"] or report["dns"]["undecodable_port_53_packets"]:
        _render_dns(console, report["dns"])
    _render_findings(console, report, verbose=verbose)

    if report["warnings"]:
        _section(console, "Capture warnings")
        for warning in report["warnings"]:
            console.print(Text("! ", style="yellow"), _text(warning, limit=None), sep="")
    _section(console, "Analysis limitations")
    for limitation in report["limitations"]:
        console.print(Text("- "), _text(limitation, limit=None), sep="")
    console.print()


def _render_processing(console: Console, processing: dict[str, Any]) -> None:
    problems = {
        "decode failures": processing["decode_failures"],
        "unsupported link type": processing["unsupported_link_type_frames"],
        "truncated records": processing["truncated_records"],
        "malformed IP headers": processing["malformed_network_headers"],
        "without timestamp": processing["frames_without_timestamp"],
        "out of order": processing["frames_out_of_order"],
        "snaplen-limited": processing["snaplen_limited_frames"],
    }
    details = ", ".join(f"{count:,} {name}" for name, count in problems.items() if count)
    line = Text.assemble(
        ("Processing  ", "bold"),
        f"{processing['frames_read']:,} frames read, {processing['frames_decoded']:,} decoded",
    )
    if details:
        line.append(f" ({details})", style="yellow")
    if processing["stopped_at_packet_limit"]:
        line.append(" - stopped at the packet limit", style="yellow")
    console.print(line)


def _render_protocols(console: Console, protocols: dict[str, Any]) -> None:
    _section(console, "Protocol distribution")
    table = Table(box=box.SIMPLE, show_edge=False, pad_edge=False)
    table.add_column("Layer")
    table.add_column("Protocol")
    table.add_column("Packets", justify="right")
    table.add_column("Share", justify="right")
    table.add_column("Identified by", style="dim")
    for layer, key, basis in (
        ("Network", "network", "decoded header"),
        ("Transport", "transport", "decoded header"),
    ):
        for row in protocols[key]:
            table.add_row(
                layer, _text(row["protocol"]), _text(row["packets"]), _share(row["share"]), basis
            )
    for row in protocols["application"]:
        table.add_row(
            "Application",
            _text(row["protocol"]),
            _text(row["packets"]),
            _share(row["share"]),
            _text(row["basis"]),
        )
    if table.row_count:
        console.print(table)
        console.print(
            Text(
                "Shares: network layer of all packets; transport and application of IP packets.",
                style="dim",
            )
        )
    else:
        console.print(Text("No packets.", style="dim"))


def _render_talkers(console: Console, talkers: dict[str, Any]) -> None:
    _section(console, "Top talkers")
    if not talkers["sources"]:
        console.print(Text("No IP traffic.", style="dim"))
        return
    for title, key in (("Source address", "sources"), ("Destination address", "destinations")):
        table = Table(box=box.SIMPLE, show_edge=False, pad_edge=False)
        table.add_column(title)
        table.add_column("Packets", justify="right")
        for row in talkers[key]:
            table.add_row(_text(row["address"]), _text(row["packets"]))
        console.print(table)

    table = Table(box=box.SIMPLE, show_edge=False, pad_edge=False)
    table.add_column("Destination port")
    table.add_column("Packets", justify="right")
    table.add_column("Flows started", justify="right")
    table.add_column("Commonly used for (hint only)", style="dim")
    for row in talkers["destination_ports"]:
        table.add_row(
            _text(f"{row['transport']}/{row['port']}"),
            _text(row["packets"]),
            _text(row["flows_initiated"]),
            _text(row["common_service_hint"] or ""),
        )
    if table.row_count:
        console.print(table)
        console.print(
            Text(
                "'Flows started' of 0 usually means the port is a client's temporary port "
                "receiving replies.",
                style="dim",
            )
        )


def _render_tcp(console: Console, tcp: dict[str, Any]) -> None:
    if not tcp["packets"]:
        return
    _section(console, "TCP")
    attempts = tcp["connection_attempts"]
    flags = ", ".join(f"{name} {count:,}" for name, count in tcp["flags"].items() if count)
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold")
    grid.add_column()
    grid.add_row("Packets", _text(tcp["packets"]))
    grid.add_row("Flags seen", _text(flags or "none"))
    grid.add_row(
        "Connection attempts",
        _text(
            f"{attempts['total']:,} (accepted {attempts['accepted_syn_ack_observed']:,}, "
            f"refused {attempts['refused_rst_observed']:,}, no reply observed "
            f"{attempts['no_reply_observed']:,}); {attempts['retransmitted_syns']:,} "
            "retransmitted SYNs not counted as new attempts",
            limit=None,
        ),
    )
    if attempts["unmatched_syn_acks"]:
        grid.add_row("Unmatched SYN-ACKs", _text(attempts["unmatched_syn_acks"]))
    console.print(grid)


def _render_dns(console: Console, dns: dict[str, Any]) -> None:
    _section(console, "DNS")
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold")
    grid.add_column()
    grid.add_row(
        "Messages",
        _text(
            f"{dns['messages']:,} total: queries {dns['queries']:,}, responses "
            f"{dns['responses']:,}, over TCP {dns['over_tcp']:,}, unique names "
            f"{dns['unique_query_names']:,}",
            limit=None,
        ),
    )
    if dns["query_types"]:
        grid.add_row(
            "Query types",
            _text(", ".join(f"{r['type']} {r['count']:,}" for r in dns["query_types"][:8])),
        )
    if dns["response_codes"]:
        grid.add_row(
            "Response codes",
            _text(", ".join(f"{r['rcode']} {r['count']:,}" for r in dns["response_codes"])),
        )
    if dns["undecodable_port_53_packets"]:
        grid.add_row(
            "Undecodable", _text(f"{dns['undecodable_port_53_packets']:,} port-53 packets")
        )
    console.print(grid)
    if dns["top_query_names"]:
        table = Table(box=box.SIMPLE, show_edge=False, pad_edge=False)
        table.add_column("Queried name (escaped)")
        table.add_column("Queries", justify="right")
        for row in dns["top_query_names"]:
            table.add_row(_text(row["name"], limit=80), _text(row["count"]))
        console.print(table)


def _render_findings(console: Console, report: dict[str, Any], *, verbose: bool) -> None:
    summary = report["findings_summary"]
    _section(console, "Findings")
    counts = Text()
    for severity, count in summary["by_severity"].items():
        counts.append(f"{severity} {count}", style=SEVERITY_STYLES[severity] if count else "dim")
        counts.append("   ")
    console.print(counts)
    if summary["below_threshold"]:
        console.print(
            Text(
                f"{summary['below_threshold']} finding(s) below the "
                f"{report['analysis']['severity_threshold']} threshold are not shown.",
                style="dim",
            )
        )
    if not report["findings"]:
        console.print(
            Text(
                "No findings at or above the threshold. This means no rule matched; it does not "
                "mean the traffic is safe.",
                style="green",
            )
        )
    for finding in report["findings"]:
        console.print(_finding_panel(finding, verbose=verbose))

    if report["suppressed_candidates"]:
        _section(console, "Suppressed candidates (met a threshold, judged likely benign)")
        for item in report["suppressed_candidates"]:
            subject = ", ".join(f"{k}={v}" for k, v in item["subject"].items())
            console.print(
                Text.assemble((item["rule_id"], "bold"), "  "),
                _text(subject),
                Text(": "),
                _text(item["reason"], limit=None),
                sep="",
            )
    for note in report["detection_notes"]:
        console.print(Text(note, style="dim"))


def _finding_panel(finding: dict[str, Any], *, verbose: bool) -> Panel:
    severity = finding["severity"]
    style = SEVERITY_STYLES[severity]
    title = Text.assemble(
        (f"[{severity}]", style), " ", (finding["id"], "bold"), "  ", _text(finding["title"])
    )
    header = Table.grid(padding=(0, 2))
    header.add_column(style="dim", no_wrap=True)
    header.add_column()
    header.add_row("Rule", Text(finding["rule_id"]))
    header.add_row("Confidence", Text(finding["confidence"]))
    header.add_row("Seen", _span(finding["first_seen"], finding["last_seen"]))
    parts: list[Any] = [
        header,
        Text(""),
        _text(finding["summary"], limit=None),
        Text(""),
        Text("Evidence", style="bold"),
        _evidence_table(finding["evidence"], verbose=verbose),
        Text(""),
        Text.assemble(("Next step: ", "bold"), _text(finding["recommendation"], limit=None)),
        Text.assemble(
            ("Limitations: ", "bold dim"),
            _text(finding["limitations"], style="dim", limit=None),
        ),
    ]
    return Panel(
        Group(*parts),
        title=title,
        title_align="left",
        border_style=style,
        box=box.ROUNDED,
        padding=(0, 1),
    )


def _span(first: str | None, last: str | None) -> Text:
    if first is None:
        return Text("unknown")
    if last is None or last == first:
        return _text(first)
    return _text(f"{compact_timestamp(first)} to {compact_timestamp(last)}", limit=None)


def _humanise(key: str) -> str:
    return key.replace("_", " ")


def _evidence_scalar(key: str, value: Any) -> Text:
    # Ports are identifiers, not quantities: never print them as "4,444".
    if isinstance(value, int) and not isinstance(value, bool) and key.endswith("port"):
        return Text(str(value))
    return _text(value)


def _evidence_list(values: list[Any], verbose: bool) -> Text:
    if not values:
        return Text("none", style="dim")
    items = [sanitize_text(v) for v in values]
    limit = None if verbose else 12
    shown = items if limit is None else items[:limit]
    long_items = any(len(item) > 30 for item in shown)
    if long_items:  # one long value (e.g. a DNS name) per line
        shown = shown if verbose else shown[:5]
        text = Text("\n".join(truncate(item, None if verbose else 90) for item in shown))
    else:
        text = Text(", ".join(shown))
    if len(shown) < len(items):
        text.append(f"\n... {len(items) - len(shown)} more (use --verbose)", style="dim")
    return text


def _evidence_table(evidence: dict[str, Any], *, verbose: bool) -> Table:
    """Lay evidence out as an aligned key/value grid.

    Nested records (for example each scanned host) are listed underneath their
    heading with indented labels, so values keep the full width of the value
    column even on an 80-column terminal.
    """
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="dim", no_wrap=True)
    grid.add_column(overflow="fold")
    for key, value in evidence.items():
        label = _humanise(key)
        if isinstance(value, list) and value and isinstance(value[0], dict):
            grid.add_row(label, Text(""))
            shown = value if verbose else value[:5]
            for number, record in enumerate(shown):
                if number:
                    grid.add_row("", Text(""))
                for position, (sub_key, sub_value) in enumerate(record.items()):
                    prefix = "  - " if position == 0 else "    "
                    rendered = (
                        _evidence_list(sub_value, verbose)
                        if isinstance(sub_value, list)
                        else _evidence_scalar(sub_key, sub_value)
                    )
                    grid.add_row(prefix + _humanise(sub_key), rendered)
            if len(value) > len(shown):
                grid.add_row(
                    "", Text(f"... {len(value) - len(shown)} more (use --verbose)", style="dim")
                )
        elif isinstance(value, list):
            grid.add_row(label, _evidence_list(value, verbose))
        else:
            grid.add_row(label, _evidence_scalar(key, value))
    return grid


def render_text(report: dict[str, Any], *, width: int = 100, verbose: bool = False) -> str:
    """Render the human-readable report as plain text (no ANSI codes) for saving."""
    buffer = io.StringIO()
    console = Console(
        file=buffer,
        width=width,
        force_terminal=False,
        color_system=None,
        highlight=False,
        emoji=False,
        soft_wrap=False,
    )
    render_terminal(console, report, verbose=verbose)
    return buffer.getvalue()
