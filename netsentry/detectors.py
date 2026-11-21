"""Detection rules.

Every rule is a plain function that takes the analyser's :class:`TrafficIndex`
plus its settings and returns the findings it produced. Rules never look at
payloads, and each one documents *what it observed*: they report patterns
worth investigating, never verdicts.

Three ideas keep false positives down:

1. **Thresholds over time windows**: a pattern must occur within a bounded
   time window, not just anywhere in a long capture.
2. **Evidence-based suppression**: when the capture shows the activity was
   probably benign (for example most "probed" ports actually accepted the
   connection), the candidate is suppressed and listed as such, not reported.
3. **No double counting**: when a specific rule already explains a pattern
   (a port scan explains many refused connections), more general rules skip
   that activity instead of raising a second alert for it.
"""

from __future__ import annotations

import ipaddress
import statistics
from collections import Counter, defaultdict
from collections.abc import Hashable, Iterable, Sequence
from dataclasses import dataclass, field
from functools import lru_cache
from math import ceil
from typing import Any

from .config import (
    DetectionConfig,
    DnsSettings,
    FailedConnectionSettings,
    HighVolumeSettings,
    HostSweepSettings,
    PortScanSettings,
    RepeatedConnectionSettings,
    UnusualPortSettings,
)
from .models import (
    AnalysisResult,
    Confidence,
    Contact,
    DetectionReport,
    DnsQueryEvent,
    DnsResponseEvent,
    Finding,
    Outcome,
    Severity,
    SuppressedCandidate,
    TrafficIndex,
)
from .protocols import dns_rcode_name, dns_type_name
from .utils import format_timestamp

PORT_SCAN = "NS-SCAN-001"
HOST_SWEEP = "NS-SCAN-002"
REPEATED_CONNECTIONS = "NS-CONN-001"
FAILED_CONNECTIONS = "NS-CONN-002"
UNUSUAL_PORT = "NS-PORT-001"
HIGH_VOLUME = "NS-VOL-001"
DNS_QUERY_RATE = "NS-DNS-001"
DNS_LONG_NAMES = "NS-DNS-002"
DNS_FAILURES = "NS-DNS-003"
DNS_REPEATED_UNUSUAL = "NS-DNS-004"
CLEARTEXT = "NS-CLEAR-001"

MAX_LISTED = 10  # cap on example lists inside a finding's evidence
MAX_PORTS_LISTED = 25

# Classic UDP traceroute sends each probe to the next port up from 33434, so a
# single trace looks like a scan of ~90 ports on one host. Firewalls
# conventionally allow 33434-33534 for traceroute.
TRACEROUTE_PORTS = range(33434, 33535)
TRACEROUTE_SHARE = 0.8  # this share of probed ports in that range -> traceroute


def _is_traceroute_probe(transport: str, port: int | None) -> bool:
    return transport == "UDP" and port in TRACEROUTE_PORTS


@dataclass(frozen=True)
class RuleInfo:
    rule_id: str
    name: str
    description: str
    limitations: str


RULES: dict[str, RuleInfo] = {
    rule.rule_id: rule
    for rule in (
        RuleInfo(
            PORT_SCAN,
            "Potential port scan",
            "One source contacts many distinct ports on the same destination within a time window.",
            "Vulnerability scanners, monitoring systems, service discovery and some applications "
            "(for example FTP passive mode) contact many ports legitimately. A scan is "
            "reconnaissance, not evidence that any system was compromised.",
        ),
        RuleInfo(
            HOST_SWEEP,
            "Potential host sweep",
            "One source contacts the same port (or sends ICMP echo requests) to many distinct "
            "destinations within a time window.",
            "Network inventory tools, monitoring, load balancers, peer-to-peer software and busy "
            "clients behind captures without reply traffic can produce the same pattern.",
        ),
        RuleInfo(
            REPEATED_CONNECTIONS,
            "Repeated connection attempts",
            "Many separate TCP connection attempts (SYN packets, retransmissions excluded) from "
            "one source to the same destination port within a time window.",
            "Retrying clients, health checks, connection-pooling software and short-lived HTTP "
            "connections repeat connections normally. Without application logs the capture "
            "cannot show whether any authentication attempt was made or succeeded.",
        ),
        RuleInfo(
            FAILED_CONNECTIONS,
            "Excessive refused connections",
            "A source whose connection attempts are mostly refused with TCP resets.",
            "Refusals are often caused by a stopped service, a misconfigured client or a "
            "firewall that sends resets. Only observed RST replies count as refusals; attempts "
            "with no reply are reported separately because their outcome is unknown.",
        ),
        RuleInfo(
            UNUSUAL_PORT,
            "Traffic to a port that merits review",
            "Connections to ports on a configurable watch list, or to inward-facing services "
            "(SMB, RDP, ...) on public internet addresses.",
            "This rule is based on port numbers only. Port numbers do not prove which "
            "application is in use, and every listed port also has legitimate uses.",
        ),
        RuleInfo(
            HIGH_VOLUME,
            "High traffic volume from one source",
            "A source that sends a very large number of packets within a short window, or that "
            "accounts for most of the capture's packets.",
            "High volume is normal for backups, downloads, streaming and file servers. Packet "
            "counts are not a bandwidth measurement, and volume alone is not evidence of a "
            "denial-of-service attack.",
        ),
        RuleInfo(
            DNS_QUERY_RATE,
            "High DNS query rate",
            "One client sends an unusually high number of DNS queries within a time window.",
            "DNS resolvers, mail servers, browsers that prefetch names and security tools all "
            "generate many queries. A high rate alone does not indicate tunnelling or malware.",
        ),
        RuleInfo(
            DNS_LONG_NAMES,
            "Unusually long DNS query names",
            "Queries for names, or labels within names, that are longer than configured limits.",
            "Content delivery networks, cloud services, anti-spam lookups and telemetry use long "
            "machine-generated names. Long names are a weak indicator of DNS tunnelling on their "
            "own.",
        ),
        RuleInfo(
            DNS_FAILURES,
            "High proportion of failed DNS lookups",
            "A client for which most observed DNS responses report an error (such as NXDOMAIN "
            "or SERVFAIL).",
            "Typing errors, stale configuration, search-domain suffixes, ad blockers and broken "
            "resolvers cause failed lookups. Responses missing from the capture cannot be counted.",
        ),
        RuleInfo(
            DNS_REPEATED_UNUSUAL,
            "Repeated queries for an unusual domain",
            "The same client repeatedly queries one name that is unusually long or that always "
            "fails to resolve.",
            "Misconfigured software often retries a name that no longer exists. Repetition is "
            "consistent with automated behaviour, which may or may not be malicious.",
        ),
        RuleInfo(
            CLEARTEXT,
            "Cleartext application protocol",
            "TCP traffic recognised by its content as HTTP, FTP control or Telnet, which are not "
            "encrypted.",
            "NetSentry recognises the protocol from the first bytes of a segment and does not "
            "inspect or store the content, so it makes no claim that credentials or sensitive "
            "data were sent. Encrypted variants (HTTPS, FTPS, SSH) are not visible to this rule.",
        ),
    )
}


def validate_rule_ids(rule_ids: Iterable[str]) -> list[str]:
    """Return the identifiers in ``rule_ids`` that are not known rules."""
    return sorted({rule_id for rule_id in rule_ids if rule_id not in RULES})


@dataclass
class RuleOutput:
    findings: list[Finding] = field(default_factory=list)
    suppressed: list[SuppressedCandidate] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


def run_detections(
    result: AnalysisResult, config: DetectionConfig | None = None
) -> DetectionReport:
    """Run every enabled rule in a fixed order and merge their output.

    The order matters only for de-duplication: specific rules run first so
    that general rules can skip activity those rules already explain.
    """
    config = config or DetectionConfig()
    index = result.index
    report = DetectionReport()

    def collect(output: RuleOutput) -> list[Finding]:
        report.findings.extend(output.findings)
        report.suppressed.extend(output.suppressed)
        return output.findings

    scanning_sources: set[str] = set()
    if config.is_enabled(PORT_SCAN):
        found = collect(detect_port_scans(index, config.port_scan))
        scanning_sources |= {finding.subject["source"] for finding in found}
    if config.is_enabled(HOST_SWEEP):
        found = collect(detect_host_sweeps(index, config.host_sweep))
        scanning_sources |= {finding.subject["source"] for finding in found}

    repeated_endpoints: set[tuple[str, str, int]] = set()
    if config.is_enabled(REPEATED_CONNECTIONS):
        found = collect(detect_repeated_connections(index, config.repeated_connections))
        repeated_endpoints = {
            (f.subject["source"], f.subject["destination"], f.subject["port"]) for f in found
        }
    if config.is_enabled(FAILED_CONNECTIONS):
        collect(
            detect_failed_connections(
                index,
                config.failed_connections,
                exclude_sources=scanning_sources,
                exclude_endpoints=repeated_endpoints,
            )
        )
    if config.is_enabled(UNUSUAL_PORT):
        collect(detect_unusual_ports(index, config.unusual_ports, exclude_sources=scanning_sources))
    if config.is_enabled(HIGH_VOLUME):
        collect(detect_high_volume(index, config.high_volume))

    flagged_names: set[tuple[str, str]] = set()
    if config.is_enabled(DNS_REPEATED_UNUSUAL):
        found = collect(detect_repeated_unusual_dns(index, config.dns))
        flagged_names = {(f.subject["source"], f.subject["name"]) for f in found}
    if config.is_enabled(DNS_QUERY_RATE):
        collect(detect_dns_query_rate(index, config.dns))
    if config.is_enabled(DNS_LONG_NAMES):
        collect(detect_long_dns_names(index, config.dns, exclude_names=flagged_names))
    if config.is_enabled(DNS_FAILURES):
        collect(detect_dns_failures(index, config.dns, exclude_names=flagged_names))
    if config.is_enabled(CLEARTEXT):
        collect(detect_cleartext_protocols(index))

    report.findings.sort(key=lambda finding: finding.sort_key)
    if result.parse.frames_without_timestamp:
        report.notes.append(
            f"{result.parse.frames_without_timestamp} frame(s) without timestamps were excluded "
            "from time-window rules."
        )
    disabled = sorted(set(config.disabled_rules) & set(RULES))
    if disabled:
        report.notes.append(f"Disabled by configuration: {', '.join(disabled)}.")
    return report


# ---------------------------------------------------------------------------
# Sliding-window helpers
# ---------------------------------------------------------------------------


def best_window_distinct(
    events: Sequence[tuple[float, Hashable]], window_seconds: float
) -> tuple[int, int, int]:
    """Find the time window containing the most *distinct* keys.

    ``events`` must be sorted by timestamp. Returns ``(distinct, start, end)``
    where ``start``/``end`` are inclusive indexes into ``events``. Two events
    are in the same window when their timestamps differ by at most
    ``window_seconds``.
    """
    counts: Counter[Hashable] = Counter()
    best = (0, 0, -1)
    left = 0
    for right, (timestamp, key) in enumerate(events):
        counts[key] += 1
        while timestamp - events[left][0] > window_seconds:
            old_key = events[left][1]
            counts[old_key] -= 1
            if counts[old_key] == 0:
                del counts[old_key]
            left += 1
        if len(counts) > best[0]:
            best = (len(counts), left, right)
    return best


def best_window_count(timestamps: Sequence[float], window_seconds: float) -> tuple[int, int, int]:
    """Find the time window containing the most events. ``timestamps`` must be sorted."""
    best = (0, 0, -1)
    left = 0
    for right, timestamp in enumerate(timestamps):
        while timestamp - timestamps[left] > window_seconds:
            left += 1
        if right - left + 1 > best[0]:
            best = (right - left + 1, left, right)
    return best


def _iso(timestamp: float | None) -> str | None:
    return format_timestamp(timestamp)


def _percent(ratio: float) -> str:
    return f"{ratio * 100:.0f}%"


def _port_label(transport: str, port: int | None) -> str:
    return f"{transport} echo" if port is None else f"{transport}/{port}"


def _seconds(value: float) -> str:
    return f"{value:g} s"


@lru_cache(maxsize=65_536)
def _is_public(address: str) -> bool:
    try:
        return ipaddress.ip_address(address).is_global
    except ValueError:
        return False


def _timed(contacts: Iterable[Contact]) -> list[Contact]:
    timed = [contact for contact in contacts if contact.timestamp is not None]
    timed.sort(key=lambda contact: contact.timestamp or 0.0)
    return timed


# ---------------------------------------------------------------------------
# Rule A: port scans (NS-SCAN-001) and host sweeps (NS-SCAN-002)
# ---------------------------------------------------------------------------


@dataclass
class _ScanTarget:
    target: str  # destination address (vertical) or service label (horizontal)
    distinct: int
    window_start: float | None
    window_end: float | None
    items: list[str]
    positive: int
    negative: int
    no_reply: int
    reply_visible: bool

    @property
    def success_ratio(self) -> float:
        return self.positive / self.distinct if self.distinct else 0.0


def _scan_confidence(target: _ScanTarget, threshold: int) -> Confidence:
    if not target.reply_visible:
        return Confidence.LOW  # cannot tell whether the probes were answered
    if target.success_ratio <= 0.2 and target.distinct >= 2 * threshold:
        return Confidence.HIGH  # many probes, almost all closed or unanswered
    return Confidence.MEDIUM


def _summarise_window(
    window: Sequence[Contact], key_of: Any, index: TrafficIndex, source: str
) -> tuple[set[Any], int, int, int, bool]:
    keys = {key_of(contact) for contact in window}
    positive = {key_of(c) for c in window if c.accepted}
    answered = {key_of(c) for c in window if c.answered}
    negative = answered - positive
    no_reply = keys - answered
    reply_visible = bool(answered) or any(
        index.reply_traffic_seen(source, contact.destination) for contact in window
    )
    return keys, len(positive), len(negative), len(no_reply), reply_visible


def detect_port_scans(index: TrafficIndex, settings: PortScanSettings) -> RuleOutput:
    """NS-SCAN-001: many distinct destination ports on one host from one source.

    For every (source, destination) pair, slide a time window over the
    source's flow-initiation events and find the window with the most distinct
    (transport, port) values. Reaching ``min_distinct_ports`` makes the pair a
    candidate. If reply traffic is visible and most probed ports answered
    positively, the pair looks like a client using real services and is
    suppressed.
    """
    output = RuleOutput()
    threshold = settings.min_distinct_ports
    groups: dict[tuple[str, str], list[Contact]] = defaultdict(list)
    for contact in index.contacts:
        if contact.port is not None and contact.timestamp is not None:
            groups[(contact.source, contact.destination)].append(contact)

    targets_by_source: dict[str, list[_ScanTarget]] = defaultdict(list)
    for (source, destination), contacts in sorted(groups.items()):
        if len({(c.transport, c.port) for c in contacts}) < threshold:
            continue
        contacts = _timed(contacts)
        events = [(c.timestamp or 0.0, (c.transport, c.port)) for c in contacts]
        distinct, start, end = best_window_distinct(events, settings.window_seconds)
        if distinct < threshold:
            continue
        window = contacts[start : end + 1]
        keys, positive, negative, no_reply, visible = _summarise_window(
            window, lambda c: (c.transport, c.port), index, source
        )
        target = _ScanTarget(
            target=destination,
            distinct=distinct,
            window_start=window[0].timestamp,
            window_end=window[-1].timestamp,
            items=[_port_label(t, p) for t, p in sorted(keys, key=lambda k: (k[1], k[0]))],
            positive=positive,
            negative=negative,
            no_reply=no_reply,
            reply_visible=visible,
        )
        subject = {"source": source, "destination": destination}
        traceroute_share = sum(1 for key in keys if _is_traceroute_probe(*key)) / distinct
        if traceroute_share >= TRACEROUTE_SHARE:
            output.suppressed.append(
                SuppressedCandidate(
                    PORT_SCAN,
                    subject,
                    f"{distinct} ports were contacted within {_seconds(settings.window_seconds)}, "
                    f"but {_percent(traceroute_share)} were UDP ports "
                    f"{TRACEROUTE_PORTS.start}-{TRACEROUTE_PORTS.stop - 1}: this is consistent "
                    "with the traceroute tool, which probes one new port per hop.",
                )
            )
            continue
        if visible and target.success_ratio > settings.max_success_ratio:
            output.suppressed.append(
                SuppressedCandidate(
                    PORT_SCAN,
                    subject,
                    f"{distinct} ports were contacted within {_seconds(settings.window_seconds)}, "
                    f"but {_percent(target.success_ratio)} of them accepted the connection; this "
                    "is consistent with a client using several real services "
                    f"(max_success_ratio={settings.max_success_ratio:g}).",
                )
            )
            continue
        targets_by_source[source].append(target)

    for source, targets in targets_by_source.items():
        targets.sort(key=lambda t: (-t.distinct, t.target))
        strongest = targets[0]
        if len(targets) == 1:
            where = f"on {strongest.target}"
        else:
            where = f"on {len(targets)} hosts (up to {strongest.distinct} on {strongest.target})"
        output.findings.append(
            Finding(
                rule_id=PORT_SCAN,
                title=f"Potential port scan from {source}",
                severity=Severity.MEDIUM,
                confidence=_scan_confidence(strongest, threshold),
                summary=(
                    f"{source} contacted {strongest.distinct} distinct ports {where} within "
                    f"{_seconds(settings.window_seconds)}. This pattern is consistent with port "
                    "scanning, but authorised scanners and some applications produce it too."
                ),
                evidence={
                    "source": source,
                    "hosts_flagged": len(targets),
                    "max_distinct_ports_in_window": strongest.distinct,
                    "window_seconds": settings.window_seconds,
                    "threshold_distinct_ports": threshold,
                    "targets": [_target_evidence(t, "destination", "ports") for t in targets][
                        :MAX_LISTED
                    ],
                },
                recommendation=(
                    "Identify the system behind the source address and whether it is an "
                    "authorised scanner or monitoring tool. Check which probed ports accepted "
                    "connections and review logs on the destination for follow-up activity."
                ),
                limitations=RULES[PORT_SCAN].limitations,
                subject={"source": source},
                first_seen=min(t.window_start or 0.0 for t in targets),
                last_seen=max(t.window_end or 0.0 for t in targets),
            )
        )
    return output


def detect_host_sweeps(index: TrafficIndex, settings: HostSweepSettings) -> RuleOutput:
    """NS-SCAN-002: the same service probed on many destinations by one source."""
    output = RuleOutput()
    threshold = settings.min_distinct_hosts
    groups: dict[tuple[str, str, int | None], list[Contact]] = defaultdict(list)
    for contact in index.contacts:
        if contact.timestamp is not None:
            groups[(contact.source, contact.transport, contact.port)].append(contact)

    targets_by_source: dict[str, list[_ScanTarget]] = defaultdict(list)
    for (source, transport, port), contacts in sorted(
        groups.items(), key=lambda item: (item[0][0], item[0][1], item[0][2] or -1)
    ):
        if len({c.destination for c in contacts}) < threshold:
            continue
        contacts = _timed(contacts)
        events = [(c.timestamp or 0.0, c.destination) for c in contacts]
        distinct, start, end = best_window_distinct(events, settings.window_seconds)
        if distinct < threshold:
            continue
        window = contacts[start : end + 1]
        hosts, positive, negative, no_reply, visible = _summarise_window(
            window, lambda c: c.destination, index, source
        )
        service = _port_label(transport, port)
        target = _ScanTarget(
            target=service,
            distinct=distinct,
            window_start=window[0].timestamp,
            window_end=window[-1].timestamp,
            items=sorted(hosts, key=_address_sort_key),
            positive=positive,
            negative=negative,
            no_reply=no_reply,
            reply_visible=visible,
        )
        if visible and target.success_ratio > settings.max_success_ratio:
            output.suppressed.append(
                SuppressedCandidate(
                    HOST_SWEEP,
                    {"source": source, "service": service},
                    f"{distinct} hosts were contacted on {service} within "
                    f"{_seconds(settings.window_seconds)}, but {_percent(target.success_ratio)} "
                    "answered positively; this is consistent with normal client activity such "
                    "as browsing or DNS resolution "
                    f"(max_success_ratio={settings.max_success_ratio:g}).",
                )
            )
            continue
        targets_by_source[source].append(target)

    for source, targets in targets_by_source.items():
        targets.sort(key=lambda t: (-t.distinct, t.target))
        strongest = targets[0]
        services = ", ".join(t.target for t in targets[:5])
        output.findings.append(
            Finding(
                rule_id=HOST_SWEEP,
                title=f"Potential host sweep from {source}",
                severity=Severity.MEDIUM,
                confidence=_scan_confidence(strongest, threshold),
                summary=(
                    f"{source} contacted {strongest.distinct} distinct hosts on "
                    f"{strongest.target} within {_seconds(settings.window_seconds)} "
                    f"(services: {services}). This is consistent with a network sweep, but "
                    "inventory and monitoring tools behave the same way."
                ),
                evidence={
                    "source": source,
                    "services_flagged": len(targets),
                    "max_distinct_hosts_in_window": strongest.distinct,
                    "window_seconds": settings.window_seconds,
                    "threshold_distinct_hosts": threshold,
                    "services": [_target_evidence(t, "service", "hosts") for t in targets][
                        :MAX_LISTED
                    ],
                },
                recommendation=(
                    "Confirm whether the source is an authorised inventory or monitoring system. "
                    "If not, identify the process responsible on that host and check whether any "
                    "of the swept hosts accepted connections."
                ),
                limitations=RULES[HOST_SWEEP].limitations,
                subject={"source": source},
                first_seen=min(t.window_start or 0.0 for t in targets),
                last_seen=max(t.window_end or 0.0 for t in targets),
            )
        )
    return output


def _target_evidence(target: _ScanTarget, name_key: str, items_key: str) -> dict[str, Any]:
    return {
        name_key: target.target,
        f"distinct_{items_key}_in_window": target.distinct,
        "window_start": _iso(target.window_start),
        "window_end": _iso(target.window_end),
        f"{items_key}_sample": target.items[:MAX_PORTS_LISTED],
        "answered_positively": target.positive,
        "refused_or_negative": target.negative,
        "no_reply_observed": target.no_reply,
        "reply_traffic_visible": target.reply_visible,
    }


def _address_sort_key(address: str) -> tuple[int, int | str]:
    try:
        parsed = ipaddress.ip_address(address)
        return (parsed.version, int(parsed))
    except ValueError:
        return (9, address)


# ---------------------------------------------------------------------------
# Rule B: repeated connection attempts (NS-CONN-001)
# ---------------------------------------------------------------------------


def detect_repeated_connections(
    index: TrafficIndex, settings: RepeatedConnectionSettings
) -> RuleOutput:
    """NS-CONN-001: many distinct SYN attempts to one destination port.

    Attempts are distinct (source port, initial sequence number) pairs, so a
    single connection whose SYN is retransmitted six times counts once.
    """
    output = RuleOutput()
    groups: dict[tuple[str, str, int], list[Any]] = defaultdict(list)
    for attempt in index.connection_attempts:
        if attempt.first_seen is not None:
            groups[(attempt.client, attempt.server, attempt.server_port)].append(attempt)

    for (client, server, port), attempts in sorted(groups.items()):
        if len(attempts) < settings.min_attempts:
            continue
        attempts.sort(key=lambda a: a.first_seen)
        count, start, end = best_window_count(
            [a.first_seen for a in attempts], settings.window_seconds
        )
        if count < settings.min_attempts:
            continue
        window = attempts[start : end + 1]
        outcomes = Counter(attempt.outcome for attempt in window)
        accepted = outcomes[Outcome.ACCEPTED]
        refused = outcomes[Outcome.REFUSED]
        unknown = outcomes[Outcome.NO_REPLY_OBSERVED]
        syn_packets = sum(attempt.syn_packets for attempt in window)
        sensitive = port in settings.sensitive_ports
        subject = {"source": client, "destination": server, "port": port}

        if not sensitive and accepted / count > settings.max_accepted_ratio:
            output.suppressed.append(
                SuppressedCandidate(
                    REPEATED_CONNECTIONS,
                    subject,
                    f"{count} connections to port {port} within "
                    f"{_seconds(settings.window_seconds)}, but {_percent(accepted / count)} were "
                    "accepted and the port is not in sensitive_ports; repeated successful "
                    "connections are normal for many clients.",
                )
            )
            continue

        known_ratio = (accepted + refused) / count
        confidence = Confidence.MEDIUM if sensitive and known_ratio >= 0.5 else Confidence.LOW
        sensitivity_note = (
            " The port belongs to a remote-access or authentication service, where repeated "
            "connections are a common password-guessing pattern."
            if sensitive
            else ""
        )
        output.findings.append(
            Finding(
                rule_id=REPEATED_CONNECTIONS,
                title=f"Repeated connection attempts from {client} to {server}:{port}",
                severity=Severity.MEDIUM if sensitive else Severity.LOW,
                confidence=confidence,
                summary=(
                    f"{client} made {count} separate connection attempts to {server} port {port} "
                    f"within {_seconds(settings.window_seconds)}."
                    + (
                        f" {syn_packets - count} retransmitted SYN(s) were not counted as new "
                        "attempts."
                        if syn_packets > count
                        else ""
                    )
                    + sensitivity_note
                ),
                evidence={
                    "source": client,
                    "destination": server,
                    "destination_port": port,
                    "attempts_in_window": count,
                    "window_seconds": settings.window_seconds,
                    "threshold_attempts": settings.min_attempts,
                    "window_start": _iso(window[0].first_seen),
                    "window_end": _iso(window[-1].first_seen),
                    "syn_packets_in_window": syn_packets,
                    "retransmitted_syns_excluded": syn_packets - count,
                    "accepted_syn_ack_observed": accepted,
                    "refused_rst_observed": refused,
                    "no_reply_observed": unknown,
                    "distinct_source_ports": len({a.client_port for a in window}),
                    "attempts_in_capture": len(attempts),
                    "sensitive_service_port": sensitive,
                },
                recommendation=(
                    "Check the destination service's logs for failed or successful logins from "
                    "the source during this period, and identify the software on the source "
                    "that opened the connections."
                ),
                limitations=RULES[REPEATED_CONNECTIONS].limitations,
                subject=subject,
                first_seen=window[0].first_seen,
                last_seen=window[-1].first_seen,
            )
        )
    return output


# ---------------------------------------------------------------------------
# Rule G: excessive refused connections (NS-CONN-002)
# ---------------------------------------------------------------------------


def detect_failed_connections(
    index: TrafficIndex,
    settings: FailedConnectionSettings,
    *,
    exclude_sources: set[str] | None = None,
    exclude_endpoints: set[tuple[str, str, int]] | None = None,
) -> RuleOutput:
    """NS-CONN-002: a source whose connection attempts are mostly refused.

    Only attempts answered by a matching RST count as refused. Attempts with
    no observed reply are reported for context but never counted as failures,
    because the capture cannot show what happened to them.

    ``exclude_sources`` (sources already reported as scanning) and
    ``exclude_endpoints`` (source/destination/port groups already reported by
    NS-CONN-001) prevent a second alert for the same activity.
    """
    output = RuleOutput()
    exclude_sources = exclude_sources or set()
    exclude_endpoints = exclude_endpoints or set()
    by_client: dict[str, list[Any]] = defaultdict(list)
    excluded_counts: Counter[str] = Counter()
    for attempt in index.connection_attempts:
        if (attempt.client, attempt.server, attempt.server_port) in exclude_endpoints:
            excluded_counts[attempt.client] += 1
            continue
        by_client[attempt.client].append(attempt)

    for client, attempts in sorted(by_client.items()):
        refused = sorted(
            a.first_seen
            for a in attempts
            if a.outcome is Outcome.REFUSED and a.first_seen is not None
        )
        if len(refused) < settings.min_refused_attempts:
            continue
        peak, start, end = best_window_count(refused, settings.window_seconds)
        if peak < settings.min_refused_attempts:
            continue
        outcomes = Counter(attempt.outcome for attempt in attempts)
        accepted = outcomes[Outcome.ACCEPTED]
        refused_total = outcomes[Outcome.REFUSED]
        ratio = refused_total / (accepted + refused_total)
        if ratio < settings.min_refused_ratio:
            continue
        subject = {"source": client}
        if client in exclude_sources:
            output.suppressed.append(
                SuppressedCandidate(
                    FAILED_CONNECTIONS,
                    subject,
                    "This source is already reported as a potential port scan or host sweep; "
                    "refused connections are an expected side effect of scanning.",
                )
            )
            continue

        refused_endpoints = Counter(
            (a.server, a.server_port) for a in attempts if a.outcome is Outcome.REFUSED
        )
        output.findings.append(
            Finding(
                rule_id=FAILED_CONNECTIONS,
                title=f"Excessive refused connections from {client}",
                severity=Severity.LOW,
                confidence=Confidence.MEDIUM,
                summary=(
                    f"{peak} connection attempts from {client} were refused with TCP resets "
                    f"within {_seconds(settings.window_seconds)}; {_percent(ratio)} of its "
                    "attempts with a known outcome were refused."
                ),
                evidence={
                    "source": client,
                    "refused_in_window": peak,
                    "window_seconds": settings.window_seconds,
                    "threshold_refused": settings.min_refused_attempts,
                    "window_start": _iso(refused[start]),
                    "window_end": _iso(refused[end]),
                    "refused_rst_observed": refused_total,
                    "accepted_syn_ack_observed": accepted,
                    "no_reply_observed_not_counted": outcomes[Outcome.NO_REPLY_OBSERVED],
                    "refused_ratio_of_known_outcomes": round(ratio, 4),
                    "distinct_destinations_refused": len({h for h, _ in refused_endpoints}),
                    "distinct_ports_refused": len({p for _, p in refused_endpoints}),
                    "attempts_excluded_as_already_reported": excluded_counts[client],
                    "top_refused_endpoints": [
                        {"destination": host, "port": port, "refused": count}
                        for (host, port), count in sorted(
                            refused_endpoints.items(), key=lambda item: (-item[1], item[0])
                        )[:MAX_LISTED]
                    ],
                },
                recommendation=(
                    "Determine whether the refused services are expected to be running. If they "
                    "are not, find the software on the source that keeps trying to reach them; "
                    "persistent attempts against many services can indicate misconfiguration "
                    "or unauthorised probing."
                ),
                limitations=RULES[FAILED_CONNECTIONS].limitations,
                subject=subject,
                first_seen=refused[start],
                last_seen=refused[end],
            )
        )
    return output


# ---------------------------------------------------------------------------
# Rule C: ports that merit review (NS-PORT-001)
# ---------------------------------------------------------------------------


def detect_unusual_ports(
    index: TrafficIndex,
    settings: UnusualPortSettings,
    *,
    exclude_sources: set[str] | None = None,
) -> RuleOutput:
    """NS-PORT-001: flows initiated toward watched ports.

    Only flow-initiation events count (a TCP SYN or the first packet of a UDP
    flow), so a server *replying from* port 4444 to a client does not trigger
    the rule. Sources already reported as scanning are skipped: a scan touches
    thousands of ports, and listing each watched one again adds no information.
    """
    output = RuleOutput()
    exclude_sources = exclude_sources or set()
    groups: dict[tuple[str, int], list[Contact]] = defaultdict(list)
    reasons: dict[tuple[str, int], tuple[str, str]] = {}
    excluded: Counter[tuple[str, int]] = Counter()

    for contact in index.contacts:
        port = contact.port
        if port is None:
            continue
        if port in settings.watched_ports:
            label = ("watched port", settings.watched_ports[port])
        elif port in settings.public_destination_ports and _is_public(contact.destination):
            label = (
                "inward-facing service on a public address",
                settings.public_destination_ports[port],
            )
        else:
            continue
        key = (contact.transport, port)
        if contact.source in exclude_sources:
            excluded[key] += 1
            continue
        groups[key].append(contact)
        reasons[key] = label

    for key, count in sorted(excluded.items()):
        if key not in groups:
            output.suppressed.append(
                SuppressedCandidate(
                    UNUSUAL_PORT,
                    {"transport": key[0], "port": key[1]},
                    f"{count} contact(s) came only from sources already reported as potential "
                    "port scans or host sweeps.",
                )
            )

    for (transport, port), contacts in sorted(groups.items()):
        category, reason = reasons[(transport, port)]
        pairs = Counter((c.source, c.destination) for c in contacts)
        accepted = sum(1 for c in contacts if c.accepted)
        timestamps = [c.timestamp for c in contacts if c.timestamp is not None]
        output.findings.append(
            Finding(
                rule_id=UNUSUAL_PORT,
                title=f"Traffic to {transport} port {port} ({category})",
                severity=Severity.LOW,
                confidence=Confidence.LOW,
                summary=(
                    f"{len(contacts)} flow(s) were initiated toward {transport} port {port} "
                    f"between {len(pairs)} host pair(s). {reason} The port number alone does not "
                    "show which application was in use."
                ),
                evidence={
                    "transport": transport,
                    "port": port,
                    "category": category,
                    "reason": reason,
                    "flows_initiated": len(contacts),
                    "accepted_or_answered": accepted,
                    "distinct_sources": len({s for s, _ in pairs}),
                    "distinct_destinations": len({d for _, d in pairs}),
                    "contacts_from_scanning_sources_excluded": excluded[(transport, port)],
                    "example_flows": [
                        {"source": s, "destination": d, "flows": n}
                        for (s, d), n in sorted(pairs.items(), key=lambda i: (-i[1], i[0]))[
                            :MAX_LISTED
                        ]
                    ],
                },
                recommendation=(
                    "Identify the process listening on the destination port and the process "
                    "on the source that connected to it, and confirm the connection is expected. "
                    "Inspecting the traffic in a protocol analyser can show what the protocol "
                    "actually is."
                ),
                limitations=RULES[UNUSUAL_PORT].limitations,
                subject={"transport": transport, "port": port},
                first_seen=min(timestamps) if timestamps else None,
                last_seen=max(timestamps) if timestamps else None,
            )
        )
    return output


# ---------------------------------------------------------------------------
# Rule D: high traffic volume (NS-VOL-001)
# ---------------------------------------------------------------------------


def peak_packets_in_window(
    per_second: Counter[int], window_seconds: float
) -> tuple[int, int | None]:
    """Largest packet count within ``window_seconds`` consecutive one-second buckets."""
    width = max(1, ceil(window_seconds))
    seconds = sorted(per_second)
    best, best_start = 0, None
    running = 0
    left = 0
    for second in seconds:
        running += per_second[second]
        while second - seconds[left] >= width:
            running -= per_second[seconds[left]]
            left += 1
        if running > best:
            best, best_start = running, seconds[left]
    return best, best_start


def detect_high_volume(index: TrafficIndex, settings: HighVolumeSettings) -> RuleOutput:
    """NS-VOL-001: very high packet counts from one source.

    Two transparent checks, reported together in one finding per source:

    * **burst**: at least ``min_packets_in_window`` packets within any
      ``window_seconds`` (counted in one-second buckets) -> LOW;
    * **concentration**: one source sends at least ``min_share_of_capture`` of
      all IP packets (and at least ``min_packets_for_share``) -> INFO.
    """
    output = RuleOutput()
    total = index.total_ip_packets
    multiple_sources = len(index.packets_by_source) > 1
    width = max(1, ceil(settings.window_seconds))
    for source, packets in sorted(index.packets_by_source.items()):
        per_second = index.packets_per_second_by_source.get(source, Counter())
        peak, peak_start = peak_packets_in_window(per_second, settings.window_seconds)
        share = packets / total if total else 0.0
        burst = peak >= settings.min_packets_in_window
        concentrated = (
            multiple_sources
            and packets >= settings.min_packets_for_share
            and share >= settings.min_share_of_capture
        )
        if not (burst or concentrated):
            continue
        reasons = []
        if burst:
            reasons.append(f"{peak:,} packets within {width} s")
        if concentrated:
            reasons.append(f"{_percent(share)} of all IP packets in the capture")
        destinations = index.destinations_by_source.get(source, Counter())
        output.findings.append(
            Finding(
                rule_id=HIGH_VOLUME,
                title=f"High traffic volume from {source}",
                severity=Severity.LOW if burst else Severity.INFO,
                confidence=Confidence.LOW,
                summary=(
                    f"{source} sent {packets:,} packets ({' and '.join(reasons)}). High volume "
                    "is often legitimate (transfers, backups, streaming) and is not by itself a "
                    "sign of an attack."
                ),
                evidence={
                    "source": source,
                    "packets_sent": packets,
                    "share_of_ip_packets": round(share, 4),
                    "bytes_on_wire_sent": index.bytes_by_source[source],
                    "peak_packets_in_window": peak,
                    "window_seconds": width,
                    "peak_window_start": _iso(float(peak_start))
                    if peak_start is not None
                    else None,
                    "approx_peak_packets_per_second": round(peak / width, 1),
                    "burst_threshold_packets": settings.min_packets_in_window,
                    "share_threshold": settings.min_share_of_capture,
                    "top_destinations": [
                        {"destination": d, "packets": n}
                        for d, n in sorted(destinations.items(), key=lambda i: (-i[1], i[0]))[:5]
                    ],
                },
                recommendation=(
                    "Identify what the source was doing at the peak time (scheduled transfer, "
                    "backup, update, streaming). Compare with this host's normal traffic levels "
                    "before drawing conclusions."
                ),
                limitations=RULES[HIGH_VOLUME].limitations,
                subject={"source": source},
                first_seen=float(peak_start) if peak_start is not None else None,
                last_seen=float(peak_start + width) if peak_start is not None else None,
            )
        )
    return output


# ---------------------------------------------------------------------------
# Rule E: DNS heuristics (NS-DNS-001 .. 004)
# ---------------------------------------------------------------------------


def _is_long_name(query: DnsQueryEvent, settings: DnsSettings) -> bool:
    return (
        query.name_length >= settings.long_name_length
        or query.longest_label >= settings.long_label_length
    )


def _parent_domain(name: str) -> str:
    """Approximate the registered domain as the last two labels.

    This is deliberately simple and wrong for names like ``example.co.uk``;
    it is only used to group long names for display.
    """
    labels = name.split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else name


def _top(counter: Counter[Any], limit: int, label: str = "name") -> list[dict[str, Any]]:
    return [
        {label: key, "count": count}
        for key, count in sorted(counter.items(), key=lambda item: (-item[1], str(item[0])))[:limit]
    ]


def detect_repeated_unusual_dns(index: TrafficIndex, settings: DnsSettings) -> RuleOutput:
    """NS-DNS-004: one client querying the same unusual name again and again.

    "Unusual" means the name is long (see NS-DNS-002 thresholds) or every
    observed response for it was an error. Duplicate packets with the same
    transaction ID were already removed by the analyser.
    """
    output = RuleOutput()
    queries: dict[tuple[str, str], list[DnsQueryEvent]] = defaultdict(list)
    for query in index.dns_queries:
        queries[(query.client, query.name)].append(query)
    responses: dict[tuple[str, str | None], list[DnsResponseEvent]] = defaultdict(list)
    for response in index.dns_responses:
        responses[(response.client, response.name)].append(response)

    for (client, name), events in sorted(queries.items()):
        if len(events) < settings.min_repeated_queries:
            continue
        long_name = _is_long_name(events[0], settings)
        answers = responses.get((client, name), [])
        always_failed = bool(answers) and all(r.rcode != 0 for r in answers)
        if not (long_name or always_failed):
            continue
        reasons = []
        if long_name:
            reasons.append(f"the name is unusually long ({events[0].name_length} bytes)")
        if always_failed:
            codes = Counter(dns_rcode_name(r.rcode) for r in answers)
            reasons.append(
                "every observed response was an error ("
                + ", ".join(f"{code} x{count}" for code, count in codes.most_common())
                + ")"
            )
        timestamps = sorted(e.timestamp for e in events if e.timestamp is not None)
        intervals = [b - a for a, b in zip(timestamps, timestamps[1:], strict=False)]
        median_interval = round(statistics.median(intervals), 3) if intervals else None
        output.findings.append(
            Finding(
                rule_id=DNS_REPEATED_UNUSUAL,
                title=f"Repeated queries for an unusual domain from {client}",
                severity=Severity.LOW,
                confidence=Confidence.LOW,
                summary=(
                    f"{client} queried the same name {len(events)} times; "
                    + " and ".join(reasons)
                    + ". Repetition suggests automated software, which may be benign."
                ),
                evidence={
                    "source": client,
                    "name": name,
                    "queries": len(events),
                    "threshold_queries": settings.min_repeated_queries,
                    "name_length_bytes": events[0].name_length,
                    "longest_label_bytes": events[0].longest_label,
                    "responses_observed": len(answers),
                    "failed_responses": sum(1 for r in answers if r.rcode != 0),
                    "median_seconds_between_queries": median_interval,
                    "first_query": _iso(timestamps[0]) if timestamps else None,
                    "last_query": _iso(timestamps[-1]) if timestamps else None,
                    "query_types": sorted({dns_type_name(e.question_type) for e in events}),
                },
                recommendation=(
                    "Find the process on the client that resolves this name (for example with "
                    "endpoint DNS logging), and check the domain's reputation and ownership. "
                    "Regular intervals between queries suggest scheduled or beaconing behaviour."
                ),
                limitations=RULES[DNS_REPEATED_UNUSUAL].limitations,
                subject={"source": client, "name": name},
                first_seen=timestamps[0] if timestamps else None,
                last_seen=timestamps[-1] if timestamps else None,
            )
        )
    return output


def detect_dns_query_rate(index: TrafficIndex, settings: DnsSettings) -> RuleOutput:
    """NS-DNS-001: very many DNS queries from one client in a time window.

    A host that also *answers* DNS queries is a resolver; resolvers query
    upstream servers constantly, so such hosts are suppressed.
    """
    output = RuleOutput()
    dns_servers = {response.server for response in index.dns_responses}
    by_client: dict[str, list[DnsQueryEvent]] = defaultdict(list)
    for query in index.dns_queries:
        if query.timestamp is not None:
            by_client[query.client].append(query)

    for client, events in sorted(by_client.items()):
        if len(events) < settings.min_queries_in_window:
            continue
        events.sort(key=lambda e: e.timestamp or 0.0)
        peak, start, end = best_window_count(
            [e.timestamp or 0.0 for e in events], settings.rate_window_seconds
        )
        if peak < settings.min_queries_in_window:
            continue
        if client in dns_servers:
            output.suppressed.append(
                SuppressedCandidate(
                    DNS_QUERY_RATE,
                    {"source": client},
                    f"{peak} queries within {_seconds(settings.rate_window_seconds)}, but this "
                    "host also answers DNS queries (it appears to be a resolver).",
                )
            )
            continue
        window = events[start : end + 1]
        names = Counter(e.name for e in window)
        output.findings.append(
            Finding(
                rule_id=DNS_QUERY_RATE,
                title=f"High DNS query rate from {client}",
                severity=Severity.LOW,
                confidence=Confidence.LOW,
                summary=(
                    f"{client} sent {peak} DNS queries within "
                    f"{_seconds(settings.rate_window_seconds)} for {len(names)} distinct names."
                ),
                evidence={
                    "source": client,
                    "queries_in_window": peak,
                    "window_seconds": settings.rate_window_seconds,
                    "threshold_queries": settings.min_queries_in_window,
                    "window_start": _iso(window[0].timestamp),
                    "window_end": _iso(window[-1].timestamp),
                    "distinct_names_in_window": len(names),
                    "queries_in_capture": len(events),
                    "dns_servers": sorted({e.server for e in window}, key=_address_sort_key)[
                        :MAX_LISTED
                    ],
                    "top_names": _top(names, 5),
                    "query_types": _top(
                        Counter(dns_type_name(e.question_type) for e in window), 5, "type"
                    ),
                },
                recommendation=(
                    "Check whether the client is a resolver, mail server or security tool. If it "
                    "is an ordinary workstation, identify the process generating the queries and "
                    "review the queried names for random-looking or encoded labels."
                ),
                limitations=RULES[DNS_QUERY_RATE].limitations,
                subject={"source": client},
                first_seen=window[0].timestamp,
                last_seen=window[-1].timestamp,
            )
        )
    return output


def detect_long_dns_names(
    index: TrafficIndex,
    settings: DnsSettings,
    *,
    exclude_names: set[tuple[str, str]] | None = None,
) -> RuleOutput:
    """NS-DNS-002: queries for unusually long names or labels.

    Many distinct long names under one parent domain is the pattern most
    associated with DNS tunnelling (data encoded into subdomains), so that
    raises the severity and confidence a step. ``exclude_names`` holds
    (client, name) pairs already reported by NS-DNS-004.
    """
    output = RuleOutput()
    exclude_names = exclude_names or set()
    by_client: dict[str, list[DnsQueryEvent]] = defaultdict(list)
    for query in index.dns_queries:
        if _is_long_name(query, settings) and (query.client, query.name) not in exclude_names:
            by_client[query.client].append(query)

    for client, events in sorted(by_client.items()):
        names = Counter(e.name for e in events)
        parents = Counter(_parent_domain(name) for name in names)
        top_parent, top_parent_count = max(parents.items(), key=lambda item: (item[1], item[0]))
        many = len(names) >= settings.min_long_names_for_low
        clustered = top_parent_count >= settings.min_long_names_for_low
        timestamps = sorted(e.timestamp for e in events if e.timestamp is not None)
        longest = max(events, key=lambda e: (e.name_length, e.name))
        output.findings.append(
            Finding(
                rule_id=DNS_LONG_NAMES,
                title=f"Unusually long DNS query names from {client}",
                severity=Severity.LOW if many else Severity.INFO,
                confidence=Confidence.MEDIUM if clustered else Confidence.LOW,
                summary=(
                    f"{client} queried {len(names)} distinct name(s) longer than "
                    f"{settings.long_name_length} bytes or with a label longer than "
                    f"{settings.long_label_length} bytes"
                    + (
                        f"; {top_parent_count} of them are under {top_parent}, a pattern "
                        "associated with data encoded in subdomains."
                        if clustered
                        else "."
                    )
                ),
                evidence={
                    "source": client,
                    "distinct_long_names": len(names),
                    "queries_for_long_names": len(events),
                    "longest_name_bytes": longest.name_length,
                    "longest_label_bytes": max(e.longest_label for e in events),
                    "name_length_threshold": settings.long_name_length,
                    "label_length_threshold": settings.long_label_length,
                    "top_parent_domains": _top(parents, 5, "parent_domain"),
                    "example_names": [name for name, _ in names.most_common(5)],
                    "first_query": _iso(timestamps[0]) if timestamps else None,
                    "last_query": _iso(timestamps[-1]) if timestamps else None,
                },
                recommendation=(
                    "Look at whether the long labels look random or encoded (hex, base32/64) and "
                    "check the reputation of the parent domain. Legitimate services usually "
                    "reuse a small set of names; tunnelling produces a stream of unique ones."
                ),
                limitations=RULES[DNS_LONG_NAMES].limitations,
                subject={"source": client},
                first_seen=timestamps[0] if timestamps else None,
                last_seen=timestamps[-1] if timestamps else None,
            )
        )
    return output


def detect_dns_failures(
    index: TrafficIndex,
    settings: DnsSettings,
    *,
    exclude_names: set[tuple[str, str]] | None = None,
) -> RuleOutput:
    """NS-DNS-003: most DNS responses to a client report an error."""
    output = RuleOutput()
    exclude_names = exclude_names or set()
    by_client: dict[str, list[DnsResponseEvent]] = defaultdict(list)
    for response in index.dns_responses:
        if (response.client, response.name or "") not in exclude_names:
            by_client[response.client].append(response)

    for client, responses in sorted(by_client.items()):
        if len(responses) < settings.min_responses_for_failure_ratio:
            continue
        failed = [r for r in responses if r.rcode != 0]
        ratio = len(failed) / len(responses)
        if ratio < settings.min_failure_ratio:
            continue
        failed_names = Counter(r.name or "(no question)" for r in failed)
        timestamps = sorted(r.timestamp for r in failed if r.timestamp is not None)
        output.findings.append(
            Finding(
                rule_id=DNS_FAILURES,
                title=f"High proportion of failed DNS lookups for {client}",
                severity=Severity.LOW,
                confidence=Confidence.LOW,
                summary=(
                    f"{len(failed)} of {len(responses)} DNS responses to {client} "
                    f"({_percent(ratio)}) reported an error, across {len(failed_names)} "
                    "distinct name(s)."
                ),
                evidence={
                    "source": client,
                    "responses_observed": len(responses),
                    "failed_responses": len(failed),
                    "failure_ratio": round(ratio, 4),
                    "threshold_ratio": settings.min_failure_ratio,
                    "minimum_responses": settings.min_responses_for_failure_ratio,
                    "response_codes": _top(
                        Counter(dns_rcode_name(r.rcode) for r in failed), 10, "rcode"
                    ),
                    "distinct_failed_names": len(failed_names),
                    "top_failed_names": _top(failed_names, 5),
                    "dns_servers": sorted({r.server for r in responses}, key=_address_sort_key)[
                        :MAX_LISTED
                    ],
                },
                recommendation=(
                    "Review the failing names: typos and stale configuration produce a few "
                    "names repeatedly, while malware using generated domains produces many "
                    "random-looking ones. Check the client's DNS configuration and search domains."
                ),
                limitations=RULES[DNS_FAILURES].limitations,
                subject={"source": client},
                first_seen=timestamps[0] if timestamps else None,
                last_seen=timestamps[-1] if timestamps else None,
            )
        )
    return output


# ---------------------------------------------------------------------------
# Rule F: cleartext protocols (NS-CLEAR-001)
# ---------------------------------------------------------------------------

_CLEARTEXT_DETAILS = {
    "HTTP": (Severity.INFO, "HTTPS"),
    "FTP": (Severity.LOW, "SFTP or FTPS"),
    "Telnet": (Severity.LOW, "SSH"),
}


def detect_cleartext_protocols(index: TrafficIndex) -> RuleOutput:
    """NS-CLEAR-001: one finding per cleartext protocol identified by content.

    FTP and Telnet are LOW because their login exchange is unencrypted by
    design. HTTP is INFO: much HTTP traffic (redirects to HTTPS, certificate
    revocation checks, signed software updates) carries nothing sensitive.
    """
    output = RuleOutput()
    by_protocol: dict[str, list[Any]] = defaultdict(list)
    for flow in index.cleartext_flows:
        by_protocol[flow.protocol].append(flow)

    for protocol, flows in sorted(by_protocol.items()):
        severity, alternative = _CLEARTEXT_DETAILS.get(
            protocol, (Severity.INFO, "an encrypted protocol")
        )
        flows.sort(key=lambda f: (-f.packets, f.client, f.server, f.server_port))
        packets = sum(f.packets for f in flows)
        firsts = [f.first_seen for f in flows if f.first_seen is not None]
        lasts = [f.last_seen for f in flows if f.last_seen is not None]
        servers = {(f.server, f.server_port) for f in flows}
        output.findings.append(
            Finding(
                rule_id=CLEARTEXT,
                title=f"Cleartext {protocol} traffic observed",
                severity=severity,
                confidence=Confidence.HIGH,
                summary=(
                    f"{packets} packet(s) were recognised as {protocol} between {len(flows)} "
                    f"client/server pair(s). {protocol} is not encrypted, so anyone on the network "
                    "path could read or modify it. NetSentry did not inspect the content."
                ),
                evidence={
                    "protocol": protocol,
                    "packets_identified": packets,
                    "client_server_pairs": len(flows),
                    "distinct_clients": len({f.client for f in flows}),
                    "distinct_servers": len(servers),
                    "identification_basis": "content signature (first bytes of TCP payload)",
                    "flows": [
                        {
                            "client": f.client,
                            "server": f.server,
                            "server_port": f.server_port,
                            "packets": f.packets,
                        }
                        for f in flows[:MAX_LISTED]
                    ],
                },
                recommendation=(
                    f"Confirm whether these services should use {alternative} instead, and "
                    "whether any credentials or personal data could travel over these "
                    "connections."
                ),
                limitations=RULES[CLEARTEXT].limitations,
                subject={"protocol": protocol},
                first_seen=min(firsts) if firsts else None,
                last_seen=max(lasts) if lasts else None,
            )
        )
    return output
