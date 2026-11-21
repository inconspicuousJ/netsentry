"""Shared data structures used across NetSentry.

The pipeline is:

    capture file -> PacketRecord (one per frame, metadata only)
                 -> AnalysisResult (statistics + a TrafficIndex of derived events)
                 -> Finding (one per detected pattern)

Keeping these types in one module lets the loader, analyser, detectors and
reporting code agree on a single vocabulary without importing each other.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Severity(StrEnum):
    """How much a finding would matter *if* the concern behind it is real.

    Severity is deliberately separate from Confidence: a MEDIUM-severity port
    scan finding can still have LOW confidence when the capture lacks the
    evidence needed to judge it.
    """

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"

    @property
    def rank(self) -> int:
        return _SEVERITY_ORDER.index(self)

    @classmethod
    def parse(cls, value: str) -> Severity:
        """Parse a case-insensitive severity name such as ``"medium"``."""
        try:
            return cls(value.strip().upper())
        except ValueError:
            valid = ", ".join(s.value.lower() for s in _SEVERITY_ORDER)
            raise ValueError(f"unknown severity {value!r}; expected one of: {valid}") from None


_SEVERITY_ORDER = (Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH)


class Confidence(StrEnum):
    """How strongly the capture's evidence supports the concern a rule looks for.

    This is *not* the probability that an attack happened. It describes the
    quality and specificity of the evidence (for example, whether reply
    traffic was visible so that connection outcomes could be judged).
    """

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"

    @property
    def rank(self) -> int:
        return ("LOW", "MEDIUM", "HIGH").index(self.value)


class Outcome(StrEnum):
    """What the capture shows happened to a TCP connection attempt."""

    ACCEPTED = "accepted"  # a matching SYN-ACK was observed
    REFUSED = "refused"  # a matching RST was observed
    NO_REPLY_OBSERVED = "no_reply_observed"  # neither was observed (the reason is unknown)


# ---------------------------------------------------------------------------
# Per-packet metadata produced by the capture loader
# ---------------------------------------------------------------------------


@dataclass(slots=True, frozen=True)
class DnsInfo:
    """Fields extracted from a successfully decoded DNS message.

    Only the first question is recorded; real-world DNS messages almost
    always carry exactly one question.
    """

    is_response: bool
    transaction_id: int
    opcode: int
    rcode: int | None  # only meaningful for responses
    question_name: str | None  # lower-cased, trailing dot removed, escaped for display
    question_name_length: int  # length of the raw name in bytes
    longest_label_length: int
    question_type: int | None
    question_count: int
    answer_count: int
    name_truncated: bool = False  # the stored name was shortened to a safe maximum


@dataclass(slots=True, frozen=True)
class PacketRecord:
    """Metadata about one captured frame.

    There is intentionally no field for payload bytes: NetSentry never stores
    or reports application payloads.
    """

    index: int  # 1-based frame number, matching Wireshark's "No." column
    timestamp: float | None  # seconds since the Unix epoch, None if the file has none
    captured_length: int  # bytes present in the file for this frame
    original_length: int | None  # length on the wire as recorded by the capture tool
    link_type: int
    network: str  # "IPv4", "IPv6", "ARP", "malformed IP", "other"
    src_ip: str | None = None
    dst_ip: str | None = None
    ip_protocol: int | None = None  # protocol number from the IP header chain
    transport: str | None = None  # "TCP", "UDP", "ICMP", "ICMPv6" when that header parsed
    src_port: int | None = None
    dst_port: int | None = None
    tcp_flags: int | None = None
    tcp_seq: int | None = None
    tcp_ack: int | None = None
    icmp_type: int | None = None
    icmp_code: int | None = None
    payload_length: int | None = None  # transport payload bytes present in the capture
    app_protocol: str | None = None  # identified from decoded content, never from port alone
    app_direction: str | None = None  # "client_to_server" / "server_to_client" when known
    dns: DnsInfo | None = None
    is_fragment: bool = False  # non-first IPv4 fragment (no transport header present)
    decode_error: str | None = None


# ---------------------------------------------------------------------------
# File-level information produced by the capture loader
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class CaptureInfo:
    """Facts about the capture file itself (not about its packets)."""

    file_name: str  # base name only: full paths can reveal user names
    file_size: int
    sha256: str
    file_format: str  # "pcap" or "pcapng"
    compressed: bool = False  # gzip-compressed capture
    timestamp_precision: str | None = None  # "microsecond" / "nanosecond" for pcap


@dataclass(slots=True)
class ParseStats:
    """Counters describing how reading and decoding went.

    These are reported so that silently skipped or damaged data never goes
    unnoticed.
    """

    frames_read: int = 0
    frames_decoded: int = 0
    decode_failures: int = 0
    unsupported_link_type_frames: Counter[int] = field(default_factory=Counter)
    link_types: Counter[int] = field(default_factory=Counter)
    truncated_records: int = 0  # the file ended before a record's data was complete
    oversized_records: int = 0  # record longer than the reader accepts; data was cut
    snaplen_limited_frames: int = 0  # capture tool stored fewer bytes than were on the wire
    malformed_network_headers: int = 0
    frames_without_timestamp: int = 0
    frames_out_of_order: int = 0
    frames_with_epoch_zero_timestamp: int = 0
    stopped_at_packet_limit: bool = False
    packet_limit: int | None = None
    trailing_bytes_unparsed: int = 0
    reader_warnings: Counter[str] = field(default_factory=Counter)
    read_error: str | None = None


# ---------------------------------------------------------------------------
# Derived events built by the analyser and consumed by the detectors
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class ConnectionAttempt:
    """One TCP connection attempt: a SYN (without ACK) and its retransmissions.

    Retransmitted SYNs reuse the same source port and initial sequence number,
    so they are counted here instead of being treated as new attempts.
    """

    client: str
    client_port: int
    server: str
    server_port: int
    initial_sequence: int
    first_seen: float | None
    last_seen: float | None
    syn_packets: int = 1
    outcome: Outcome = Outcome.NO_REPLY_OBSERVED


@dataclass(slots=True)
class Contact:
    """A flow-initiation event: one host reaching out to a host/port.

    Built from TCP connection attempts, the first packet of each UDP flow and
    ICMP echo requests. Port scan rules work on these events.
    """

    timestamp: float | None
    source: str
    destination: str
    transport: str  # "TCP", "UDP", "ICMP", "ICMPv6"
    port: int | None  # None for ICMP echo
    answered: bool  # any reply (SYN-ACK, RST, UDP reply, echo reply) was observed
    accepted: bool  # the destination accepted/answered positively


@dataclass(slots=True, frozen=True)
class DnsQueryEvent:
    timestamp: float | None
    client: str
    client_port: int | None
    server: str
    name: str
    name_length: int
    longest_label: int
    question_type: int | None
    transaction_id: int


@dataclass(slots=True, frozen=True)
class DnsResponseEvent:
    timestamp: float | None
    client: str  # destination of the response = the host that asked
    server: str
    name: str | None
    rcode: int
    answer_count: int


@dataclass(slots=True)
class CleartextFlow:
    """Packets identified as a cleartext protocol for one client/server pair."""

    protocol: str
    client: str
    server: str
    server_port: int
    packets: int = 0
    client_to_server: int = 0
    server_to_client: int = 0
    first_seen: float | None = None
    last_seen: float | None = None


@dataclass(slots=True)
class TrafficIndex:
    """Derived events that detection rules evaluate."""

    connection_attempts: list[ConnectionAttempt] = field(default_factory=list)
    contacts: list[Contact] = field(default_factory=list)
    dns_queries: list[DnsQueryEvent] = field(default_factory=list)
    dns_responses: list[DnsResponseEvent] = field(default_factory=list)
    cleartext_flows: list[CleartextFlow] = field(default_factory=list)
    # Packets per source address per whole second, for volume rules.
    packets_per_second_by_source: dict[str, Counter[int]] = field(default_factory=dict)
    packets_by_source: Counter[str] = field(default_factory=Counter)
    bytes_by_source: Counter[str] = field(default_factory=Counter)
    destinations_by_source: dict[str, Counter[str]] = field(default_factory=dict)
    # Directed (source, destination) address pairs that carried any IP packet.
    directed_pairs: set[tuple[str, str]] = field(default_factory=set)
    total_ip_packets: int = 0

    def reply_traffic_seen(self, source: str, destination: str) -> bool:
        """True if any packet flowed from ``destination`` back to ``source``."""
        return (destination, source) in self.directed_pairs


# ---------------------------------------------------------------------------
# Analysis output
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class TrafficStats:
    total_packets: int = 0
    ip_packets: int = 0
    bytes_on_wire: int = 0  # sum of recorded original lengths
    bytes_captured: int = 0
    first_timestamp: float | None = None
    last_timestamp: float | None = None
    duration_seconds: float | None = None
    packets_per_second: float | None = None
    network_counts: Counter[str] = field(default_factory=Counter)
    transport_counts: Counter[str] = field(default_factory=Counter)
    application_counts: Counter[str] = field(default_factory=Counter)
    source_counts: Counter[str] = field(default_factory=Counter)
    destination_counts: Counter[str] = field(default_factory=Counter)
    destination_port_counts: Counter[tuple[str, int]] = field(default_factory=Counter)
    timestamped_packets: int = 0
    ip_fragments: int = 0
    undecoded_transport: int = 0  # IP said TCP/UDP/... but the header could not be parsed
    icmp_unreachable: int = 0  # ICMP / ICMPv6 "destination unreachable" messages
    # Flow-initiating events (TCP attempts, new UDP flows) per (transport, port).
    flows_initiated_by_port: Counter[tuple[str, int]] = field(default_factory=Counter)


@dataclass(slots=True)
class TcpStats:
    packets: int = 0
    flag_counts: Counter[str] = field(default_factory=Counter)
    syn_only: int = 0  # connection attempts, including retransmissions
    syn_ack: int = 0
    rst: int = 0
    fin: int = 0
    connection_attempts: int = 0  # distinct attempts (retransmissions removed)
    retransmitted_syns: int = 0
    accepted: int = 0
    refused: int = 0
    no_reply_observed: int = 0
    unmatched_syn_acks: int = 0  # SYN-ACKs whose SYN was not in the capture
    resets_after_accept: int = 0
    rst_sources: Counter[str] = field(default_factory=Counter)


@dataclass(slots=True)
class DnsStats:
    messages: int = 0
    queries: int = 0
    responses: int = 0
    malformed: int = 0  # port-53 traffic that did not decode as DNS
    query_names: Counter[str] = field(default_factory=Counter)
    query_types: Counter[int] = field(default_factory=Counter)
    response_codes: Counter[int] = field(default_factory=Counter)
    responses_with_answers: int = 0
    over_tcp: int = 0
    mdns_messages: int = 0


@dataclass(slots=True)
class AnalysisResult:
    capture: CaptureInfo
    parse: ParseStats
    traffic: TrafficStats
    tcp: TcpStats
    dns: DnsStats
    index: TrafficIndex
    warnings: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Detection output
# ---------------------------------------------------------------------------


@dataclass(slots=True, frozen=True)
class Finding:
    """One detected traffic pattern with the evidence that triggered it."""

    rule_id: str
    title: str
    severity: Severity
    confidence: Confidence
    summary: str
    evidence: dict[str, Any]
    recommendation: str
    limitations: str
    subject: dict[str, Any]  # what the finding is about, e.g. {"source": "192.0.2.10"}
    first_seen: float | None = None
    last_seen: float | None = None

    @property
    def sort_key(self) -> tuple[int, int, str, str]:
        return (-self.severity.rank, -self.confidence.rank, self.rule_id, repr(self.subject))


@dataclass(slots=True, frozen=True)
class SuppressedCandidate:
    """A pattern that met a rule's threshold but was deliberately not reported.

    Suppressions are reported so the user can see that NetSentry noticed the
    activity and why it judged it to be likely benign or already covered.
    """

    rule_id: str
    subject: dict[str, Any]
    reason: str


@dataclass(slots=True)
class DetectionReport:
    findings: list[Finding] = field(default_factory=list)
    suppressed: list[SuppressedCandidate] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
