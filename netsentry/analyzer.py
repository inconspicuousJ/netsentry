"""Turn a stream of PacketRecords into statistics and a TrafficIndex.

The analyser makes a single pass over the packets. For each one it updates
counters (protocols, talkers, ports, TCP flags, DNS) and builds a few compact
derived structures that the detection rules need:

* **TCP connection attempts** - a SYN plus its retransmissions, and what the
  capture shows happened to it (SYN-ACK, RST, or nothing observed).
* **Contacts** - flow-initiation events (TCP attempts, the first packet of a
  UDP flow, ICMP echo requests) used by the port-scan rules.
* **DNS query/response events**, **cleartext protocol flows** and
  **per-second packet counts** per source.

It never sees payload bytes: PacketRecords do not contain them.
"""

from __future__ import annotations

import ipaddress
import math
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from .capture_loader import (
    DEFAULT_MAX_PACKETS,
    DNS_UNDECODABLE,
    inspect_capture_file,
    link_type_name,
    read_packets,
)
from .models import (
    AnalysisResult,
    CaptureInfo,
    CleartextFlow,
    ConnectionAttempt,
    Contact,
    DnsQueryEvent,
    DnsResponseEvent,
    DnsStats,
    Outcome,
    PacketRecord,
    ParseStats,
    TcpStats,
    TrafficIndex,
    TrafficStats,
)
from .protocols import ACK, CLIENT_TO_SERVER, FIN, RST, SYN, TCP_FLAG_NAMES

# Below this duration a packets-per-second figure is more misleading than useful.
MIN_DURATION_FOR_RATE = 1.0
_TCP_SEQUENCE_SPACE = 2**32
_CLEARTEXT_PROTOCOLS = frozenset({"HTTP", "FTP", "Telnet"})
_TUNNEL_PROTOCOLS = {4: "IP-in-IP", 41: "IPv6-in-IPv4", 47: "GRE", 50: "IPsec ESP"}
_PROTOCOL_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6"}


@dataclass(slots=True)
class _UdpFlow:
    initiator: str
    initiator_port: int
    responder: str
    responder_port: int
    first_seen: float | None
    replied: bool = False


@dataclass(slots=True)
class _EchoFlow:
    source: str
    destination: str
    transport: str
    first_seen: float | None
    replied: bool = False


@lru_cache(maxsize=65_536)
def is_multicast_or_broadcast(address: str) -> bool:
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return False
    return parsed.is_multicast or str(parsed) == "255.255.255.255"


class TrafficAnalyzer:
    """Accumulates statistics from PacketRecords. Call :meth:`finish` at the end."""

    def __init__(self) -> None:
        self.traffic = TrafficStats()
        self.tcp = TcpStats()
        self.dns = DnsStats()
        self.index = TrafficIndex()
        self._attempts_by_flow: dict[tuple[str, int, str, int], ConnectionAttempt] = {}
        self._udp_flows: dict[tuple[tuple[str, int], tuple[str, int]], _UdpFlow] = {}
        self._echo_flows: dict[tuple[str, str], _EchoFlow] = {}
        self._cleartext: dict[tuple[str, str, str, int], CleartextFlow] = {}
        self._seen_dns_queries: set[tuple[object, ...]] = set()
        self._seen_dns_responses: set[tuple[object, ...]] = set()
        self._tunnel_protocols: Counter[int] = Counter()

    # -- per packet -----------------------------------------------------------

    def add(self, record: PacketRecord) -> None:
        traffic = self.traffic
        traffic.total_packets += 1
        traffic.bytes_captured += record.captured_length
        traffic.bytes_on_wire += record.original_length or record.captured_length
        traffic.network_counts[record.network] += 1

        timestamp = record.timestamp
        if timestamp is not None and math.isfinite(timestamp):
            traffic.timestamped_packets += 1
            if traffic.first_timestamp is None or timestamp < traffic.first_timestamp:
                traffic.first_timestamp = timestamp
            if traffic.last_timestamp is None or timestamp > traffic.last_timestamp:
                traffic.last_timestamp = timestamp
        else:
            timestamp = None

        source, destination = record.src_ip, record.dst_ip
        if source is None or destination is None:
            return  # not IP traffic (ARP, LLDP, undecodable...)

        traffic.ip_packets += 1
        traffic.source_counts[source] += 1
        traffic.destination_counts[destination] += 1
        index = self.index
        index.total_ip_packets += 1
        index.directed_pairs.add((source, destination))
        index.packets_by_source[source] += 1
        index.bytes_by_source[source] += record.original_length or record.captured_length
        index.destinations_by_source.setdefault(source, Counter())[destination] += 1
        if timestamp is not None:
            per_second = index.packets_per_second_by_source.setdefault(source, Counter())
            per_second[math.floor(timestamp)] += 1

        if record.is_fragment:
            traffic.ip_fragments += 1
            traffic.transport_counts["IP fragment (no transport header)"] += 1
            return
        if record.ip_protocol in _TUNNEL_PROTOCOLS:
            self._tunnel_protocols[record.ip_protocol] += 1

        transport = record.transport
        if transport is None:
            protocol = record.ip_protocol
            if protocol in _PROTOCOL_NAMES:
                traffic.undecoded_transport += 1
                label = f"{_PROTOCOL_NAMES[protocol]} (header not decodable)"
            else:
                label = f"IP protocol {protocol}"
            traffic.transport_counts[label] += 1
            return

        traffic.transport_counts[transport] += 1
        if record.dst_port is not None:
            traffic.destination_port_counts[(transport, record.dst_port)] += 1
        if record.app_protocol:
            traffic.application_counts[record.app_protocol] += 1

        if transport == "TCP":
            self._add_tcp(record, source, destination, timestamp)
        elif transport == "UDP":
            self._add_udp(record, source, destination, timestamp)
        else:
            self._add_icmp(record, source, destination, timestamp, transport)

        if record.app_protocol == "DNS" and record.dns is not None:
            self._add_dns(record, source, destination, timestamp)
        elif record.app_protocol == DNS_UNDECODABLE:
            self.dns.malformed += 1
        elif record.app_protocol == "mDNS":
            self.dns.mdns_messages += 1
        elif record.app_protocol in _CLEARTEXT_PROTOCOLS:
            self._add_cleartext(record, source, destination, timestamp)

    def _add_tcp(
        self, record: PacketRecord, source: str, destination: str, timestamp: float | None
    ) -> None:
        tcp = self.tcp
        flags = record.tcp_flags or 0
        src_port = record.src_port or 0
        dst_port = record.dst_port or 0
        tcp.packets += 1
        for bit, name in TCP_FLAG_NAMES:
            if flags & bit:
                tcp.flag_counts[name] += 1
        if flags & FIN:
            tcp.fin += 1

        if flags & SYN and not flags & ACK:
            tcp.syn_only += 1
            key = (source, src_port, destination, dst_port)
            attempt = self._attempts_by_flow.get(key)
            if attempt is not None and attempt.initial_sequence == record.tcp_seq:
                # Same ports and same initial sequence number: a retransmission
                # (or a duplicated packet), not a new connection attempt.
                attempt.syn_packets += 1
                if timestamp is not None:
                    attempt.last_seen = (
                        timestamp
                        if attempt.last_seen is None
                        else max(attempt.last_seen, timestamp)
                    )
                    if attempt.first_seen is None or timestamp < attempt.first_seen:
                        attempt.first_seen = timestamp
            else:
                attempt = ConnectionAttempt(
                    client=source,
                    client_port=src_port,
                    server=destination,
                    server_port=dst_port,
                    initial_sequence=record.tcp_seq or 0,
                    first_seen=timestamp,
                    last_seen=timestamp,
                )
                self._attempts_by_flow[key] = attempt
                self.index.connection_attempts.append(attempt)
            return

        # Replies travel in the opposite direction, so look the attempt up reversed.
        reply_to = self._attempts_by_flow.get((destination, dst_port, source, src_port))
        acknowledges_syn = reply_to is not None and record.tcp_ack == (
            (reply_to.initial_sequence + 1) % _TCP_SEQUENCE_SPACE
        )

        if flags & SYN and flags & ACK:
            tcp.syn_ack += 1
            if reply_to is not None and acknowledges_syn:
                reply_to.outcome = Outcome.ACCEPTED
            else:
                tcp.unmatched_syn_acks += 1

        if flags & RST:
            tcp.rst += 1
            tcp.rst_sources[source] += 1
            if reply_to is None:
                return
            if reply_to.outcome is Outcome.ACCEPTED:
                tcp.resets_after_accept += 1
            elif acknowledges_syn or not flags & ACK:
                # RFC 9293: a closed port answers a SYN with RST+ACK, ack = ISN + 1.
                reply_to.outcome = Outcome.REFUSED

    def _add_udp(
        self, record: PacketRecord, source: str, destination: str, timestamp: float | None
    ) -> None:
        src_port = record.src_port or 0
        dst_port = record.dst_port or 0
        local, remote = (source, src_port), (destination, dst_port)
        key = (local, remote) if local <= remote else (remote, local)
        flow = self._udp_flows.get(key)
        if flow is None:
            # The first packet seen defines who started the conversation.
            self._udp_flows[key] = _UdpFlow(source, src_port, destination, dst_port, timestamp)
        elif source == flow.responder and src_port == flow.responder_port:
            flow.replied = True

    def _add_icmp(
        self,
        record: PacketRecord,
        source: str,
        destination: str,
        timestamp: float | None,
        transport: str,
    ) -> None:
        icmp_type = record.icmp_type
        is_v4 = transport == "ICMP"
        if (is_v4 and icmp_type == 3) or (not is_v4 and icmp_type == 1):
            self.traffic.icmp_unreachable += 1
        if (is_v4 and icmp_type == 8) or (not is_v4 and icmp_type == 128):
            if (source, destination) not in self._echo_flows:
                self._echo_flows[(source, destination)] = _EchoFlow(
                    source, destination, transport, timestamp
                )
        elif (is_v4 and icmp_type == 0) or (not is_v4 and icmp_type == 129):
            flow = self._echo_flows.get((destination, source))
            if flow is not None:
                flow.replied = True

    def _add_dns(
        self, record: PacketRecord, source: str, destination: str, timestamp: float | None
    ) -> None:
        info = record.dns
        assert info is not None
        dns = self.dns
        dns.messages += 1
        if record.transport == "TCP":
            dns.over_tcp += 1
        name = info.question_name

        if not info.is_response:
            dns.queries += 1
            if name is not None:
                dns.query_names[name] += 1
            if info.question_type is not None:
                dns.query_types[info.question_type] += 1
            if name is None:
                return
            # The same query seen twice (duplicate packet or retransmission
            # with the same transaction ID) is counted once for detection.
            key = (source, record.src_port, info.transaction_id, name, info.question_type)
            if key in self._seen_dns_queries:
                return
            self._seen_dns_queries.add(key)
            self.index.dns_queries.append(
                DnsQueryEvent(
                    timestamp=timestamp,
                    client=source,
                    client_port=record.src_port,
                    server=destination,
                    name=name,
                    name_length=info.question_name_length,
                    longest_label=info.longest_label_length,
                    question_type=info.question_type,
                    transaction_id=info.transaction_id,
                )
            )
            return

        dns.responses += 1
        rcode = info.rcode if info.rcode is not None else 0
        dns.response_codes[rcode] += 1
        if info.answer_count:
            dns.responses_with_answers += 1
        response_key = (destination, record.dst_port, info.transaction_id, name)
        if response_key in self._seen_dns_responses:
            return
        self._seen_dns_responses.add(response_key)
        self.index.dns_responses.append(
            DnsResponseEvent(
                timestamp=timestamp,
                client=destination,
                server=source,
                name=name,
                rcode=rcode,
                answer_count=info.answer_count,
            )
        )

    def _add_cleartext(
        self, record: PacketRecord, source: str, destination: str, timestamp: float | None
    ) -> None:
        protocol = record.app_protocol or "unknown"
        if record.app_direction == CLIENT_TO_SERVER:
            client, server, server_port = source, destination, record.dst_port or 0
        else:
            client, server, server_port = destination, source, record.src_port or 0
        key = (protocol, client, server, server_port)
        flow = self._cleartext.get(key)
        if flow is None:
            flow = CleartextFlow(protocol, client, server, server_port)
            self._cleartext[key] = flow
            self.index.cleartext_flows.append(flow)
        flow.packets += 1
        if record.app_direction == CLIENT_TO_SERVER:
            flow.client_to_server += 1
        else:
            flow.server_to_client += 1
        if timestamp is not None:
            if flow.first_seen is None or timestamp < flow.first_seen:
                flow.first_seen = timestamp
            if flow.last_seen is None or timestamp > flow.last_seen:
                flow.last_seen = timestamp

    # -- end of capture ---------------------------------------------------------

    def finish(self, capture: CaptureInfo, parse: ParseStats) -> AnalysisResult:
        traffic = self.traffic
        if (
            traffic.timestamped_packets >= 2
            and traffic.first_timestamp is not None
            and traffic.last_timestamp is not None
        ):
            traffic.duration_seconds = traffic.last_timestamp - traffic.first_timestamp
            if traffic.duration_seconds >= MIN_DURATION_FOR_RATE:
                traffic.packets_per_second = traffic.timestamped_packets / traffic.duration_seconds

        self._finish_tcp()
        self._build_contacts()
        result = AnalysisResult(
            capture=capture,
            parse=parse,
            traffic=traffic,
            tcp=self.tcp,
            dns=self.dns,
            index=self.index,
        )
        result.warnings = _build_warnings(result)
        result.limitations = self._build_limitations(result)
        return result

    def _finish_tcp(self) -> None:
        tcp = self.tcp
        attempts = self.index.connection_attempts
        tcp.connection_attempts = len(attempts)
        tcp.retransmitted_syns = sum(attempt.syn_packets - 1 for attempt in attempts)
        outcomes = Counter(attempt.outcome for attempt in attempts)
        tcp.accepted = outcomes[Outcome.ACCEPTED]
        tcp.refused = outcomes[Outcome.REFUSED]
        tcp.no_reply_observed = outcomes[Outcome.NO_REPLY_OBSERVED]

    def _build_contacts(self) -> None:
        contacts = self.index.contacts
        initiated = self.traffic.flows_initiated_by_port
        for attempt in self.index.connection_attempts:
            initiated[("TCP", attempt.server_port)] += 1
            if is_multicast_or_broadcast(attempt.server):
                continue
            contacts.append(
                Contact(
                    timestamp=attempt.first_seen,
                    source=attempt.client,
                    destination=attempt.server,
                    transport="TCP",
                    port=attempt.server_port,
                    answered=attempt.outcome is not Outcome.NO_REPLY_OBSERVED,
                    accepted=attempt.outcome is Outcome.ACCEPTED,
                )
            )
        for flow in self._udp_flows.values():
            initiated[("UDP", flow.responder_port)] += 1
            if is_multicast_or_broadcast(flow.responder):
                continue
            contacts.append(
                Contact(
                    timestamp=flow.first_seen,
                    source=flow.initiator,
                    destination=flow.responder,
                    transport="UDP",
                    port=flow.responder_port,
                    answered=flow.replied,
                    accepted=flow.replied,
                )
            )
        for echo in self._echo_flows.values():
            if is_multicast_or_broadcast(echo.destination):
                continue
            contacts.append(
                Contact(
                    timestamp=echo.first_seen,
                    source=echo.source,
                    destination=echo.destination,
                    transport=echo.transport,
                    port=None,
                    answered=echo.replied,
                    accepted=echo.replied,
                )
            )

    def _build_limitations(self, result: AnalysisResult) -> list[str]:
        notes = [
            "Findings are heuristic indicators derived from packet metadata. They describe "
            "what was observed and are not proof of malicious activity or compromise.",
            "Port numbers are shown only as hints: any protocol can use any port, and "
            "encrypted traffic (TLS, QUIC, SSH, VPNs) cannot be inspected.",
        ]
        traffic, parse, tcp = result.traffic, result.parse, result.tcp
        if traffic.total_packets and traffic.duration_seconds is None:
            notes.append(
                "The capture duration is unknown (fewer than two packets have timestamps), "
                "so rates and time-window rules could not be evaluated fully."
            )
        elif traffic.duration_seconds is not None and traffic.packets_per_second is None:
            notes.append(
                f"The capture spans less than {MIN_DURATION_FOR_RATE:g} second, so no "
                "packets-per-second rate is reported."
            )
        if parse.snaplen_limited_frames:
            notes.append(
                f"{parse.snaplen_limited_frames} frame(s) were stored shorter than their "
                "length on the wire (capture snapshot length). Protocol identification for "
                "those frames may be incomplete."
            )
        if traffic.ip_fragments:
            notes.append(
                f"{traffic.ip_fragments} IP fragment(s) were seen. NetSentry does not "
                "reassemble fragments, so their transport headers were not analysed."
            )
        one_way, pairs = _one_way_pairs(self.index)
        if pairs >= 10 and one_way / pairs > 0.5:
            notes.append(
                f"{one_way} of {pairs} host pairs show traffic in one direction only. The "
                "capture may be filtered, taken from a one-way mirror port, or affected by "
                "asymmetric routing, so connection outcomes may be unknown."
            )
        if tcp.unmatched_syn_acks:
            notes.append(
                f"{tcp.unmatched_syn_acks} SYN-ACK packet(s) had no matching SYN in the "
                "capture: some connections probably began before capture started."
            )
        if tcp.connection_attempts:
            notes.append(
                "TCP connection outcomes are inferred only from SYN-ACK and RST replies. "
                "'No reply observed' can mean a filtered port, packet loss or a capture gap."
            )
        if self._tunnel_protocols:
            kinds = ", ".join(
                f"{_TUNNEL_PROTOCOLS[p]} ({count})"
                for p, count in sorted(self._tunnel_protocols.items())
            )
            notes.append(
                f"Encapsulated traffic was observed: {kinds}. Only the outer headers were analysed."
            )
        if result.dns.malformed:
            notes.append(
                f"{result.dns.malformed} packet(s) on port 53 did not decode as DNS (for example "
                "DNS-over-TCP segments that continue a larger message, or non-DNS traffic)."
            )
        return notes


def _one_way_pairs(index: TrafficIndex) -> tuple[int, int]:
    """Count unicast host pairs, and how many of them only carried traffic one way."""
    pairs: set[frozenset[str]] = set()
    two_way: set[frozenset[str]] = set()
    for source, destination in index.directed_pairs:
        if is_multicast_or_broadcast(destination) or source == destination:
            continue
        pair = frozenset((source, destination))
        pairs.add(pair)
        if (destination, source) in index.directed_pairs:
            two_way.add(pair)
    return len(pairs) - len(two_way), len(pairs)


def _build_warnings(result: AnalysisResult) -> list[str]:
    """Describe problems with the capture data itself, most serious first."""
    parse, traffic = result.parse, result.traffic
    warnings: list[str] = []
    if parse.read_error:
        warnings.append(
            f"Reading stopped early: {parse.read_error}. Results cover only the "
            "packets read before that point."
        )
    if parse.stopped_at_packet_limit:
        warnings.append(
            f"Analysis stopped at the packet limit ({parse.packet_limit:,} packets). The rest "
            "of the capture was not analysed; use --max-packets to change the limit."
        )
    if parse.truncated_records:
        warnings.append(
            f"{parse.truncated_records} record(s) were cut off by the end of the file; the "
            "capture was probably truncated (for example, the capture tool was stopped abruptly)."
        )
    if parse.trailing_bytes_unparsed:
        warnings.append(
            f"{parse.trailing_bytes_unparsed} byte(s) at the end of the file could not be parsed "
            "as a complete record."
        )
    if parse.oversized_records:
        warnings.append(
            f"{parse.oversized_records} record(s) declared a length larger than the reader "
            "accepts and were cut short."
        )
    if parse.decode_failures:
        warnings.append(
            f"{parse.decode_failures} frame(s) could not be decoded and were counted "
            "but not analysed."
        )
    for link_type, count in sorted(parse.unsupported_link_type_frames.items()):
        warnings.append(
            f"{count} frame(s) use an unsupported link type ({link_type_name(link_type)}); they "
            "were counted but not decoded."
        )
    if parse.malformed_network_headers:
        warnings.append(
            f"{parse.malformed_network_headers} frame(s) announced an IP packet whose header "
            "could not be decoded (malformed or truncated)."
        )
    if traffic.undecoded_transport:
        warnings.append(
            f"{traffic.undecoded_transport} IP packet(s) had a TCP/UDP/ICMP header that could not "
            "be decoded (malformed or truncated)."
        )
    if parse.frames_without_timestamp:
        warnings.append(
            f"{parse.frames_without_timestamp} frame(s) have no timestamp (PCAPNG simple packet "
            "blocks); they are excluded from time-window rules."
        )
    if parse.frames_with_epoch_zero_timestamp:
        warnings.append(
            f"{parse.frames_with_epoch_zero_timestamp} frame(s) have a timestamp of 0 "
            "(1970-01-01); the capture clock may not have been set."
        )
    if parse.frames_out_of_order:
        warnings.append(
            f"{parse.frames_out_of_order} frame(s) have timestamps earlier than a previous "
            "frame (merged or reordered capture). Time-window rules sort events by time."
        )
    for message, count in sorted(parse.reader_warnings.items()):
        suffix = f" (x{count})" if count > 1 else ""
        warnings.append(f"Capture reader warning: {message}{suffix}")
    if traffic.total_packets == 0 and not parse.read_error:
        warnings.append("The capture is valid but contains no packets.")
    return warnings


def analyze_capture(
    path: str | Path,
    *,
    max_packets: int | None = DEFAULT_MAX_PACKETS,
    progress: Callable[[int], None] | None = None,
) -> AnalysisResult:
    """Read and analyse a capture file end to end (without running detections)."""
    info = inspect_capture_file(path)
    parse = ParseStats()
    analyzer = TrafficAnalyzer()
    for record in read_packets(path, info, parse, max_packets=max_packets, progress=progress):
        analyzer.add(record)
    return analyzer.finish(info, parse)
