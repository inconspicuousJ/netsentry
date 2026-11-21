"""Reading capture files and decoding frames into metadata-only PacketRecords.

Design notes
------------
* **Streaming.** Frames are read and decoded one at a time and handed to the
  caller as a generator, so memory use does not grow with the file size. Only
  small metadata records leave this module; Scapy packet objects (and the
  payload bytes inside them) are discarded immediately.
* **Read-only.** The capture is opened in binary read mode and never modified.
* **Honest accounting.** Every frame read is counted, and truncated records,
  undecodable frames, unsupported link types and odd timestamps are recorded in
  :class:`ParseStats` so that nothing is silently dropped.
* **Format detection by content.** The file's first bytes ("magic number")
  decide whether it is PCAP or PCAPNG; the file extension is not trusted.
"""

from __future__ import annotations

import gzip
import hashlib
import ipaddress
import logging
import struct
import zlib
from collections import Counter
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import IO, Any

# Scapy prints warnings on import (for example about missing libpcap, which is
# only needed for live capture). Silence them before importing Scapy itself.
logging.getLogger("scapy").setLevel(logging.ERROR)

from scapy.config import conf  # noqa: E402
from scapy.data import MTU  # noqa: E402
from scapy.error import Scapy_Exception  # noqa: E402
from scapy.layers.dns import DNS  # noqa: E402
from scapy.layers.inet import ICMP, IP, TCP, UDP  # noqa: E402
from scapy.layers.inet6 import (  # noqa: E402
    IPv6,
    IPv6ExtHdrDestOpt,
    IPv6ExtHdrFragment,
    IPv6ExtHdrHopByHop,
    IPv6ExtHdrRouting,
)
from scapy.layers.l2 import ARP  # noqa: E402
from scapy.packet import NoPayload, Packet, Padding, Raw  # noqa: E402
from scapy.utils import RawPcapNgReader, RawPcapReader  # noqa: E402

from .models import CaptureInfo, DnsInfo, PacketRecord, ParseStats  # noqa: E402
from .protocols import identify_cleartext_protocol  # noqa: E402
from .utils import escape_bytes, sanitize_text  # noqa: E402

DEFAULT_MAX_PACKETS = 1_000_000
DNS_UNDECODABLE = "DNS (undecodable)"
MAX_DNS_NAME_BYTES = 255  # RFC 1035 limit; longer names are cut and flagged
_SIGNATURE_BYTES = 4200  # enough for an HTTP request line check; never stored
_PROGRESS_EVERY = 5_000
_MAX_DISTINCT_WARNINGS = 25

_PCAP_MAGIC = {
    b"\xa1\xb2\xc3\xd4": "microsecond",
    b"\xd4\xc3\xb2\xa1": "microsecond",
    b"\xa1\xb2\x3c\x4d": "nanosecond",
    b"\x4d\x3c\xb2\xa1": "nanosecond",
}
_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
_GZIP_MAGIC = b"\x1f\x8b"

LINK_TYPE_NAMES: dict[int, str] = {
    0: "BSD loopback",
    1: "Ethernet",
    12: "Raw IP",
    101: "Raw IP",
    108: "OpenBSD loopback",
    113: "Linux cooked capture (SLL)",
    228: "Raw IPv4",
    229: "Raw IPv6",
    276: "Linux cooked capture v2 (SLL2)",
}
_RAW_IP_LINK_TYPES = frozenset({12, 14, 101, 228, 229})
_IP_ETHERTYPES = frozenset({0x0800, 0x86DD})
_LOOPBACK_IP_FAMILIES = frozenset({2, 24, 28, 30})  # AF_INET and the BSD AF_INET6 values
_IPV6_EXTENSION_HEADERS = (
    IPv6ExtHdrHopByHop,
    IPv6ExtHdrRouting,
    IPv6ExtHdrDestOpt,
    IPv6ExtHdrFragment,
)


def link_type_name(link_type: int) -> str:
    return LINK_TYPE_NAMES.get(link_type, f"link type {link_type}")


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class CaptureError(Exception):
    """A problem with the input capture that should be shown to the user."""


class CaptureNotFoundError(CaptureError):
    pass


class CaptureFormatError(CaptureError):
    pass


# ---------------------------------------------------------------------------
# File inspection
# ---------------------------------------------------------------------------


def inspect_capture_file(path: str | Path) -> CaptureInfo:
    """Validate the input path, identify the format and hash the file.

    The SHA-256 hash lets an analyst prove later which exact file a report was
    produced from (useful for evidence handling).
    """
    capture_path = Path(path)
    display_name = sanitize_text(capture_path.name or str(capture_path), max_length=120)
    if not capture_path.exists():
        raise CaptureNotFoundError(f"capture file not found: {display_name}")
    if not capture_path.is_file():
        raise CaptureError(f"not a regular file: {display_name}")

    digest = hashlib.sha256()
    try:
        with capture_path.open("rb") as handle:
            head = handle.read(1024 * 1024)
            digest.update(head)
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
        size = capture_path.stat().st_size
    except PermissionError:
        raise CaptureError(f"permission denied when reading {display_name}") from None
    except OSError as exc:
        raise CaptureError(f"could not read {display_name}: {sanitize_text(exc)}") from None

    if size == 0 or not head:
        raise CaptureFormatError(f"{display_name} is empty (0 bytes), so it is not a capture")

    compressed = head.startswith(_GZIP_MAGIC)
    magic = head[:4]
    if compressed:
        try:
            with gzip.open(capture_path, "rb") as inner:
                magic = inner.read(4)
        except (OSError, EOFError, zlib.error):
            raise CaptureFormatError(
                f"{display_name} looks gzip-compressed but could not be decompressed"
            ) from None

    if magic in _PCAP_MAGIC:
        file_format, precision = "pcap", _PCAP_MAGIC[magic]
    elif magic == _PCAPNG_MAGIC:
        file_format, precision = "pcapng", None
    else:
        raise CaptureFormatError(
            f"{display_name} is not a supported capture: it does not start with a PCAP or "
            "PCAPNG signature (is it a text file, a different capture format, or damaged?)"
        )

    return CaptureInfo(
        file_name=display_name,
        file_size=size,
        sha256=digest.hexdigest(),
        file_format=file_format,
        compressed=compressed,
        timestamp_precision=precision,
    )


# ---------------------------------------------------------------------------
# Streaming reader
# ---------------------------------------------------------------------------


class _WarningCollector(logging.Handler):
    """Captures Scapy's reader warnings so they can be reported, not printed."""

    def __init__(self) -> None:
        super().__init__(logging.WARNING)
        self.total = 0
        self.messages: Counter[str] = Counter()

    def emit(self, record: logging.LogRecord) -> None:
        try:
            message = record.getMessage()
        except Exception:  # a malformed log call must never break analysis
            message = str(record.msg)
        self.total += 1
        text = sanitize_text(message, max_length=160)
        if text in self.messages or len(self.messages) < _MAX_DISTINCT_WARNINGS:
            self.messages[text] += 1


@contextmanager
def _collect_scapy_warnings() -> Iterator[_WarningCollector]:
    runtime_logger = logging.getLogger("scapy.runtime")
    collector = _WarningCollector()
    saved = (runtime_logger.propagate, runtime_logger.level, conf.warning_threshold)
    runtime_logger.addHandler(collector)
    runtime_logger.propagate = False  # keep Scapy from printing to the terminal
    runtime_logger.setLevel(logging.WARNING)
    conf.warning_threshold = 0  # disable Scapy's rate limiting so every warning is counted
    try:
        yield collector
    finally:
        runtime_logger.removeHandler(collector)
        runtime_logger.propagate, level, conf.warning_threshold = saved
        runtime_logger.setLevel(level)


def read_packets(
    path: str | Path,
    info: CaptureInfo,
    stats: ParseStats,
    *,
    max_packets: int | None = DEFAULT_MAX_PACKETS,
    progress: Callable[[int], None] | None = None,
) -> Iterator[PacketRecord]:
    """Yield one :class:`PacketRecord` per frame, updating ``stats`` as it goes.

    ``max_packets`` bounds processing time for very large captures; ``None``
    or 0 means no limit. If the limit is reached, ``stats.stopped_at_packet_limit``
    is set so the report can say the analysis is partial.
    """
    limit = max_packets or None
    stats.packet_limit = limit
    with _collect_scapy_warnings() as collector, Path(path).open("rb") as handle:
        try:
            # Scapy accepts an open file object here (its type hint only says str).
            # Passing our own handle guarantees the file is closed on every path.
            reader = RawPcapReader(handle)  # type: ignore[arg-type]
        except (Scapy_Exception, EOFError, OSError, struct.error, zlib.error) as exc:
            raise CaptureFormatError(
                f"{info.file_name} could not be opened as a capture: {_reason(exc, collector)}"
            ) from None

        try:
            yield from _read_frames(reader, info, stats, limit, progress, collector)
        finally:
            for message, count in collector.messages.items():
                stats.reader_warnings[message] += count


def _read_frames(
    reader: Any,
    info: CaptureInfo,
    stats: ParseStats,
    limit: int | None,
    progress: Callable[[int], None] | None,
    collector: _WarningCollector,
) -> Iterator[PacketRecord]:
    is_pcapng = isinstance(reader, RawPcapNgReader)
    nanosecond = bool(getattr(reader, "nano", False))
    stream: IO[bytes] = reader.f
    latest_timestamp: float | None = None
    frame_number = 0

    while True:
        position_before = _tell(stream)
        warnings_before = collector.total
        try:
            data, metadata = next(reader)
        except StopIteration:
            _check_end_of_capture(
                stream, position_before, warnings_before, collector, is_pcapng, info, stats
            )
            return
        except (Scapy_Exception, EOFError, OSError, struct.error, zlib.error, ValueError) as exc:
            # Keep what was read so far, but make the failure prominent.
            stats.read_error = (
                f"reading stopped after frame {frame_number}: {_reason(exc, collector)}"
            )
            return

        if limit is not None and frame_number >= limit:
            stats.stopped_at_packet_limit = True
            return
        frame_number += 1
        stats.frames_read += 1

        if is_pcapng:
            link_type = metadata.linktype
            timestamp = (
                None
                if metadata.tshigh is None
                else ((metadata.tshigh << 32) | metadata.tslow) / metadata.tsresol
            )
            original_length = metadata.wirelen
            stored_length = len(data)
        else:
            link_type = reader.linktype
            timestamp = metadata.sec + metadata.usec / (1e9 if nanosecond else 1e6)
            original_length = metadata.wirelen
            stored_length = metadata.caplen
            if len(data) < min(metadata.caplen, MTU):
                stats.truncated_records += 1  # the file ended part-way through this frame
            elif metadata.caplen > MTU:
                stats.oversized_records += 1

        if original_length is not None and stored_length < original_length:
            stats.snaplen_limited_frames += 1

        if timestamp is None:
            stats.frames_without_timestamp += 1
        else:
            if timestamp == 0:
                stats.frames_with_epoch_zero_timestamp += 1
            if latest_timestamp is not None and timestamp < latest_timestamp:
                stats.frames_out_of_order += 1
            latest_timestamp = (
                timestamp if latest_timestamp is None else max(latest_timestamp, timestamp)
            )

        stats.link_types[link_type] += 1
        yield decode_frame(data, link_type, frame_number, timestamp, original_length, stats)

        if progress is not None and frame_number % _PROGRESS_EVERY == 0:
            progress(frame_number)


def _check_end_of_capture(
    stream: IO[bytes],
    position_before: int | None,
    warnings_before: int,
    collector: _WarningCollector,
    is_pcapng: bool,
    info: CaptureInfo,
    stats: ParseStats,
) -> None:
    """Work out whether reading ended cleanly or because the file was damaged."""
    position_after = _tell(stream)
    if (
        not is_pcapng
        and position_before is not None
        and position_after is not None
        and position_after > position_before
    ):
        # A clean PCAP ends exactly after a record. Leftover bytes are a
        # partial record header: the file was cut off (e.g. capture killed).
        stats.trailing_bytes_unparsed += position_after - position_before
    if is_pcapng and collector.total > warnings_before:
        stats.read_error = stats.read_error or "the final PCAPNG block is incomplete or corrupt"
    if not info.compressed and position_after is not None and position_after < info.file_size:
        stats.trailing_bytes_unparsed += info.file_size - position_after


def _tell(stream: IO[bytes]) -> int | None:
    try:
        return stream.tell()
    except (OSError, ValueError, AttributeError):
        return None


def _reason(exc: BaseException, collector: _WarningCollector) -> str:
    detail = str(exc) or exc.__class__.__name__
    if collector.messages:
        detail = f"{detail} ({next(iter(collector.messages))})"
    return sanitize_text(detail, max_length=200)


# ---------------------------------------------------------------------------
# Frame decoding
# ---------------------------------------------------------------------------


def decode_frame(
    data: bytes,
    link_type: int,
    index: int,
    timestamp: float | None,
    original_length: int | None,
    stats: ParseStats,
) -> PacketRecord:
    """Decode one frame with Scapy and keep only the metadata NetSentry needs."""
    base: dict[str, Any] = {
        "index": index,
        "timestamp": timestamp,
        "captured_length": len(data),
        "original_length": original_length,
        "link_type": link_type,
    }
    layer_class = conf.l2types.num2layer.get(link_type)
    if layer_class is None:
        stats.unsupported_link_type_frames[link_type] += 1
        return PacketRecord(**base, network="other", decode_error="unsupported link type")

    try:
        packet = layer_class(data)
        fields = _extract_fields(packet, link_type)
    except Exception as exc:  # Scapy can raise many exception types on hostile input
        stats.decode_failures += 1
        return PacketRecord(
            **base, network="other", decode_error=f"decoding failed ({exc.__class__.__name__})"
        )

    stats.frames_decoded += 1
    if fields["network"] == "malformed IP":
        stats.malformed_network_headers += 1
    return PacketRecord(**base, **fields)


def _extract_fields(packet: Packet, link_type: int) -> dict[str, Any]:
    network_layer = _find_network_layer(packet)
    if network_layer is None:
        malformed = _link_layer_announces_ip(packet, link_type)
        return {"network": "malformed IP" if malformed else "other"}
    if isinstance(network_layer, ARP):
        return {"network": "ARP"}

    fields: dict[str, Any] = {
        "src_ip": _normalise_address(network_layer.src),
        "dst_ip": _normalise_address(network_layer.dst),
    }
    is_fragment = False
    if type(network_layer) is IP:
        fields["network"] = "IPv4"
        protocol = int(network_layer.proto)
        is_fragment = int(network_layer.frag) > 0
        transport_layer = network_layer.payload
    else:
        fields["network"] = "IPv6"
        protocol = int(network_layer.nh)
        transport_layer = network_layer.payload
        # IPv6 can chain optional "extension headers" before the transport header.
        while isinstance(transport_layer, _IPV6_EXTENSION_HEADERS):
            if isinstance(transport_layer, IPv6ExtHdrFragment) and int(transport_layer.offset) > 0:
                is_fragment = True
            protocol = int(transport_layer.nh)
            transport_layer = transport_layer.payload

    fields["ip_protocol"] = protocol
    fields["is_fragment"] = is_fragment
    if is_fragment:
        # Later fragments carry no transport header; NetSentry does not reassemble.
        return fields

    layer_type = type(transport_layer)
    if layer_type is TCP or layer_type is UDP:
        _extract_ports(transport_layer, fields)
    elif layer_type is ICMP:
        fields["transport"] = "ICMP"
        fields["icmp_type"] = int(transport_layer.type)
        fields["icmp_code"] = int(transport_layer.code)
    elif protocol == 58 and layer_type.__name__.startswith("ICMPv6"):
        fields["transport"] = "ICMPv6"
        fields["icmp_type"] = int(transport_layer.type)
        fields["icmp_code"] = int(getattr(transport_layer, "code", 0))
    return fields


def _extract_ports(layer: Packet, fields: dict[str, Any]) -> None:
    is_tcp = type(layer) is TCP
    src_port = int(layer.sport)
    dst_port = int(layer.dport)
    fields["transport"] = "TCP" if is_tcp else "UDP"
    fields["src_port"] = src_port
    fields["dst_port"] = dst_port
    if is_tcp:
        fields["tcp_flags"] = int(layer.flags)
        fields["tcp_seq"] = int(layer.seq)
        fields["tcp_ack"] = int(layer.ack)

    payload = layer.payload
    if isinstance(payload, DNS):
        if 53 in (src_port, dst_port):
            try:
                fields["dns"] = _extract_dns(payload)
                fields["app_protocol"] = "DNS"
            except Exception:  # hostile DNS content must only cost the DNS fields
                fields["app_protocol"] = DNS_UNDECODABLE
        elif 5353 in (src_port, dst_port):
            fields["app_protocol"] = "mDNS"
        fields["payload_length"] = _payload_length(layer)
        return

    data = _payload_bytes(layer)
    fields["payload_length"] = len(data)
    if not data:
        return
    if 53 in (src_port, dst_port):
        fields["app_protocol"] = DNS_UNDECODABLE
    elif is_tcp:
        identified = identify_cleartext_protocol(data[:_SIGNATURE_BYTES], src_port, dst_port)
        if identified is not None:
            fields["app_protocol"], fields["app_direction"] = identified


def _extract_dns(dns: Packet) -> DnsInfo:
    questions = dns.qd if isinstance(dns.qd, list) else []
    question = questions[0] if questions else None
    raw_name = getattr(question, "qname", None) if question is not None else None
    if isinstance(raw_name, str):
        raw_name = raw_name.encode("utf-8", "surrogateescape")

    name: str | None = None
    name_length = 0
    longest_label = 0
    truncated = False
    if isinstance(raw_name, bytes):
        name_bytes = raw_name.rstrip(b".").lower()
        name_length = len(name_bytes)
        if name_length > MAX_DNS_NAME_BYTES:
            name_bytes = name_bytes[:MAX_DNS_NAME_BYTES]
            truncated = True
        longest_label = max((len(label) for label in name_bytes.split(b".")), default=0)
        name = escape_bytes(name_bytes) if name_bytes else "."

    answers = dns.an if isinstance(dns.an, list) else []
    is_response = bool(dns.qr)
    question_type = getattr(question, "qtype", None)
    return DnsInfo(
        is_response=is_response,
        transaction_id=int(dns.id),
        opcode=int(dns.opcode),
        rcode=int(dns.rcode) if is_response else None,
        question_name=name,
        question_name_length=name_length,
        longest_label_length=longest_label,
        question_type=int(question_type) if question_type is not None else None,
        question_count=len(questions),
        answer_count=len(answers),
        name_truncated=truncated,
    )


def _find_network_layer(packet: Packet) -> Packet | None:
    """Return the outermost IPv4, IPv6 or ARP layer.

    Exact type checks are used on purpose: Scapy's ``IPerror``/``TCPerror``
    (headers quoted inside ICMP error messages) are subclasses of IP/TCP and
    must not be mistaken for the packet's own headers.
    """
    layer: Packet = packet
    while not isinstance(layer, NoPayload):
        if type(layer) is IP or type(layer) is IPv6 or type(layer) is ARP:
            return layer
        layer = layer.payload
    return None


def _link_layer_announces_ip(packet: Packet, link_type: int) -> bool:
    """True when the link layer says "IP follows" but no IP header decoded."""
    if link_type in _RAW_IP_LINK_TYPES:
        return True
    layer: Packet = packet
    while not isinstance(layer, NoPayload | Raw):
        ethertype = getattr(layer, "type", None)
        if ethertype in _IP_ETHERTYPES or getattr(layer, "proto", None) in _IP_ETHERTYPES:
            return True
        if link_type in (0, 108) and ethertype in _LOOPBACK_IP_FAMILIES:
            return True
        layer = layer.payload
    return False


def _payload_bytes(layer: Packet) -> bytes:
    """Transport payload bytes as captured, excluding Ethernet padding."""
    payload = layer.payload
    if isinstance(payload, NoPayload):
        return b""
    data = bytes(payload)
    padding = layer.getlayer(Padding)
    if padding is not None:
        data = data[: len(data) - len(padding.load)]
    return data


def _payload_length(layer: Packet) -> int | None:
    try:
        return len(_payload_bytes(layer))
    except Exception:  # re-serialising a hostile decoded layer can fail; length is optional
        return None


_ADDRESS_CACHE: dict[str, str] = {}


def _normalise_address(value: object) -> str | None:
    """Return a canonical address string (e.g. compressed IPv6), cached for speed."""
    if value is None:
        return None
    text = str(value)
    cached = _ADDRESS_CACHE.get(text)
    if cached is None:
        try:
            cached = str(ipaddress.ip_address(text))
        except ValueError:
            cached = sanitize_text(text, max_length=64)
        if len(_ADDRESS_CACHE) < 200_000:
            _ADDRESS_CACHE[text] = cached
    return cached
