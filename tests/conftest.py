"""Shared test helpers: deterministic synthetic traffic written to real capture files.

All addresses come from documentation ranges (RFC 5737 / RFC 3849) unless a
test specifically needs a public address. Every packet gets an explicit
timestamp so results never depend on the clock.
"""

from __future__ import annotations

import struct
from collections.abc import Callable
from pathlib import Path

import pytest
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import ICMPv6EchoReply, ICMPv6EchoRequest, IPv6
from scapy.layers.l2 import Ether
from scapy.packet import Packet, Raw
from scapy.utils import PcapNgWriter, PcapWriter

# Importing NetSentry first silences Scapy's import-time warnings.
from netsentry.analyzer import analyze_capture
from netsentry.config import DetectionConfig
from netsentry.detectors import run_detections
from netsentry.models import AnalysisResult, DetectionReport

START = 1_700_000_000.0  # 2023-11-14T22:13:20Z

CLIENT = "192.0.2.10"
SERVER = "198.51.100.20"
RESOLVER = "192.0.2.53"
CLIENT6 = "2001:db8::10"
SERVER6 = "2001:db8::20"


def eth() -> Packet:
    """Ethernet header with explicit, locally administered MAC addresses.

    Leaving the MACs unset makes Scapy try to resolve them (route lookups and
    possibly ARP), which is slow and is network activity a test must not cause.
    """
    return Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")


def _ip(src: str, dst: str) -> Packet:
    return IPv6(src=src, dst=dst) if ":" in src else IP(src=src, dst=dst)


class TrafficBuilder:
    """Builds a list of timestamped Scapy packets with protocol-correct replies."""

    def __init__(self, start: float = START) -> None:
        self.start = start
        self.packets: list[Packet] = []

    def add(self, packet: Packet, t: float) -> Packet:
        packet.time = self.start + t
        self.packets.append(packet)
        return packet

    # -- TCP ---------------------------------------------------------------

    def tcp(
        self,
        src: str,
        dst: str,
        sport: int,
        dport: int,
        flags: str,
        t: float,
        seq: int = 0,
        ack: int = 0,
        payload: bytes = b"",
    ) -> Packet:
        packet = (
            eth() / _ip(src, dst) / TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack)
        )
        if payload:
            packet = packet / Raw(payload)
        return self.add(packet, t)

    def syn(self, src: str, dst: str, sport: int, dport: int, t: float, seq: int = 1000) -> Packet:
        return self.tcp(src, dst, sport, dport, "S", t, seq=seq)

    def syn_ack(
        self, server: str, client: str, sport: int, cport: int, t: float, client_seq: int = 1000
    ) -> Packet:
        return self.tcp(server, client, sport, cport, "SA", t, seq=5000, ack=client_seq + 1)

    def rst_ack(
        self, server: str, client: str, sport: int, cport: int, t: float, client_seq: int = 1000
    ) -> Packet:
        return self.tcp(server, client, sport, cport, "RA", t, seq=0, ack=client_seq + 1)

    def connect(
        self,
        client: str,
        server: str,
        cport: int,
        sport: int,
        t: float,
        outcome: str = "accept",
        seq: int = 1000,
    ) -> None:
        """A SYN plus the reply: 'accept' (SYN-ACK), 'refuse' (RST) or 'none'."""
        self.syn(client, server, cport, sport, t, seq=seq)
        if outcome == "accept":
            self.syn_ack(server, client, sport, cport, t + 0.001, client_seq=seq)
        elif outcome == "refuse":
            self.rst_ack(server, client, sport, cport, t + 0.001, client_seq=seq)

    # -- UDP / DNS / ICMP ------------------------------------------------------

    def udp(
        self, src: str, dst: str, sport: int, dport: int, t: float, payload: bytes = b"data"
    ) -> Packet:
        return self.add(eth() / _ip(src, dst) / UDP(sport=sport, dport=dport) / Raw(payload), t)

    def dns_query(
        self,
        client: str,
        name: str | bytes,
        t: float,
        txid: int = 1,
        sport: int = 53000,
        server: str = RESOLVER,
        qtype: str = "A",
    ) -> Packet:
        dns = DNS(id=txid, rd=1, qd=DNSQR(qname=name, qtype=qtype))
        return self.add(eth() / _ip(client, server) / UDP(sport=sport, dport=53) / dns, t)

    def dns_response(
        self,
        client: str,
        name: str | bytes,
        t: float,
        txid: int = 1,
        dport: int = 53000,
        server: str = RESOLVER,
        rcode: int = 0,
    ) -> Packet:
        dns = DNS(id=txid, qr=1, ra=1, rcode=rcode, qd=DNSQR(qname=name))
        return self.add(eth() / _ip(server, client) / UDP(sport=53, dport=dport) / dns, t)

    def ping(self, src: str, dst: str, t: float, reply: bool = False) -> None:
        if ":" in src:
            self.add(eth() / IPv6(src=src, dst=dst) / ICMPv6EchoRequest(), t)
            if reply:
                self.add(eth() / IPv6(src=dst, dst=src) / ICMPv6EchoReply(), t + 0.001)
        else:
            self.add(eth() / IP(src=src, dst=dst) / ICMP(type=8), t)
            if reply:
                self.add(eth() / IP(src=dst, dst=src) / ICMP(type=0), t + 0.001)

    # -- output ------------------------------------------------------------------

    def write(self, path: Path, file_format: str = "pcap") -> Path:
        writer_class = PcapNgWriter if file_format == "pcapng" else PcapWriter
        writer = writer_class(str(path))
        for packet in self.packets:
            writer.write(packet)
        writer.close()
        return path


@pytest.fixture
def builder() -> TrafficBuilder:
    return TrafficBuilder()


@pytest.fixture
def write_capture(tmp_path: Path) -> Callable[..., Path]:
    counter = {"n": 0}

    def _write(traffic: TrafficBuilder, file_format: str = "pcap") -> Path:
        counter["n"] += 1
        suffix = "pcapng" if file_format == "pcapng" else "pcap"
        return traffic.write(tmp_path / f"capture{counter['n']}.{suffix}", file_format)

    return _write


@pytest.fixture
def analyze(write_capture: Callable[..., Path]) -> Callable[..., AnalysisResult]:
    def _analyze(
        traffic: TrafficBuilder, file_format: str = "pcap", **kwargs: object
    ) -> AnalysisResult:
        return analyze_capture(write_capture(traffic, file_format), **kwargs)  # type: ignore[arg-type]

    return _analyze


@pytest.fixture
def detect(
    analyze: Callable[..., AnalysisResult],
) -> Callable[..., tuple[AnalysisResult, DetectionReport]]:
    def _detect(
        traffic: TrafficBuilder, config: DetectionConfig | None = None
    ) -> tuple[AnalysisResult, DetectionReport]:
        result = analyze(traffic)
        return result, run_detections(result, config or DetectionConfig())

    return _detect


def rule_findings(report: DetectionReport, rule_id: str) -> list:
    return [finding for finding in report.findings if finding.rule_id == rule_id]


def rule_suppressed(report: DetectionReport, rule_id: str) -> list:
    return [item for item in report.suppressed if item.rule_id == rule_id]


# -- hand-built PCAPNG blocks (for cases Scapy's writer cannot produce) ------------


def pcapng_block(block_type: int, body: bytes) -> bytes:
    padded = body + b"\x00" * (-len(body) % 4)
    total = 12 + len(padded)
    return struct.pack("<II", block_type, total) + padded + struct.pack("<I", total)


def pcapng_with_simple_packets(frames: list[bytes], link_type: int = 1) -> bytes:
    """A PCAPNG file whose packets are Simple Packet Blocks, which carry no timestamp."""
    section = pcapng_block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    interface = pcapng_block(1, struct.pack("<HHI", link_type, 0, 65535))
    simple = b"".join(pcapng_block(3, struct.pack("<I", len(f)) + f) for f in frames)
    return section + interface + simple


def pcap_bytes(frames: list[tuple[float, bytes]], link_type: int = 1) -> bytes:
    """A classic little-endian PCAP built by hand (lets tests control every field)."""
    header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, link_type)
    records = b""
    for timestamp, frame in frames:
        seconds = int(timestamp)
        micros = int(round((timestamp - seconds) * 1_000_000))
        records += struct.pack("<IIII", seconds, micros, len(frame), len(frame)) + frame
    return header + records
