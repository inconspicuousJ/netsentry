"""Capture loading: formats, damaged files, decoding edge cases."""

from __future__ import annotations

import gzip
import hashlib
from pathlib import Path

import pytest
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6, IPv6ExtHdrHopByHop
from scapy.layers.l2 import ARP, CookedLinux
from scapy.packet import Raw
from scapy.utils import PcapWriter

from conftest import (
    CLIENT,
    CLIENT6,
    SERVER,
    SERVER6,
    START,
    TrafficBuilder,
    eth,
    pcap_bytes,
    pcapng_with_simple_packets,
)
from netsentry import capture_loader
from netsentry.capture_loader import (
    DNS_UNDECODABLE,
    CaptureError,
    CaptureFormatError,
    CaptureNotFoundError,
    inspect_capture_file,
    read_packets,
)
from netsentry.models import PacketRecord, ParseStats


def load(path: Path, **kwargs: object) -> tuple[list[PacketRecord], ParseStats]:
    info = inspect_capture_file(path)
    stats = ParseStats()
    records = list(read_packets(path, info, stats, **kwargs))  # type: ignore[arg-type]
    return records, stats


def three_packets() -> TrafficBuilder:
    traffic = TrafficBuilder()
    traffic.syn(CLIENT, SERVER, 40000, 80, t=0.0)
    traffic.syn_ack(SERVER, CLIENT, 80, 40000, t=0.5)
    traffic.udp(CLIENT, SERVER, 5000, 9999, t=1.25)
    return traffic


# -- valid captures -------------------------------------------------------------------


@pytest.mark.parametrize("file_format", ["pcap", "pcapng"])
def test_valid_capture_is_read_in_order_with_timestamps(write_capture, file_format):
    path = write_capture(three_packets(), file_format)
    records, stats = load(path)

    assert [r.index for r in records] == [1, 2, 3]
    assert [r.timestamp for r in records] == pytest.approx([START, START + 0.5, START + 1.25])
    assert stats.frames_read == stats.frames_decoded == 3
    assert stats.link_types == {1: 3}
    first = records[0]
    assert (first.network, first.transport) == ("IPv4", "TCP")
    assert (first.src_ip, first.dst_ip, first.src_port, first.dst_port) == (
        CLIENT,
        SERVER,
        40000,
        80,
    )
    assert first.tcp_flags == 0x02
    assert inspect_capture_file(path).file_format == file_format


def test_capture_info_hash_matches_file_and_uses_base_name_only(write_capture):
    path = write_capture(three_packets())
    info = inspect_capture_file(path)
    assert info.sha256 == hashlib.sha256(path.read_bytes()).hexdigest()
    assert info.file_name == path.name  # no directory components (they can reveal user names)
    assert info.file_size == path.stat().st_size


def test_gzip_compressed_capture_is_supported(write_capture, tmp_path):
    plain = write_capture(three_packets())
    compressed = tmp_path / "capture.pcap.gz"
    compressed.write_bytes(gzip.compress(plain.read_bytes()))
    records, stats = load(compressed)
    assert inspect_capture_file(compressed).compressed is True
    assert len(records) == 3 and stats.trailing_bytes_unparsed == 0


def test_nanosecond_pcap_timestamps(tmp_path):
    path = tmp_path / "nano.pcap"
    writer = PcapWriter(str(path), nano=True)
    packet = eth() / IP(src=CLIENT, dst=SERVER) / UDP()
    packet.time = START + 0.000000250
    writer.write(packet)
    writer.close()
    records, _ = load(path)
    assert inspect_capture_file(path).timestamp_precision == "nanosecond"
    assert records[0].timestamp == pytest.approx(START + 0.00000025, abs=1e-6)


def test_input_capture_is_not_modified(write_capture):
    path = write_capture(three_packets())
    before = (path.read_bytes(), path.stat().st_mtime_ns)
    load(path)
    assert (path.read_bytes(), path.stat().st_mtime_ns) == before


# -- invalid and damaged files ----------------------------------------------------------


def test_missing_file(tmp_path):
    with pytest.raises(CaptureNotFoundError, match="not found"):
        inspect_capture_file(tmp_path / "nope.pcap")


def test_directory_is_rejected(tmp_path):
    with pytest.raises(CaptureError, match="not a regular file"):
        inspect_capture_file(tmp_path)


def test_empty_file_is_rejected(tmp_path):
    path = tmp_path / "empty.pcap"
    path.write_bytes(b"")
    with pytest.raises(CaptureFormatError, match="empty"):
        inspect_capture_file(path)


def test_text_file_is_rejected_by_content_not_extension(tmp_path):
    path = tmp_path / "notes.pcap"
    path.write_text("this is not a packet capture\n")
    with pytest.raises(CaptureFormatError, match="not a supported capture"):
        inspect_capture_file(path)


def test_invalid_gzip_is_rejected(tmp_path):
    path = tmp_path / "broken.pcap.gz"
    path.write_bytes(b"\x1f\x8b" + b"\x00" * 20)
    with pytest.raises(CaptureFormatError, match="gzip"):
        inspect_capture_file(path)


def test_header_shorter_than_pcap_global_header_is_rejected(tmp_path):
    path = tmp_path / "short.pcap"
    path.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x02\x00\x04\x00")  # valid magic, then cut off
    info = inspect_capture_file(path)
    with pytest.raises(CaptureFormatError, match="could not be opened"):
        list(read_packets(path, info, ParseStats()))


def test_valid_capture_with_zero_packets_is_not_an_error(tmp_path):
    path = tmp_path / "header-only.pcap"
    path.write_bytes(pcap_bytes([]))
    records, stats = load(path)
    assert records == []
    assert (
        stats.frames_read == 0 and stats.read_error is None and stats.trailing_bytes_unparsed == 0
    )


def test_record_cut_off_mid_packet_is_counted_as_truncated(write_capture, tmp_path):
    data = write_capture(three_packets()).read_bytes()
    path = tmp_path / "cut.pcap"
    path.write_bytes(data[:-10])
    records, stats = load(path)
    assert len(records) == 3  # earlier packets are still analysed
    assert stats.truncated_records == 1
    assert stats.reader_warnings  # Scapy's warning was captured instead of printed


def test_partial_record_header_at_end_is_reported(write_capture, tmp_path):
    data = write_capture(three_packets()).read_bytes()
    path = tmp_path / "cut-header.pcap"
    path.write_bytes(data + b"\x01\x02\x03\x04\x05")  # 5 bytes of a 16-byte record header
    records, stats = load(path)
    assert len(records) == 3
    assert stats.trailing_bytes_unparsed == 5


def test_truncated_pcapng_block_is_reported(write_capture, tmp_path):
    data = write_capture(three_packets(), "pcapng").read_bytes()
    path = tmp_path / "cut.pcapng"
    path.write_bytes(data[:-10])
    records, stats = load(path)
    assert len(records) == 2
    assert stats.read_error is not None and "incomplete" in stats.read_error


def test_pcapng_simple_packet_blocks_have_no_timestamp(tmp_path):
    frame = bytes(eth() / IP(src=CLIENT, dst=SERVER) / UDP(sport=1, dport=2))
    path = tmp_path / "spb.pcapng"
    path.write_bytes(pcapng_with_simple_packets([frame, frame]))
    records, stats = load(path)
    assert [r.timestamp for r in records] == [None, None]
    assert stats.frames_without_timestamp == 2
    assert records[0].transport == "UDP"


def test_unsupported_link_type_is_counted_not_decoded(tmp_path):
    path = tmp_path / "linktype.pcap"
    path.write_bytes(pcap_bytes([(START, b"\x00" * 30)], link_type=147))  # DLT_USER0
    records, stats = load(path)
    assert stats.unsupported_link_type_frames == {147: 1}
    assert records[0].decode_error == "unsupported link type"
    assert records[0].src_ip is None


def test_raw_ip_and_linux_cooked_link_types(tmp_path):
    raw_ip = bytes(IP(src=CLIENT, dst=SERVER) / TCP(sport=1234, dport=443, flags="S"))
    path = tmp_path / "raw.pcap"
    path.write_bytes(pcap_bytes([(START, raw_ip)], link_type=101))
    assert load(path)[0][0].dst_port == 443

    cooked = bytes(CookedLinux(proto=0x0800) / IP(src=CLIENT, dst=SERVER) / UDP(sport=1, dport=53))
    path = tmp_path / "sll.pcap"
    path.write_bytes(pcap_bytes([(START, cooked)], link_type=113))
    record = load(path)[0][0]
    assert (record.network, record.transport, record.dst_port) == ("IPv4", "UDP", 53)


def test_out_of_order_and_epoch_zero_timestamps(tmp_path):
    frame = bytes(eth() / IP(src=CLIENT, dst=SERVER) / UDP())
    path = tmp_path / "odd-times.pcap"
    path.write_bytes(pcap_bytes([(START + 5, frame), (START + 1, frame), (0.0, frame)]))
    records, stats = load(path)
    assert stats.frames_out_of_order == 2
    assert stats.frames_with_epoch_zero_timestamp == 1
    assert [r.index for r in records] == [1, 2, 3]  # file order is preserved


def test_packet_limit_stops_and_is_reported(write_capture):
    traffic = TrafficBuilder()
    for i in range(5):
        traffic.udp(CLIENT, SERVER, 5000 + i, 9999, t=i)
    path = write_capture(traffic)

    records, stats = load(path, max_packets=3)
    assert len(records) == 3 and stats.stopped_at_packet_limit is True and stats.packet_limit == 3

    records, stats = load(path, max_packets=5)  # exactly at the limit: nothing was skipped
    assert len(records) == 5 and stats.stopped_at_packet_limit is False

    records, stats = load(path, max_packets=0)  # 0 means unlimited
    assert len(records) == 5 and stats.packet_limit is None


# -- decoding --------------------------------------------------------------------------


def single(write_capture, packet, t: float = 0.0) -> PacketRecord:
    traffic = TrafficBuilder()
    traffic.add(packet, t)
    return load(write_capture(traffic))[0][0]


def test_ipv6_tcp_behind_extension_header(write_capture):
    packet = (
        eth()
        / IPv6(src=CLIENT6, dst=SERVER6)
        / IPv6ExtHdrHopByHop()
        / TCP(sport=1000, dport=22, flags="S")
    )
    record = single(write_capture, packet)
    assert (record.network, record.transport, record.ip_protocol) == ("IPv6", "TCP", 6)
    assert (record.src_ip, record.dst_ip, record.dst_port) == (CLIENT6, SERVER6, 22)


def test_ipv6_addresses_are_canonicalised(write_capture):
    packet = eth() / IPv6(src="2001:0DB8:0000:0000:0000:0000:0000:0010", dst=SERVER6) / UDP()
    assert single(write_capture, packet).src_ip == "2001:db8::10"


def test_icmp_error_quoting_tcp_is_icmp_not_tcp(write_capture):
    quoted = IP(src=CLIENT, dst=SERVER) / TCP(sport=40000, dport=80, flags="S")
    packet = eth() / IP(src=SERVER, dst=CLIENT) / ICMP(type=3, code=3) / quoted
    record = single(write_capture, packet)
    assert (record.transport, record.icmp_type, record.icmp_code) == ("ICMP", 3, 3)
    assert record.src_port is None and record.tcp_flags is None


def test_non_first_ip_fragment_has_no_transport(write_capture):
    packet = eth() / IP(src=CLIENT, dst=SERVER, proto=6, frag=100) / Raw(b"x" * 40)
    record = single(write_capture, packet)
    assert record.is_fragment and record.transport is None and record.ip_protocol == 6


def test_truncated_ip_header_is_reported_as_malformed(tmp_path):
    frame = bytes(eth() / IP(src=CLIENT, dst=SERVER) / TCP())[: 14 + 12]
    path = tmp_path / "bad-ip.pcap"
    path.write_bytes(pcap_bytes([(START, frame)]))
    records, stats = load(path)
    assert records[0].network == "malformed IP" and records[0].src_ip is None
    assert stats.malformed_network_headers == 1


def test_truncated_tcp_header_keeps_ip_metadata(tmp_path):
    frame = bytes(eth() / IP(src=CLIENT, dst=SERVER) / TCP())[: 14 + 20 + 6]
    path = tmp_path / "bad-tcp.pcap"
    path.write_bytes(pcap_bytes([(START, frame)]))
    record = load(path)[0][0]
    assert record.src_ip == CLIENT and record.ip_protocol == 6 and record.transport is None


def test_arp_is_counted_as_non_ip(write_capture):
    record = single(write_capture, eth() / ARP(psrc=CLIENT, pdst=SERVER))
    assert record.network == "ARP" and record.src_ip is None


def test_dns_fields_are_normalised(write_capture):
    packet = (
        eth()
        / IP(src=CLIENT, dst=SERVER)
        / UDP(sport=5000, dport=53)
        / DNS(id=77, qd=DNSQR(qname="WWW.Example.COM.", qtype="AAAA"))
    )
    record = single(write_capture, packet)
    assert record.app_protocol == "DNS" and record.dns is not None
    dns = record.dns
    assert (dns.question_name, dns.question_type, dns.transaction_id) == ("www.example.com", 28, 77)
    assert (dns.question_name_length, dns.longest_label_length, dns.is_response) == (15, 7, False)


def test_dns_name_control_bytes_are_escaped(write_capture):
    packet = (
        eth()
        / IP(src=CLIENT, dst=SERVER)
        / UDP(sport=5000, dport=53)
        / DNS(qd=DNSQR(qname=b"evil\x1b[31m.example"))
    )
    name = single(write_capture, packet).dns.question_name
    assert "\x1b" not in name and name == "evil\\x1b[31m.example"


def test_overlong_dns_name_is_cut_and_flagged(write_capture):
    long_name = ".".join(["a" * 60] * 6)  # 365 bytes: more than DNS allows
    packet = (
        eth()
        / IP(src=CLIENT, dst=SERVER)
        / UDP(sport=5000, dport=53)
        / DNS(qd=DNSQR(qname=long_name))
    )
    dns = single(write_capture, packet).dns
    assert dns.name_truncated is True
    assert dns.question_name_length == len(long_name)
    assert len(dns.question_name) == capture_loader.MAX_DNS_NAME_BYTES


def test_garbage_on_port_53_is_marked_undecodable(write_capture):
    packet = eth() / IP(src=CLIENT, dst=SERVER) / UDP(sport=5000, dport=53) / Raw(b"\xff" * 7)
    record = single(write_capture, packet)
    assert record.app_protocol == DNS_UNDECODABLE and record.dns is None


def test_dns_field_extraction_failure_keeps_packet_metadata(write_capture, monkeypatch):
    def broken(_dns):
        raise TypeError("hostile DNS content")

    monkeypatch.setattr(capture_loader, "_extract_dns", broken)
    packet = (
        eth()
        / IP(src=CLIENT, dst=SERVER)
        / UDP(sport=5000, dport=53)
        / DNS(qd=DNSQR(qname="x.example"))
    )
    record = single(write_capture, packet)
    assert record.app_protocol == DNS_UNDECODABLE and record.dns is None
    assert (record.src_ip, record.transport, record.dst_port) == (CLIENT, "UDP", 53)


def test_records_never_contain_payload_bytes(write_capture):
    secret = b"password=hunter2"
    packet = (
        eth()
        / IP(src=CLIENT, dst=SERVER)
        / TCP(sport=40000, dport=80, flags="PA")
        / Raw(b"POST /login HTTP/1.1\r\nHost: x\r\n\r\n" + secret)
    )
    record = single(write_capture, packet)
    assert record.app_protocol == "HTTP" and record.payload_length is not None
    assert "hunter2" not in repr(record)
    assert not hasattr(record, "payload")


def test_dissection_exception_is_counted_not_fatal(write_capture, monkeypatch):
    class Exploding:
        def __init__(self, data: bytes) -> None:
            raise ValueError("boom")

    path = write_capture(three_packets())
    monkeypatch.setitem(capture_loader.conf.l2types.num2layer, 1, Exploding)
    records, stats = load(path)
    assert len(records) == 3 and stats.decode_failures == 3
    assert records[0].decode_error == "decoding failed (ValueError)"


def test_scapy_logging_state_is_restored(write_capture):
    import logging

    runtime = logging.getLogger("scapy.runtime")
    before = (
        runtime.propagate,
        runtime.level,
        list(runtime.handlers),
        capture_loader.conf.warning_threshold,
    )
    load(write_capture(three_packets()))
    after = (
        runtime.propagate,
        runtime.level,
        list(runtime.handlers),
        capture_loader.conf.warning_threshold,
    )
    assert before == after
