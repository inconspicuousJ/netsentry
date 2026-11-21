"""Generate synthetic demo captures for trying NetSentry.

    python samples/generate_samples.py            # writes into samples/
    python samples/generate_samples.py --output-dir somewhere/

Every packet is fabricated: addresses come from the IETF documentation ranges
(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32), which are
reserved for examples and never routed on the internet. Nothing is sent on the
network; the packets are only written to files.

Scenarios
---------
benign_browsing.pcap   DNS lookups, HTTPS connections and NTP: should be quiet.
port_scan.pcap         Ordinary traffic plus one host scanning another's ports.
mixed_incident.pcapng  Several patterns at once (scan, SSH connection storm,
                       DNS tunnelling-like names, a failing beacon domain,
                       Telnet, a connection to port 4444, cleartext HTTP).
"""

from __future__ import annotations

import argparse
import logging
import random
from pathlib import Path

logging.getLogger("scapy").setLevel(logging.ERROR)

from scapy.layers.dns import DNS, DNSQR, DNSRR  # noqa: E402
from scapy.layers.inet import IP, TCP, UDP  # noqa: E402
from scapy.layers.inet6 import IPv6  # noqa: E402
from scapy.layers.l2 import Ether  # noqa: E402
from scapy.packet import Packet, Raw  # noqa: E402
from scapy.utils import PcapNgWriter, PcapWriter  # noqa: E402

START = 1_735_725_600.0  # 2025-01-01T10:00:00Z

WORKSTATION = "192.0.2.15"
LAPTOP = "192.0.2.23"
RESOLVER = "192.0.2.53"
SCANNER = "203.0.113.66"
FILE_SERVER = "192.0.2.80"
WEB_SERVERS = [f"198.51.100.{n}" for n in (10, 11, 12, 20, 21, 30)]
SITES = [
    "www.example.com",
    "news.example.org",
    "cdn.example.net",
    "mail.example.com",
    "docs.example.org",
    "static.example.net",
]


class Capture:
    def __init__(self, seed: int) -> None:
        self.packets: list[Packet] = []
        self.random = random.Random(seed)  # deterministic: same files every run
        self._ports = 49152

    def ephemeral_port(self) -> int:
        self._ports += 1
        return self._ports

    def add(self, packet: Packet, t: float) -> None:
        packet.time = START + t
        self.packets.append(packet)

    def frame(self, src: str, dst: str) -> Packet:
        network = IPv6(src=src, dst=dst) if ":" in src else IP(src=src, dst=dst)
        return Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / network

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
    ) -> None:
        packet = self.frame(src, dst) / TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack)
        self.add(packet / Raw(payload) if payload else packet, t)

    def session(
        self,
        client: str,
        server: str,
        port: int,
        t: float,
        *,
        outcome: str = "accept",
        request: bytes = b"",
        response: bytes = b"",
        data_packets: int = 4,
    ) -> None:
        """A TCP handshake followed by a little traffic, or a refused/unanswered attempt."""
        cport = self.ephemeral_port()
        isn = self.random.randrange(1, 2**31)
        self.tcp(client, server, cport, port, "S", t, seq=isn)
        if outcome == "refuse":
            self.tcp(server, client, port, cport, "RA", t + 0.0004, ack=isn + 1)
            return
        if outcome == "none":
            return
        server_isn = self.random.randrange(1, 2**31)
        rtt = self.random.uniform(0.008, 0.03)
        self.tcp(server, client, port, cport, "SA", t + rtt, seq=server_isn, ack=isn + 1)
        self.tcp(client, server, cport, port, "A", t + rtt * 1.1, seq=isn + 1, ack=server_isn + 1)
        moment = t + rtt * 1.2
        first_payload = request or bytes(self.random.getrandbits(8) for _ in range(64))
        self.tcp(
            client,
            server,
            cport,
            port,
            "PA",
            moment,
            seq=isn + 1,
            ack=server_isn + 1,
            payload=first_payload,
        )
        for i in range(data_packets):
            body = (
                response
                if (i == 0 and response)
                else bytes(self.random.getrandbits(8) for _ in range(200))
            )
            moment += rtt
            self.tcp(
                server,
                client,
                port,
                cport,
                "PA",
                moment,
                seq=server_isn + 1,
                ack=isn + 65,
                payload=body,
            )
        self.tcp(client, server, cport, port, "FA", moment + 0.01, seq=isn + 65)
        self.tcp(server, client, port, cport, "FA", moment + 0.02, seq=server_isn + 1)

    def lookup(
        self, client: str, name: str, t: float, *, rcode: int = 0, address: str = "198.51.100.10"
    ) -> None:
        txid = self.random.randrange(1, 65535)
        sport = self.ephemeral_port()
        query = DNS(id=txid, rd=1, qd=DNSQR(qname=name))
        self.add(self.frame(client, RESOLVER) / UDP(sport=sport, dport=53) / query, t)
        answers = [DNSRR(rrname=name, rdata=address, ttl=300)] if rcode == 0 else []
        response = DNS(id=txid, qr=1, rd=1, ra=1, rcode=rcode, qd=DNSQR(qname=name), an=answers)
        self.add(self.frame(RESOLVER, client) / UDP(sport=53, dport=sport) / response, t + 0.012)

    def write(self, path: Path) -> None:
        self.packets.sort(key=lambda p: float(p.time))
        writer = (PcapNgWriter if path.suffix == ".pcapng" else PcapWriter)(str(path))
        for packet in self.packets:
            writer.write(packet)
        writer.close()


def normal_activity(capture: Capture, duration: float) -> None:
    """Browsing-like background traffic: lookups, HTTPS sessions, NTP."""
    t = 0.0
    while t < duration:
        client = capture.random.choice([WORKSTATION, LAPTOP])
        index = capture.random.randrange(len(SITES))
        capture.lookup(client, SITES[index], t, address=WEB_SERVERS[index])
        capture.session(client, WEB_SERVERS[index], 443, t + 0.05)
        t += capture.random.uniform(0.8, 3.0)
    for minute in range(int(duration // 60) + 1):
        sport = capture.ephemeral_port()
        capture.add(
            capture.frame(WORKSTATION, "192.0.2.1")
            / UDP(sport=sport, dport=123)
            / Raw(b"\x23" + b"\x00" * 47),
            minute * 60 + 5,
        )
        capture.add(
            capture.frame("192.0.2.1", WORKSTATION)
            / UDP(sport=123, dport=sport)
            / Raw(b"\x24" + b"\x00" * 47),
            minute * 60 + 5.01,
        )


def port_scan(capture: Capture, start: float, target: str, ports: range) -> None:
    open_ports = {22, 80, 443}
    for i, port in enumerate(ports):
        capture.session(
            SCANNER,
            target,
            port,
            start + i * 0.02,
            outcome="accept" if port in open_ports else "refuse",
            data_packets=0,
        )


def build_benign() -> Capture:
    capture = Capture(seed=1)
    normal_activity(capture, duration=180)
    return capture


def build_port_scan() -> Capture:
    capture = Capture(seed=2)
    normal_activity(capture, duration=120)
    port_scan(capture, start=40.0, target=FILE_SERVER, ports=range(1, 101))
    return capture


def build_mixed_incident() -> Capture:
    capture = Capture(seed=3)
    normal_activity(capture, duration=300)
    port_scan(capture, start=20.0, target=FILE_SERVER, ports=range(1, 61))

    # Many short SSH connections refused by the server: a connection storm.
    for i in range(25):
        capture.session(LAPTOP, FILE_SERVER, 22, 100 + i * 1.5, outcome="refuse")

    # Long, encoded-looking subdomains under one domain (DNS tunnelling pattern).
    for i in range(15):
        label = "".join(capture.random.choice("0123456789abcdef") for _ in range(56))
        capture.lookup(WORKSTATION, f"{label}.{i:03d}.data.exfil-demo.example", 150 + i * 0.7)

    # A name that never resolves, queried every 10 seconds (beacon-like).
    for i in range(24):
        capture.lookup(LAPTOP, "update.stale-service.example", 30 + i * 10, rcode=3)

    # Telnet option negotiation and a connection to port 4444.
    capture.session(
        WORKSTATION,
        "192.0.2.90",
        23,
        200,
        request=b"\xff\xfb\x18\xff\xfb\x1f",
        response=b"\xff\xfd\x18\xff\xfd\x20",
    )
    capture.session(WORKSTATION, "198.51.100.99", 4444, 210, data_packets=2)

    # Cleartext HTTP.
    capture.session(
        LAPTOP,
        WEB_SERVERS[0],
        80,
        220,
        request=b"GET /status HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        response=b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
    )

    # A little IPv6 traffic so both address families appear.
    for i in range(5):
        capture.session("2001:db8::15", "2001:db8:100::443", 443, 240 + i)
    return capture


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate synthetic NetSentry demo captures.")
    parser.add_argument("--output-dir", type=Path, default=Path(__file__).resolve().parent)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    for name, build in (
        ("benign_browsing.pcap", build_benign),
        ("port_scan.pcap", build_port_scan),
        ("mixed_incident.pcapng", build_mixed_incident),
    ):
        capture = build()
        path = args.output_dir / name
        capture.write(path)
        print(f"wrote {path} ({len(capture.packets)} packets)")


if __name__ == "__main__":
    main()
