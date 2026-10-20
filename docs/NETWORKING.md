# Networking concepts used by NetSentry

This guide explains the networking ideas you need to understand NetSentry's output and to talk
about it confidently. It starts from the basics and stays practical: each section ends with
what it means for traffic analysis.

- [Layers](#layers-how-a-packet-is-built)
- [IP addresses](#ip-addresses)
- [TCP and UDP](#tcp-and-udp)
- [Ports](#ports)
- [TCP flags and the handshake](#tcp-flags-and-the-three-way-handshake)
- [Retransmissions](#retransmissions)
- [ICMP](#icmp)
- [DNS](#dns)
- [Packet captures](#packet-captures)
- [Capture filters and missing packets](#capture-filters-and-missing-packets)
- [Encryption](#encryption-what-a-capture-cannot-show)

---

## Layers: how a packet is built

Network data is wrapped in layers, like an envelope inside an envelope. Each layer adds a
*header* with the information it needs:

```text
+-----------------+--------------------+--------------------+-------------------------+
| Ethernet header | IP header          | TCP header         | Payload (application)   |
| MAC addresses   | source/destination | ports, flags,      | e.g. an HTTP request    |
| (local link)    | IP address         | sequence numbers   | or a TLS record         |
+-----------------+--------------------+--------------------+-------------------------+
   Link layer        Network layer        Transport layer      Application layer
```

When NetSentry says a protocol was identified from a **decoded header**, it means Scapy
parsed that header successfully. That is stronger evidence than a guess based on a port number.

## IP addresses

An IP address identifies a network interface.

- **IPv4** addresses are 32 bits, written as four numbers: `192.0.2.10`.
- **IPv6** addresses are 128 bits, written in hexadecimal groups: `2001:db8::10` (`::` stands
  for a run of zero groups). NetSentry prints IPv6 addresses in this compressed, lower-case
  canonical form so the same address always looks the same.

Some ranges are special:

| Range | Meaning |
|---|---|
| `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7` | Private: used inside networks, not routed on the internet. |
| `127.0.0.0/8`, `::1` | Loopback: the machine talking to itself. |
| `224.0.0.0/4`, `ff00::/8`, `255.255.255.255` | Multicast and broadcast: one sender, many receivers. |
| `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32` | Documentation ranges, reserved for examples. NetSentry's samples and tests use these. |

The `/24` part is **CIDR notation**: the number of leading bits that identify the network.

*For analysis:* a source address tells you which interface sent a packet, not which person or
program did. Addresses can be shared (NAT puts a whole office behind one public address) and
spoofed in one-way traffic such as UDP. NetSentry treats multicast and broadcast destinations
separately, because "one host contacted 40 destinations" means something different when those
destinations are multicast groups.

## TCP and UDP

The two main transport protocols carry data between programs:

| | TCP | UDP |
|---|---|---|
| Connection | Yes — set up with a handshake | No — each datagram stands alone |
| Reliability | Lost data is retransmitted, order is guaranteed | No retransmission, no ordering |
| Typical uses | Web (HTTP/HTTPS), SSH, email, file transfer | DNS, NTP, VoIP, video, QUIC (HTTP/3) |

*For analysis:* with TCP you can usually tell whether a connection was **accepted** or
**refused**, because the server answers the opening packet. With UDP there is no handshake: a
reply proves something answered, but silence proves nothing (the port may be closed, filtered,
or the service may simply not reply). NetSentry treats a UDP "conversation" as starting with
the first packet seen between two endpoints; the host that sent it is the initiator.

## Ports

A port number (0–65535) identifies which program on a host should receive the data.

| Range | Name | Examples |
|---|---|---|
| 0–1023 | Well-known | 22 SSH, 53 DNS, 80 HTTP, 443 HTTPS |
| 1024–49151 | Registered | 3306 MySQL, 3389 RDP, 8080 HTTP alternate |
| 49152–65535 | Dynamic / ephemeral | Temporary ports chosen by clients |

A connection has two ports: the **server's** well-known port and the **client's** temporary
(ephemeral) port. That is why NetSentry's destination-port table includes a *Flows started*
column: replies are addressed to the client's temporary port, so a port that received many
packets but started zero flows is a client port, not a service.

*For analysis:* **a port number is a convention, not proof.** Port 443 usually carries HTTPS,
but nothing stops a program from running SSH, a VPN or malware on port 443, or HTTPS on port
8443. NetSentry shows port-based service names only as labelled hints and identifies
application protocols from their content.

## TCP flags and the three-way handshake

The TCP header contains one-bit **flags** that say what a segment is for:

| Flag | Name | Meaning |
|---|---|---|
| SYN | Synchronise | "I want to open a connection; here is my initial sequence number." |
| ACK | Acknowledge | "I have received your data up to this sequence number." |
| FIN | Finish | "I have finished sending." (graceful close) |
| RST | Reset | "Abort" — or, in reply to a SYN, "nothing is listening on this port." |
| PSH | Push | "Deliver this data to the application now." |
| URG, ECE, CWR | Urgent / congestion | Rarely relevant for security analysis. |

Every TCP connection starts with a **three-way handshake**:

```text
 Client                                        Server (port 22)
   |  SYN       seq=1000                          |   "Can we talk?"
   | -------------------------------------------> |
   |  SYN-ACK   seq=5000  ack=1001                |   "Yes, port is open."
   | <------------------------------------------- |
   |  ACK       ack=5001                          |   "Great, connected."
   | -------------------------------------------> |
```

If nothing listens on the port, the server's operating system answers with a reset instead:

```text
   |  SYN       seq=1000                          |
   | -------------------------------------------> |
   |  RST-ACK   ack=1001                          |   "Port closed."
   | <------------------------------------------- |
```

The **sequence number** in the SYN (the *initial sequence number*, ISN) is chosen at random.
The reply acknowledges it with `ack = ISN + 1`. NetSentry uses exactly this rule to match a
SYN-ACK or RST to the attempt it answers, so an unrelated reset is not mistaken for a refusal.
(Sequence numbers are 32-bit and wrap around: an ISN of 4294967295 is acknowledged with 0.)

*For analysis:*
- A **SYN without ACK** is a connection *attempt*. Counting attempts per destination port is
  how port scans and repeated-connection patterns are measured.
- **SYN-ACK** means the port is open; **RST** means closed. A port scanner sees mostly resets.
- **No reply at all** can mean a firewall silently dropped the SYN ("filtered"), the reply was
  lost, or the capture simply did not record it. NetSentry reports this as *no reply
  observed* and never counts it as a failure.
- A RST *after* a connection was established is a different event (an abort) and is counted
  separately.

## Retransmissions

When TCP sends a segment and hears nothing back, it sends it again after a timeout, doubling
the wait each time ("exponential back-off"). An unanswered SYN on Linux is typically resent
after about 1, 2, 4, 8, 16 and 32 seconds — seven SYNs for **one** attempt.

A retransmitted SYN has the **same source port and the same initial sequence number** as the
original. NetSentry merges such packets into one connection attempt. Without this, one stubborn
connection to a dead server would look like seven connection attempts, and a single unanswered
client would look like a brute-force attack. Duplicate packets (the same packet captured twice,
common with mirror ports) are merged the same way.

## ICMP

ICMP carries control messages for IP:

- **Echo request / echo reply** (types 8/0 for IPv4, 128/129 for ICMPv6) — the `ping` tool. A
  source sending echo requests to many addresses is performing a *ping sweep*.
- **Destination unreachable** (type 3, or 1 for ICMPv6) — "I could not deliver your packet."
  For UDP this is often how a closed port answers. These messages quote the header of the
  packet that failed; NetSentry recognises the quoted header and does not count it as traffic.

## DNS

The Domain Name System turns names like `www.example.com` into addresses.

```text
 Client                         Resolver (port 53)
   |  Query    id=4711  www.example.com  type A    |
   | --------------------------------------------> |
   |  Response id=4711  rcode=NOERROR  A 198.51.100.10
   | <-------------------------------------------- |
```

- Queries and responses are usually **UDP port 53** (TCP is used for large responses).
- The **transaction ID** links a response to its query.
- The **record type** says what is being asked: `A` (IPv4 address), `AAAA` (IPv6), `MX` (mail
  server), `TXT` (free text), `CNAME` (alias), `PTR` (reverse lookup)...
- The **response code** says how it went: `NOERROR`, `NXDOMAIN` (the name does not exist),
  `SERVFAIL` (the server failed), `REFUSED`...
- A name is a series of **labels** separated by dots (`www`, `example`, `com`). A label can be
  up to 63 bytes and a whole name up to 253 bytes.
- **mDNS** (port 5353) and **LLMNR** (5355) are local-network variants that devices use to find
  each other without a server. NetSentry counts mDNS separately and does not apply DNS
  anomaly rules to it.

*Why DNS matters for security:* almost every network allows DNS out, so attackers abuse it:

- **DNS tunnelling** encodes data into query names, e.g.
  `6f72646572732e637376.0001.exfil.example`. This produces long, random-looking, unique labels
  under one domain.
- **Domain generation algorithms (DGA)** make malware try many generated domains until one
  works, producing many `NXDOMAIN` responses.
- **Beaconing** is malware checking in with its controller at regular intervals, which can
  show up as the same name queried again and again.

Each of these has innocent look-alikes (CDNs use long names, typos cause NXDOMAIN, update
checkers repeat), which is why NetSentry's DNS rules are labelled heuristics with LOW or
MEDIUM confidence.

## Packet captures

A **packet capture** records frames seen by a network interface, each with a timestamp.

- **PCAP** is the classic format: a 24-byte file header followed by records, each with a
  16-byte header (timestamp, captured length, original length) and the frame bytes.
- **PCAPNG** ("next generation") is organised in blocks. It supports several interfaces per
  file, comments and per-interface timestamp resolution. Its *Simple Packet Block* has no
  timestamp at all, which is why NetSentry handles packets with unknown times.
- The **link type** says what kind of link the frames came from: Ethernet, Wi-Fi, "Linux cooked
  capture" (what `tcpdump -i any` produces), raw IP and others.
- The **snapshot length (snaplen)** limits how many bytes of each frame are stored. If a frame's
  captured length is shorter than its original length, the end of the frame is missing.
  NetSentry counts these frames so you know protocol identification may be incomplete.
- **Timestamps** come from the capturing machine's clock. They can be wrong (a timestamp of
  1970 means the clock was not set), duplicated (low-resolution clocks) or out of order
  (merged captures). NetSentry reports all three.

A file is identified by its first bytes — its **magic number** — not by its name: `a1b2c3d4`
(or its byte-swapped form) for PCAP, `0a0d0d0a` for PCAPNG.

## Capture filters and missing packets

A capture shows only what the capturing interface saw, and only what it kept:

- **Capture filters** (`tcpdump port 443`) deliberately drop everything else.
- **Placement** matters: a capture on one laptop does not see its neighbours' traffic on a
  switched network; a firewall's inside interface sees different traffic from its outside one.
- **Mirror (SPAN) ports** can be configured to copy only one direction, and drop packets when
  overloaded.
- **Asymmetric routing** sends requests and replies along different paths, so a capture point
  may see only one direction of a conversation.
- **Packet loss** during capture happens when the capturing machine is too slow.
- **Captures start and stop mid-conversation:** a connection may have begun before the
  capture, so its SYN is missing (NetSentry notes SYN-ACKs with no matching SYN).

*For analysis:* absence of evidence is not evidence of absence. If NetSentry reports that most
conversations are one-directional, it cannot judge whether connections succeeded, and its scan
findings carry LOW confidence.

## Encryption: what a capture cannot show

Most modern traffic is encrypted (HTTPS/TLS, QUIC, SSH, VPNs). A capture of encrypted traffic
still shows **metadata** — who talked to whom, when, on which ports, how much data, which
connections were refused — but not the content. NetSentry works only with metadata. The one
place it looks at content is the first bytes of TCP segments, to recognise the *cleartext*
protocols HTTP, FTP and Telnet, whose content anyone on the path could read.
