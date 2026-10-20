# Detection rules

This document describes every NetSentry rule: what it looks for, exactly how it decides, the
default thresholds (and the configuration keys that change them), the evidence it reports,
the situations that produce false positives, and how to investigate a finding.

- [Core ideas](#core-ideas)
- [Rule A — NS-SCAN-001 Potential port scan](#ns-scan-001-potential-port-scan)
- [Rule A — NS-SCAN-002 Potential host sweep](#ns-scan-002-potential-host-sweep)
- [Rule B — NS-CONN-001 Repeated connection attempts](#ns-conn-001-repeated-connection-attempts)
- [Rule C — NS-PORT-001 Traffic to a port that merits review](#ns-port-001-traffic-to-a-port-that-merits-review)
- [Rule D — NS-VOL-001 High traffic volume](#ns-vol-001-high-traffic-volume-from-one-source)
- [Rule E — NS-DNS-001 High DNS query rate](#ns-dns-001-high-dns-query-rate)
- [Rule E — NS-DNS-002 Unusually long DNS names](#ns-dns-002-unusually-long-dns-query-names)
- [Rule E — NS-DNS-003 Failed DNS lookups](#ns-dns-003-high-proportion-of-failed-dns-lookups)
- [Rule E — NS-DNS-004 Repeated queries for an unusual domain](#ns-dns-004-repeated-queries-for-an-unusual-domain)
- [Rule F — NS-CLEAR-001 Cleartext protocol](#ns-clear-001-cleartext-application-protocol)
- [Rule G — NS-CONN-002 Excessive refused connections](#ns-conn-002-excessive-refused-connections)
- [Tuning and disabling rules](#tuning-and-disabling-rules)

---

## Core ideas

### Suspicious is not malicious

Every rule describes a **pattern that was observed**. Many legitimate activities produce the
same patterns: vulnerability scanners, monitoring systems, backups, resolvers, misconfigured
software. A finding is a lead for an analyst to confirm or dismiss with other evidence (host
logs, asset inventories, the owner of the system). NetSentry never states that an attack
happened or that a system was compromised.

### Severity and confidence are separate

| | Question it answers | Values |
|---|---|---|
| **Severity** | If the concern behind this rule is real, how much would it matter? | INFO, LOW, MEDIUM, HIGH |
| **Confidence** | How strongly does *this capture's* evidence support that concern? | LOW, MEDIUM, HIGH |

Examples: a port scan is MEDIUM severity, but if the capture contains no reply traffic the
confidence is LOW, because NetSentry cannot tell whether the probes reached anything. Cleartext
HTTP is only INFO severity, but its confidence is HIGH, because the protocol was recognised from
its content.

No rule currently uses HIGH severity, and there is no CRITICAL level: nothing NetSentry can see
in packet metadata alone justifies it. HIGH is reserved for a future rule with a defensible
basis.

### Time windows

Rules that count events use a **sliding time window**: two events are in the same window when
their timestamps differ by **at most** `window_seconds`. NetSentry finds the window with the
most events (or the most *distinct* ports/hosts) and compares that peak with the threshold. A
long capture containing 20 port probes spread over a day does not look like a scan.

Packets without timestamps (PCAPNG Simple Packet Blocks) are excluded from windowed rules,
and the report says how many were excluded.

### Building blocks the rules use

The analyser turns packets into a few kinds of derived event:

- **Connection attempt (TCP):** a SYN without ACK. Retransmissions (same source port and the
  same initial sequence number) are merged into the attempt rather than counted again. The
  attempt's **outcome** is:
  - `accepted` — a SYN-ACK came back acknowledging the attempt (ack = ISN + 1);
  - `refused` — a RST came back acknowledging it;
  - `no_reply_observed` — neither was seen. This is **not** a failure: the port may be
    filtered, the reply may have been lost, or the capture may not include the reply direction.
- **Contact:** a flow-initiation event — a TCP connection attempt, the first packet of a UDP
  conversation (the side that sent first is the initiator; replies are not contacts), or an
  ICMP echo request. Multicast and broadcast destinations are excluded.
- **DNS query and response events** — duplicate packets with the same client, port,
  transaction ID and name are counted once.

### Suppression and de-duplication

When a candidate meets a threshold but the capture shows it is probably benign, or another
rule already explains it, NetSentry **suppresses** it. Suppressions are listed in the report
(`suppressed_candidates` in JSON) with the reason, so nothing disappears silently.

Rules run in a fixed order so that specific rules can claim activity first:

1. NS-SCAN-001, NS-SCAN-002 (scans)
2. NS-CONN-001 (repeated attempts to one service)
3. NS-CONN-002 (refused connections) — skips sources reported as scanning, and attempts to
   endpoints already reported by NS-CONN-001
4. NS-PORT-001 (unusual ports) — skips sources reported as scanning
5. NS-VOL-001
6. NS-DNS-004 (repeated unusual name), then NS-DNS-001, NS-DNS-002 and NS-DNS-003 — the last
   two skip names already reported by NS-DNS-004
7. NS-CLEAR-001

### Evidence

Every finding carries a structured `evidence` object (shown in the terminal and in JSON) with
the counts that triggered it, the threshold that was crossed, the time range and the addresses
involved. Lists inside evidence are capped (10 entries, 25 ports) to keep reports readable.

---

## NS-SCAN-001 Potential port scan

**Looks for:** one source contacting many **distinct destination ports** on the **same
destination** within a time window (a "vertical" scan, e.g. `nmap 192.0.2.80`).

**Logic**

1. Group contacts with a port (TCP and UDP) by (source, destination).
2. Slide the window over each group and find the peak number of distinct (transport, port) pairs.
3. If the peak is at least `min_distinct_ports`, the pair is a candidate.
4. Within that peak window, count ports that answered positively (TCP SYN-ACK / any UDP reply),
   negatively (TCP RST) or not at all.
5. **Suppression — traceroute:** if at least 80 % of the probed ports in the window are UDP
   ports 33434–33534, the activity is suppressed as traceroute. Classic UDP traceroute sends
   each probe (three per hop, up to 30 hops) to the next port up from 33434, which looks
   exactly like a 90-port scan of one host.
6. **Suppression — real services:** if reply traffic is visible and more than
   `max_success_ratio` of the probed ports answered positively, the source is probably a client
   using real services, not probing for them. Scans mostly hit closed ports.
7. All flagged destinations of one source are combined into **one finding per source**.

| Setting (`port_scan.*`) | Default | Meaning |
|---|---|---|
| `window_seconds` | 60 | Window length. |
| `min_distinct_ports` | 20 | Distinct ports needed in one window. |
| `max_success_ratio` | 0.5 | Above this share of positive answers the candidate is suppressed. |

**Severity:** MEDIUM. **Confidence:** LOW if no reply traffic from the target is visible;
HIGH if at most 20 % of probed ports answered positively and at least twice the threshold were
probed; otherwise MEDIUM.

**Evidence:** `source`, `hosts_flagged`, `max_distinct_ports_in_window`, `window_seconds`,
`threshold_distinct_ports`, and per target: `destination`, `distinct_ports_in_window`,
`window_start`, `window_end`, `ports_sample`, `answered_positively`, `refused_or_negative`,
`no_reply_observed`, `reply_traffic_visible`.

**False-positive scenarios:** authorised vulnerability scanners and penetration tests; network
monitoring that checks many services; service discovery; FTP passive mode (each transfer opens
a new high port); some peer-to-peer and VoIP software; a captured host that runs many
services and is contacted by an inventory tool. (UDP traceroute is recognised and suppressed.
TCP-based traceroute probes a single port, so it cannot trigger this rule, although its
repeated SYNs may appear as a LOW NS-CONN-001 finding.)

**Blind spot:** because of the traceroute suppression, a UDP scan confined to ports
33434–33534 is not reported. Those ports carry no ordinary services, so little is lost.

**Investigate:** identify who owns the source address and whether a scan was scheduled; check
which ports answered positively (those services were discovered); review the destination's
logs after the scan time for connections to those services.

---

## NS-SCAN-002 Potential host sweep

**Looks for:** one source contacting the **same service on many destinations** within a time
window (a "horizontal" scan or sweep, e.g. probing port 445 across a subnet, or a ping sweep).

**Logic:** group contacts by (source, transport, port) — ICMP echo requests form a service
called `ICMP echo` — and find the window with the most distinct destinations. Suppression works
as in NS-SCAN-001: if replies are visible and more than `max_success_ratio` of hosts answered
positively, it is normal client behaviour (a browser opening many HTTPS connections, a
resolver contacting many DNS servers). One finding per source.

| Setting (`host_sweep.*`) | Default | Meaning |
|---|---|---|
| `window_seconds` | 60 | Window length. |
| `min_distinct_hosts` | 30 | Distinct destinations needed in one window. |
| `max_success_ratio` | 0.5 | Above this share of positive answers the candidate is suppressed. |

**Severity:** MEDIUM. **Confidence:** as NS-SCAN-001.

**Evidence:** `source`, `services_flagged`, `max_distinct_hosts_in_window`, `window_seconds`,
`threshold_distinct_hosts`, and per service: `service`, `distinct_hosts_in_window`,
`window_start`, `window_end`, `hosts_sample`, `answered_positively`, `refused_or_negative`,
`no_reply_observed`, `reply_traffic_visible`.

**False-positive scenarios:** asset inventory and monitoring (ping every host), DHCP/ARP-related
tools, load balancers health-checking a pool, software update or P2P clients, and *any* busy
client when the capture contains only one direction of traffic (nothing can be judged as
"answered", so confidence is LOW).

**Investigate:** confirm whether the source is an inventory/monitoring system; if not, identify
the process on the source responsible; check which swept hosts answered.

---

## NS-CONN-001 Repeated connection attempts

**Looks for:** many **separate** TCP connection attempts from one source to the **same
destination and port** within a time window — for example a password-guessing tool opening a
new SSH connection for each guess.

**Logic**

1. Group connection attempts by (source, destination, port). Retransmitted SYNs are already
   merged, so one stubborn connection whose SYN is resent six times counts **once**.
2. Find the window with the most attempts; compare with `min_attempts`.
3. Count outcomes in that window (accepted, refused, no reply observed).
4. **Suppression:** for ports *not* in `sensitive_ports`, if more than `max_accepted_ratio` of
   attempts were accepted, it is ordinary repeated use (polling an API, short-lived HTTP
   connections) and is suppressed.

| Setting (`repeated_connections.*`) | Default | Meaning |
|---|---|---|
| `window_seconds` | 60 | Window length. |
| `min_attempts` | 10 | Distinct attempts needed in one window. |
| `sensitive_ports` | 21, 22, 23, 445, 3389, 5900 | Remote-access and file-sharing logins (FTP, SSH, Telnet, SMB, RDP, VNC). |
| `max_accepted_ratio` | 0.5 | Suppression threshold for non-sensitive ports. |

**Severity:** MEDIUM for sensitive ports, otherwise LOW. **Confidence:** MEDIUM for sensitive
ports when outcomes are known for at least half of the attempts; otherwise LOW.

**Evidence:** `source`, `destination`, `destination_port`, `attempts_in_window`,
`window_seconds`, `threshold_attempts`, `window_start`, `window_end`, `syn_packets_in_window`,
`retransmitted_syns_excluded`, `accepted_syn_ack_observed`, `refused_rst_observed`,
`no_reply_observed`, `distinct_source_ports`, `attempts_in_capture`, `sensitive_service_port`.

Databases (1433, 3306, 5432) and mail (25, 110, 143) are deliberately **not** sensitive by
default: web applications often open a new database connection per request and mail relays
open one per message, so many accepted connections to them are normal. Refused or unanswered
attempts to them are still reported at LOW severity. Add them to `sensitive_ports` if repeated
connections to them are unusual in your environment.

**False-positive scenarios:** clients retrying a service that is down; health checks and
monitoring probes; connection pools re-establishing connections; legitimate automation such as
configuration management logging in to many machines over SSH.

**Investigate:** check the destination service's authentication logs (SSH, RDP, database) for
failed and successful logins from the source at that time; identify the software on the source.
The capture alone cannot show whether a password was tried or whether a login succeeded.

---

## NS-PORT-001 Traffic to a port that merits review

**Looks for:** flows **initiated toward** ports that deserve a second look:

- **Watched ports** (any destination): ports whose default use is notable.
- **Inward-facing services on public addresses**: services that normally stay inside a network
  (SMB, RDP, VNC, MS-RPC, NetBIOS) contacted on a globally routable internet address.

Only flow initiations count (a TCP SYN or the first packet of a UDP flow). A server *replying
from* port 4444, or a client that happens to pick 4444 as its own temporary source port, does
not trigger the rule. Sources already reported as scanning are skipped, because a scan touches
thousands of ports and listing each watched one adds nothing.

| Setting (`unusual_ports.*`) | Default |
|---|---|
| `watched_ports` | 2323 (alternate Telnet, IoT botnets), 4444 (default handler port of penetration-testing tools), 5555 (Android Debug Bridge), 6667 (IRC, historic botnet C2), 31337 (historic backdoor port) |
| `public_destination_ports` | 135 (MS RPC), 139 (NetBIOS), 445 (SMB), 3389 (RDP), 5900 (VNC) |

Both are JSON objects mapping a port to the reason shown in the finding, so you can add your
own (`{"watched_ports": {"8888": "Port used by our lab C2 framework"}}`). Note that supplying
`watched_ports` replaces the default list rather than extending it.

**Severity:** LOW. **Confidence:** LOW — it is based on the port number alone.

**Evidence:** `transport`, `port`, `category`, `reason`, `flows_initiated`,
`accepted_or_answered`, `distinct_sources`, `distinct_destinations`,
`contacts_from_scanning_sources_excluded`, `example_flows`.

**False-positive scenarios:** every listed port has legitimate uses (developers using ADB;
applications that pick 4444 or 6667; SMB or RDP to a cloud server that is intentionally
exposed); the list is deliberately short and conservative. Non-standard ports in general are
**not** flagged: plenty of legitimate software uses them.

**Investigate:** identify the listening process on the destination and the connecting process
on the source; confirm the connection is expected; open the flow in Wireshark to see which
protocol it actually carries.

---

## NS-VOL-001 High traffic volume from one source

**Looks for:** two transparent kinds of high volume, reported together as one finding per
source:

- **Burst:** at least `min_packets_in_window` packets from the source within any
  `window_seconds` (measured in one-second buckets) → LOW.
- **Concentration:** one source sending at least `min_share_of_capture` of all IP packets in the
  capture, and at least `min_packets_for_share` packets → INFO. Not evaluated when the capture
  contains only one source.

| Setting (`high_volume.*`) | Default |
|---|---|
| `window_seconds` | 10 |
| `min_packets_in_window` | 10,000 (about 1,000 packets per second sustained) |
| `min_share_of_capture` | 0.8 |
| `min_packets_for_share` | 1,000 |

**Severity:** LOW for a burst, INFO for concentration only. **Confidence:** LOW: volume is not
specific to any threat.

**Evidence:** `source`, `packets_sent`, `share_of_ip_packets`, `bytes_on_wire_sent`,
`peak_packets_in_window`, `window_seconds`, `peak_window_start`,
`approx_peak_packets_per_second`, the thresholds, `top_destinations`.

**What it does not do:** it does not measure bandwidth (packet counts and the recorded packet
lengths are not a throughput measurement when packets are missing or truncated), and it does
not call anything a denial-of-service attack.

**False-positive scenarios:** file transfers, backups, software updates, video streaming,
a capture taken on a busy server.

**Investigate:** determine what the source was doing at the peak time and compare with its
normal behaviour.

---

## NS-DNS-001 High DNS query rate

**Looks for:** one client sending a very large number of DNS queries (port 53) within a window.
mDNS (5353) and LLMNR are local-link protocols and are not included.

**Logic:** count de-duplicated queries per client in a sliding window. **Suppression:** a host
that also *answers* DNS queries in the capture is a resolver — resolvers query upstream servers
constantly — so it is suppressed.

| Setting (`dns.*`) | Default |
|---|---|
| `rate_window_seconds` | 60 |
| `min_queries_in_window` | 200 |

**Severity:** LOW. **Confidence:** LOW.

**Evidence:** `source`, `queries_in_window`, `window_seconds`, `threshold_queries`,
`window_start`, `window_end`, `distinct_names_in_window`, `queries_in_capture`, `dns_servers`,
`top_names`, `query_types`.

**Why it matters:** DNS tunnelling and some malware generate bursts of queries. **False
positives:** resolvers not seen answering in the capture, mail servers (anti-spam lookups),
browsers prefetching names, security scanners, reverse-lookup heavy tools.

**Investigate:** check what kind of host the client is; if it is a workstation, identify the
process and look at the queried names for random or encoded labels.

---

## NS-DNS-002 Unusually long DNS query names

**Looks for:** queries for names of at least `long_name_length` bytes, or containing a label of
at least `long_label_length` bytes (DNS limits: 253 bytes per name, 63 per label). Data
tunnelled through DNS is typically encoded into long subdomain labels.

**Logic:** collect distinct long names per client (excluding names already reported by
NS-DNS-004). Group them by an approximate parent domain (the last two labels — wrong for
suffixes like `co.uk`, used only for grouping).

| Setting (`dns.*`) | Default |
|---|---|
| `long_name_length` | 100 bytes |
| `long_label_length` | 50 bytes |
| `min_long_names_for_low` | 10 |

**Severity:** INFO, or LOW when the client queried at least `min_long_names_for_low` distinct
long names. **Confidence:** MEDIUM when at least that many share one parent domain (the pattern
most associated with tunnelling), otherwise LOW.

**Evidence:** `source`, `distinct_long_names`, `queries_for_long_names`, `longest_name_bytes`,
`longest_label_bytes`, the thresholds, `top_parent_domains`, `example_names`, `first_query`,
`last_query`.

**False-positive scenarios:** CDNs and cloud load balancers, anti-spam DNS blocklists, DKIM and
other TXT-record lookups, telemetry and licensing services with generated names.

**Investigate:** do the labels look random or encoded (hex, base32, base64)? Is there a steady
stream of *unique* names under one domain? Check the domain's registration and reputation.

---

## NS-DNS-003 High proportion of failed DNS lookups

**Looks for:** a client for which most observed DNS responses report an error (any non-zero
response code: NXDOMAIN, SERVFAIL, REFUSED, ...). Malware using domain-generation algorithms
produces many lookups for names that do not exist.

**Logic:** count de-duplicated responses addressed to each client (excluding names reported by
NS-DNS-004). Report when there are at least `min_responses_for_failure_ratio` responses and the
failure share is at least `min_failure_ratio`.

| Setting (`dns.*`) | Default |
|---|---|
| `min_responses_for_failure_ratio` | 20 |
| `min_failure_ratio` | 0.5 |

**Severity:** LOW. **Confidence:** LOW.

**Evidence:** `source`, `responses_observed`, `failed_responses`, `failure_ratio`, the
thresholds, `response_codes`, `distinct_failed_names`, `top_failed_names`, `dns_servers`.

**False-positive scenarios:** typing errors, stale configuration, search-domain suffixes being
appended to names, ad blockers and DNS filters, a broken or unreachable upstream resolver.
Responses missing from the capture cannot be counted.

**Investigate:** a few names failing repeatedly suggests misconfiguration; many random-looking
names suggests generated domains. Check the client's DNS settings.

---

## NS-DNS-004 Repeated queries for an unusual domain

**Looks for:** the same client querying the same name at least `min_repeated_queries` times
where the name is **unusual**: either long (NS-DNS-002 thresholds) or **every** observed
response for it was an error. Malware often keeps trying to reach a command-and-control domain,
sometimes at a regular interval ("beaconing").

| Setting (`dns.*`) | Default |
|---|---|
| `min_repeated_queries` | 20 |

**Severity:** LOW. **Confidence:** LOW.

**Evidence:** `source`, `name`, `queries`, `threshold_queries`, `name_length_bytes`,
`longest_label_bytes`, `responses_observed`, `failed_responses`,
`median_seconds_between_queries` (a very regular interval suggests scheduled behaviour),
`first_query`, `last_query`, `query_types`.

**False-positive scenarios:** software retrying a decommissioned server name, update checkers,
WPAD/ISATAP lookups, monitoring tools.

**Investigate:** find the process that resolves the name (endpoint DNS logging, Sysmon event
22), check the domain's ownership and reputation.

---

## NS-CLEAR-001 Cleartext application protocol

**Looks for:** TCP traffic whose **content** identifies it as a protocol that is not encrypted:

| Protocol | Signature | Port requirement | Severity |
|---|---|---|---|
| HTTP | Request line `METHOD target HTTP/1.x` or status line `HTTP/1.x NNN` | any port | INFO |
| FTP control | Server reply `NNN ` / `NNN-` or a known FTP command | 21 | LOW |
| Telnet | Option negotiation: byte 255 (IAC) followed by WILL/WONT/DO/DONT | 23 | LOW |

FTP and Telnet signatures are short and generic, so they also require the standard port. HTTP
is recognised on any port because its request line is distinctive.

FTP and Telnet are LOW because their logins are unencrypted by design. HTTP is INFO because a
lot of HTTP carries nothing sensitive (redirects to HTTPS, certificate revocation checks,
signed updates).

**Confidence:** HIGH — the protocol was recognised from its content.

**What it does not do:** the signature check looks at the first bytes of a segment in memory
and discards them. NetSentry does **not** search for, store or report credentials or any other
content, so it makes no claim that sensitive data was sent. HTTPS, FTPS and SSH are encrypted
and are not visible to this rule.

**Evidence:** `protocol`, `packets_identified`, `client_server_pairs`, `distinct_clients`,
`distinct_servers`, `identification_basis`, `flows`.

**Investigate:** decide whether the service should use HTTPS, SFTP/FTPS or SSH instead, and
whether credentials or personal data could cross these connections.

---

## NS-CONN-002 Excessive refused connections

**Looks for:** a source whose TCP connection attempts are **mostly refused with resets** — for
example a misconfigured client hammering a stopped service, or slow probing that stays under the
scan thresholds.

**Logic**

1. Collect each source's connection attempts, leaving out attempts to endpoints already
   reported by NS-CONN-001.
2. Only attempts **answered by a matching RST** count as refused. Attempts with no reply are
   reported for context as `no_reply_observed_not_counted`, but never treated as failures,
   because the capture cannot show what happened to them.
3. Report when at least `min_refused_attempts` refusals fall within a window **and** refusals
   make up at least `min_refused_ratio` of the attempts whose outcome is known.
4. **Suppression:** sources already reported by NS-SCAN-001/002 are suppressed; refusals are an
   expected side effect of scanning.

| Setting (`failed_connections.*`) | Default |
|---|---|
| `window_seconds` | 300 |
| `min_refused_attempts` | 10 |
| `min_refused_ratio` | 0.5 |

**Severity:** LOW. **Confidence:** MEDIUM — the refusals were observed directly, but they have
many innocent causes.

**Evidence:** `source`, `refused_in_window`, `window_seconds`, `threshold_refused`,
`window_start`, `window_end`, `refused_rst_observed`, `accepted_syn_ack_observed`,
`no_reply_observed_not_counted`, `refused_ratio_of_known_outcomes`,
`distinct_destinations_refused`, `distinct_ports_refused`,
`attempts_excluded_as_already_reported`, `top_refused_endpoints`.

**False-positive scenarios:** a service that is down; a client configured with the wrong port;
firewalls that reject with RST; isolated resets are never enough on their own.

**Investigate:** check whether the refused services should be running and which software on
the source keeps trying them.

---

## Tuning and disabling rules

Print every threshold with its default value, edit what you need and pass the file back:

```bash
python main.py info --default-config > thresholds.json
python main.py analyze capture.pcap --config thresholds.json
```

Only the keys you include are changed; unknown keys or invalid values (negative windows, ratios
outside 0–1, ports above 65535, `true` where a number is expected) are rejected with a clear
error.

Disable a rule for one run with `--disable-rule NS-DNS-002` (repeatable), or permanently with
`"disabled_rules": ["NS-DNS-002"]` in the configuration file. Disabled rules are listed in the
report. When a specific rule is disabled, the activity it would have claimed is no longer
excluded from the general rules (for example, with NS-SCAN-001 disabled, a scan's refusals are
reported by NS-CONN-002 instead).

The thresholds actually used are always recorded in the JSON report under
`analysis.configuration`, so results can be reproduced.
