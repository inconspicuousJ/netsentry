# NetSentry

**Offline network traffic analyser and defensive threat-detection toolkit for PCAP/PCAPNG files.**

NetSentry reads a packet capture you already have, summarises what is in it (protocols, top
talkers, TCP behaviour, DNS activity) and runs a small set of **explainable** detection rules
that point an analyst at patterns worth investigating: port scans, host sweeps, repeated or
refused connections, unusual ports, traffic bursts, suspicious DNS patterns and cleartext
protocols.

It is deliberately small, careful and honest:

- **Offline and private.** Everything runs locally. No packets are sent, nothing is uploaded,
  there is no telemetry and no account. No administrator rights are needed.
- **Metadata only.** Payloads are never printed or stored in reports.
- **Explainable findings.** Every finding states what was observed, the evidence, the
  threshold it crossed, how to investigate, and what the rule *cannot* tell you.
- **False positives treated as bugs.** Rules suppress activity the capture shows to be benign
  and never report the same underlying pattern twice.

> NetSentry produces leads for investigation, not verdicts. A finding means "this pattern was
> observed", never "you have been hacked".

---

## Contents

1. [Features](#features)
2. [Sample output](#sample-output)
3. [Supported capture formats](#supported-capture-formats)
4. [Technology stack](#technology-stack)
5. [Installation (Windows PowerShell)](#installation-windows-powershell)
6. [Installation (macOS / Linux)](#installation-macos--linux)
7. [Usage](#usage)
8. [JSON reports](#json-reports)
9. [Running the tests](#running-the-tests)
10. [Detection rules](#detection-rules)
11. [Example findings and their limitations](#example-findings-and-their-limitations)
12. [Privacy and safety](#privacy-and-safety)
13. [Troubleshooting](#troubleshooting)
14. [Known limitations](#known-limitations)
15. [Future improvements](#future-improvements)
16. [Learning outcomes](#learning-outcomes)

Further reading: [docs/NETWORKING.md](docs/NETWORKING.md) (the networking concepts used),
[docs/DETECTIONS.md](docs/DETECTIONS.md) (every rule in detail),
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) (how the code fits together) and
[SECURITY.md](SECURITY.md).

---

## Features

**Capture ingestion**
- Streams PCAP and PCAPNG files frame by frame, so memory use stays flat as files grow.
- Detects the format from the file's signature, not its extension; gzip-compressed captures work.
- Reports damaged input instead of hiding it: truncated files, partial records, corrupt PCAPNG
  blocks, undecodable frames, unsupported link types, malformed IP headers, missing,
  zero or out-of-order timestamps.
- Distinguishes a valid capture with zero packets from a file that could not be parsed.
- Bounded run time: a configurable packet limit (default 1,000,000), reported when reached.
- SHA-256 of the input recorded in every report, so you can prove which file was analysed.

**Traffic analysis**
- Packet, byte, duration and rate statistics (rates only when the duration makes them meaningful).
- Protocol distribution from *decoded headers*; application protocols only from *content*.
  Port numbers appear as clearly labelled hints.
- IPv4 and IPv6 (including extension headers), TCP, UDP, ICMP, ICMPv6, DNS.
- Top sources, destinations and destination ports, with how many flows each port started.
- TCP flag statistics and connection-attempt tracking that merges SYN retransmissions and
  matches SYN-ACK/RST replies by acknowledgement number.
- DNS statistics: queries, responses, names, record types and response codes.

**Detection** — 11 rules across the 7 required categories (details below), each with a stable
identifier, severity, separate confidence, evidence, recommended next step and limitations.

**Reporting**
- Readable terminal report (Rich) with severity written as words, so it works without colour.
- A stable, documented JSON schema for automation.
- Safe file output: never overwrites without `--overwrite`, never overwrites the input,
  atomic replacement, owner-only file permissions on Linux/macOS.

---

## Sample output

The commands below run on synthetic captures produced by `samples/generate_samples.py`
(documentation-range addresses, no real traffic). This is unedited output at an
80-column terminal; only the middle sections are omitted:

```text
> python main.py analyze samples/port_scan.pcap --threshold medium

╭────────────────────────────────────────────────────────────────╮
│ NetSentry 0.1.0  offline network traffic analysis              │
│ Findings are leads for investigation, not proof of compromise. │
╰────────────────────────────────────────────────────────────────╯

Capture ────────────────────────────────────────────────────────────────────────
File          port_scan.pcap
Size          121.0 KiB
SHA-256       2a48d95a6f68f6896afad31fd8b7c5c4331429337274546ddb8a9c93f20f1d66
Format        PCAP
Link types    Ethernet (946)
First packet  2025-01-01T10:00:00Z
Last packet   2025-01-01T10:02:05.01Z
Duration      2 min 05.0 s
Packets       946 (946 IP)
Data on wire  106.2 KiB
Packet rate   7.6 packets/s
Unique        12 sources, 12 destinations, 328 destination ports
Processing  946 frames read, 946 decoded

...  (protocol, top-talker and TCP sections omitted here)

Findings ───────────────────────────────────────────────────────────────────────
HIGH 0   MEDIUM 1   LOW 0   INFO 0
╭─ [MEDIUM] F-001  Potential port scan from 203.0.113.66 ──────────────────────╮
│ Rule        NS-SCAN-001                                                      │
│ Confidence  HIGH                                                             │
│ Seen        2025-01-01T10:00:40Z to 2025-01-01T10:00:41.98Z                  │
│                                                                              │
│ 203.0.113.66 contacted 100 distinct ports on 192.0.2.80 within 60 s. This    │
│ pattern is consistent with port scanning, but authorised scanners and some   │
│ applications produce it too.                                                 │
│                                                                              │
│ Evidence                                                                     │
│ source                        203.0.113.66                                   │
│ hosts flagged                 1                                              │
│ max distinct ports in window  100                                            │
│ window seconds                60                                             │
│ threshold distinct ports      20                                             │
│ targets                                                                      │
│   - destination               192.0.2.80                                     │
│     distinct ports in window  100                                            │
│     window start              2025-01-01T10:00:40Z                           │
│     window end                2025-01-01T10:00:41.98Z                        │
│     ports sample              TCP/1, TCP/2, TCP/3, TCP/4, TCP/5, TCP/6,      │
│                               TCP/7, TCP/8, TCP/9, TCP/10, TCP/11, TCP/12    │
│                               ... 13 more (use --verbose)                    │
│     answered positively       2                                              │
│     refused or negative       98                                             │
│     no reply observed         0                                              │
│     reply traffic visible     yes                                            │
│                                                                              │
│ Next step: Identify the system behind the source address and whether it is   │
│ an authorised scanner or monitoring tool. Check which probed ports accepted  │
│ connections and review logs on the destination for follow-up activity.       │
│ Limitations: Vulnerability scanners, monitoring systems, service discovery   │
│ and some applications (for example FTP passive mode) contact many ports      │
│ legitimately. A scan is reconnaissance, not evidence that any system was     │
│ compromised.                                                                 │
╰──────────────────────────────────────────────────────────────────────────────╯

Suppressed candidates (met a threshold, judged likely benign) ──────────────────
NS-CONN-002  source=203.0.113.66: This source is already reported as a potential
port scan or host sweep; refused connections are an expected side effect of
scanning.
```

Notice the last section: the scan also produced 98 TCP resets, which would normally trip the
"excessive refused connections" rule. NetSentry recognises that the scan already explains them
and reports them **once**, listing the suppression so nothing is hidden.

The benign sample produces no findings at all:

```text
> python main.py analyze samples/benign_browsing.pcap
...
Findings ───────────────────────────────────────────────────────────────────────
HIGH 0   MEDIUM 0   LOW 0   INFO 0
No findings at or above the threshold. This means no rule matched; it does not
mean the traffic is safe.
```

---

## Supported capture formats

| Format | Notes |
|---|---|
| PCAP (`.pcap`, `.cap`) | Microsecond and nanosecond variants, either byte order. |
| PCAPNG (`.pcapng`) | Multiple interfaces and link types; Simple Packet Blocks (no timestamp) are handled. |
| gzip-compressed PCAP/PCAPNG | Detected automatically (`.pcap.gz`). |

Link types decoded: Ethernet (including VLAN tags), Linux cooked capture (SLL and SLL2),
raw IPv4/IPv6 and BSD/OpenBSD loopback. Frames with other link types are counted and
reported as unsupported rather than guessed at.

Captures can be made with Wireshark, `tcpdump`, `dumpcap` or `tshark`. NetSentry itself never
captures traffic.

---

## Technology stack

| Component | Purpose |
|---|---|
| Python 3.11+ | Language (tested with Python 3.13). |
| [Scapy](https://scapy.net) 2.8+ | Reading capture files and decoding protocol headers. |
| [Rich](https://github.com/Textualize/rich) | Terminal tables, panels and colour. |
| `argparse` | Command-line interface. |
| `pytest` | Automated tests. |
| ruff / mypy | Linting, formatting and type checking (optional, development only). |

---

## Installation (Windows PowerShell)

> These steps use standard Python tooling. The project was developed and tested on Linux; if a
> step behaves differently on your Windows machine, see [Troubleshooting](#troubleshooting).

1. Install Python 3.11 or newer from <https://www.python.org/downloads/> and tick
   **"Add python.exe to PATH"**. Check it in a new PowerShell window:

   ```powershell
   py --version
   ```

2. Get the code and enter the folder:

   ```powershell
   git clone https://github.com/inconspicuousJ/netsentry.git
   cd netsentry
   ```

3. Create and activate a virtual environment (an isolated folder for this project's packages):

   ```powershell
   py -3 -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```

   If PowerShell refuses to run the activation script, allow scripts for this window only and
   try again:

   ```powershell
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
   .\.venv\Scripts\Activate.ps1
   ```

   Your prompt now starts with `(.venv)`.

4. Install the dependencies:

   ```powershell
   python -m pip install --upgrade pip
   python -m pip install -r requirements-dev.txt
   ```

   Optional: `python -m pip install -e .` also installs a `netsentry` command, so you can type
   `netsentry analyze ...` instead of `python main.py analyze ...`.

5. Create the demo captures and run a first analysis:

   ```powershell
   python samples\generate_samples.py
   python main.py analyze samples\port_scan.pcap
   ```

Npcap is **not** required: it is only needed for live capture, which NetSentry does not do.

## Installation (macOS / Linux)

```bash
git clone https://github.com/inconspicuousJ/netsentry.git
cd netsentry
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements-dev.txt
python samples/generate_samples.py
python main.py analyze samples/port_scan.pcap
```

---

## Usage

```text
python main.py --help                      # overview and examples
python main.py info                        # version, rules, privacy notes, exit codes
python main.py analyze CAPTURE [options]
```

| Option | Meaning |
|---|---|
| `-f, --format text\|json` | Report format (default `text`; `json` when `--output` ends in `.json`). |
| `-o, --output PATH` | Write the report to a file instead of the terminal. Parent folders are created. |
| `--overwrite` | Allow `--output` to replace an existing file (never the input capture). |
| `-t, --threshold SEVERITY` | Only report findings at or above `info`, `low`, `medium` or `high`. |
| `--fail-on SEVERITY` | Exit with code 1 if any finding reaches this severity (for scripts). |
| `--top N` | Rows in top-talker and DNS tables (default 10). |
| `--max-packets N` | Stop after N packets (default 1,000,000; `0` = no limit). |
| `-c, --config FILE` | JSON file overriding detection thresholds. |
| `--disable-rule RULE_ID` | Turn off a rule, e.g. `--disable-rule NS-DNS-002` (repeatable). |
| `-v, --verbose` | Show every evidence entry instead of the first few. |
| `--no-color` | Plain output (the `NO_COLOR` environment variable also works). |
| `--debug` | Show a Python traceback for unexpected internal errors. |

Examples (PowerShell; on macOS/Linux use `/` in paths):

```powershell
python main.py analyze samples\mixed_incident.pcapng
python main.py analyze samples\mixed_incident.pcapng --threshold medium
python main.py analyze C:\captures\office.pcapng --top 25 --verbose
python main.py analyze samples\port_scan.pcap --output reports\port_scan.txt
```

### Tuning thresholds

```powershell
python main.py info --default-config > thresholds.json   # every threshold, with defaults
notepad thresholds.json                                    # edit the values you want
python main.py analyze capture.pcap --config thresholds.json
```

Only the keys you include need to be present. Unknown keys and invalid values are rejected
with a clear message, so a typo can never silently leave a threshold unchanged.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Analysis completed (and, with `--fail-on`, nothing reached that severity). |
| 1 | `--fail-on` matched at least one finding. |
| 2 | Invalid arguments or configuration. |
| 3 | Capture missing, unreadable or not a supported format. |
| 4 | Report could not be written. |
| 70 | Unexpected internal error (re-run with `--debug`). |
| 130 | Interrupted with Ctrl+C. |

In PowerShell, read the last exit code with `$LASTEXITCODE`; in bash, with `$?`.

---

## JSON reports

```powershell
python main.py analyze samples\port_scan.pcap --format json                 # to the terminal
python main.py analyze samples\port_scan.pcap --output reports\scan.json    # to a file
python main.py analyze samples\port_scan.pcap -f json | python -m json.tool # pretty-check it
```

Top-level structure (schema version `1.0`):

| Key | Contents |
|---|---|
| `schema_version`, `tool` | Report format version, tool name and version. |
| `analysis` | `generated_at` (when the **report** was produced — not a capture time), threshold, packet limit, the full threshold configuration used. |
| `capture` | File name (no directory path), size, SHA-256, format, link types, first/last packet times (ISO 8601 UTC and epoch seconds), duration. |
| `processing` | Frames read/decoded and every kind of parsing problem counted. |
| `summary` | Packets, bytes, rate, unique addresses and ports. |
| `protocols` | Network, transport and application protocol counts with the basis of identification. |
| `top_talkers` | Sources, destinations, destination ports (with flows started and a port hint). |
| `tcp`, `dns` | TCP flags and connection outcomes; DNS counts, types, codes, top names. |
| `findings_summary` | Counts by severity, how many were hidden by the threshold. |
| `findings` | One object per finding (below). |
| `suppressed_candidates` | Patterns that met a threshold but were judged benign or already covered, with the reason. |
| `detection_notes`, `warnings`, `limitations` | Disabled rules, data problems, analysis caveats. |

A finding (real output; long strings and `ports_sample` shortened with `...`):

```json
{
  "id": "F-001",
  "rule_id": "NS-SCAN-001",
  "title": "Potential port scan from 203.0.113.66",
  "severity": "MEDIUM",
  "confidence": "HIGH",
  "summary": "203.0.113.66 contacted 100 distinct ports on 192.0.2.80 within 60 s. ...",
  "evidence": {
    "source": "203.0.113.66",
    "hosts_flagged": 1,
    "max_distinct_ports_in_window": 100,
    "window_seconds": 60.0,
    "threshold_distinct_ports": 20,
    "targets": [
      {
        "destination": "192.0.2.80",
        "distinct_ports_in_window": 100,
        "window_start": "2025-01-01T10:00:40.000000Z",
        "window_end": "2025-01-01T10:00:41.980000Z",
        "ports_sample": ["TCP/1", "TCP/2", "TCP/3", "TCP/4", "TCP/5", "..."],
        "answered_positively": 2,
        "refused_or_negative": 98,
        "no_reply_observed": 0,
        "reply_traffic_visible": true
      }
    ]
  },
  "recommendation": "Identify the system behind the source address and whether it is an authorised scanner or monitoring tool. ...",
  "limitations": "Vulnerability scanners, monitoring systems, service discovery and some applications (for example FTP passive mode) contact many ports legitimately. ...",
  "subject": { "source": "203.0.113.66" },
  "first_seen": "2025-01-01T10:00:40.000000Z",
  "last_seen": "2025-01-01T10:00:41.980000Z"
}
```

Field names are stable within a schema version. Strings that came from the capture (such as
DNS names) are escaped (`\x1b`, `\x00`, ...) so they are safe to print, and the JSON is
written with `ensure_ascii`, so it never contains raw control characters.

---

## Running the tests

```powershell
python -m pytest            # the whole suite (about 200 tests, a few seconds)
python -m pytest -q tests\test_detectors.py
python -m pytest -k dns     # tests whose name contains "dns"
```

The tests generate deterministic synthetic packets with Scapy, write real PCAP/PCAPNG files
to a temporary folder and run the full pipeline. They need no internet access and no external
capture files. They cover:

- **Loading:** valid PCAP/PCAPNG/gzip, nanosecond timestamps, empty files, text files,
  truncated records and headers, corrupt PCAPNG blocks, missing timestamps, unsupported link
  types, raw-IP and Linux-cooked links, the packet limit, the input file staying unmodified.
- **Decoding:** IPv6 extension headers, ICMP errors that quote TCP headers, IP fragments,
  truncated IP/TCP headers, DNS normalisation, hostile and over-long DNS names.
- **Analysis:** packet/protocol/address/port counts, durations including zero and unknown,
  out-of-order timestamps, SYN retransmissions, sequence-number wraparound, RST handling.
- **Every detection rule:** triggering at the threshold, not triggering just below it,
  time-window boundaries, benign look-alikes, IPv6, retransmissions, duplicates, and
  de-duplication between rules.
- **Security and robustness:** terminal escape sequences and Rich markup in packet data,
  payloads never appearing in reports, invalid and existing output paths, symlinks,
  write failures, Ctrl+C, unexpected exceptions, and a test that blocks all socket
  operations to prove analysis is fully offline.

Development checks (optional):

```powershell
python -m pip install ruff mypy
ruff check . ; ruff format --check . ; mypy netsentry
```

---

## Detection rules

| Rule | Category | Looks for | Default threshold | Severity |
|---|---|---|---|---|
| `NS-SCAN-001` | A. Port scan | Many distinct ports on one host from one source | 20 ports in 60 s | MEDIUM |
| `NS-SCAN-002` | A. Host sweep | Same port (or ICMP echo) on many hosts | 30 hosts in 60 s | MEDIUM |
| `NS-CONN-001` | B. Repeated attempts | Separate SYN attempts to one host and port (retransmissions merged) | 10 in 60 s | LOW, MEDIUM for remote-access ports |
| `NS-PORT-001` | C. Unusual ports | Watch-list ports, or SMB/RDP/VNC/RPC to public addresses | any flow | LOW |
| `NS-VOL-001` | D. High volume | Packet bursts or one source dominating the capture | 10,000 packets in 10 s / 80 % share | LOW / INFO |
| `NS-DNS-001` | E. DNS | High query rate from one client | 200 queries in 60 s | LOW |
| `NS-DNS-002` | E. DNS | Long names or labels | 100-byte name / 50-byte label | INFO, LOW if many |
| `NS-DNS-003` | E. DNS | High proportion of failed lookups | 50 % of ≥ 20 responses | LOW |
| `NS-DNS-004` | E. DNS | Same unusual (long or always-failing) name queried repeatedly | 20 queries | LOW |
| `NS-CLEAR-001` | F. Cleartext | HTTP, FTP, Telnet recognised by content | any | INFO (HTTP), LOW |
| `NS-CONN-002` | G. Failed connections | Source whose attempts are mostly refused by RST | 10 refused in 300 s and ≥ 50 % | LOW |

**Severity vs confidence.** Severity says how much a finding would matter *if* the concern is
real. Confidence says how strongly *this capture's evidence* supports that concern — for
example, a port scan seen in a capture with no reply traffic has LOW confidence because
NetSentry cannot tell whether the probes were answered. Neither one means "confirmed".

**How false positives are kept down.**
1. Patterns must occur inside a time window, not just anywhere in a long capture.
2. When the capture shows activity was probably benign (most "scanned" ports accepted the
   connection; the "scan" is really `traceroute`; a "high DNS rate" host is itself a DNS
   server) the candidate is suppressed and listed under *Suppressed candidates* with the reason.
3. Specific rules run first; general rules skip activity those rules already explain, so one
   behaviour produces one finding.
4. Retransmitted SYNs and duplicated DNS packets are counted once.

Every rule, its logic, evidence fields, false-positive scenarios and investigation steps are
documented in [docs/DETECTIONS.md](docs/DETECTIONS.md).

---

## Example findings and their limitations

Running `python main.py analyze samples/mixed_incident.pcapng` reports seven findings, one per
planted pattern, and nothing else:

| Finding | What it means | What it does *not* mean |
|---|---|---|
| MEDIUM `NS-SCAN-001` port scan, confidence HIGH | 203.0.113.66 probed 60 ports on 192.0.2.80 in about one second; 59 were refused. | That anything was compromised. It could be an authorised vulnerability scanner. |
| MEDIUM `NS-CONN-001` repeated connections to SSH | 25 separate connection attempts to port 22, all refused. | That passwords were being guessed. The capture cannot show authentication; check SSH logs. |
| LOW `NS-CLEAR-001` Telnet | Telnet option negotiation was seen. | That credentials were sent. NetSentry did not look at the content. |
| LOW `NS-DNS-002` long names, confidence MEDIUM | 15 unique hex-looking names under one domain. | That data was exfiltrated. CDNs and telemetry also use long generated names. |
| LOW `NS-DNS-004` repeated failing name | One name queried 24 times, every 10 s, always NXDOMAIN. | Malware. Stale configuration retries dead names too — but the regular interval is worth a look. |
| LOW `NS-PORT-001` port 4444 | A connection to a port used by default by penetration-testing tools. | That the tool was in use. Any program can listen on 4444. |
| INFO `NS-CLEAR-001` HTTP | Unencrypted HTTP was used. | That anything sensitive was exposed. |

---

## Privacy and safety

- **Only analyse traffic you are authorised to inspect.** Captures can contain other people's
  private communications; analysing traffic without permission may be illegal.
- NetSentry processes files locally and makes no network connections (a test enforces this).
- Payload bytes are never stored, printed or exported. The cleartext rule examines only the
  first bytes of a TCP segment, in memory, to recognise a protocol signature.
- Reports still contain IP addresses, DNS names and timing. Treat them as sensitive: store
  them privately, share them only with people entitled to see the traffic, delete them when
  you no longer need them. Report files are created with owner-only permissions on
  Linux/macOS, and only the capture's *file name* (not its full path, which can contain your
  user name) is recorded.
- Reports are written only where you ask (`--output`), never automatically, and an existing
  file is never replaced without `--overwrite`.
- Text taken from packets is escaped before display, so hostile captures cannot inject
  terminal control sequences (which can recolour, hide or rewrite output) into your terminal.
- `.gitignore` excludes `*.pcap`, `*.pcapng` and `reports/` so captures and reports are not
  committed by accident.

See [SECURITY.md](SECURITY.md) for the threat model and how to report a vulnerability.

---

## Troubleshooting

| Problem | Fix |
|---|---|
| `py` / `python` is not recognised | Reinstall Python with "Add python.exe to PATH", then open a new terminal. |
| `Activate.ps1 cannot be loaded because running scripts is disabled` | Run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` in that window, then activate again. |
| `ModuleNotFoundError: No module named 'scapy'` | The virtual environment is not active, or dependencies are not installed: activate it and run `python -m pip install -r requirements.txt`. |
| `... is not a supported capture: it does not start with a PCAP or PCAPNG signature` | The file is not a capture (e.g. a text export or `.etl` file). In Wireshark use *File → Save As* and choose pcap or pcapng. |
| `... is empty (0 bytes)` | The capture tool was stopped before writing anything. |
| A warning says records were truncated | The capture was cut off (for example the tool was killed). Packets before the damage are still analysed. |
| `... already exists; choose another name or pass --overwrite` | NetSentry protects existing files. Use a new name or add `--overwrite`. |
| Strange characters (`\x1b`, `\xe2`) in DNS names | Intentional: unusual bytes are shown as escapes so they cannot affect your terminal. |
| Analysis is slow on a huge capture | Decoding runs at roughly 3,000–6,000 packets per second in pure Python. Use `--max-packets`, or split the file with `editcap -c 500000 big.pcap part.pcap`. |
| Box-drawing characters look garbled on an old Windows console | Use Windows Terminal, or add `--no-color` and save with `--output report.txt`. |
| No colours in the output | Colour is off when output is redirected, with `--no-color`, or when `NO_COLOR` is set. |

---

## Known limitations

- **Metadata, not content.** Encrypted traffic (TLS, QUIC, SSH, VPNs) is opaque; NetSentry sees
  addresses, ports, sizes and timing only.
- **No reassembly.** IP fragments and TCP streams are not reassembled. DNS over TCP is decoded
  only when a message fits in one segment.
- **Connection outcomes are inferred** from SYN-ACK and RST replies. ICMP "unreachable"
  responses are counted but not linked to the attempt they answer.
- **The capture's view is partial.** Filters, one-way mirror ports, asymmetric routing and
  packet loss hide traffic; NetSentry notes when most conversations are one-directional.
- **Thresholds are generic.** They are conservative starting points, not a baseline of *your*
  network. Busy servers and scanners may need tuned thresholds or disabled rules.
- **Outer headers only.** Tunnels (GRE, IP-in-IP, VXLAN) are noted but not unwrapped.
- **One DNS question per message** is recorded (real queries virtually always have one).
- **Speed.** Pure-Python decoding is far slower than Wireshark/Zeek; large captures take minutes.
- **Single file.** Each run analyses one capture; there is no correlation across files.
- Developed and tested on Linux with Python 3.13. Windows and macOS should work (only
  portable standard-library features are used) but have not been verified by the author yet.

## Future improvements

- Correlate ICMP "port unreachable" messages with the UDP/TCP probes they answer.
- TCP stream reassembly for DNS over TCP and better cleartext detection.
- TLS metadata (SNI, certificate issuer, JA3/JA4 fingerprints) without decrypting anything.
- Beaconing detection from connection-interval regularity.
- Optional address/domain redaction in reports for safer sharing.
- An HTML report, and CSV export of the top-talker tables.
- Baselines: learn normal volumes per host from known-good captures.
- Reading Zeek or NetFlow logs as alternative inputs.

## Learning outcomes

Building and studying NetSentry practises the skills a junior SOC analyst or detection engineer
uses every day:

- **Networking fundamentals:** how IP, TCP, UDP, ICMP and DNS look on the wire; the TCP
  handshake; what SYN, SYN-ACK and RST tell you; why port numbers are only hints.
- **Packet-capture literacy:** PCAP vs PCAPNG, link types, snapshot length, timestamps, and why
  a capture is never the whole picture.
- **Detection engineering:** turning a behaviour (scanning, brute force, tunnelling) into a
  measurable rule; choosing thresholds and time windows; separating severity from confidence;
  documenting false positives; suppressing and de-duplicating alerts.
- **Secure coding with untrusted input:** treating every byte from a capture as hostile —
  malformed files, oversized fields, terminal-escape injection, safe file writing.
- **Software engineering:** modular design, streaming data processing, typed Python,
  structured output schemas, exit codes, and a test suite that uses generated fixtures,
  boundary values and mutation-style checks to prove the tests can fail.

---

## Licence

[MIT](LICENSE). NetSentry has not been independently audited or certified; see
[SECURITY.md](SECURITY.md).
