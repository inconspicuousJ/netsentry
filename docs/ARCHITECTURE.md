# Architecture

NetSentry is a small pipeline. Each stage has one job and hands a simpler, safer data
structure to the next one.

```text
                capture file (.pcap / .pcapng / .gz)
                               |
  capture_loader.py            |  validate path, detect format by magic number, SHA-256,
                               |  stream frames with Scapy's raw readers, decode headers
                               v
                 PacketRecord (one per frame, metadata only)  +  ParseStats
                               |
  analyzer.py                  |  one pass: counters, protocol/talker/port/TCP/DNS stats,
                               |  connection attempts with outcomes, contacts, DNS events
                               v
                 AnalysisResult  (TrafficStats, TcpStats, DnsStats, TrafficIndex,
                               |  warnings, limitations)
  detectors.py                 |  11 rules in a fixed order, suppression + de-duplication
                               v
                 DetectionReport (Findings + SuppressedCandidates + notes)
                               |
  reporting.py                 |  build_report(): one JSON-compatible dictionary
                               v
              render_json()  /  render_terminal()  /  render_text()
                               |
  cli.py                       |  arguments, configuration, output file, exit codes
                               v
                    terminal, or a report file written safely (utils.py)
```

## Modules

| Module | Responsibility |
|---|---|
| `main.py` | Thin entry point: `python main.py ...`. |
| `netsentry/__main__.py` | Allows `python -m netsentry ...`. |
| `netsentry/cli.py` | `argparse` interface, configuration loading, error messages, exit codes, Ctrl+C handling, optional progress spinner for large files. |
| `netsentry/capture_loader.py` | File validation and hashing, format detection, streaming reads, integrity checks, frame decoding into `PacketRecord`. The only module that touches Scapy packets. |
| `netsentry/analyzer.py` | `TrafficAnalyzer` consumes records and produces statistics and the `TrafficIndex` the rules use; builds warnings and limitations. `analyze_capture()` runs loader + analyser. |
| `netsentry/detectors.py` | Rule metadata (`RULES`), sliding-window helpers, one function per rule, and `run_detections()` which orders them and removes duplicates. |
| `netsentry/reporting.py` | Builds the report dictionary (the JSON schema) and renders it as JSON or with Rich. |
| `netsentry/models.py` | Dataclasses shared by every stage: `PacketRecord`, `ParseStats`, `ConnectionAttempt`, `Contact`, `Finding`, `Severity`, `Confidence`, ... |
| `netsentry/config.py` | Typed threshold settings with defaults, JSON loading and strict validation. |
| `netsentry/protocols.py` | Protocol knowledge: TCP flag bits, DNS type/response-code names, port hints, cleartext content signatures. |
| `netsentry/utils.py` | Escaping untrusted text, formatting, and safe report writing. |
| `samples/generate_samples.py` | Deterministic synthetic demo captures. |
| `tests/` | pytest suite; `conftest.py` provides a `TrafficBuilder` that writes real capture files. |

Dependencies point one way: `cli → reporting / detectors / analyzer → capture_loader →
models / protocols / utils`. Nothing below the CLI prints to the terminal.

## Key data structures

**`PacketRecord`** (frozen, slotted dataclass) holds what NetSentry needs from one frame:
frame number, timestamp, lengths, link type, network label, addresses, IP protocol number,
transport, ports, TCP flags/sequence/acknowledgement numbers, ICMP type/code, payload *length*,
a content-identified application protocol, decoded DNS fields, and a fragment flag. There is
**no field for payload bytes**, so payloads cannot leak into later stages even by accident.

**`TrafficIndex`** holds the derived events the rules evaluate:

| Field | Built from |
|---|---|
| `connection_attempts` | TCP SYNs (retransmissions merged), each with an `Outcome`. |
| `contacts` | Connection attempts + first packet of each UDP flow + ICMP echo requests. |
| `dns_queries`, `dns_responses` | Decoded port-53 DNS messages, duplicates removed. |
| `cleartext_flows` | Packets identified as HTTP/FTP/Telnet, per client/server pair. |
| `packets_per_second_by_source` | One-second packet buckets, for the volume rule. |
| `directed_pairs` | Every (source, destination) pair seen, to judge whether replies are visible. |

**`Finding`** carries `rule_id`, `title`, `severity`, `confidence`, `summary`, `evidence`
(JSON-compatible dict), `recommendation`, `limitations`, `subject` (what it is about, used for
de-duplication) and the time range.

## Important design decisions

### Streaming with bounded state

Frames are read one at a time (`read_packets` is a generator) and converted to small records
immediately; Scapy's heavyweight packet objects are discarded. The analyser keeps counters and
compact event lists, not packets. Measured on a synthetic 300,000-packet (167 MB) capture,
peak memory stayed around 53 MiB, the same as for 50,000 packets. A packet limit (default
1,000,000, `--max-packets`) bounds run time, and reaching it is reported as a warning.

### Raw readers plus integrity checks

NetSentry uses Scapy's `RawPcapReader` / `RawPcapNgReader` and dissects frames itself instead of
using `rdpcap`. That gives access to each record's declared length and link type, so it can
detect truncated records, partial trailing headers, unsupported link types and corrupt PCAPNG
blocks — cases where Scapy would otherwise just stop or print a warning. Scapy's own warnings
are captured with a temporary logging handler (its rate-limiting filter is disabled meanwhile)
and included in the report instead of being printed. The previous logging state is restored
afterwards.

### Protocols from layers, not ports

Network and transport protocols come from decoded headers. Application protocols are recorded
only when the content proves them: a DNS message that decodes, an HTTP request line. Port-based
service names are hints in the report only. Exact type checks (`type(layer) is TCP`) stop the
headers that ICMP error messages quote (Scapy's `TCPerror` subclass) from being mistaken for
real traffic.

### One report, two renderings

`build_report()` produces a plain dictionary that *is* the JSON schema. The terminal renderer
reads the same dictionary, so JSON and terminal output can never disagree, and testing the
dictionary tests both.

### Defence in depth for display

Untrusted strings are escaped twice: when they enter the system (DNS names are converted from
bytes with every non-printable byte shown as `\xNN`) and when they are displayed
(`sanitize_text` plus Rich `Text` objects, which never interpret `[markup]`). JSON uses
`ensure_ascii=True` and `allow_nan=False`, so it is always valid and free of raw control
characters.

### Rule ordering for de-duplication

`run_detections()` runs specific rules before general ones and passes their subjects on as
exclusions (scanning sources, repeated-connection endpoints, repeatedly queried names). Each
rule function still works on its own when called directly with no exclusions, which keeps the
rules independently testable.

## Error handling and exit codes

User-facing problems are raised as specific exception types and turned into short messages
and exit codes by `cli.py`:

| Exception | Raised by | Exit code |
|---|---|---|
| argparse errors, `ConfigError`, unknown rule IDs | `cli.py`, `config.py` | 2 |
| `CaptureError` (`CaptureNotFoundError`, `CaptureFormatError`) | `capture_loader.py` | 3 |
| `ReportWriteError` | `utils.py` | 4 |
| any other exception | anywhere | 70 (traceback only with `--debug`) |
| `KeyboardInterrupt` | anywhere | 130 |

Damaged-but-readable input is **not** an error: the packets that could be read are analysed and
the damage is reported in `warnings`. Decoding problems inside one frame are counted and never
stop the analysis.

## Adding a detection rule

1. Add a rule ID constant and a `RuleInfo` entry (name, description, limitations) in
   `detectors.py`.
2. Add a settings dataclass with conservative defaults to `config.py` and register it in
   `DetectionConfig` and `_SECTION_NAMES` (validation then works automatically).
3. Write `detect_<name>(index, settings) -> RuleOutput`. Use the existing helpers
   (`best_window_count`, `best_window_distinct`), put counts and thresholds in `evidence`, and
   add a `SuppressedCandidate` when you deliberately skip a borderline case.
4. If the analyser does not yet record what the rule needs, add a compact derived event to
   `TrafficIndex` in `analyzer.py` rather than storing packets.
5. Call it from `run_detections()` in the right place in the order.
6. Write tests: triggers at the threshold, does not trigger just below it, a benign look-alike,
   and any interaction with other rules. Document the rule in `docs/DETECTIONS.md`.

## Testing approach

- `tests/conftest.py` builds protocol-correct synthetic traffic (handshakes, resets, DNS
  query/response pairs) with explicit timestamps and explicit MAC addresses (an unset MAC makes
  Scapy try to resolve it, which is slow and is network activity).
- Most tests run the full pipeline on real temporary PCAP/PCAPNG files; damaged files are made
  by truncating or hand-building bytes.
- The volume rule is also tested on a hand-built `TrafficIndex`, so large thresholds can be
  tested without generating 10,000 packets.
- The suite was checked by deliberately breaking the code (window boundaries, retransmission
  handling, sequence wraparound, each suppression and de-duplication rule, the terminal
  sanitiser, markup escaping) and confirming that tests fail each time.
