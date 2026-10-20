# Security policy

## Intended use

NetSentry is a **defensive** tool for analysing packet captures that you are **authorised** to
inspect: traffic from your own systems, a lab, a network you administer with permission, or
published sample captures.

Packet captures can contain other people's private communications. Capturing or analysing
traffic without authorisation may break the law (for example interception, computer-misuse or
data-protection law) and workplace policy. Get permission first.

NetSentry deliberately does **not**:

- capture live traffic, send packets, scan networks or inject traffic;
- intercept, decrypt or modify communications;
- extract, store or print credentials or application payloads;
- upload anything, contact any external service, or collect telemetry.

## Handling captures and reports safely

- Keep captures in a private location, not in shared or synced folders, and delete them when
  they are no longer needed.
- Treat reports as sensitive too: they contain IP addresses, DNS names, timing and traffic
  volumes. NetSentry writes reports only where you ask, never overwrites without
  `--overwrite`, creates report files readable only by you on Linux/macOS, and records the
  capture's file name rather than its full path.
- Never commit captures or reports to version control. The project's `.gitignore` excludes
  `*.pcap`, `*.pcapng`, `*.cap` and `reports/`.
- Captures downloaded from the internet (for example malware-traffic archives) can contain
  real malicious files inside the traffic. NetSentry does not extract them, but other tools
  might: handle such captures inside an isolated virtual machine.
- Before sharing a capture or report, consider removing or anonymising addresses with a tool
  such as `editcap`, `tcprewrite` or TraceWrangler.

## How NetSentry protects itself against hostile captures

A capture may be crafted by an attacker. NetSentry treats every byte in it as untrusted:

| Risk | Mitigation |
|---|---|
| Malformed or truncated files | Format detected by magic number; truncated records, partial headers and corrupt blocks are counted and reported; decoding errors in one frame never stop the analysis or show a traceback. |
| Huge length fields causing memory exhaustion | Scapy ≥ 2.8 bounds the bytes read per record; frames are streamed; derived state is compact; a packet limit bounds run time. |
| Terminal control-sequence injection (ANSI/OSC escapes, bidi overrides) in DNS names | Bytes are escaped as `\xNN` on ingest; displayed text is sanitised again and rendered through Rich `Text` objects, which never interpret markup; JSON is ASCII-only. Covered by tests. |
| Over-long DNS names | Names longer than 255 bytes are cut and flagged; display lengths are capped. |
| Payload disclosure | Records have no payload field; reports contain only metadata. Covered by tests that look for secrets in every output. |
| Report path abuse | Output is created with an exclusive-create flag (no silent overwrite, symlinks not followed); overwriting uses a temporary file plus atomic rename; the input capture can never be the output. |
| Network access | None during analysis; a test blocks socket operations to prove it. |

## Limitations

NetSentry's findings are heuristic. It can miss malicious activity (encrypted traffic, slow
attacks below thresholds, techniques no rule covers) and it can flag legitimate activity. It is
a learning and triage aid, not a replacement for an intrusion detection system, endpoint
monitoring or professional incident response. The software is provided "as is" under the MIT
licence.

**NetSentry has not been independently audited, certified or penetration-tested**, and it has
not been deployed in production environments.

## Reporting a vulnerability

If you find a security problem in NetSentry itself (for example a capture that crashes it,
causes excessive resource use, or injects content into the terminal or a report):

1. Please do **not** open a public issue containing a working exploit or a real capture.
2. Use GitHub's private vulnerability reporting (*Security → Report a vulnerability*) if it
   is enabled for the repository; otherwise contact the maintainer through their GitHub
   profile and ask for a private channel.
3. Include the NetSentry version (`python main.py --version`), your operating system and Python
   version, and a minimal **synthetic** capture or steps that reproduce the problem.

You can expect an acknowledgement within a reasonable time; this is a personal project
maintained in spare time, so there is no formal response deadline.
