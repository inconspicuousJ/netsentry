# Sample captures

This folder holds a generator for **synthetic** demo captures. Generate them with:

```bash
python samples/generate_samples.py
```

The `.pcap` / `.pcapng` files are not committed (the project ignores all capture files so that
real captures are never committed by accident); run the generator to recreate them. With the
same Scapy version the files are byte-for-byte identical on every run.

All packets are fabricated with documentation-only addresses (`192.0.2.0/24`,
`198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`). Nothing is sent on any network.

| File | Contents | Expected result |
|---|---|---|
| `benign_browsing.pcap` | DNS lookups followed by HTTPS sessions, NTP. | No findings. |
| `port_scan.pcap` | The same background traffic plus one host scanning ports 1–100 on a server. | One `NS-SCAN-001` finding (confidence HIGH); the scan's resets appear as a suppressed `NS-CONN-002` candidate rather than a second finding. |
| `mixed_incident.pcapng` | Background traffic plus: a port scan, 25 refused SSH connections, 15 tunnelling-style DNS names, a domain that never resolves queried every 10 s, Telnet negotiation, a connection to port 4444, cleartext HTTP, some IPv6. | Seven findings, one per planted pattern. |

```bash
python main.py analyze samples/benign_browsing.pcap
python main.py analyze samples/port_scan.pcap
python main.py analyze samples/mixed_incident.pcapng --format json --output reports/mixed.json
```

## Using real captures

To practise on realistic traffic, capture your **own** machine's traffic with Wireshark or
`tcpdump` (for example while browsing for a minute), or use published sample captures such as
the [Wireshark sample captures](https://wiki.wireshark.org/SampleCaptures). Captures from
malware-analysis sites can contain live malicious files: open them only in an isolated virtual
machine. Never commit real captures to a repository.
