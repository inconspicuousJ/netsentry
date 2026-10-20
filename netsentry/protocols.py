"""Protocol knowledge: TCP flags, DNS codes, port hints and content signatures.

Two kinds of protocol knowledge are kept clearly apart:

* **Port hints** (``service_hint``) say what a port is *commonly* used for.
  They are labels for humans, never evidence: port 443 often carries HTTPS,
  but any protocol can run on any port.
* **Content signatures** (``identify_cleartext_protocol``) recognise a protocol
  from the first bytes of a TCP payload. The bytes are examined in memory and
  discarded; they are never stored, printed or exported.
"""

from __future__ import annotations

import re

# --- TCP flags --------------------------------------------------------------
# Each flag is one bit in the TCP header's flags byte.
FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80

TCP_FLAG_NAMES: tuple[tuple[int, str], ...] = (
    (SYN, "SYN"),
    (ACK, "ACK"),
    (FIN, "FIN"),
    (RST, "RST"),
    (PSH, "PSH"),
    (URG, "URG"),
    (ECE, "ECE"),
    (CWR, "CWR"),
)


def describe_tcp_flags(flags: int) -> str:
    names = [name for bit, name in TCP_FLAG_NAMES if flags & bit]
    return "+".join(names) if names else "none"


# --- DNS codes ----------------------------------------------------------------

DNS_QUERY_TYPES: dict[int, str] = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    13: "HINFO",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    35: "NAPTR",
    43: "DS",
    46: "RRSIG",
    47: "NSEC",
    48: "DNSKEY",
    52: "TLSA",
    64: "SVCB",
    65: "HTTPS",
    99: "SPF",
    252: "AXFR",
    255: "ANY",
    257: "CAA",
}

DNS_RESPONSE_CODES: dict[int, str] = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
    6: "YXDOMAIN",
    7: "YXRRSET",
    8: "NXRRSET",
    9: "NOTAUTH",
    10: "NOTZONE",
}


def dns_type_name(code: int | None) -> str:
    if code is None:
        return "unknown"
    return DNS_QUERY_TYPES.get(code, f"TYPE{code}")


def dns_rcode_name(code: int | None) -> str:
    if code is None:
        return "unknown"
    return DNS_RESPONSE_CODES.get(code, f"RCODE{code}")


# --- Port hints ----------------------------------------------------------------

_COMMON_PORTS: dict[tuple[str, int], str] = {
    ("TCP", 20): "FTP data",
    ("TCP", 21): "FTP control",
    ("TCP", 22): "SSH",
    ("TCP", 23): "Telnet",
    ("TCP", 25): "SMTP",
    ("TCP", 53): "DNS",
    ("UDP", 53): "DNS",
    ("UDP", 67): "DHCP server",
    ("UDP", 68): "DHCP client",
    ("TCP", 80): "HTTP",
    ("TCP", 110): "POP3",
    ("UDP", 123): "NTP",
    ("TCP", 135): "MS RPC",
    ("UDP", 137): "NetBIOS name",
    ("UDP", 138): "NetBIOS datagram",
    ("TCP", 139): "NetBIOS session",
    ("TCP", 143): "IMAP",
    ("UDP", 161): "SNMP",
    ("TCP", 389): "LDAP",
    ("TCP", 443): "HTTPS",
    ("UDP", 443): "QUIC / HTTP/3",
    ("TCP", 445): "SMB",
    ("TCP", 465): "SMTP over TLS",
    ("UDP", 514): "Syslog",
    ("TCP", 587): "SMTP submission",
    ("TCP", 636): "LDAP over TLS",
    ("TCP", 853): "DNS over TLS",
    ("TCP", 993): "IMAP over TLS",
    ("TCP", 995): "POP3 over TLS",
    ("TCP", 1433): "Microsoft SQL Server",
    ("UDP", 1900): "SSDP",
    ("TCP", 3306): "MySQL",
    ("TCP", 3389): "RDP",
    ("UDP", 3389): "RDP",
    ("UDP", 5353): "mDNS",
    ("UDP", 5355): "LLMNR",
    ("TCP", 5432): "PostgreSQL",
    ("TCP", 5900): "VNC",
    ("TCP", 6379): "Redis",
    ("TCP", 8080): "HTTP alternate",
    ("TCP", 8443): "HTTPS alternate",
}


def service_hint(transport: str, port: int) -> str | None:
    """Return the service *commonly* associated with a port, or None."""
    return _COMMON_PORTS.get((transport, port))


# --- Cleartext content signatures --------------------------------------------

_HTTP_METHODS = frozenset(
    {b"GET", b"POST", b"HEAD", b"PUT", b"DELETE", b"OPTIONS", b"PATCH", b"CONNECT", b"TRACE"}
)
_HTTP_VERSIONS = (b" HTTP/1.0", b" HTTP/1.1")
_HTTP_STATUS = re.compile(rb"HTTP/1\.[01] [1-5][0-9][0-9][ \r]")
# A request line longer than this is not treated as HTTP (keeps the check cheap).
_MAX_REQUEST_LINE = 4096

_FTP_REPLY = re.compile(rb"[1-5][0-9][0-9][ -]")
_FTP_COMMANDS = frozenset(
    {
        b"USER",
        b"PASS",
        b"ACCT",
        b"CWD",
        b"CDUP",
        b"QUIT",
        b"PORT",
        b"PASV",
        b"EPSV",
        b"EPRT",
        b"TYPE",
        b"RETR",
        b"STOR",
        b"LIST",
        b"NLST",
        b"SYST",
        b"FEAT",
        b"AUTH",
        b"PWD",
        b"MKD",
        b"RMD",
        b"DELE",
        b"SIZE",
        b"MDTM",
        b"NOOP",
        b"OPTS",
        b"STAT",
        b"HELP",
        b"REST",
        b"RNFR",
        b"RNTO",
        b"ABOR",
        b"MLSD",
        b"MLST",
    }
)

# Telnet option negotiation: IAC (255) followed by WILL/WONT/DO/DONT (251-254).
_TELNET_IAC = 0xFF
_TELNET_NEGOTIATION = frozenset({0xFB, 0xFC, 0xFD, 0xFE})

CLIENT_TO_SERVER = "client_to_server"
SERVER_TO_CLIENT = "server_to_client"


def identify_cleartext_protocol(
    payload: bytes, src_port: int, dst_port: int
) -> tuple[str, str] | None:
    """Recognise HTTP, FTP control or Telnet from the start of a TCP payload.

    Returns ``(protocol, direction)`` or None. HTTP is recognised on any port
    from its request/status line. FTP and Telnet signatures are short and
    generic, so they also require the protocol's standard port (21 / 23).
    """
    if not payload:
        return None

    if payload.startswith(b"HTTP/1.") and _HTTP_STATUS.match(payload):
        return "HTTP", SERVER_TO_CLIENT
    method, separator, _ = payload[:16].partition(b" ")
    if separator and method in _HTTP_METHODS:
        line_end = payload.find(b"\r\n", 0, _MAX_REQUEST_LINE)
        if line_end != -1 and payload[:line_end].endswith(_HTTP_VERSIONS):
            return "HTTP", CLIENT_TO_SERVER

    if src_port == 21 and _FTP_REPLY.match(payload):
        return "FTP", SERVER_TO_CLIENT
    if dst_port == 21:
        command = payload[:5].split(b" ", 1)[0].split(b"\r", 1)[0]
        if command.upper() in _FTP_COMMANDS:
            return "FTP", CLIENT_TO_SERVER

    if (
        23 in (src_port, dst_port)
        and len(payload) >= 2
        and payload[0] == _TELNET_IAC
        and payload[1] in _TELNET_NEGOTIATION
    ):
        return "Telnet", SERVER_TO_CLIENT if src_port == 23 else CLIENT_TO_SERVER

    return None
