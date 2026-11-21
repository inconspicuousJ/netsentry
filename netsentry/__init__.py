"""NetSentry: offline network traffic analysis and defensive threat detection.

NetSentry reads existing PCAP/PCAPNG capture files, summarises the traffic they
contain and evaluates a small set of explainable detection rules. It never
captures live traffic, sends packets, or contacts external services.
"""

__version__ = "0.1.0"
TOOL_NAME = "NetSentry"
