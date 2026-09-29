# Packet Sniffer and Traffic Analyzer

[![CI](https://github.com/hassanali-30/Packet-Sniffer-Traffic-Analyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/hassanali-30/Packet-Sniffer-Traffic-Analyzer/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)

A defensive, metadata-first packet and traffic analyzer for authorized PCAP review and controlled live capture. It summarizes protocols, endpoints, conversations, services, DNS queries, and selected traffic patterns without saving packet payloads.

> **Safety boundary:** This project does not inject, replay, modify, or transmit packets. It does not extract credentials, cookies, tokens, or message contents.

## Features

- Offline PCAP and PCAPNG analysis
- Optional authorized live capture through Scapy
- Protocol and byte statistics
- Top endpoints and conversations
- Common service-port summaries
- DNS query metadata
- Possible port-scan signal
- Cleartext-service review signal
- Human-readable and JSON reports
- Automated tests and GitHub Actions CI

## Requirements

- Python 3.10+
- Scapy
- For live capture on Windows: Npcap installed in a permitted capture configuration
- Administrator privileges may be required by the operating system for live capture

## Installation

```
git clone https://github.com/hassanali-30/Packet-Sniffer-Traffic-Analyzer.git
cd Packet-Sniffer-Traffic-Analyzer
python -m venv .venv
```

Activate the environment:

**Windows PowerShell**

```
.venv\\Scripts\\Activate.ps1
```

**macOS/Linux**

```
source .venv/bin/activate
```

Install dependencies:

```
python -m pip install -r requirements.txt
```

## Analyze an offline capture

Use only a capture you are authorized to inspect:

```
python traffic_analyzer.py --pcap capture.pcap
```

Export a report:

```
python traffic_analyzer.py --pcap capture.pcap --json > report.json
```

The analyzer extracts metadata needed for summaries and discards the packet objects after processing. The repository ignores local PCAP and JSON files by default.

## Authorized live capture

List or select an interface using your operating system's approved network tooling, then run:

```
python traffic_analyzer.py --interface "Ethernet" --count 100 --timeout 30
```

Live capture is disabled by default unless an interface is explicitly supplied. Capture only traffic belonging to systems and networks within your written authorization.

## Findings

- **Possible port scan:** one source contacted at least 20 destination ports in the observed capture.
- **Plaintext service:** traffic used a commonly cleartext service port such as Telnet, FTP, POP3, IMAP, or SMTP.

These are review signals, not proof of compromise. Encrypted traffic, NAT, proxies, virtual networks, and legitimate administrative activity can affect interpretation.

## Project layout

```
traffic_analyzer.py   # Capture and analysis CLI
tests/                # Unit tests using synthetic metadata
SECURITY.md           # Safe-use policy
requirements.txt      # Scapy dependency
```

## Testing

```
python -m pip install "pytest>=8,<9"
python -m pytest -q
```

## Limitations

Metadata-only analysis cannot inspect encrypted payloads, kernel-level behavior, or every application protocol. It is not an intrusion-prevention system and does not replace approved network monitoring or incident-response procedures.

## License

See [LICENSE](LICENSE).
