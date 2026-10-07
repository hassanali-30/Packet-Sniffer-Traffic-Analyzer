#!/usr/bin/env python3
"""Defensive metadata-first packet and traffic analyzer.

It supports authorized offline PCAP review and optional live capture. It does
not inject packets, alter traffic, save payloads, or extract credentials.
"""

from __future__ import annotations

import argparse
import json
import platform
import sys
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from typing import Any, Iterable

COMMON_PORTS = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 80: "http", 110: "pop3", 143: "imap", 443: "https",
    445: "smb", 587: "submission", 993: "imaps", 995: "pop3s",
    3389: "rdp", 5353: "mdns",
}


@dataclass
class PacketRecord:
    timestamp: float
    source: str
    destination: str
    protocol: str
    source_port: int | None
    destination_port: int | None
    length: int
    dns_query: str | None = None


def service_for(port: int | None) -> str | None:
    return COMMON_PORTS.get(port) if port is not None else None


def packet_to_record(packet: Any) -> PacketRecord | None:
    """Convert a Scapy packet to metadata and discard all payload contents."""
    try:
        from scapy.layers.dns import DNS, DNSQR
        from scapy.layers.inet import IP, TCP, UDP
        from scapy.layers.inet6 import IPv6
    except ImportError as exc:
        raise RuntimeError("Install scapy with: python -m pip install scapy") from exc

    source = destination = ""
    if packet.haslayer(IP):
        layer = packet[IP]
        source, destination = layer.src, layer.dst
    elif packet.haslayer(IPv6):
        layer = packet[IPv6]
        source, destination = layer.src, layer.dst
    else:
        return None

    source_port = destination_port = None
    protocol = "IP"
    if packet.haslayer(TCP):
        layer = packet[TCP]
        source_port, destination_port, protocol = layer.sport, layer.dport, "TCP"
    elif packet.haslayer(UDP):
        layer = packet[UDP]
        source_port, destination_port, protocol = layer.sport, layer.dport, "UDP"
    elif hasattr(packet, "proto"):
        protocol = str(getattr(packet, "proto", "IP"))

    dns_query = None
    if packet.haslayer(DNS) and packet.haslayer(DNSQR):
        try:
            dns_query = packet[DNSQR].qname.decode(errors="replace").rstrip(".")
        except (AttributeError, UnicodeError):
            dns_query = None

    return PacketRecord(
        timestamp=float(getattr(packet, "time", 0.0)),
        source=source,
        destination=destination,
        protocol=protocol,
        source_port=source_port,
        destination_port=destination_port,
        length=len(packet),
        dns_query=dns_query,
    )


def summarize(records: Iterable[PacketRecord]) -> dict[str, Any]:
    packet_list = list(records)
    protocol_counts = Counter(record.protocol for record in packet_list)
    endpoint_bytes = Counter()
    conversations = Counter()
    destination_ports: dict[str, set[int]] = defaultdict(set)
    dns_queries = Counter()
    services = Counter()
    findings: list[dict[str, Any]] = []

    for record in packet_list:
        endpoint_bytes[record.source] += record.length
        endpoint_bytes[record.destination] += record.length
        endpoints = tuple(sorted((record.source, record.destination)))
        conversations[endpoints] += record.length
        if record.destination_port is not None:
            destination_ports[record.source].add(record.destination_port)
        service = service_for(record.destination_port) or service_for(record.source_port)
        if service:
            services[service] += 1
        if record.dns_query:
            dns_queries[record.dns_query] += 1

    for source, ports in destination_ports.items():
        if len(ports) >= 20:
            findings.append({
                "type": "possible-port-scan",
                "source": source,
                "detail": f"{len(ports)} destination ports observed",
                "severity": "medium",
            })

    plaintext_services = {"ftp", "telnet", "pop3", "imap", "smtp"}
    for service in sorted(plaintext_services & set(services)):
        findings.append({
            "type": "plaintext-service",
            "service": service,
            "detail": "Traffic used a commonly cleartext service port; review authorization and encryption.",
            "severity": "medium",
        })

    top_conversations = [
        {"source": pair[0], "destination": pair[1], "bytes": total}
        for pair, total in conversations.most_common(20)
    ]
    return {
        "tool": "Packet Sniffer and Traffic Analyzer",
        "version": "1.0.0",
        "metadata_only": True,
        "payloads_saved": False,
        "packet_injection": False,
        "packet_count": len(packet_list),
        "total_bytes": sum(record.length for record in packet_list),
        "protocols": dict(protocol_counts.most_common()),
        "top_endpoints": [
            {"address": address, "bytes": total}
            for address, total in endpoint_bytes.most_common(20)
        ],
        "top_conversations": top_conversations,
        "services": dict(services.most_common()),
        "dns_queries": [
            {"query": query, "count": count}
            for query, count in dns_queries.most_common(50)
        ],
        "findings": findings,
        "limitations": [
            "Metadata analysis can miss threats hidden in encrypted traffic.",
            "A finding is a review signal, not proof of malicious activity.",
            "Live capture requires authorization and may require administrator privileges.",
        ],
    }


def read_pcap(path: str) -> list[PacketRecord]:
    try:
        from scapy.utils import rdpcap
    except ImportError as exc:
        raise RuntimeError("Install scapy with: python -m pip install scapy") from exc
    packets = rdpcap(path)
    records = [packet_to_record(packet) for packet in packets]
    return [record for record in records if record is not None]


def live_capture(interface: str, count: int, timeout: int | None) -> list[PacketRecord]:
    try:
        from scapy.sendrecv import sniff
    except ImportError as exc:
        raise RuntimeError("Install scapy with: python -m pip install scapy") from exc
    records: list[PacketRecord] = []

    def collect(packet: Any) -> None:
        record = packet_to_record(packet)
        if record is not None:
            records.append(record)

    # store=False prevents Scapy from retaining full packets after the callback.
    sniff(iface=interface, prn=collect, store=False, count=count, timeout=timeout)
    return records


def main() -> int:
    parser = argparse.ArgumentParser(description="Metadata-first traffic analysis")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--pcap", help="Authorized PCAP/PCAPNG file to inspect")
    source.add_argument("--interface", help="Authorized interface for live metadata capture")
    parser.add_argument("--count", type=int, default=100, help="Live packet limit")
    parser.add_argument("--timeout", type=int, default=30, help="Live capture timeout in seconds")
    parser.add_argument("--json", action="store_true", help="Print JSON output")
    args = parser.parse_args()

    try:
        records = read_pcap(args.pcap) if args.pcap else live_capture(
            args.interface, max(0, args.count), max(1, args.timeout)
        )
        report = summarize(records)
        report["source"] = args.pcap or args.interface
        report["platform"] = platform.platform()
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(report, indent=2))
        return 0
    print(f"Source:       {report['source']}")
    print(f"Packets:      {report['packet_count']}")
    print(f"Bytes:        {report['total_bytes']}")
    print(f"Protocols:    {report['protocols']}")
    print(f"Services:     {report['services']}")
    print(f"Findings:     {len(report['findings'])}")
    for finding in report["findings"]:
        print(f"[{finding['severity']}] {finding['type']}: {finding['detail']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
