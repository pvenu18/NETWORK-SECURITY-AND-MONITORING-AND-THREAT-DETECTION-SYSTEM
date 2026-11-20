"""Authorized offline file-import adapters. No live capture is started here."""

from __future__ import annotations

import csv
import ipaddress
import io
from datetime import datetime, timezone


def parse_traffic_csv(content: bytes) -> list[dict]:
    """Validate an uploaded firewall CSV using the existing CSV parser."""
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError("CSV file must use UTF-8 text encoding.") from exc
    reader = csv.DictReader(io.StringIO(text))
    required = {"timestamp", "src_ip", "dst_ip", "dst_port", "protocol", "bytes", "action"}
    if reader.fieldnames is None:
        raise ValueError("CSV is empty or missing a header row.")
    missing = required.difference(reader.fieldnames)
    if missing:
        raise ValueError(f"CSV is missing required columns: {', '.join(sorted(missing))}.")

    records: list[dict] = []
    for line_number, row in enumerate(reader, start=2):
        try:
            timestamp = datetime.fromisoformat((row["timestamp"] or "").strip().replace("Z", "+00:00"))
            if timestamp.tzinfo is None:
                raise ValueError("timestamp must include a timezone.")
            src_ip = str(ipaddress.ip_address(row["src_ip"] or ""))
            dst_ip = str(ipaddress.ip_address(row["dst_ip"] or ""))
            dst_port = int(row["dst_port"] or "")
            byte_count = int(row["bytes"] or "")
            protocol = (row["protocol"] or "").strip().upper()
            action = (row["action"] or "").strip().lower()
            if not 1 <= dst_port <= 65535:
                raise ValueError("destination port must be between 1 and 65535.")
            if byte_count < 0:
                raise ValueError("bytes must be zero or greater.")
            if protocol not in {"TCP", "UDP", "ICMP"}:
                raise ValueError("protocol must be TCP, UDP, or ICMP.")
            if action not in {"allowed", "blocked"}:
                raise ValueError("action must be allowed or blocked.")
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"CSV line {line_number}: {exc}") from exc
        records.append(
            {
                "timestamp": timestamp.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "protocol": protocol,
                "byte_count": byte_count,
                "action": action,
            }
        )
    return records


def parse_authorized_pcap(file_path: str) -> list[dict]:
    """Read an authorized local PCAP file using Scapy, without opening sockets."""
    try:
        from scapy.layers.inet import ICMP, IP, TCP, UDP
        from scapy.error import Scapy_Exception
        from scapy.utils import PcapReader
    except ImportError as exc:
        raise RuntimeError("PCAP import requires Scapy. Install it with: pip install scapy") from exc

    parsed: list[dict] = []
    try:
        with PcapReader(file_path) as capture:
            for packet in capture:
                if IP not in packet:
                    continue
                ip = packet[IP]
                if TCP in packet:
                    protocol, port = "TCP", int(packet[TCP].dport)
                elif UDP in packet:
                    protocol, port = "UDP", int(packet[UDP].dport)
                elif ICMP in packet:
                    protocol, port = "ICMP", 1
                else:
                    continue
                if not 1 <= port <= 65535:
                    continue
                parsed.append(
                    {
                        "timestamp": datetime.fromtimestamp(float(packet.time), timezone.utc)
                        .isoformat()
                        .replace("+00:00", "Z"),
                        "src_ip": str(ipaddress.ip_address(ip.src)),
                        "dst_ip": str(ipaddress.ip_address(ip.dst)),
                        "dst_port": port,
                        "protocol": protocol,
                        "byte_count": len(packet),
                        "action": "allowed",
                    }
                )
    except Scapy_Exception as exc:
        raise ValueError(f"Could not parse the supplied PCAP file: {exc}") from exc
    return parsed
