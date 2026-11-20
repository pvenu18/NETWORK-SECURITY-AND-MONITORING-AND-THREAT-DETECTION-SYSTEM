"""Parse and analyze firewall-style CSV traffic logs."""

from __future__ import annotations

import csv
import ipaddress
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable, TextIO


CSV_COLUMNS = (
    "timestamp",
    "src_ip",
    "dst_ip",
    "dst_port",
    "protocol",
    "bytes",
    "action",
)
SUPPORTED_PROTOCOLS = {"tcp", "udp", "icmp"}
SUPPORTED_ACTIONS = {"allowed", "blocked"}


@dataclass(frozen=True)
class TrafficRecord:
    timestamp: datetime
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: str
    byte_count: int
    action: str


@dataclass(frozen=True)
class Alert:
    rule: str
    severity: str
    source_ip: str
    timestamp: datetime
    message: str
    evidence: str


def _parse_timestamp(value: str) -> datetime:
    try:
        timestamp = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"invalid ISO 8601 timestamp: {value!r}") from exc
    if timestamp.tzinfo is None:
        raise ValueError("timestamp must include a timezone, such as Z or +00:00")
    return timestamp.astimezone(timezone.utc)


def _parse_record(row: dict[str, str | None], line_number: int) -> TrafficRecord:
    try:
        timestamp = _parse_timestamp(row["timestamp"] or "")
        src_ip = str(ipaddress.ip_address(row["src_ip"] or ""))
        dst_ip = str(ipaddress.ip_address(row["dst_ip"] or ""))
        dst_port = int(row["dst_port"] or "")
        byte_count = int(row["bytes"] or "")
        protocol = (row["protocol"] or "").strip().lower()
        action = (row["action"] or "").strip().lower()
        if not 1 <= dst_port <= 65535:
            raise ValueError("dst_port must be between 1 and 65535")
        if byte_count < 0:
            raise ValueError("bytes must be zero or greater")
        if protocol not in SUPPORTED_PROTOCOLS:
            raise ValueError(f"protocol must be one of {sorted(SUPPORTED_PROTOCOLS)}")
        if action not in SUPPORTED_ACTIONS:
            raise ValueError(f"action must be one of {sorted(SUPPORTED_ACTIONS)}")
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(f"CSV line {line_number}: {exc}") from exc
    return TrafficRecord(timestamp, src_ip, dst_ip, dst_port, protocol, byte_count, action)


def load_csv(source: str | Path | TextIO) -> list[TrafficRecord]:
    """Load and validate traffic records from a CSV path or open text stream."""
    should_close = not hasattr(source, "read")
    stream = Path(source).open("r", newline="", encoding="utf-8-sig") if should_close else source
    try:
        reader = csv.DictReader(stream)
        if reader.fieldnames is None:
            raise ValueError("CSV is empty or missing a header row")
        missing = [column for column in CSV_COLUMNS if column not in reader.fieldnames]
        if missing:
            raise ValueError(f"CSV is missing required columns: {', '.join(missing)}")
        records: list[TrafficRecord] = []
        for line_number, row in enumerate(reader, start=2):
            records.append(_parse_record(row, line_number))
        return records
    finally:
        if should_close:
            stream.close()


def analyze_traffic(
    records: Iterable[TrafficRecord],
    *,
    window_minutes: int = 5,
    port_scan_threshold: int = 6,
    blocked_attempt_threshold: int = 5,
) -> list[Alert]:
    """Generate one alert per source and rule when a threshold is first reached."""
    if window_minutes <= 0:
        raise ValueError("window_minutes must be greater than zero")
    if port_scan_threshold <= 0 or blocked_attempt_threshold <= 0:
        raise ValueError("alert thresholds must be greater than zero")

    by_source: dict[str, list[TrafficRecord]] = defaultdict(list)
    for record in records:
        by_source[record.src_ip].append(record)

    window = timedelta(minutes=window_minutes)
    alerts: list[Alert] = []
    for source_ip, source_records in by_source.items():
        source_records.sort(key=lambda record: record.timestamp)
        left = 0
        ports_in_window: Counter[int] = Counter()
        blocked_in_window = 0
        port_scan_alerted = False
        blocked_alerted = False

        for right, record in enumerate(source_records):
            ports_in_window[record.dst_port] += 1
            if record.action == "blocked":
                blocked_in_window += 1

            cutoff = record.timestamp - window
            while source_records[left].timestamp < cutoff:
                expired = source_records[left]
                ports_in_window[expired.dst_port] -= 1
                if ports_in_window[expired.dst_port] == 0:
                    del ports_in_window[expired.dst_port]
                if expired.action == "blocked":
                    blocked_in_window -= 1
                left += 1

            unique_ports = len(ports_in_window)
            if not port_scan_alerted and unique_ports >= port_scan_threshold:
                alerts.append(
                    Alert(
                        rule="port_scan",
                        severity="medium",
                        source_ip=source_ip,
                        timestamp=record.timestamp,
                        message=f"Contacted {unique_ports} distinct destination ports in {window_minutes} minutes",
                        evidence=f"{unique_ports} distinct ports; threshold {port_scan_threshold}",
                    )
                )
                port_scan_alerted = True
            if not blocked_alerted and blocked_in_window >= blocked_attempt_threshold:
                alerts.append(
                    Alert(
                        rule="repeated_blocked_connections",
                        severity="high",
                        source_ip=source_ip,
                        timestamp=record.timestamp,
                        message=f"Had {blocked_in_window} blocked connections in {window_minutes} minutes",
                        evidence=f"{blocked_in_window} blocked connections; threshold {blocked_attempt_threshold}",
                    )
                )
                blocked_alerted = True

    return sorted(alerts, key=lambda alert: (alert.timestamp, alert.source_ip, alert.rule))
