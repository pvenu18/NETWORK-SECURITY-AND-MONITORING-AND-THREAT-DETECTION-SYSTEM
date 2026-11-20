"""Explainable defensive rules for identifying traffic worth investigating."""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone


@dataclass(frozen=True)
class Threat:
    timestamp: str
    category: str
    severity: str
    src_ip: str
    dst_ip: str
    description: str
    evidence: str
    traffic_log_id: int | None = None


def detect_threats(records: list[dict], settings: dict[str, int]) -> list[Threat]:
    """Evaluate one batch, returning at most one alert per source and rule."""
    window = timedelta(minutes=settings["window_minutes"])
    by_source: dict[str, list[dict]] = defaultdict(list)
    for record in records:
        by_source[record["src_ip"]].append(record)

    threats: list[Threat] = []
    for source, events in by_source.items():
        events.sort(key=lambda event: event["timestamp"])
        active: deque[dict] = deque()
        alerted: set[str] = set()
        for event in events:
            current = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
            active.append(event)
            while active:
                first = datetime.fromisoformat(active[0]["timestamp"].replace("Z", "+00:00"))
                if current - first <= window:
                    break
                active.popleft()

            distinct_ports = len({item["dst_port"] for item in active})
            if distinct_ports >= settings["port_scan_threshold"] and "Potential port scan" not in alerted:
                threats.append(
                    Threat(
                        event["timestamp"],
                        "Potential port scan",
                        "Medium",
                        source,
                        event["dst_ip"],
                        "One source contacted many distinct destination ports in a short period.",
                        f"{distinct_ports} unique ports within {settings['window_minutes']} minutes; "
                        f"threshold {settings['port_scan_threshold']}.",
                        event.get("id"),
                    )
                )
                alerted.add("Potential port scan")

            repeated_count = len(active)
            if (
                repeated_count >= settings["repeat_connection_threshold"]
                and "Unusual connection frequency" not in alerted
            ):
                threats.append(
                    Threat(
                        event["timestamp"],
                        "Unusual connection frequency",
                        "Medium",
                        source,
                        event["dst_ip"],
                        "One source generated a high number of connection records in a short period.",
                        f"{repeated_count} records within {settings['window_minutes']} minutes; "
                        f"threshold {settings['repeat_connection_threshold']}.",
                        event.get("id"),
                    )
                )
                alerted.add("Unusual connection frequency")

            if (
                event["byte_count"] >= settings["high_volume_bytes"]
                and "Unexpected traffic volume" not in alerted
            ):
                threats.append(
                    Threat(
                        event["timestamp"],
                        "Unexpected traffic volume",
                        "Low",
                        source,
                        event["dst_ip"],
                        "A single traffic record exceeded the configured byte-volume threshold.",
                        f"{event['byte_count']} bytes; threshold {settings['high_volume_bytes']} bytes.",
                        event.get("id"),
                    )
                )
                alerted.add("Unexpected traffic volume")

            if (
                event["dst_port"] in {23, 3389}
                and "Sensitive destination port" not in alerted
            ):
                threats.append(
                    Threat(
                        event["timestamp"],
                        "Sensitive destination port",
                        "Low",
                        source,
                        event["dst_ip"],
                        f"Traffic used destination port {event['dst_port']}, which may merit policy review.",
                        f"Destination port {event['dst_port']} observed; this is a review indicator, not proof of abuse.",
                        event.get("id"),
                    )
                )
                alerted.add("Sensitive destination port")

    return sorted(threats, key=lambda threat: threat.timestamp)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
