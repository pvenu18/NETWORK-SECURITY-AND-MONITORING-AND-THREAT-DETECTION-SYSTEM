from __future__ import annotations

import io
import unittest
from datetime import datetime, timezone

from netwatch.analyzer import TrafficRecord, analyze_traffic, load_csv


def record(
    second: int,
    *,
    minute: int = 0,
    port: int = 443,
    action: str = "allowed",
    source: str = "192.0.2.10",
) -> TrafficRecord:
    return TrafficRecord(
        timestamp=datetime(2026, 10, 12, 10, minute, second, tzinfo=timezone.utc),
        src_ip=source,
        dst_ip="198.51.100.20",
        dst_port=port,
        protocol="tcp",
        byte_count=64,
        action=action,
    )


class TrafficAnalyzerTests(unittest.TestCase):
    def test_detects_port_scan_and_repeated_blocked_connections(self) -> None:
        records = [
            record(second, port=port, action="blocked")
            for second, port in enumerate((22, 23, 80, 443, 445, 3389))
        ]

        alerts = analyze_traffic(records)

        self.assertEqual(
            [alert.rule for alert in alerts],
            ["repeated_blocked_connections", "port_scan"],
        )
        self.assertEqual(alerts[0].severity, "high")
        self.assertEqual(alerts[1].severity, "medium")

    def test_repeated_same_port_is_not_a_port_scan(self) -> None:
        alerts = analyze_traffic([record(second) for second in range(6)])
        self.assertEqual(alerts, [])

    def test_events_outside_the_window_do_not_accumulate(self) -> None:
        records = [
            record(0, minute=0, port=22),
            record(0, minute=2, port=23),
            record(0, minute=4, port=80),
            record(0, minute=6, port=443),
            record(0, minute=8, port=445),
            record(0, minute=10, port=3389),
            record(0, minute=12, port=8080),
        ]
        alerts = analyze_traffic(records, window_minutes=1, port_scan_threshold=6)
        self.assertEqual(alerts, [])

    def test_csv_rejects_timezone_free_timestamps(self) -> None:
        csv_text = (
            "timestamp,src_ip,dst_ip,dst_port,protocol,bytes,action\n"
            "2026-10-12T10:00:00,192.0.2.1,198.51.100.1,443,tcp,64,allowed\n"
        )
        with self.assertRaisesRegex(ValueError, "must include a timezone"):
            load_csv(io.StringIO(csv_text))

    def test_csv_parses_z_timestamp_as_utc(self) -> None:
        csv_text = (
            "timestamp,src_ip,dst_ip,dst_port,protocol,bytes,action\n"
            "2026-10-12T10:00:00Z,192.0.2.1,198.51.100.1,443,tcp,64,allowed\n"
        )
        parsed = load_csv(io.StringIO(csv_text))
        self.assertEqual(parsed[0].timestamp.tzinfo, timezone.utc)


if __name__ == "__main__":
    unittest.main()
