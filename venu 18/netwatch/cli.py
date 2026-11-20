"""Command-line entry point for NetWatch."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from datetime import timezone
from pathlib import Path

from .analyzer import analyze_traffic, load_csv


def _format_timestamp(value) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Analyze a firewall-style CSV log for suspicious traffic patterns."
    )
    parser.add_argument("csv_file", type=Path, help="path to the traffic CSV file")
    parser.add_argument("--window-minutes", type=int, default=5)
    parser.add_argument("--port-scan-threshold", type=int, default=6)
    parser.add_argument("--blocked-threshold", type=int, default=5)
    parser.add_argument("--json", action="store_true", help="print machine-readable JSON")
    args = parser.parse_args(argv)

    try:
        records = load_csv(args.csv_file)
        alerts = analyze_traffic(
            records,
            window_minutes=args.window_minutes,
            port_scan_threshold=args.port_scan_threshold,
            blocked_attempt_threshold=args.blocked_threshold,
        )
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        output = [
            {
                **asdict(alert),
                "timestamp": _format_timestamp(alert.timestamp),
            }
            for alert in alerts
        ]
        print(json.dumps(output, indent=2))
    elif not alerts:
        print(f"Analyzed {len(records)} records. No alerts.")
    else:
        print(f"Analyzed {len(records)} records. {len(alerts)} alert(s):")
        for alert in alerts:
            print(
                f"[{alert.severity.upper()}] {alert.rule} | {alert.source_ip} | "
                f"{_format_timestamp(alert.timestamp)}\n"
                f"  {alert.message} ({alert.evidence})"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
