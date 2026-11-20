"""Generate synthetic, documentation-range traffic for safe demonstrations."""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone


DOCUMENTATION_HOSTS = (
    "198.51.100.10",
    "198.51.100.20",
    "203.0.113.8",
    "203.0.113.15",
)


def generate_traffic_batch(count: int = 24, seed: int | None = None) -> list[dict]:
    """Create normal records plus a small, deliberately suspicious test pattern."""
    if not 8 <= count <= 500:
        raise ValueError("count must be between 8 and 500")
    generator = random.Random(seed)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    records: list[dict] = []
    for index in range(count):
        suspicious = index < min(6, count)
        timestamp = now - timedelta(seconds=(count - index) * 12)
        records.append(
            {
                "timestamp": timestamp.isoformat().replace("+00:00", "Z"),
                "src_ip": "192.0.2.50" if suspicious else f"192.0.2.{20 + (index % 8)}",
                "dst_ip": DOCUMENTATION_HOSTS[index % len(DOCUMENTATION_HOSTS)],
                "dst_port": (22, 23, 80, 443, 445, 3389)[index]
                if suspicious
                else generator.choice((53, 80, 443, 123, 8080)),
                "protocol": generator.choice(("TCP", "UDP", "ICMP")),
                "byte_count": 64 if suspicious else generator.randint(96, 18000),
                "action": "blocked" if suspicious else "allowed",
            }
        )
    return records
