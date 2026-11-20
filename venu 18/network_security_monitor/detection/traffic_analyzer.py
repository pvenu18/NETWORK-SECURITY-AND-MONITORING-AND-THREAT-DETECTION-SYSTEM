"""Pandas-backed traffic summaries used by the dashboard and reports."""

from __future__ import annotations

import pandas as pd


def traffic_frame(rows: list[dict]) -> pd.DataFrame:
    frame = pd.DataFrame(rows)
    if frame.empty:
        return frame
    frame["timestamp"] = pd.to_datetime(frame["timestamp"], utc=True, errors="coerce")
    frame["byte_count"] = pd.to_numeric(frame["byte_count"], errors="coerce").fillna(0)
    frame = frame.dropna(subset=["timestamp"])
    frame["hour"] = frame["timestamp"].dt.strftime("%Y-%m-%d %H:00")
    frame["day"] = frame["timestamp"].dt.strftime("%Y-%m-%d")
    return frame


def summarize_traffic(rows: list[dict]) -> dict:
    """Return JSON-friendly protocol, hourly, daily, and traffic totals."""
    frame = traffic_frame(rows)
    if frame.empty:
        return {
            "protocols": {"TCP": 0, "UDP": 0, "ICMP": 0},
            "hourly": {"labels": [], "values": []},
            "daily": {"labels": [], "values": []},
            "bytes_total": 0,
            "normal_count": 0,
        }

    protocol_counts = frame["protocol"].value_counts().to_dict()
    hourly = frame.groupby("hour").size().tail(24)
    daily = frame.groupby("day").size().tail(14)
    return {
        "protocols": {
            protocol: int(protocol_counts.get(protocol, 0))
            for protocol in ("TCP", "UDP", "ICMP")
        },
        "hourly": {"labels": hourly.index.tolist(), "values": hourly.astype(int).tolist()},
        "daily": {"labels": daily.index.tolist(), "values": daily.astype(int).tolist()},
        "bytes_total": int(frame["byte_count"].sum()),
        "normal_count": int(len(frame)),
    }
