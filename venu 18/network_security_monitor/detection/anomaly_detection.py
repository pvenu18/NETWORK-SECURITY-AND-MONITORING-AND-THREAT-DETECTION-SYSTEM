"""Optional Isolation Forest analysis over numeric traffic features."""

from __future__ import annotations

from datetime import datetime, timezone

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest


FEATURE_COLUMNS = ["dst_port", "byte_count", "protocol_code", "source_frequency"]
PROTOCOL_CODES = {"TCP": 0, "UDP": 1, "ICMP": 2}


def detect_anomalies(records: list[dict]) -> list[dict]:
    """Fit a small Isolation Forest and return one scored result per record.

    Fewer than eight rows do not provide a useful reference set, so that case is
    reported to the caller rather than returning misleading model output.
    """
    if len(records) < 8:
        raise ValueError("At least 8 traffic records are required for anomaly analysis.")

    frame = pd.DataFrame(records)
    frame["protocol_code"] = frame["protocol"].map(PROTOCOL_CODES).fillna(-1)
    source_frequency = frame["src_ip"].value_counts()
    frame["source_frequency"] = frame["src_ip"].map(source_frequency)
    frame["byte_count"] = pd.to_numeric(frame["byte_count"], errors="coerce").fillna(0)
    frame["dst_port"] = pd.to_numeric(frame["dst_port"], errors="coerce").fillna(0)
    features = frame[FEATURE_COLUMNS].astype(float)

    model = IsolationForest(
        n_estimators=100,
        contamination="auto",
        random_state=42,
    )
    labels = model.fit_predict(features)
    scores = model.decision_function(features)
    detected_at = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    return [
        {
            "traffic_log_id": int(record["id"]),
            "is_anomaly": int(label == -1),
            "anomaly_score": float(score),
            "detected_at": detected_at,
        }
        for record, label, score in zip(records, labels, scores, strict=True)
    ]
