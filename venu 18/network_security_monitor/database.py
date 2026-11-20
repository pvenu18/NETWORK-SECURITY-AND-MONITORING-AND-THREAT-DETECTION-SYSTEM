"""SQLite schema and small persistence helpers for the monitoring app."""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from config import DATABASE_PATH, DEFAULT_SETTINGS


@contextmanager
def get_connection(
    database_path: str | Path | None = None,
) -> Iterator[sqlite3.Connection]:
    """Create a transaction-scoped connection with foreign-key validation."""
    path = Path(database_path or DATABASE_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    try:
        with connection:
            yield connection
    finally:
        connection.close()


def initialize_database(database_path: str | Path | None = None) -> None:
    """Create all application tables and indexes if they do not exist."""
    with get_connection(database_path) as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS monitoring_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                started_at TEXT NOT NULL,
                ended_at TEXT,
                source TEXT NOT NULL,
                status TEXT NOT NULL CHECK (status IN ('running', 'completed', 'failed')),
                records_count INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS traffic_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER REFERENCES monitoring_sessions(id),
                timestamp TEXT NOT NULL,
                src_ip TEXT NOT NULL,
                dst_ip TEXT NOT NULL,
                dst_port INTEGER NOT NULL CHECK (dst_port BETWEEN 1 AND 65535),
                protocol TEXT NOT NULL CHECK (protocol IN ('TCP', 'UDP', 'ICMP')),
                byte_count INTEGER NOT NULL CHECK (byte_count >= 0),
                action TEXT NOT NULL CHECK (action IN ('allowed', 'blocked'))
            );
            CREATE TABLE IF NOT EXISTS security_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                traffic_log_id INTEGER REFERENCES traffic_logs(id),
                session_id INTEGER REFERENCES monitoring_sessions(id),
                timestamp TEXT NOT NULL,
                category TEXT NOT NULL,
                severity TEXT NOT NULL CHECK (severity IN ('Low', 'Medium', 'High')),
                src_ip TEXT NOT NULL,
                dst_ip TEXT NOT NULL,
                description TEXT NOT NULL,
                evidence TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Open'
                    CHECK (status IN ('Open', 'Investigating', 'Resolved'))
            );
            CREATE TABLE IF NOT EXISTS detection_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                traffic_log_id INTEGER NOT NULL REFERENCES traffic_logs(id),
                model_name TEXT NOT NULL,
                detected_at TEXT NOT NULL,
                is_anomaly INTEGER NOT NULL CHECK (is_anomaly IN (0, 1)),
                anomaly_score REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS app_settings (
                setting_key TEXT PRIMARY KEY,
                setting_value TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_traffic_timestamp ON traffic_logs(timestamp);
            CREATE INDEX IF NOT EXISTS idx_traffic_source_time ON traffic_logs(src_ip, timestamp);
            CREATE INDEX IF NOT EXISTS idx_alert_timestamp ON security_alerts(timestamp);
            CREATE INDEX IF NOT EXISTS idx_alert_status ON security_alerts(status);
            CREATE INDEX IF NOT EXISTS idx_detection_log ON detection_results(traffic_log_id);
            """
        )
        connection.executemany(
            "INSERT OR IGNORE INTO app_settings(setting_key, setting_value) VALUES (?, ?)",
            [(key, str(value)) for key, value in DEFAULT_SETTINGS.items()],
        )


def query_all(
    sql: str, parameters: tuple[Any, ...] = (), database_path: str | Path | None = None
) -> list[sqlite3.Row]:
    with get_connection(database_path) as connection:
        return list(connection.execute(sql, parameters).fetchall())


def query_one(
    sql: str, parameters: tuple[Any, ...] = (), database_path: str | Path | None = None
) -> sqlite3.Row | None:
    with get_connection(database_path) as connection:
        return connection.execute(sql, parameters).fetchone()


def insert_many(
    sql: str, rows: list[tuple[Any, ...]], database_path: str | Path | None = None
) -> list[int]:
    """Insert a batch and return its generated row IDs."""
    if not rows:
        return []
    with get_connection(database_path) as connection:
        cursor = connection.executemany(sql, rows)
        first_id = cursor.lastrowid
        if first_id is None:
            return []
        return list(range(first_id - len(rows) + 1, first_id + 1))


def get_settings(database_path: str | Path | None = None) -> dict[str, int]:
    rows = query_all("SELECT setting_key, setting_value FROM app_settings", database_path=database_path)
    settings = dict(DEFAULT_SETTINGS)
    settings.update({row["setting_key"]: int(row["setting_value"]) for row in rows})
    return settings


def update_settings(values: dict[str, int], database_path: str | Path | None = None) -> None:
    with get_connection(database_path) as connection:
        connection.executemany(
            """INSERT INTO app_settings(setting_key, setting_value) VALUES (?, ?)
               ON CONFLICT(setting_key) DO UPDATE SET setting_value = excluded.setting_value""",
            [(key, str(value)) for key, value in values.items()],
        )
