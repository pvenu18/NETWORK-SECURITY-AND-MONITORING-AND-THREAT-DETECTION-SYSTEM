"""Application configuration and safe, tunable detection defaults."""

import os
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = Path(
    os.environ.get("NSM_DATABASE_PATH", BASE_DIR / "data" / "network_monitor.db")
)
SECRET_KEY = os.environ.get("NSM_SECRET_KEY", "local-development-key-change-me")
MAX_UPLOAD_BYTES = 15 * 1024 * 1024

DEFAULT_SETTINGS = {
    "window_minutes": 5,
    "port_scan_threshold": 6,
    "repeat_connection_threshold": 8,
    "high_volume_bytes": 1_000_000,
}
