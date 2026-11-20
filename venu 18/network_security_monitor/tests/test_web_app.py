from __future__ import annotations

import io
import tempfile
import unittest
from pathlib import Path

from app import create_app


class DashboardApplicationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        database_path = Path(self.temporary_directory.name) / "test.sqlite3"
        self.app = create_app(
            {
                "TESTING": True,
                "DATABASE_PATH": database_path,
                "SECRET_KEY": "test-key",
            }
        )
        self.client = self.app.test_client()

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def test_sidebar_pages_render(self) -> None:
        for page in ("dashboard", "monitoring", "analysis", "threats", "alerts", "reports", "settings"):
            with self.subTest(page=page):
                response = self.client.get(f"/{page}")
                self.assertEqual(response.status_code, 200)

    def test_seed_data_is_stored_and_alerted(self) -> None:
        overview = self.client.get("/api/overview").get_json()
        self.assertGreaterEqual(overview["connections"], 8)
        self.assertGreater(overview["alerts"], 0)

    def test_simulation_adds_records_and_detection_alerts(self) -> None:
        response = self.client.post("/api/simulate", json={"count": 24})
        self.assertEqual(response.status_code, 200)
        result = response.get_json()
        self.assertEqual(result["records_added"], 24)
        self.assertGreater(result["alerts_created"], 0)

    def test_invalid_simulation_count_is_reported(self) -> None:
        response = self.client.post("/api/simulate", json={"count": 2})
        self.assertEqual(response.status_code, 400)
        self.assertIn("error", response.get_json())

    def test_csv_report_is_downloadable(self) -> None:
        response = self.client.get("/reports/export.csv")
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/csv", response.content_type)
        self.assertIn(b"src_ip,dst_ip", response.data)

    def test_settings_are_saved_and_validated(self) -> None:
        saved = self.client.post(
            "/api/settings",
            json={
                "window_minutes": 10,
                "port_scan_threshold": 7,
                "repeat_connection_threshold": 9,
                "high_volume_bytes": 2048,
            },
        )
        self.assertEqual(saved.status_code, 200)
        invalid = self.client.post("/api/settings", json={"window_minutes": 0})
        self.assertEqual(invalid.status_code, 400)

    def test_csv_import_runs_detection_and_persists_records(self) -> None:
        content = (
            b"timestamp,src_ip,dst_ip,dst_port,protocol,bytes,action\n"
            b"2026-11-05T10:00:00Z,192.0.2.90,198.51.100.10,443,tcp,64,allowed\n"
        )
        response = self.client.post(
            "/api/import/csv",
            data={"file": (io.BytesIO(content), "authorized-export.csv")},
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["records_added"], 1)

    def test_pcap_import_requires_authorization_confirmation(self) -> None:
        response = self.client.post("/api/import/pcap")
        self.assertEqual(response.status_code, 400)
        self.assertIn("authorized", response.get_json()["error"])

    def test_alert_status_can_be_updated(self) -> None:
        response = self.client.post("/api/alerts/1/status", json={"status": "Investigating"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["status"], "Investigating")

    def test_anomaly_model_scores_and_persists_results(self) -> None:
        before = self.client.get("/api/overview").get_json()
        response = self.client.post("/api/anomalies/run")
        self.assertEqual(response.status_code, 200)
        result = response.get_json()
        self.assertGreaterEqual(result["records_analyzed"], 8)
        self.assertGreaterEqual(result["anomalies"], 0)
        after = self.client.get("/api/overview").get_json()
        self.assertGreaterEqual(after["alerts"], before["alerts"] + result["anomalies"])
        page = self.client.get("/threats")
        self.assertIn(b"Isolation Forest results", page.data)


if __name__ == "__main__":
    unittest.main()
