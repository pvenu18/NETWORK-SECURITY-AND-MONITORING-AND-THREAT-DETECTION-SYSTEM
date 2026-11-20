"""Flask application for the Network Security Monitoring prototype."""

from __future__ import annotations

import csv
import io
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, Response, jsonify, redirect, render_template, request, url_for

from config import DATABASE_PATH, MAX_UPLOAD_BYTES, SECRET_KEY
from database import (
    get_connection,
    get_settings,
    initialize_database,
    query_all,
    query_one,
    update_settings,
)
from detection.anomaly_detection import detect_anomalies
from detection.threat_detector import detect_threats, utc_now_iso
from detection.traffic_analyzer import summarize_traffic
from monitoring.simulated_traffic import generate_traffic_batch
from monitoring.traffic_monitor import parse_authorized_pcap, parse_traffic_csv

PAGES = {
    "dashboard": ("Dashboard", "dashboard.html"),
    "monitoring": ("Network Monitoring", "monitoring.html"),
    "analysis": ("Traffic Analysis", "analysis.html"),
    "threats": ("Threat Detection", "threats.html"),
    "alerts": ("Security Alerts", "alerts.html"),
    "reports": ("Reports", "reports.html"),
    "settings": ("Settings", "settings.html"),
}


def create_app(test_config: dict | None = None) -> Flask:
    application = Flask(__name__)
    application.config.update(
        SECRET_KEY=SECRET_KEY,
        DATABASE_PATH=DATABASE_PATH,
        MAX_CONTENT_LENGTH=MAX_UPLOAD_BYTES,
    )
    if test_config:
        application.config.update(test_config)
    initialize_database(application.config["DATABASE_PATH"])
    seed_sample_traffic(application.config["DATABASE_PATH"])

    @application.get("/")
    def home():
        return redirect(url_for("page", page_name="dashboard"))

    @application.get("/<page_name>")
    def page(page_name: str):
        if page_name not in PAGES:
            return render_template("not_found.html"), 404
        title, template = PAGES[page_name]
        context = {"page_title": title, "active_page": page_name}
        if page_name == "alerts":
            context["alerts"] = query_all(
                "SELECT * FROM security_alerts ORDER BY timestamp DESC, id DESC LIMIT 200",
                database_path=application.config["DATABASE_PATH"],
            )
        elif page_name == "settings":
            context["settings"] = get_settings(application.config["DATABASE_PATH"])
        elif page_name == "threats":
            context["detection_results"] = query_all(
                """SELECT dr.*, tl.src_ip, tl.dst_ip, tl.dst_port, tl.protocol, tl.timestamp
                   FROM detection_results dr
                   JOIN traffic_logs tl ON tl.id = dr.traffic_log_id
                   ORDER BY dr.detected_at DESC, dr.id DESC LIMIT 100""",
                database_path=application.config["DATABASE_PATH"],
            )
        elif page_name == "monitoring":
            context["recent_traffic"] = query_all(
                "SELECT * FROM traffic_logs ORDER BY timestamp DESC, id DESC LIMIT 25",
                database_path=application.config["DATABASE_PATH"],
            )
        return render_template(template, **context)

    @application.get("/api/overview")
    def overview():
        database_path = application.config["DATABASE_PATH"]
        counts = query_one(
            """SELECT COUNT(*) AS connections,
                      SUM(CASE WHEN action = 'blocked' THEN 1 ELSE 0 END) AS blocked
               FROM traffic_logs""",
            database_path=database_path,
        )
        alert_counts = query_one(
            """SELECT COUNT(*) AS total,
                      SUM(CASE WHEN status = 'Open' THEN 1 ELSE 0 END) AS open
               FROM security_alerts""",
            database_path=database_path,
        )
        model_counts = query_one(
            """SELECT COUNT(*) AS total,
                      SUM(CASE WHEN is_anomaly = 1 THEN 1 ELSE 0 END) AS anomalies
               FROM detection_results""",
            database_path=database_path,
        )
        rows = query_all(
            "SELECT timestamp, protocol, byte_count FROM traffic_logs ORDER BY timestamp DESC LIMIT 5000",
            database_path=database_path,
        )
        traffic = summarize_traffic([dict(row) for row in rows])
        latest_session = query_one(
            "SELECT * FROM monitoring_sessions ORDER BY id DESC LIMIT 1",
            database_path=database_path,
        )
        recent_alerts = query_all(
            "SELECT * FROM security_alerts ORDER BY timestamp DESC, id DESC LIMIT 6",
            database_path=database_path,
        )
        return jsonify(
            {
                "connections": counts["connections"] or 0,
                "suspicious": counts["blocked"] or 0,
                "alerts": alert_counts["total"] or 0,
                "open_alerts": alert_counts["open"] or 0,
                "normal": max((counts["connections"] or 0) - (counts["blocked"] or 0), 0),
                "anomalies": model_counts["anomalies"] or 0,
                "model_records": model_counts["total"] or 0,
                "traffic": traffic,
                "session": dict(latest_session) if latest_session else None,
                "recent_alerts": [dict(row) for row in recent_alerts],
            }
        )

    @application.get("/api/traffic")
    def traffic():
        rows = query_all(
            "SELECT * FROM traffic_logs ORDER BY timestamp DESC, id DESC LIMIT 200",
            database_path=application.config["DATABASE_PATH"],
        )
        return jsonify([dict(row) for row in rows])

    @application.post("/api/simulate")
    def simulate():
        payload = request.get_json(silent=True) or {}
        try:
            count = int(payload.get("count", 24))
            records = generate_traffic_batch(count)
            session_id, saved_records, alerts_created = persist_batch(
                records,
                source="synthetic simulation",
                database_path=application.config["DATABASE_PATH"],
            )
        except (TypeError, ValueError) as exc:
            return jsonify({"error": str(exc)}), 400
        return jsonify(
            {
                "session_id": session_id,
                "records_added": len(saved_records),
                "alerts_created": alerts_created,
                "message": "Synthetic traffic batch analyzed and stored.",
            }
        )

    @application.post("/api/import/csv")
    def import_csv():
        upload = request.files.get("file")
        if upload is None or not upload.filename:
            return jsonify({"error": "Choose a CSV file first."}), 400
        if Path(upload.filename).suffix.lower() != ".csv":
            return jsonify({"error": "Only .csv files are accepted."}), 400
        try:
            records = parse_traffic_csv(upload.read(MAX_UPLOAD_BYTES + 1))
            if not records:
                return jsonify({"error": "The CSV contains no traffic records."}), 400
            session_id, saved_records, alerts_created = persist_batch(
                records,
                source="uploaded CSV",
                database_path=application.config["DATABASE_PATH"],
            )
        except (ValueError, OSError) as exc:
            return jsonify({"error": str(exc)}), 400
        return jsonify(
            {
                "session_id": session_id,
                "records_added": len(saved_records),
                "alerts_created": alerts_created,
            }
        )

    @application.post("/api/import/pcap")
    def import_pcap():
        if request.form.get("authorized") != "yes":
            return jsonify({"error": "Confirm that you are authorized to analyze this capture."}), 400
        upload = request.files.get("file")
        if upload is None or not upload.filename:
            return jsonify({"error": "Choose a PCAP file first."}), 400
        if Path(upload.filename).suffix.lower() != ".pcap":
            return jsonify({"error": "Only classic .pcap files are accepted."}), 400
        try:
            content = upload.read(MAX_UPLOAD_BYTES + 1)
            if len(content) > MAX_UPLOAD_BYTES:
                return jsonify({"error": "The upload exceeds the 15 MB limit."}), 413
            with tempfile.NamedTemporaryFile(suffix=".pcap") as temporary_file:
                temporary_file.write(content)
                temporary_file.flush()
                records = parse_authorized_pcap(temporary_file.name)
            if not records:
                return jsonify({"error": "No IPv4 TCP, UDP, or ICMP packets were found."}), 400
            session_id, saved_records, alerts_created = persist_batch(
                records,
                source="authorized offline PCAP import",
                database_path=application.config["DATABASE_PATH"],
            )
        except (OSError, ValueError, RuntimeError) as exc:
            return jsonify({"error": str(exc)}), 400
        return jsonify(
            {
                "session_id": session_id,
                "records_added": len(saved_records),
                "alerts_created": alerts_created,
            }
        )

    @application.post("/api/anomalies/run")
    def run_anomalies():
        database_path = application.config["DATABASE_PATH"]
        rows = query_all(
            """SELECT id, session_id, timestamp, src_ip, dst_ip, dst_port, protocol, byte_count, action
               FROM traffic_logs ORDER BY timestamp DESC LIMIT 5000""",
            database_path=database_path,
        )
        records = [dict(row) for row in reversed(rows)]
        try:
            results = detect_anomalies(records)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        with get_connection(database_path) as connection:
            connection.executemany(
                """INSERT INTO detection_results
                   (traffic_log_id, model_name, detected_at, is_anomaly, anomaly_score)
                   VALUES (?, 'Isolation Forest', ?, ?, ?)""",
                [
                    (
                        result["traffic_log_id"],
                        result["detected_at"],
                        result["is_anomaly"],
                        result["anomaly_score"],
                    )
                    for result in results
                ],
            )
            records_by_id = {record["id"]: record for record in records}
            for result in results:
                if not result["is_anomaly"]:
                    continue
                record = records_by_id[result["traffic_log_id"]]
                connection.execute(
                    """INSERT INTO security_alerts
                       (traffic_log_id, session_id, timestamp, category, severity, src_ip,
                        dst_ip, description, evidence)
                       VALUES (?, ?, ?, 'Potential ML anomaly', 'Low', ?, ?, ?, ?)""",
                    (
                        record["id"],
                        record["session_id"],
                        result["detected_at"],
                        record["src_ip"],
                        record["dst_ip"],
                        "Isolation Forest flagged this traffic record as unusual; analyst review is recommended.",
                        f"Model decision score: {result['anomaly_score']:.4f}. This is an investigation indicator.",
                    ),
                )
        return jsonify(
            {
                "records_analyzed": len(results),
                "anomalies": sum(result["is_anomaly"] for result in results),
                "message": "Anomalies are investigation indicators, not proof of an attack.",
            }
        )

    @application.post("/api/alerts/<int:alert_id>/status")
    def update_alert_status(alert_id: int):
        payload = request.get_json(silent=True) or {}
        status = payload.get("status")
        if status not in {"Open", "Investigating", "Resolved"}:
            return jsonify({"error": "Status must be Open, Investigating, or Resolved."}), 400
        with get_connection(application.config["DATABASE_PATH"]) as connection:
            cursor = connection.execute(
                "UPDATE security_alerts SET status = ? WHERE id = ?",
                (status, alert_id),
            )
        if cursor.rowcount == 0:
            return jsonify({"error": "Alert not found."}), 404
        return jsonify({"id": alert_id, "status": status})

    @application.get("/api/settings")
    def settings():
        return jsonify(get_settings(application.config["DATABASE_PATH"]))

    @application.post("/api/settings")
    def save_settings():
        payload = request.get_json(silent=True) or {}
        limits = {
            "window_minutes": (1, 60),
            "port_scan_threshold": (2, 100),
            "repeat_connection_threshold": (2, 500),
            "high_volume_bytes": (1024, 1_000_000_000),
        }
        values: dict[str, int] = {}
        try:
            for key, (minimum, maximum) in limits.items():
                value = int(payload[key])
                if not minimum <= value <= maximum:
                    raise ValueError(f"{key} must be between {minimum} and {maximum}.")
                values[key] = value
        except (KeyError, TypeError, ValueError) as exc:
            return jsonify({"error": str(exc) or "All setting values must be integers."}), 400
        update_settings(values, application.config["DATABASE_PATH"])
        return jsonify(values)

    @application.get("/reports/export.csv")
    def export_csv():
        rows = query_all(
            "SELECT timestamp, src_ip, dst_ip, dst_port, protocol, byte_count, action "
            "FROM traffic_logs ORDER BY timestamp DESC",
            database_path=application.config["DATABASE_PATH"],
        )
        output = io.StringIO(newline="")
        writer = csv.writer(output)
        writer.writerow(("timestamp", "src_ip", "dst_ip", "dst_port", "protocol", "bytes", "action"))
        writer.writerows(
            (
                row["timestamp"],
                row["src_ip"],
                row["dst_ip"],
                row["dst_port"],
                row["protocol"],
                row["byte_count"],
                row["action"],
            )
            for row in rows
        )
        return Response(
            output.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": "attachment; filename=network_traffic_report.csv"},
        )

    @application.get("/reports/download")
    def download_report():
        database_path = application.config["DATABASE_PATH"]
        traffic_counts = query_one(
            """SELECT COUNT(*) AS total,
                      SUM(CASE WHEN action = 'blocked' THEN 1 ELSE 0 END) AS blocked
               FROM traffic_logs""",
            database_path=database_path,
        )
        alert_counts = query_one(
            "SELECT COUNT(*) AS total FROM security_alerts",
            database_path=database_path,
        )
        generated = datetime.now(timezone.utc).isoformat(timespec="seconds")
        body = (
            "Network Security Monitoring and Threat Detection System\n"
            f"Generated (UTC): {generated}\n"
            f"Traffic records: {traffic_counts['total'] or 0}\n"
            f"Blocked records: {traffic_counts['blocked'] or 0}\n"
            f"Security alerts: {alert_counts['total'] or 0}\n\n"
            "Important: rule alerts and model anomalies are triage indicators, not proof of an attack.\n"
            "This prototype uses simulated or user-authorized offline input; it does not claim live monitoring.\n"
        )
        return Response(
            body,
            mimetype="text/plain",
            headers={"Content-Disposition": "attachment; filename=security_summary.txt"},
        )

    @application.errorhandler(413)
    def request_too_large(_error):
        return jsonify({"error": "The upload exceeds the 15 MB limit."}), 413

    return application


def seed_sample_traffic(database_path: str | Path) -> None:
    """Load the included synthetic CSV once so a fresh install has demo data."""
    row = query_one("SELECT COUNT(*) AS total FROM traffic_logs", database_path=database_path)
    if row and row["total"]:
        return
    sample_path = Path(__file__).parent / "data" / "sample_traffic.csv"
    records = parse_traffic_csv(sample_path.read_bytes())
    persist_batch(records, "included synthetic sample", database_path)


def persist_batch(
    records: list[dict], source: str, database_path: str | Path
) -> tuple[int, list[dict], int]:
    """Atomically persist one input batch, session, and all rule alerts."""
    started_at = utc_now_iso()
    settings = get_settings(database_path)
    with get_connection(database_path) as connection:
        session_id = connection.execute(
            """INSERT INTO monitoring_sessions(started_at, source, status, records_count)
               VALUES (?, ?, 'running', 0)""",
            (started_at, source),
        ).lastrowid
        saved_records: list[dict] = []
        for record in records:
            cursor = connection.execute(
                """INSERT INTO traffic_logs
                   (session_id, timestamp, src_ip, dst_ip, dst_port, protocol, byte_count, action)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    session_id,
                    record["timestamp"],
                    record["src_ip"],
                    record["dst_ip"],
                    record["dst_port"],
                    record["protocol"],
                    record["byte_count"],
                    record["action"],
                ),
            )
            saved_records.append({**record, "id": cursor.lastrowid})

        threats = detect_threats(saved_records, settings)
        connection.executemany(
            """INSERT INTO security_alerts
               (traffic_log_id, session_id, timestamp, category, severity, src_ip, dst_ip,
                description, evidence)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            [
                (
                    threat.traffic_log_id,
                    session_id,
                    threat.timestamp,
                    threat.category,
                    threat.severity,
                    threat.src_ip,
                    threat.dst_ip,
                    threat.description,
                    threat.evidence,
                )
                for threat in threats
            ],
        )
        connection.execute(
            """UPDATE monitoring_sessions
               SET ended_at = ?, status = 'completed', records_count = ? WHERE id = ?""",
            (utc_now_iso(), len(saved_records), session_id),
        )
    return int(session_id), saved_records, len(threats)


app = create_app()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
