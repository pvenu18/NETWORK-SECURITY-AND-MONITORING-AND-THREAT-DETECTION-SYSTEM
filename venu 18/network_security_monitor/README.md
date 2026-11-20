# Network Security Monitoring and Threat Detection System

A beginner-friendly SOC dashboard prototype built with Flask, SQLite, Pandas, Chart.js, Scikit-learn, and Scapy. It analyzes **simulated traffic** or a user-supplied CSV / authorized offline PCAP file. It does not open a packet-capture interface, scan a network, or represent itself as real-time monitoring.

## Features

- Dark responsive dashboard with working navigation for Dashboard, Network Monitoring, Traffic Analysis, Threat Detection, Security Alerts, Reports, and Settings.
- SQLite persistence for `traffic_logs`, `security_alerts`, `detection_results`, `monitoring_sessions`, and detection settings.
- Synthetic data generation with documentation-range IP addresses and explainable rules for potential port scans, unusually frequent connections, high-volume records, and review of selected sensitive ports.
- Pandas-backed hourly, daily, and protocol summaries displayed by Chart.js.
- Optional Isolation Forest analysis; results are stored and presented as potential anomalies, not proof of an attack.
- CSV validation / import, authorized local `.pcap` import through Scapy, downloadable traffic CSV, and downloadable text summary.
- Adjustable and validated defensive-rule thresholds.

## Project layout

```text
network_security_monitor/
├── app.py
├── config.py
├── database.py
├── requirements.txt
├── detection/
├── monitoring/
├── templates/
├── static/css/
├── static/js/
├── data/sample_traffic.csv
└── tests/
```

## Run in Visual Studio Code (Windows PowerShell)

1. Open the `network_security_monitor` folder in VS Code (`File > Open Folder`).
2. Open the VS Code terminal and create a virtual environment:

   ```powershell
   py -3 -m venv .venv
   ```

3. Activate it and install dependencies:

   ```powershell
   .\.venv\Scripts\Activate.ps1
   python -m pip install --upgrade pip
   pip install -r requirements.txt
   ```

   If PowerShell blocks activation, use the environment interpreter directly:

   ```powershell
   .\.venv\Scripts\python.exe -m pip install -r requirements.txt
   ```

4. In VS Code, choose `.venv\Scripts\python.exe` using **Python: Select Interpreter**.
5. Initialize SQLite and load the included synthetic CSV. The database is created automatically at `data/network_monitor.db` the first time the app starts. To initialize without starting the web server:

   ```powershell
   python -c "from database import initialize_database; initialize_database(); print('SQLite schema initialized')"
   ```

6. Start the dashboard:

   ```powershell
   python app.py
   ```

7. Open `http://127.0.0.1:5000` in a browser. Keep the terminal open while using the app.
8. Use **Network Monitoring > Generate & analyze** to add synthetic records and verify alerts. Review **Security Alerts** and **Traffic Analysis** afterward. The same page accepts firewall CSV input and explicitly authorized local PCAP files.
9. Run the tests from the project directory:

   ```powershell
   python -m unittest discover -s tests -v
   ```

## CSV input format

CSV uploads need the columns `timestamp,src_ip,dst_ip,dst_port,protocol,bytes,action`. Timestamps must include an ISO 8601 timezone (`Z` or an offset); protocols are `tcp`, `udp`, or `icmp`; actions are `allowed` or `blocked`. The included CSV uses documentation-only addresses and synthetic events.

For PCAP imports, use only a file you are authorized to analyze. Uploads are limited to 15 MB, parsed locally, and not used to initiate network traffic. Scapy is used only as an offline file reader.

## Detection and model notes

Threshold rules are deterministic and editable under **Settings**. They are starting heuristics: ordinary applications may trigger them, and activity can go undetected if thresholds are unsuitable. Isolation Forest scores the observed numeric port, byte count, protocol, and per-source frequency features; its output is an investigation aid, not a classification of attacker intent. Model analysis requires at least eight records.

This is a portfolio / educational prototype. For production monitoring, integrate authorized flow or endpoint telemetry, secure access and secrets, retention controls, analyst tuning, and operational incident procedures.

## Interview explanation

> “I built a modular Python network-monitoring prototype with a Flask SOC dashboard and SQLite persistence. It ingests synthetic events or authorized offline traffic files, aggregates hourly and protocol metrics with Pandas, and applies explainable rolling-window detection rules. It also offers an optional Isolation Forest anomaly score and lets analysts review alerts and export reports. I deliberately avoid active scanning or claiming live capture; simulated data and model flags are explicitly labeled as indicators that need human investigation.”
