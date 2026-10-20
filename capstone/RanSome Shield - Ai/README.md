# RansomShield AI — Ransomware Behavior Detection and File Protection System

<p align="center">
  <strong>An Explainable Behavioral Heuristic Surveillance and Cryptographic File Shield for Endpoint Defense</strong><br>
  <em>Suitable for B.Tech Information Technology / Cybersecurity Ethical Hacking Capstone Projects</em>
</p>

---

## 1. Project Overview

**RansomShield AI** is a locally hosted, production-grade cybersecurity defensive solution designed to detect ransomware-like behavioral anomalies and protect user files in real time. Rather than relying on static signature scans alone, RansomShield AI implements a **multi-layered behavioral detection engine** with sliding-window event correlation, combined with **SHA-256 cryptographic integrity verification**, **secure local snapshot backups**, **conservative quarantine management**, and **automated PDF/CSV incident reporting**.

The system is built without any external cloud APIs, telemetry tracking, paid models, or node dependencies, ensuring 100% operational privacy and reliable offline execution.

---

## 2. Key Features

- **Real-Time File System Surveillance**: Leverages thread-safe Python `watchdog` observers to intercept file creation, rapid modification, mass renaming, and deletion events without blocking Flask requests.
- **Explainable Behavioral Heuristics Engine**:
  - Sliding time window analysis (configurable $1-120\text{s}$).
  - Burst modification and mass rename detection.
  - Multi-extension divergence and known pseudo-encrypted extension detection (`.locked`, `.crypto`, `.enc`, etc.).
  - Risk scoring ($0–100$) mapped to structured severity levels (**Low**, **Medium**, **High**, **Critical**).
  - Cooldown periods to prevent alert fatigue.
- **Cryptographic File Integrity Verification**:
  - Chunked SHA-256 baseline hashing.
  - Differential comparison identifying modified, missing, and new untracked files.
  - User-driven baseline approval workflow.
- **Resilient Backup & Verification**:
  - Application-isolated snapshot vault (`instance/backups/`).
  - Pre- and post-restoration SHA-256 hash checks to guarantee file fidelity.
  - Protection against recursive self-backup loops and path traversal attacks.
- **Targeted Quarantine Vault**:
  - UUID-based isolated file containment with full audit logging.
  - Safe restoration to original or operator-specified paths.
- **SOC Executive Incident Reports**:
  - Generates downloadable CSV audit logs and formatted PDF incident summaries via ReportLab.
- **Safe Capstone Demonstration Sandbox**:
  - Fully sandboxed simulation environment (`instance/demo_sandbox/`) using harmless sample text files.
  - Never executes real malware or demands payment.
  - One-click preparation, burst simulation, and safe cleanup.

---

## 3. Architecture & Modular Structure

```
RanSome Shield - Ai/
├── app.py                          # Flask application factory & lifecycle management
├── config.py                       # Security bindings, path constants, engine defaults
├── database.py                     # SQLAlchemy database instance
├── models.py                       # Data models (MonitoredFolder, FileEvent, SecurityAlert, etc.)
├── requirements.txt                # Production and test dependencies
├── pytest.ini                      # Test runner configuration
├── README.md                       # Comprehensive documentation
│
├── detection/                      # Behavioral detection package
│   ├── __init__.py
│   ├── behavior_detector.py        # Sliding-window event processor & cooldown deduplicator
│   ├── integrity_checker.py        # Streaming SHA-256 baseline & comparison engine
│   └── risk_scorer.py              # Explainable 0-100 risk scoring & severity mapping
│
├── monitoring/                     # File system surveillance package
│   ├── __init__.py
│   ├── file_monitor.py             # Watchdog event handler with security ignore filters
│   └── monitoring_manager.py       # Thread-safe multi-folder observer coordinator
│
├── protection/                     # Snapshot & isolation package
│   ├── __init__.py
│   ├── backup_manager.py           # Snapshot creator & checksum validator
│   ├── recovery_manager.py         # Post-restore integrity verification
│   └── quarantine_manager.py       # Safe file isolation & restoration
│
├── routes/                         # Application route blueprints
│   ├── __init__.py
│   ├── dashboard_routes.py         # SOC dashboard telemetry & Chart.js feeds
│   ├── monitoring_routes.py        # Folder registration & integrity API endpoints
│   ├── protection_routes.py        # Backup, restore & quarantine endpoints
│   ├── alert_routes.py             # Incident triage & investigation notes
│   ├── report_routes.py            # Summary metrics, CSV & PDF report generators
│   ├── settings_routes.py          # Engine threshold calibration
│   └── demo_routes.py              # Sandbox simulation & cleanup endpoints
│
├── templates/                      # Jinja2 HTML templates
│   ├── base.html                   # Master layout with SOC aesthetic & navigation
│   ├── dashboard.html              # Real-time metrics & telemetry charts
│   ├── monitoring.html             # Directory monitoring & integrity modal
│   ├── protection.html             # Snapshots, quarantine & restoration logs
│   ├── alerts.html                 # Incident triage & investigation modal
│   ├── reports.html                # Executive summaries & report export
│   ├── settings.html               # Heuristic threshold calibration
│   ├── 404.html                    # Endpoint error page
│   └── 500.html                    # Exception error page
│
├── static/
│   ├── css/
│   │   └── style.css               # SOC dark navy design system & animations
│   └── js/
│       ├── app.js                  # Global utilities, live clock, CSRF handler
│       ├── dashboard.js            # Live telemetry polling & Chart.js instances
│       ├── monitoring.js           # Directory management & baseline review
│       ├── protection.js           # Snapshot operations & quarantine controls
│       ├── alerts.js               # Incident investigation workflow
│       └── reports.js              # Export triggers
│
├── instance/                       # Local runtime directory (DB, backups, logs, sandbox)
│   └── .gitkeep
│
└── tests/                          # Automated pytest verification suite
    ├── test_detection.py           # Heuristic & risk score tests
    ├── test_integrity.py           # SHA-256 & differential comparison tests
    ├── test_backup_recovery.py     # Snapshot, restore & guard tests
    └── test_routes_and_security.py # API endpoints, PDF export & sandbox lifecycle tests
```

---

## 4. Installation & Setup

### Prerequisites
- **Python 3.10+** (Tested on Python 3.14 on Windows 10/11 and Python 3.11+ on Kali Linux)
- Git (optional)

### Setup on Windows 10 / 11

1. Open PowerShell or Command Prompt in the project folder:
   ```powershell
   cd "c:\path\to\RanSome Shield - Ai"
   ```

2. Create and activate a Python virtual environment:
   ```powershell
   py -m venv .venv
   .\.venv\Scripts\activate
   ```

3. Install required dependencies:
   ```powershell
   python -m pip install -r requirements.txt
   ```

4. Launch the application:
   ```powershell
   python app.py
   ```

5. Open your browser and navigate to:
   ```
   http://127.0.0.1:5000
   ```

---

### Setup on Kali Linux / Ubuntu

1. Open a terminal in the project directory:
   ```bash
   cd /path/to/RansomShield-AI
   ```

2. Create and activate a virtual environment:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Run the server:
   ```bash
   python3 app.py
   ```

5. Open your browser at `http://127.0.0.1:5000`.

---

## 5. Running Automated Tests

Run the full automated test suite using `pytest`:

```bash
# Windows
.\.venv\Scripts\pytest -v

# Linux
pytest -v
```

All 14 tests will execute, validating:
- Explainable risk calculation and severity assignment.
- Rapid modification and renaming heuristic detections.
- Alert deduplication and cooldown periods.
- Streaming SHA-256 chunk hashing and baseline differential comparisons.
- Safe backup snapshot creation and post-restore integrity checks.
- Path traversal rejection and recursive self-backup prevention.
- Incident report CSV and PDF generation.
- Full sandbox lifecycle (prepare, simulate, and clean).

---

## 6. Demonstration Workflow for Capstone Presentations

1. **Open the Application**: Navigate to `http://127.0.0.1:5000` in your web browser.
2. **Access the Simulator**: Click the **Launch Demo Suite** button in the left sidebar.
3. **Step 1 — Prepare Sandbox**: Click **Prepare Sandbox**. This generates 12 harmless sample text files inside `instance/demo_sandbox/` and automatically registers the directory with an active Watchdog observer.
4. **Step 2 — Create Baseline & Backup**:
   - Go to **File Monitoring** &rarr; click **Create Baseline** on the demo directory.
   - Go to **Protection & Backups** &rarr; click **Create Backup Snapshot** on any sample file.
5. **Step 3 — Trigger Simulation**:
   - Return to the Demo Suite and click **Trigger Burst Event**.
   - The simulator rapidly modifies files and appends `.locked` extensions to mimic ransomware velocity.
6. **Step 4 — Observe Defensive Response**:
   - Look at the **SOC Dashboard**: Notice the live chart spike, incrementing suspicious event counts, and critical incident cards.
   - Look at **Security Alerts**: Inspect the incident details, examine the explainable heuristic evidence (e.g. *mass renaming*, *modification velocity*, *suspicious extension signature*), acknowledge the alert, and record investigation notes.
   - Run an **Integrity Check**: Go to **File Monitoring** &rarr; click **Verify Integrity** on the demo directory to inspect the list of modified, deleted, and newly created files.
   - Test **Recovery**: Go to **Protection & Backups** &rarr; click **Restore** on your backup snapshot to recover the original file and verify that post-restoration SHA-256 checksums match.
7. **Step 5 — Generate Incident Report**:
   - Go to **Incident Reports** &rarr; click **Export PDF Report** to download an executive forensic report.
8. **Step 6 — Cleanup**:
   - Open the Demo Suite and click **Purge Demo Files** to reset the sandbox cleanly.

---

## 7. Security Architecture & Defensive Posture

- **Strict Localhost Binding**: The server is configured to bind strictly to `127.0.0.1:5000` to prevent unauthenticated access over local area networks.
- **Path Traversal Guards**: All user-supplied paths are validated on the server using `Path.resolve()`, preventing directory traversal and access outside authorized bounds.
- **Dedicated Isolation Vaults**: Backups, quarantine files, databases, and logs are kept strictly outside the static web folder in an unserved `instance/` storage directory.
- **CSRF Protection**: All state-changing requests (`POST`, `DELETE`, `PUT`) require valid session tokens passed via headers or forms.
- **Streaming Cryptography**: SHA-256 checksums are calculated in 64KB chunks to prevent memory spikes on large files.
- **Defensive Limitation Advisory**: While RansomShield AI provides local behavioral anomaly detection and file snapshot recovery, backups stored on the same writable physical disk can theoretically be affected by ransomware operating with elevated administrative privileges. Critical environments must always maintain offline, air-gapped backups.

---

## 8. Technology Stack

- **Backend**: Python 3.10+, Flask, Flask-SQLAlchemy, SQLite, Watchdog, ReportLab, Pytest
- **Frontend**: HTML5, Vanilla CSS3 (Custom SOC Dark Navy Theme), Vanilla JavaScript (ES6+), Chart.js
- **Security Utilities**: `hashlib`, `pathlib`, `shutil`, `secrets`, `threading`
