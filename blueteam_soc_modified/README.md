# 🛡️ BlueTeam SOC — Unified Threat Detection System

A production-grade Security Operations Center (SOC) built in Python, featuring
real-time threat detection, attack simulation, MITRE ATT&CK mapping, risk scoring,
and a live Flask dashboard. Runs entirely on Windows 10/11 with optional Splunk integration.

---

## 📁 Project Structure

```
blueteam_soc/
├── main.py                        ← CLI entry point (all commands)
├── config.py                      ← Central configuration
├── requirements.txt
│
├── core/
│   ├── event_model.py             ← SecurityEvent + Alert dataclasses
│   ├── alert_store.py             ← Thread-safe JSON alert persistence
│   └── monitor.py                 ← Real-time log watcher + console alerts
│
├── parsers/
│   └── log_parser.py              ← Sysmon + Windows Event log parsers
│
├── detections/
│   ├── rules_engine.py            ← All 8 detection rules (MITRE-mapped)
│   └── risk_scorer.py             ← Composite risk scoring per host
│
├── simulations/
│   └── attack_simulator.py        ← Full APT kill-chain simulator
│
├── dashboard/
│   ├── app.py                     ← Flask + SocketIO real-time dashboard
│   └── templates/
│       └── dashboard.html         ← Cyberpunk SOC dashboard UI
│
├── splunk_queries/
│   └── spl_queries.md             ← Advanced SPL queries for Splunk
│
├── reports/
│   └── report_generator.py        ← Incident report generator
│
├── data/
│   ├── logs/                      ← Sysmon + Windows event JSON logs
│   └── alerts/                    ← Persisted alerts + risk scores
│
└── .vscode/
    └── launch.json                ← VSCode debug configurations
```

---

## 🚀 Step-by-Step Setup in VSCode

### STEP 1 — Prerequisites

Install the following before starting:

- **Python 3.10+** → https://www.python.org/downloads/
  - ✅ Check "Add Python to PATH" during install
- **VSCode** → https://code.visualstudio.com/
- **Git** (optional) → https://git-scm.com/

Verify Python works:
```
python --version
pip --version
```

---

### STEP 2 — Open Project in VSCode

1. Extract the `blueteam_soc.zip` file to a folder (e.g. `C:\Projects\blueteam_soc`)
2. Open VSCode
3. `File → Open Folder` → select the `blueteam_soc` folder
4. You should see the full project tree in the Explorer panel

---

### STEP 3 — Install VSCode Extensions

Open the Extensions panel (`Ctrl+Shift+X`) and install:

- **Python** (by Microsoft) — IntelliSense, debugging
- **Pylance** — Type checking
- **REST Client** (optional) — test API endpoints inline

---

### STEP 4 — Create a Virtual Environment

Open the integrated terminal (`Ctrl+` ` `` ` or Terminal → New Terminal):

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# macOS / Linux
python3 -m venv venv
source venv/bin/activate
```

You should see `(venv)` at the start of your terminal prompt.

---

### STEP 5 — Install Dependencies

```bash
pip install -r requirements.txt
```

Expected output: colorama, flask, flask-socketio, watchdog, schedule, eventlet all installed.

---

### STEP 6 — Select Python Interpreter in VSCode

1. Press `Ctrl+Shift+P`
2. Type: `Python: Select Interpreter`
3. Choose the interpreter inside your `venv` folder
   - Windows: `.\venv\Scripts\python.exe`
   - macOS/Linux: `./venv/bin/python`

---

## ⚔️ Running the System — All Workflows

### Workflow A — Full Demo (Recommended First Run)

Open **3 separate terminals** in VSCode (`+` button in terminal panel):

**Terminal 1 — Launch Dashboard:**
```bash
python main.py dashboard
```
Open browser: http://127.0.0.1:5000

**Terminal 2 — Start Real-time Monitor:**
```bash
python main.py monitor --interval 5
```

**Terminal 3 — Simulate Full Attack Chain:**
```bash
python main.py simulate --scenario full_chain --host WORKSTATION-01 --user attacker
```

Watch alerts appear live in the terminal AND the browser dashboard simultaneously.

---

### Workflow B — VSCode Debug (F5 Launch Configs)

The `.vscode/launch.json` has 5 pre-built configs. Press `F5` and choose:

| Config | What it does |
|--------|--------------|
| 🛡️ Dashboard (Flask) | Starts the web dashboard |
| ⚔️ Simulate: Full Attack Chain | Injects APT kill-chain logs |
| 🔍 Monitor (Real-time) | Watches logs every 5s |
| 📊 Analyse Once | Runs all detection rules once |
| 📄 Generate Report | Creates incident report |

---

### Workflow C — Individual Scenarios

```bash
# Brute force only
python main.py simulate --scenario brute_force --user jdoe

# Mimikatz / credential dump
python main.py simulate --scenario mimikatz --host DC-01

# C2 beacon
python main.py simulate --scenario c2_connection

# Registry persistence
python main.py simulate --scenario persistence

# Lateral movement
python main.py simulate --scenario lateral_movement

# Suspicious PowerShell
python main.py simulate --scenario suspicious_powershell

# Privilege escalation
python main.py simulate --scenario privilege_escalation
```

---

### Workflow D — Generate Incident Report

```bash
python main.py report
```

Report is saved to `reports/soc_report_YYYYMMDD_HHMMSS.txt`

---

### Workflow E — Clear Everything and Start Fresh

```bash
python main.py clear
```

This clears `data/alerts/alerts.json`. Log files in `data/logs/` are preserved.
To also clear logs:
```bash
del data\logs\sysmon_events.json
del data\logs\windows_events.json
```

---

## 🔍 Detection Rules Reference

| Rule | Event IDs | MITRE | Severity |
|------|-----------|-------|----------|
| Brute Force | 4625 ×5 in 60s | T1110 | MEDIUM→HIGH |
| Login After Failures | 4625→4624 | T1110 | HIGH |
| Suspicious Process | Sysmon EID 1 | T1059 | MEDIUM→HIGH |
| Privilege Escalation | 4672 | T1068 | HIGH |
| Persistence | Sysmon EID 13 | T1547 | HIGH |
| C2 Connection | Sysmon EID 3 | T1071 | CRITICAL |
| Lateral Movement | Sysmon EID 3 + WMIC/PSExec | T1021 | HIGH |
| Credential Dumping | mimikatz / lsass | T1003 | CRITICAL |

---

## 🌐 Dashboard Features

| Panel | Description |
|-------|-------------|
| KPI Strip | Live counts: Total, Critical, High, Medium, Low |
| Live Alert Feed | Real-time scrolling alerts with severity badges |
| Severity Donut | Chart.js doughnut breakdown |
| Detection Bar Chart | Alerts grouped by detection type |
| Alert Timeline | Chronological event timeline |
| MITRE Table | Full ATT&CK technique/tactic coverage |
| Attack Simulator | Launch any scenario from the UI |

---

## 🔌 Optional: Real Splunk Integration

1. Install Splunk Free Trial: https://www.splunk.com/en_us/download/splunk-enterprise.html
2. Install **Sysmon**: https://docs.microsoft.com/sysinternals/downloads/sysmon
3. Apply Sysmon config: `sysmon -accepteula -i sysmonconfig.xml`
4. In `config.py` set:
   ```python
   SPLUNK_ENABLED = True
   SPLUNK_HOST    = "localhost"
   SPLUNK_TOKEN   = "your_HEC_token"
   ```
5. Import queries from `splunk_queries/spl_queries.md` into your Splunk search

---

## 📧 Optional: Email Alerts

In `config.py`:
```python
EMAIL_ENABLED   = True
SMTP_HOST       = "smtp.gmail.com"
SMTP_PORT       = 587
SMTP_USER       = "your_email@gmail.com"
SMTP_PASS       = "your_app_password"    # Gmail App Password
ALERT_RECIPIENT = "soc@yourorg.com"
```

Email alerts fire automatically for every HIGH / CRITICAL detection.

---

## 🧪 Testing the Full Kill Chain (What Happens)

When you run `simulate --scenario full_chain`, 7 attack phases inject events:

```
Phase 1 → Brute Force (7× failed login + 1 success)   → T1110
Phase 2 → Privilege Escalation (SeDebugPrivilege)      → T1068
Phase 3 → Encoded PowerShell download cradle           → T1059
Phase 4 → Registry Run key modification                → T1547
Phase 5 → Mimikatz credential dump                     → T1003
Phase 6 → C2 beacon to known-bad IP on port 4444       → T1071
Phase 7 → WMIC lateral movement to 192.168.1.200       → T1021
```

Expected alerts: 7–9 alerts across CRITICAL/HIGH/MEDIUM severities.

---

## 🛠️ Troubleshooting

| Problem | Fix |
|---------|-----|
| `ModuleNotFoundError` | Run `pip install -r requirements.txt` with venv active |
| Port 5000 in use | Change `FLASK_PORT` in `config.py` |
| No alerts generated | Run `simulate` first, then `analyse` or `monitor` |
| `colorama` error on Windows | `pip install colorama --upgrade` |
| Dashboard blank | Wait 2-3s and refresh; check terminal for errors |

---

## 🏆 Advanced Extensions

- Add **ML anomaly detection** using `scikit-learn` IsolationForest on process baselines
- Integrate **VirusTotal API** for real-time hash/IP lookups
- Add **Sigma rule parser** to load community detection rules
- Export alerts to **Elasticsearch** for long-term storage
- Add **automated response**: kill process via `psutil`, block IP via Windows Firewall API

---

## 📜 License

MIT License — Educational / Research use. Do not deploy against systems you do not own.
