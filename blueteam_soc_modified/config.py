# ============================================================
#   config.py — Central configuration for BluTeam SOC System
# ============================================================

import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ── Directories ────────────────────────────────────────────
LOG_DIR        = os.path.join(BASE_DIR, "data", "logs")
ALERT_DIR      = os.path.join(BASE_DIR, "data", "alerts")
REPORT_DIR     = os.path.join(BASE_DIR, "reports")
QUARANTINE_DIR = os.path.join(BASE_DIR, "data", "quarantine")

# ── Simulated log files written by attack simulator ────────
SYSMON_LOG     = os.path.join(LOG_DIR, "sysmon_events.json")
WINEVENT_LOG   = os.path.join(LOG_DIR, "windows_events.json")
ALERT_LOG      = os.path.join(ALERT_DIR, "alerts.json")
RISK_LOG       = os.path.join(ALERT_DIR, "risk_scores.json")

# ── Response engine data files ─────────────────────────────
RESPONSE_LOG   = os.path.join(LOG_DIR, "response_logs.json")
BLOCKED_IPS    = os.path.join(LOG_DIR, "blocked_ips.json")
KILLED_PROCS   = os.path.join(LOG_DIR, "killed_procs.json")
QUARANTINE_LOG = os.path.join(LOG_DIR, "quarantine_log.json")

# ── Detection thresholds ───────────────────────────────────
BRUTE_FORCE_THRESHOLD   = 5
BRUTE_FORCE_WINDOW_SEC  = 60
HIGH_RISK_SCORE         = 70
CRITICAL_RISK_SCORE     = 90

# ── Suspicious process names ───────────────────────────────
SUSPICIOUS_PROCESSES = [
    "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "regsvr32.exe", "rundll32.exe", "certutil.exe",
    "bitsadmin.exe", "msiexec.exe", "wmic.exe", "psexec.exe",
    "mimikatz.exe", "nc.exe", "ncat.exe", "netcat.exe",
]

SUSPICIOUS_CMD_PATTERNS = [
    r"-enc\s", r"-encodedcommand", r"invoke-expression",
    r"iex\s*\(", r"downloadstring", r"frombase64string",
    r"bypass", r"hidden", r"-nop", r"webclient",
    r"net user .* /add", r"net localgroup administrators",
]

# ── Known bad / C2 IPs (demo list) ────────────────────────
KNOWN_BAD_IPS = [
    "185.220.101.0", "194.165.16.0", "45.33.32.0",
    "10.10.99.99",
]

# ── MITRE ATT&CK Mapping ──────────────────────────────────
MITRE_MAP = {
    "brute_force"         : {"id": "T1110",  "tactic": "Credential Access"},
    "privilege_escalation": {"id": "T1068",  "tactic": "Privilege Escalation"},
    "suspicious_process"  : {"id": "T1059",  "tactic": "Execution"},
    "persistence"         : {"id": "T1547",  "tactic": "Persistence"},
    "lateral_movement"    : {"id": "T1021",  "tactic": "Lateral Movement"},
    "c2_connection"       : {"id": "T1071",  "tactic": "Command and Control"},
    "data_exfiltration"   : {"id": "T1041",  "tactic": "Exfiltration"},
    "credential_dump"     : {"id": "T1003",  "tactic": "Credential Access"},
}

# ── Risk weights per detection type ───────────────────────
RISK_WEIGHTS = {
    "brute_force"         : 40,
    "privilege_escalation": 80,
    "suspicious_process"  : 50,
    "persistence"         : 70,
    "lateral_movement"    : 75,
    "c2_connection"       : 90,
    "data_exfiltration"   : 85,
    "credential_dump"     : 95,
    "failed_login"        : 10,
    "successful_login"    : 5,
}

# ── Email alert config (fill in to enable) ────────────────
EMAIL_ENABLED   = False
SMTP_HOST       = "smtp.gmail.com"
SMTP_PORT       = 587
SMTP_USER       = "your_email@gmail.com"
SMTP_PASS       = "your_app_password"
ALERT_RECIPIENT = "soc_team@yourorg.com"

# ── Flask dashboard ───────────────────────────────────────
FLASK_HOST      = "127.0.0.1"
FLASK_PORT      = 5000
FLASK_DEBUG     = False

# ── Splunk (optional) ─────────────────────────────────────
SPLUNK_ENABLED  = False
SPLUNK_HOST     = "localhost"
SPLUNK_PORT     = 8089
SPLUNK_TOKEN    = "your_splunk_hec_token"

# ══════════════════════════════════════════════════════════
#   ACTIVE RESPONSE ENGINE CONFIGURATION
# ══════════════════════════════════════════════════════════

# True  → simulate actions only (safe demo mode, no real OS calls)
# False → execute real OS-level prevention (use in live environments)
SAFE_MODE = True

# Severity → response policy
RESPONSE_POLICY = {
    "LOW"      : "LOG_ONLY",
    "MEDIUM"   : "MONITOR",
    "HIGH"     : "AUTO",
    "CRITICAL" : "IMMEDIATE",
}

# Detection type → response actions
RESPONSE_ACTIONS = {
    "brute_force"         : ["block_ip", "disable_user"],
    "credential_dump"     : ["kill_process", "block_ip", "isolate_host"],
    "c2_connection"       : ["block_ip", "kill_process"],
    "suspicious_process"  : ["kill_process"],
    "privilege_escalation": ["disable_user", "alert_soc"],
    "persistence"         : ["quarantine_file", "alert_soc"],
    "lateral_movement"    : ["block_ip", "isolate_host"],
}

AUTO_RESPONSE_SEVERITIES = {"HIGH", "CRITICAL"}
