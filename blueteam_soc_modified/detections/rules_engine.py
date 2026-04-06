# ============================================================
#   detections/rules_engine.py — All detection rules
# ============================================================

import re
from collections import defaultdict
from datetime import datetime, timedelta
from typing import List, Tuple
from core.event_model import SecurityEvent, Alert
import config


# ── Helpers ───────────────────────────────────────────────

def _ts(ev: SecurityEvent) -> datetime:
    try:
        return datetime.fromisoformat(ev.timestamp.replace("Z", ""))
    except Exception:
        return datetime.utcnow()


def _make_alert(title, description, severity, risk, detection,
                hostname="", username="", events=None,
                recommended="", auto_response="") -> Alert:
    mitre = config.MITRE_MAP.get(detection, {})
    return Alert(
        title         = title,
        description   = description,
        severity      = severity,
        risk_score    = risk,
        detection     = detection,
        mitre_id      = mitre.get("id", ""),
        mitre_tactic  = mitre.get("tactic", ""),
        hostname      = hostname,
        username      = username,
        source_events = [e.uid for e in (events or [])],
        recommended   = recommended,
        auto_response = auto_response,
    )


# ── Rule 1: Brute Force ───────────────────────────────────

def detect_brute_force(events: List[SecurityEvent]) -> List[Alert]:
    alerts = []
    failures = [e for e in events if e.event_id == "4625"]
    # Group by username
    by_user: dict = defaultdict(list)
    for ev in failures:
        by_user[ev.username].append(ev)

    for user, evs in by_user.items():
        evs.sort(key=_ts)
        window_start = None
        window_evs: list = []
        for ev in evs:
            t = _ts(ev)
            if window_start is None:
                window_start = t
                window_evs = [ev]
            elif (t - window_start).total_seconds() <= config.BRUTE_FORCE_WINDOW_SEC:
                window_evs.append(ev)
            else:
                window_start = t
                window_evs = [ev]

            if len(window_evs) >= config.BRUTE_FORCE_THRESHOLD:
                score = min(40 + len(window_evs) * 5, 85)
                alerts.append(_make_alert(
                    title        = f"Brute Force Attack Detected — {user}",
                    description  = f"{len(window_evs)} failed logins for '{user}' within {config.BRUTE_FORCE_WINDOW_SEC}s.",
                    severity     = Alert.severity_from_score(score),
                    risk         = score,
                    detection    = "brute_force",
                    hostname     = evs[0].hostname,
                    username     = user,
                    events       = window_evs,
                    recommended  = "Lock account, investigate source IP, review auth logs.",
                    auto_response= "Block source IP; notify SOC.",
                ))
                break   # one alert per user per pass
    return alerts


# ── Rule 2: Successful Login After Failures (credential stuffing) ─

def detect_login_after_failures(events: List[SecurityEvent]) -> List[Alert]:
    alerts = []
    by_user: dict = defaultdict(list)
    for ev in events:
        if ev.event_id in ("4624", "4625"):
            by_user[ev.username].append(ev)

    for user, evs in by_user.items():
        evs.sort(key=_ts)
        fail_count = 0
        for ev in evs:
            if ev.event_id == "4625":
                fail_count += 1
            elif ev.event_id == "4624" and fail_count >= 3:
                alerts.append(_make_alert(
                    title        = f"Successful Login After {fail_count} Failures — {user}",
                    description  = f"User '{user}' logged in successfully after {fail_count} failures. Possible credential stuffing.",
                    severity     = "HIGH",
                    risk         = 70,
                    detection    = "brute_force",
                    hostname     = ev.hostname,
                    username     = user,
                    events       = [ev],
                    recommended  = "Verify with user; check MFA; review session activity.",
                    auto_response= "Force MFA re-challenge.",
                ))
                fail_count = 0
    return alerts


# ── Rule 3: Suspicious Process Execution ─────────────────

def detect_suspicious_process(events: List[SecurityEvent]) -> List[Alert]:
    alerts = []
    for ev in events:
        if ev.category != "process":
            continue
        proc   = ev.process_name.lower()
        cmdline = ev.command_line.lower()

        # Check process name
        if proc in config.SUSPICIOUS_PROCESSES:
            score = 50
            # Escalate if encoded/obfuscated command
            for pattern in config.SUSPICIOUS_CMD_PATTERNS:
                if re.search(pattern, cmdline, re.IGNORECASE):
                    score = 80
                    break

            alerts.append(_make_alert(
                title        = f"Suspicious Process: {proc}",
                description  = f"Process '{proc}' spawned on {ev.hostname}. Command: {ev.command_line[:120]}",
                severity     = Alert.severity_from_score(score),
                risk         = score,
                detection    = "suspicious_process",
                hostname     = ev.hostname,
                username     = ev.username,
                events       = [ev],
                recommended  = "Investigate parent process; check if process is expected.",
                auto_response= "Terminate process if risk > 75.",
            ))
    return alerts


# ── Rule 4: Privilege Escalation ─────────────────────────

def detect_privilege_escalation(events: List[SecurityEvent]) -> List[Alert]:
    alerts = []
    for ev in events:
        if ev.event_id == "4672":
            alerts.append(_make_alert(
                title        = f"Privilege Escalation — {ev.username}",
                description  = f"Special privileges assigned to '{ev.username}' on {ev.hostname}.",
                severity     = "HIGH",
                risk         = 80,
                detection    = "privilege_escalation",
                hostname     = ev.hostname,
                username     = ev.username,
                events       = [ev],
                recommended  = "Verify if privilege grant was authorized; review PAM logs.",
                auto_response= "Alert SOC lead; initiate privilege audit.",
            ))
    return alerts


# ── Rule 5: Persistence Mechanism ────────────────────────

PERSISTENCE_KEYS = [
    r"\\currentversion\\run",
    r"\\currentversion\\runonce",
    r"startup",
    r"\\services\\",
    r"\\winlogon\\",
    r"schedtasks",
    r"\\currentversion\\policies\\explorer\\run",
]

def detect_persistence(events: List[SecurityEvent]) -> List[Alert]:
    alerts = []
    for ev in events:
        if ev.category not in ("registry", "file"):
            continue
        target = (ev.registry_key + ev.file_path).lower()
        for pattern in PERSISTENCE_KEYS:
            if re.search(pattern, target, re.IGNORECASE):
                alerts.append(_make_alert(
                    title        = "Persistence Mechanism Detected",
                    description  = f"Modification to persistence location: {target[:120]} on {ev.hostname}",
                    severity     = "HIGH",
                    risk         = 70,
                    detection    = "persistence",
                    hostname     = ev.hostname,
                    username     = ev.username,
                    events       = [ev],
                    recommended  = "Review registry key / startup file; check if change is authorized.",
                    auto_response= "Revert registry change; isolate host if unauthorized.",
                ))
                break
    return alerts


# ── Rule 6: C2 / Suspicious Network Activity ─────────────

def detect_c2_connections(events: List[SecurityEvent]) -> List[Alert]:
    alerts = []
    for ev in events:
        if ev.category != "network":
            continue
        if ev.dst_ip in config.KNOWN_BAD_IPS:
            alerts.append(_make_alert(
                title        = f"C2 Connection — {ev.dst_ip}:{ev.dst_port}",
                description  = f"Host {ev.hostname} connected to known-bad IP {ev.dst_ip}:{ev.dst_port} via {ev.process_name}.",
                severity     = "CRITICAL",
                risk         = 90,
                detection    = "c2_connection",
                hostname     = ev.hostname,
                username     = ev.username,
                events       = [ev],
                recommended  = "Isolate host immediately; capture memory; start IR process.",
                auto_response= "Block IP at firewall; kill process; snapshot host.",
            ))
        elif ev.dst_port in (4444, 1337, 8888, 9999, 31337):
            alerts.append(_make_alert(
                title        = f"Suspicious Outbound Port {ev.dst_port}",
                description  = f"Process '{ev.process_name}' on {ev.hostname} connecting to {ev.dst_ip}:{ev.dst_port}.",
                severity     = "HIGH",
                risk         = 75,
                detection    = "c2_connection",
                hostname     = ev.hostname,
                username     = ev.username,
                events       = [ev],
                recommended  = "Investigate process; check for reverse shell.",
                auto_response= "Block outbound port; alert IR team.",
            ))
    return alerts


# ── Rule 7: Lateral Movement ─────────────────────────────

LATERAL_PROCS = ["psexec.exe", "wmic.exe", "winrm.cmd", "net.exe", "sc.exe"]

def detect_lateral_movement(events: List[SecurityEvent]) -> List[Alert]:
    alerts = []
    for ev in events:
        if ev.process_name in LATERAL_PROCS and ev.dst_ip and ev.dst_ip != ev.src_ip:
            alerts.append(_make_alert(
                title        = f"Lateral Movement — {ev.process_name}",
                description  = f"'{ev.process_name}' used on {ev.hostname} to reach {ev.dst_ip}. Possible lateral movement.",
                severity     = "HIGH",
                risk         = 75,
                detection    = "lateral_movement",
                hostname     = ev.hostname,
                username     = ev.username,
                events       = [ev],
                recommended  = "Verify if remote admin is authorized; review SMB/WMI logs.",
                auto_response= "Isolate source host; notify IR.",
            ))
    return alerts


# ── Rule 8: Credential Dumping ───────────────────────────

CRED_DUMP_PROCS   = ["mimikatz.exe", "procdump.exe", "wce.exe", "fgdump.exe"]
CRED_DUMP_CMDLINE = [r"lsass", r"sekurlsa", r"logonpasswords", r"hashdump",
                     r"dcsync", r"ntds"]

def detect_credential_dump(events: List[SecurityEvent]) -> List[Alert]:
    alerts = []
    for ev in events:
        hit = ev.process_name in CRED_DUMP_PROCS
        if not hit:
            for p in CRED_DUMP_CMDLINE:
                if re.search(p, ev.command_line, re.IGNORECASE):
                    hit = True
                    break
        if hit:
            alerts.append(_make_alert(
                title        = "Credential Dumping Detected",
                description  = f"Credential dump activity via '{ev.process_name}' on {ev.hostname}. CMD: {ev.command_line[:100]}",
                severity     = "CRITICAL",
                risk         = 95,
                detection    = "credential_dump",
                hostname     = ev.hostname,
                username     = ev.username,
                events       = [ev],
                recommended  = "Immediate host isolation; full IR engagement; credential rotation.",
                auto_response= "Kill process; isolate host; alert CISO.",
            ))
    return alerts


# ── Master runner ─────────────────────────────────────────

ALL_RULES = [
    detect_brute_force,
    detect_login_after_failures,
    detect_suspicious_process,
    detect_privilege_escalation,
    detect_persistence,
    detect_c2_connections,
    detect_lateral_movement,
    detect_credential_dump,
]

def run_all_rules(events: List[SecurityEvent]) -> List[Alert]:
    all_alerts: list = []
    for rule_fn in ALL_RULES:
        try:
            new_alerts = rule_fn(events)
            all_alerts.extend(new_alerts)
        except Exception as ex:
            print(f"[RULE ERROR] {rule_fn.__name__}: {ex}")
    return all_alerts
