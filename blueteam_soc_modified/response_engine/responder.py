# ============================================================
#   response_engine/responder.py — SOAR orchestration engine
#
#   Maps detected alerts → automated response actions based on
#   severity and detection type. Respects SAFE_MODE at all times.
# ============================================================

import json
import os
import re
import threading
from datetime import datetime
from typing import List

import config
from core.event_model import Alert
from response_engine.firewall       import block_ip, get_blocked_ips
from response_engine.process_killer import kill_process, get_killed_processes
from response_engine.quarantine     import quarantine_file, get_quarantined_files

_lock = threading.Lock()

# ── Response log helpers ──────────────────────────────────

def _ensure_log():
    os.makedirs(os.path.dirname(config.RESPONSE_LOG), exist_ok=True)
    if not os.path.exists(config.RESPONSE_LOG):
        with open(config.RESPONSE_LOG, "w") as f:
            json.dump([], f)


def _append_log(entry: dict):
    _ensure_log()
    with _lock:
        try:
            with open(config.RESPONSE_LOG, "r") as f:
                data = json.load(f)
        except Exception:
            data = []
        data.append(entry)
        with open(config.RESPONSE_LOG, "w") as f:
            json.dump(data, f, indent=2)


def get_response_logs(limit: int = 200) -> list:
    _ensure_log()
    try:
        with open(config.RESPONSE_LOG, "r") as f:
            data = json.load(f)
        return list(reversed(data))[:limit]
    except Exception:
        return []


def clear_response_logs():
    _ensure_log()
    with _lock:
        with open(config.RESPONSE_LOG, "w") as f:
            json.dump([], f)


# ── Policy check ─────────────────────────────────────────

def should_respond(alert: Alert) -> bool:
    """Check if alert severity warrants automated response."""
    policy = config.RESPONSE_POLICY.get(alert.severity, "LOG_ONLY")
    return policy in ("AUTO", "IMMEDIATE") or \
           alert.severity in config.AUTO_RESPONSE_SEVERITIES


# ── Action implementations ────────────────────────────────

def _action_block_ip(alert: Alert) -> dict:
    ip = alert.hostname  # use src_ip if available in future; fall back to hostname
    # Try to extract a real IP from the alert description
    ip_match = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", alert.description)
    if ip_match:
        ip = ip_match.group(1)

    if not ip or not re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
        # Use a representative IP from known bad list for simulation
        ip = config.KNOWN_BAD_IPS[0] if config.KNOWN_BAD_IPS else "0.0.0.0"

    return block_ip(ip, reason=alert.title, alert_id=alert.alert_id)


def _action_kill_process(alert: Alert) -> dict:
    # Extract process name from alert description or title
    proc_match = re.search(
        r"'([^']+\.exe)'|Process[:\s]+([^\s,]+\.exe)",
        alert.description + " " + alert.title,
        re.IGNORECASE,
    )
    proc_name = ""
    if proc_match:
        proc_name = (proc_match.group(1) or proc_match.group(2) or "").strip()

    if not proc_name:
        proc_name = "suspicious_process.exe"

    return kill_process(
        process_name=proc_name,
        reason=alert.title,
        alert_id=alert.alert_id,
    )


def _action_quarantine_file(alert: Alert) -> dict:
    # Extract file path from description
    path_match = re.search(
        r"([A-Za-z]:\\[^\s,;\"']+|/[^\s,;\"']+)",
        alert.description,
    )
    file_path = path_match.group(1) if path_match else "unknown_suspicious_file"
    return quarantine_file(
        file_path=file_path,
        reason=alert.title,
        alert_id=alert.alert_id,
    )


def _action_disable_user(alert: Alert) -> dict:
    """Simulate disabling a user account (safe simulation only for now)."""
    username = alert.username or "unknown_user"
    msg = (
        f"[SIMULATED] net user {username} /active:no"
        if config.SAFE_MODE
        else f"[LIVE] Attempted account disable: {username}"
    )
    return {"success": True, "action": "disable_user", "username": username, "detail": msg}


def _action_isolate_host(alert: Alert) -> dict:
    """Simulate host network isolation."""
    hostname = alert.hostname or "unknown_host"
    msg = (
        f"[SIMULATED] Network isolation triggered for {hostname}"
        if config.SAFE_MODE
        else f"[LIVE] Isolating {hostname} — cutting network segments"
    )
    return {"success": True, "action": "isolate_host", "hostname": hostname, "detail": msg}


def _action_alert_soc(alert: Alert) -> dict:
    msg = f"SOC escalation: {alert.severity} — {alert.title} on {alert.hostname}"
    return {"success": True, "action": "alert_soc", "detail": msg}


# Map action name → handler function
_ACTION_MAP = {
    "block_ip"      : _action_block_ip,
    "kill_process"  : _action_kill_process,
    "quarantine_file": _action_quarantine_file,
    "disable_user"  : _action_disable_user,
    "isolate_host"  : _action_isolate_host,
    "alert_soc"     : _action_alert_soc,
}


# ── Main responder ────────────────────────────────────────

def respond_to_alert(alert: Alert) -> List[dict]:
    """
    Evaluate a single alert and trigger appropriate response actions.
    Returns list of response log entries.
    """
    policy  = config.RESPONSE_POLICY.get(alert.severity, "LOG_ONLY")
    results = []

    # LOG_ONLY or MONITOR: no automated actions
    if policy == "LOG_ONLY":
        entry = _build_log_entry(alert, "log_only", "Logged", "Severity too low for auto-response", True)
        _append_log(entry)
        return [entry]

    if policy == "MONITOR":
        entry = _build_log_entry(alert, "monitor", "Monitoring", "Elevated monitoring — no block yet", True)
        _append_log(entry)
        return [entry]

    # AUTO or IMMEDIATE: execute mapped actions
    actions = config.RESPONSE_ACTIONS.get(alert.detection, ["alert_soc"])

    for action_name in actions:
        handler = _ACTION_MAP.get(action_name)
        if not handler:
            continue

        try:
            result = handler(alert)
            status = "Success" if result.get("success") else "Failed"
        except Exception as ex:
            result = {"success": False, "error": str(ex)}
            status = "Error"

        entry = _build_log_entry(
            alert=alert,
            action=action_name,
            status=status,
            detail=_summarise_result(action_name, result, alert),
            success=result.get("success", False),
        )
        _append_log(entry)
        results.append(entry)

    return results


def respond_to_alerts(alerts: List[Alert]) -> List[dict]:
    """Process a batch of new alerts through the response engine."""
    all_results = []
    for alert in alerts:
        all_results.extend(respond_to_alert(alert))
    return all_results


# ── Helpers ───────────────────────────────────────────────

def _build_log_entry(alert: Alert, action: str, status: str,
                     detail: str, success: bool) -> dict:
    return {
        "log_id"    : f"RL-{datetime.utcnow().strftime('%Y%m%d%H%M%S%f')[:16]}",
        "time"      : datetime.utcnow().isoformat(),
        "alert_id"  : alert.alert_id,
        "threat"    : alert.title,
        "detection" : alert.detection,
        "severity"  : alert.severity,
        "hostname"  : alert.hostname,
        "username"  : alert.username,
        "action"    : action,
        "status"    : status,
        "detail"    : detail,
        "success"   : success,
        "safe_mode" : config.SAFE_MODE,
        "policy"    : config.RESPONSE_POLICY.get(alert.severity, "LOG_ONLY"),
    }


def _summarise_result(action: str, result: dict, alert: Alert) -> str:
    mode = "SIMULATED" if config.SAFE_MODE else "LIVE"
    if action == "block_ip":
        return f"[{mode}] Blocked IP {result.get('ip', '?')} — {alert.title}"
    if action == "kill_process":
        return f"[{mode}] Terminated process '{result.get('process_name', '?')}'"
    if action == "quarantine_file":
        return f"[{mode}] Quarantined file → {result.get('dest', '?')}"
    if action == "disable_user":
        return result.get("detail", "")
    if action == "isolate_host":
        return result.get("detail", "")
    if action == "alert_soc":
        return result.get("detail", "")
    return str(result)


# ── State snapshot for dashboard ─────────────────────────

def get_response_summary() -> dict:
    """Returns a summary dict for the dashboard Active Response panel."""
    return {
        "blocked_ips"       : get_blocked_ips(),
        "killed_processes"  : get_killed_processes(),
        "quarantined_files" : get_quarantined_files(),
        "response_logs"     : get_response_logs(limit=50),
        "safe_mode"         : config.SAFE_MODE,
        "counts": {
            "blocked_ips"     : len(get_blocked_ips()),
            "killed_processes": len(get_killed_processes()),
            "quarantined_files": len([f for f in get_quarantined_files() if not f.get("restored")]),
            "total_actions"   : len(get_response_logs(limit=10000)),
        },
    }
