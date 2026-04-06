# ============================================================
#   response_engine/firewall.py — IP blocking & unblocking
# ============================================================

import json
import os
import subprocess
import platform
import threading
from datetime import datetime

import config

_lock = threading.Lock()


def _load_blocklist() -> list:
    os.makedirs(os.path.dirname(config.BLOCKED_IPS), exist_ok=True)
    if not os.path.exists(config.BLOCKED_IPS):
        with open(config.BLOCKED_IPS, "w") as f:
            json.dump([], f)
        return []
    try:
        with open(config.BLOCKED_IPS, "r") as f:
            return json.load(f)
    except Exception:
        return []


def _save_blocklist(data: list):
    os.makedirs(os.path.dirname(config.BLOCKED_IPS), exist_ok=True)
    with open(config.BLOCKED_IPS, "w") as f:
        json.dump(data, f, indent=2)


def get_blocked_ips() -> list:
    with _lock:
        return _load_blocklist()


def is_blocked(ip: str) -> bool:
    return any(e["ip"] == ip for e in get_blocked_ips())


def block_ip(ip: str, reason: str = "", alert_id: str = "") -> dict:
    """
    Block an IP address.
    In SAFE_MODE: records the intent without OS-level action.
    In live mode: applies a real firewall rule (Windows netsh / Linux iptables).
    Returns a result dict.
    """
    if not ip or ip in ("", "0.0.0.0", "127.0.0.1"):
        return {"success": False, "reason": "Invalid or localhost IP — skipped"}

    with _lock:
        blocklist = _load_blocklist()
        if any(e["ip"] == ip for e in blocklist):
            return {"success": True, "reason": "Already blocked", "ip": ip}

        entry = {
            "ip"       : ip,
            "reason"   : reason or "Automated response",
            "alert_id" : alert_id,
            "blocked_at": datetime.utcnow().isoformat(),
            "safe_mode" : config.SAFE_MODE,
            "rule_applied": False,
        }

        if not config.SAFE_MODE:
            result = _apply_os_block(ip)
            entry["rule_applied"] = result["success"]
            entry["os_output"]    = result.get("output", "")
        else:
            entry["rule_applied"] = True  # simulated

        blocklist.append(entry)
        _save_blocklist(blocklist)

    mode = "SIMULATED" if config.SAFE_MODE else "LIVE"
    return {
        "success": True,
        "ip"     : ip,
        "mode"   : mode,
        "reason" : reason,
    }


def unblock_ip(ip: str) -> dict:
    """Remove an IP from the blocklist and lift the firewall rule."""
    with _lock:
        blocklist = _load_blocklist()
        new_list  = [e for e in blocklist if e["ip"] != ip]
        if len(new_list) == len(blocklist):
            return {"success": False, "reason": f"{ip} not in blocklist"}

        if not config.SAFE_MODE:
            _remove_os_block(ip)

        _save_blocklist(new_list)

    return {"success": True, "ip": ip, "action": "unblocked"}


def _apply_os_block(ip: str) -> dict:
    """Apply OS-level block rule. Platform-aware."""
    system = platform.system()
    try:
        if system == "Windows":
            rule_name = f"BlueTeamSOC_Block_{ip}"
            cmd = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}", "dir=in", "action=block",
                f"remoteip={ip}", "enable=yes",
            ]
            out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=10)
            return {"success": True, "output": out.decode(errors="replace")}

        elif system == "Linux":
            cmd = ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"]
            out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=10)
            return {"success": True, "output": out.decode(errors="replace")}

        else:
            return {"success": False, "output": f"Unsupported OS: {system}"}

    except subprocess.CalledProcessError as e:
        return {"success": False, "output": e.output.decode(errors="replace")}
    except Exception as ex:
        return {"success": False, "output": str(ex)}


def _remove_os_block(ip: str) -> dict:
    system = platform.system()
    try:
        if system == "Windows":
            rule_name = f"BlueTeamSOC_Block_{ip}"
            cmd = ["netsh", "advfirewall", "firewall", "delete", "rule",
                   f"name={rule_name}"]
            subprocess.call(cmd, timeout=10)
        elif system == "Linux":
            cmd = ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
            subprocess.call(cmd, timeout=10)
        return {"success": True}
    except Exception as ex:
        return {"success": False, "output": str(ex)}
