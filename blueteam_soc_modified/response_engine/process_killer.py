# ============================================================
#   response_engine/process_killer.py — Process termination
# ============================================================

import json
import os
import threading
from datetime import datetime

import config

_lock = threading.Lock()


def _load_killed() -> list:
    os.makedirs(os.path.dirname(config.KILLED_PROCS), exist_ok=True)
    if not os.path.exists(config.KILLED_PROCS):
        with open(config.KILLED_PROCS, "w") as f:
            json.dump([], f)
        return []
    try:
        with open(config.KILLED_PROCS, "r") as f:
            return json.load(f)
    except Exception:
        return []


def _save_killed(data: list):
    os.makedirs(os.path.dirname(config.KILLED_PROCS), exist_ok=True)
    with open(config.KILLED_PROCS, "w") as f:
        json.dump(data, f, indent=2)


def get_killed_processes() -> list:
    with _lock:
        return _load_killed()


def kill_process(process_name: str, pid: int = 0,
                 reason: str = "", alert_id: str = "") -> dict:
    """
    Terminate a malicious process.
    SAFE_MODE = True  → records intent only, no actual kill.
    SAFE_MODE = False → calls psutil to terminate matching processes.
    """
    if not process_name:
        return {"success": False, "reason": "No process name provided"}

    entry = {
        "process_name": process_name,
        "pid"         : pid,
        "reason"      : reason or "Automated response",
        "alert_id"    : alert_id,
        "killed_at"   : datetime.utcnow().isoformat(),
        "safe_mode"   : config.SAFE_MODE,
        "actually_killed": False,
        "pids_killed" : [],
    }

    if not config.SAFE_MODE:
        result = _do_kill(process_name, pid)
        entry["actually_killed"] = result["success"]
        entry["pids_killed"]     = result.get("pids", [])
        entry["error"]           = result.get("error", "")
    else:
        entry["actually_killed"] = True   # simulated

    with _lock:
        killed = _load_killed()
        killed.append(entry)
        _save_killed(killed)

    mode = "SIMULATED" if config.SAFE_MODE else "LIVE"
    return {
        "success"     : True,
        "process_name": process_name,
        "pid"         : pid,
        "mode"        : mode,
    }


def _do_kill(process_name: str, pid: int) -> dict:
    """Attempt real process termination via psutil."""
    try:
        import psutil
        killed_pids = []
        name_lower  = process_name.lower()

        for proc in psutil.process_iter(["pid", "name"]):
            try:
                pname = (proc.info["name"] or "").lower()
                if pname == name_lower or (pid and proc.info["pid"] == pid):
                    proc.terminate()
                    killed_pids.append(proc.info["pid"])
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        return {"success": bool(killed_pids), "pids": killed_pids}

    except ImportError:
        return {"success": False, "error": "psutil not installed"}
    except Exception as ex:
        return {"success": False, "error": str(ex)}
