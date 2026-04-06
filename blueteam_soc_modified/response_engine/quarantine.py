# ============================================================
#   response_engine/quarantine.py — File quarantine system
# ============================================================

import json
import os
import shutil
import threading
from datetime import datetime

import config

_lock = threading.Lock()


def _ensure_dirs():
    os.makedirs(config.QUARANTINE_DIR, exist_ok=True)
    os.makedirs(os.path.dirname(config.QUARANTINE_LOG), exist_ok=True)


def _load_log() -> list:
    _ensure_dirs()
    if not os.path.exists(config.QUARANTINE_LOG):
        with open(config.QUARANTINE_LOG, "w") as f:
            json.dump([], f)
        return []
    try:
        with open(config.QUARANTINE_LOG, "r") as f:
            return json.load(f)
    except Exception:
        return []


def _save_log(data: list):
    _ensure_dirs()
    with open(config.QUARANTINE_LOG, "w") as f:
        json.dump(data, f, indent=2)


def get_quarantined_files() -> list:
    with _lock:
        return _load_log()


def quarantine_file(file_path: str, reason: str = "", alert_id: str = "") -> dict:
    """
    Move a suspicious file to the quarantine directory.
    SAFE_MODE = True  → records intent, does not move the file.
    SAFE_MODE = False → physically moves the file to QUARANTINE_DIR.
    """
    entry = {
        "original_path"  : file_path,
        "quarantine_path": "",
        "reason"         : reason or "Automated quarantine",
        "alert_id"       : alert_id,
        "quarantined_at" : datetime.utcnow().isoformat(),
        "safe_mode"      : config.SAFE_MODE,
        "restored"       : False,
    }

    if not config.SAFE_MODE and file_path and os.path.exists(file_path):
        result = _do_quarantine(file_path)
        entry["quarantine_path"] = result.get("dest", "")
        entry["error"]           = result.get("error", "")
        success = result["success"]
    else:
        # Simulated: generate a fake quarantine path
        fname = os.path.basename(file_path) if file_path else "unknown_file"
        entry["quarantine_path"] = os.path.join(
            config.QUARANTINE_DIR,
            f"{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{fname}.qtn"
        )
        success = True

    with _lock:
        log = _load_log()
        log.append(entry)
        _save_log(log)

    mode = "SIMULATED" if config.SAFE_MODE else "LIVE"
    return {
        "success"  : success,
        "file_path": file_path,
        "mode"     : mode,
        "dest"     : entry["quarantine_path"],
    }


def restore_file(quarantine_path: str) -> dict:
    """Restore a quarantined file back to its original location."""
    with _lock:
        log = _load_log()
        entry = next((e for e in log if e["quarantine_path"] == quarantine_path), None)

    if not entry:
        return {"success": False, "reason": "File not found in quarantine log"}

    if not config.SAFE_MODE and os.path.exists(quarantine_path):
        try:
            shutil.move(quarantine_path, entry["original_path"])
        except Exception as ex:
            return {"success": False, "reason": str(ex)}

    with _lock:
        log = _load_log()
        for e in log:
            if e["quarantine_path"] == quarantine_path:
                e["restored"] = True
                e["restored_at"] = datetime.utcnow().isoformat()
        _save_log(log)

    return {
        "success"     : True,
        "restored_to" : entry["original_path"],
        "mode"        : "SIMULATED" if config.SAFE_MODE else "LIVE",
    }


def _do_quarantine(file_path: str) -> dict:
    """Physically move file to quarantine directory."""
    try:
        _ensure_dirs()
        fname = os.path.basename(file_path)
        ts    = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        dest  = os.path.join(config.QUARANTINE_DIR, f"{ts}_{fname}.qtn")
        shutil.move(file_path, dest)
        return {"success": True, "dest": dest}
    except Exception as ex:
        return {"success": False, "error": str(ex), "dest": ""}
