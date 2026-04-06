# ============================================================
#   core/alert_store.py — Thread-safe JSON alert persistence
# ============================================================

import json
import os
import threading
from datetime import datetime
from typing import List, Optional
from core.event_model import Alert
import config

_lock = threading.Lock()


def _ensure_files():
    os.makedirs(config.ALERT_DIR, exist_ok=True)
    for path in (config.ALERT_LOG, config.RISK_LOG):
        if not os.path.exists(path):
            with open(path, "w") as f:
                json.dump([], f)


def save_alert(alert: Alert):
    _ensure_files()
    with _lock:
        with open(config.ALERT_LOG, "r") as f:
            data = json.load(f)
        data.append(alert.to_dict())
        with open(config.ALERT_LOG, "w") as f:
            json.dump(data, f, indent=2)


def load_alerts(limit: int = 200, severity: Optional[str] = None) -> List[dict]:
    _ensure_files()
    with _lock:
        with open(config.ALERT_LOG, "r") as f:
            data = json.load(f)
    if severity:
        data = [a for a in data if a.get("severity") == severity]
    return list(reversed(data))[:limit]


def clear_alerts():
    _ensure_files()
    with _lock:
        with open(config.ALERT_LOG, "w") as f:
            json.dump([], f)


def alert_stats() -> dict:
    alerts = load_alerts(limit=10000)
    stats = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "total": len(alerts)}
    for a in alerts:
        sev = a.get("severity", "LOW")
        stats[sev] = stats.get(sev, 0) + 1

    # detections breakdown
    detections: dict = {}
    hostnames: dict  = {}
    for a in alerts:
        d = a.get("detection", "unknown")
        detections[d] = detections.get(d, 0) + 1
        h = a.get("hostname", "unknown")
        hostnames[h] = hostnames.get(h, 0) + 1

    stats["by_detection"] = detections
    stats["by_hostname"]  = hostnames
    return stats
