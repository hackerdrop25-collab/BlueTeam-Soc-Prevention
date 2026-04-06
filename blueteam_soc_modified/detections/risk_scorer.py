# ============================================================
#   detections/risk_scorer.py — Risk scoring & correlation
# ============================================================

from typing import List, Dict
from core.event_model import Alert
import config


class RiskScorer:
    """
    Correlates multiple alerts for the same host/user and
    produces a composite risk score with severity escalation.
    """

    def __init__(self, alerts: List[Alert]):
        self.alerts  = alerts
        self.scores: Dict[str, int] = {}   # hostname -> cumulative score

    def compute(self) -> Dict[str, dict]:
        host_data: Dict[str, dict] = {}

        for alert in self.alerts:
            host = alert.hostname or "UNKNOWN"
            if host not in host_data:
                host_data[host] = {
                    "hostname"    : host,
                    "total_score" : 0,
                    "alert_count" : 0,
                    "detections"  : set(),
                    "max_severity": "LOW",
                    "users"       : set(),
                }
            d = host_data[host]
            d["total_score"]  += alert.risk_score
            d["alert_count"]  += 1
            d["detections"].add(alert.detection)
            d["users"].add(alert.username)

            # Track highest severity
            sev_order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
            if sev_order.get(alert.severity, 0) > sev_order.get(d["max_severity"], 0):
                d["max_severity"] = alert.severity

        # Cap at 100 and convert sets to lists for serialisation
        for host, d in host_data.items():
            d["total_score"] = min(d["total_score"], 100)
            d["detections"]  = list(d["detections"])
            d["users"]       = list(d["users"])
            d["risk_level"]  = Alert.severity_from_score(d["total_score"])

        return host_data

    @staticmethod
    def score_label(score: int) -> str:
        if score >= 90: return "🔴 CRITICAL"
        if score >= 70: return "🟠 HIGH"
        if score >= 40: return "🟡 MEDIUM"
        return "🟢 LOW"
