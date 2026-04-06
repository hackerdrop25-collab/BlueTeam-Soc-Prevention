# ============================================================
#   reports/report_generator.py — Generate SOC incident report
# ============================================================

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
from datetime import datetime
from collections import defaultdict
from core.alert_store import load_alerts, alert_stats
from detections.risk_scorer import RiskScorer
import config

os.makedirs(config.REPORT_DIR, exist_ok=True)


def generate_report(output_format="txt") -> str:
    alerts = load_alerts(limit=1000)
    stats  = alert_stats()
    scorer = RiskScorer([])  # just use static methods here

    lines = []
    sep   = "=" * 70

    lines += [
        sep,
        "  BLUETEAM SOC — INCIDENT REPORT",
        f"  Generated : {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}",
        f"  Total Alerts: {stats['total']}",
        sep, "",
        "  SEVERITY SUMMARY",
        f"  CRITICAL : {stats['CRITICAL']}",
        f"  HIGH     : {stats['HIGH']}",
        f"  MEDIUM   : {stats['MEDIUM']}",
        f"  LOW      : {stats['LOW']}",
        "",
    ]

    # By detection
    lines.append("  DETECTIONS BREAKDOWN")
    for det, cnt in sorted(stats.get("by_detection", {}).items(), key=lambda x: -x[1]):
        lines.append(f"  {det:35s} {cnt:4d} alerts")
    lines.append("")

    # Host risk
    lines.append("  HOST RISK SCORES")
    by_host: dict = defaultdict(list)
    for a in alerts:
        by_host[a.get("hostname","UNKNOWN")].append(a)
    for host, h_alerts in sorted(by_host.items()):
        total = min(sum(a.get("risk_score",0) for a in h_alerts), 100)
        label = RiskScorer.score_label(total)
        lines.append(f"  {host:30s} {label}  ({total}/100)  alerts={len(h_alerts)}")
    lines.append("")

    # MITRE mapping
    lines.append("  MITRE ATT&CK COVERAGE")
    mitre_seen: dict = {}
    for a in alerts:
        mid = a.get("mitre_id","")
        if mid and mid not in mitre_seen:
            mitre_seen[mid] = a.get("mitre_tactic","")
    for mid, tactic in sorted(mitre_seen.items()):
        lines.append(f"  {mid:12s} {tactic}")
    lines.append("")

    # Top 15 critical/high alerts
    lines.append("  TOP CRITICAL / HIGH ALERTS")
    lines.append("-" * 70)
    top = [a for a in alerts if a.get("severity") in ("CRITICAL","HIGH")][:15]
    for a in top:
        lines += [
            f"  [{a['severity']:8s}] {a['title']}",
            f"           Host: {a.get('hostname','')}  User: {a.get('username','')}",
            f"           MITRE: {a.get('mitre_id','')} {a.get('mitre_tactic','')}",
            f"           Risk: {a.get('risk_score',0)}/100",
            f"           {a.get('description','')[:90]}",
            f"           Recommended: {a.get('recommended','')}",
            "",
        ]

    lines += [sep, "  END OF REPORT", sep]

    report_text = "\n".join(lines)

    # Save
    fname = f"soc_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.txt"
    fpath = os.path.join(config.REPORT_DIR, fname)
    with open(fpath, "w") as f:
        f.write(report_text)

    print(f"[REPORT] Saved to {fpath}")
    return report_text


if __name__ == "__main__":
    report = generate_report()
    print(report)
