# ============================================================
#   core/monitor.py — Real-time log watcher + alerting engine
# ============================================================

import json
import os
import sys
import time
import smtplib
import threading
from datetime import datetime
from email.mime.text import MIMEText
from colorama import Fore, Style, init

init(autoreset=True)

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config
from parsers.log_parser   import load_all_events
from detections.rules_engine import run_all_rules
from detections.risk_scorer  import RiskScorer
from core.alert_store     import save_alert, load_alerts
from core.event_model     import Alert

_processed_event_ids: set = set()
_seen_alert_titles:   set = set()


# ── Console printing ──────────────────────────────────────

SEV_COLOR = {
    "CRITICAL": Fore.RED + Style.BRIGHT,
    "HIGH"    : Fore.RED,
    "MEDIUM"  : Fore.YELLOW,
    "LOW"     : Fore.GREEN,
}

def _print_banner():
    print(Fore.CYAN + Style.BRIGHT + r"""
  ____  _            _____                      ____   ___   ____
 | __ )| |_   _  __|_   _|__  __ _ _ __ ___   / ___| / _ \ / ___|
 |  _ \| | | | |/ _ \| |/ _ \/ _` | '_ ` _ \  \___ \| | | | |
 | |_) | | |_| |  __/| |  __/ (_| | | | | | |  ___) | |_| | |___
 |____/|_|\__,_|\___||_|\___|\__,_|_| |_| |_| |____/ \___/ \____|

        Unified Threat Detection System  |  Blue Team SOC
""")


def _print_alert(alert: Alert):
    col = SEV_COLOR.get(alert.severity, "")
    ts  = alert.timestamp[:19]
    print(col + f"\n{'='*70}")
    print(col + f"  [{alert.severity}]  {alert.title}")
    print(col + f"  Time     : {ts}")
    print(col + f"  Host     : {alert.hostname}   User: {alert.username}")
    print(col + f"  MITRE    : {alert.mitre_id} — {alert.mitre_tactic}")
    print(col + f"  Risk     : {alert.risk_score}/100")
    print(col + f"  Detail   : {alert.description[:120]}")
    print(col + f"  Recommend: {alert.recommended}")
    print(col + f"  AutoResp : {alert.auto_response}")
    print(col + f"{'='*70}")


# ── Email alert ───────────────────────────────────────────

def _send_email(alert: Alert):
    if not config.EMAIL_ENABLED:
        return
    try:
        body = (
            f"SEVERITY : {alert.severity}\n"
            f"TITLE    : {alert.title}\n"
            f"HOST     : {alert.hostname}\n"
            f"USER     : {alert.username}\n"
            f"MITRE    : {alert.mitre_id} {alert.mitre_tactic}\n"
            f"RISK     : {alert.risk_score}/100\n"
            f"DETAIL   : {alert.description}\n"
            f"RECOMMEND: {alert.recommended}\n"
            f"TIME     : {alert.timestamp}\n"
        )
        msg            = MIMEText(body)
        msg["Subject"] = f"[SOC ALERT] {alert.severity}: {alert.title}"
        msg["From"]    = config.SMTP_USER
        msg["To"]      = config.ALERT_RECIPIENT

        with smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT, timeout=10) as s:
            s.starttls()
            s.login(config.SMTP_USER, config.SMTP_PASS)
            s.sendmail(config.SMTP_USER, config.ALERT_RECIPIENT, msg.as_string())
        print(Fore.GREEN + f"  📧 Email alert sent to {config.ALERT_RECIPIENT}")
    except Exception as ex:
        print(Fore.RED + f"  [EMAIL ERROR] {ex}")


# ── Main analysis pass ────────────────────────────────────

def analyse_once(verbose=True):
    events     = load_all_events()
    new_events = [e for e in events if e.uid not in _processed_event_ids]
    if not new_events:
        return []

    for e in new_events:
        _processed_event_ids.add(e.uid)

    alerts     = run_all_rules(events)
    new_alerts = [a for a in alerts if a.title not in _seen_alert_titles]

    for alert in new_alerts:
        _seen_alert_titles.add(alert.title)
        save_alert(alert)
        if verbose:
            _print_alert(alert)
        if alert.severity in ("HIGH", "CRITICAL"):
            threading.Thread(target=_send_email, args=(alert,), daemon=True).start()

    # ── Active Response Engine ─────────────────────────────
    if new_alerts:
        try:
            from response_engine.responder import respond_to_alerts
            resp_results = respond_to_alerts(new_alerts)
            if verbose and resp_results:
                print(Fore.CYAN + f"\n  ── ACTIVE RESPONSES TRIGGERED: {len(resp_results)} ──")
                for r in resp_results:
                    status_col = Fore.GREEN if r.get("success") else Fore.RED
                    print(status_col + f"  [{r['action'].upper()}] {r['detail']}")
        except Exception as ex:
            if verbose:
                print(Fore.YELLOW + f"  [RESPONDER] {ex}")

    # Risk summary
    if new_alerts and verbose:
        scorer = RiskScorer(load_alerts_as_objects())
        scores = scorer.compute()
        print(Fore.CYAN + "\n  ── HOST RISK SCORES ──")
        for host, data in scores.items():
            label = RiskScorer.score_label(data["total_score"])
            print(Fore.CYAN + f"  {host:25s}  {label}  ({data['total_score']}/100)  alerts={data['alert_count']}")

    return new_alerts


def load_alerts_as_objects() -> list:
    raw    = load_alerts(limit=500)
    result = []
    for r in raw:
        a = Alert(**{k: v for k, v in r.items() if k in Alert.__dataclass_fields__})
        result.append(a)
    return result


# ── Continuous monitor ────────────────────────────────────

def run_monitor(interval_sec=5):
    _print_banner()
    print(Fore.WHITE + f"  Monitoring logs every {interval_sec}s. Press Ctrl+C to stop.\n")
    safe_label = "SAFE MODE (simulated)" if config.SAFE_MODE else "LIVE MODE (real OS actions)"
    print(Fore.YELLOW + f"  Response Engine: {safe_label}\n")
    try:
        while True:
            analyse_once()
            time.sleep(interval_sec)
    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n\n  [MONITOR] Stopped by user.")


if __name__ == "__main__":
    run_monitor()
