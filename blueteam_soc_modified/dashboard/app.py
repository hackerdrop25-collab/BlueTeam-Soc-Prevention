# ============================================================
#   dashboard/app.py — Flask real-time SOC dashboard
# ============================================================

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
import threading, time

import config
from core.alert_store import load_alerts, alert_stats, clear_alerts
from core.monitor     import analyse_once
from simulations.attack_simulator import (
    run_full_attack_chain, ALL_SCENARIOS, _append_events
)

app      = Flask(__name__)
app.config["SECRET_KEY"] = "blueteam-soc-secret"
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

_monitor_running = False


# ── Background monitor thread ─────────────────────────────

def _bg_monitor():
    while _monitor_running:
        new = analyse_once(verbose=False)
        if new:
            # Import here to avoid circular at startup
            from response_engine.responder import get_response_summary
            socketio.emit("new_alerts", {
                "alerts"  : [a.to_dict() for a in new],
                "stats"   : alert_stats(),
                "response": get_response_summary(),
            })
        time.sleep(3)


# ── Existing routes (untouched) ───────────────────────────

@app.route("/")
def index():
    return render_template("dashboard.html")


@app.route("/api/alerts")
def api_alerts():
    sev   = request.args.get("severity")
    limit = int(request.args.get("limit", 100))
    return jsonify(load_alerts(limit=limit, severity=sev))


@app.route("/api/stats")
def api_stats():
    return jsonify(alert_stats())


@app.route("/api/clear", methods=["POST"])
def api_clear():
    clear_alerts()
    return jsonify({"status": "cleared"})


@app.route("/api/simulate", methods=["POST"])
def api_simulate():
    data     = request.json or {}
    scenario = data.get("scenario", "full_chain")
    host     = data.get("host", "WORKSTATION-SIM")
    user     = data.get("user", "simuser")

    if scenario == "full_chain":
        threading.Thread(
            target=run_full_attack_chain,
            kwargs={"host": host, "user": user},
            daemon=True
        ).start()
        return jsonify({"status": "running", "scenario": "full_chain"})

    fn = ALL_SCENARIOS.get(scenario)
    if not fn:
        return jsonify({"error": "Unknown scenario"}), 400

    evs = fn(host=host, user=user) if "host" in fn.__code__.co_varnames else fn()
    log_path = config.SYSMON_LOG if any(
        e.get("EventID") in ("1","3","11","12","13") for e in evs
    ) else config.WINEVENT_LOG
    _append_events(log_path, evs)
    return jsonify({"status": "injected", "scenario": scenario, "events": len(evs)})


@app.route("/api/scenarios")
def api_scenarios():
    return jsonify(list(ALL_SCENARIOS.keys()) + ["full_chain"])


# ── NEW: Response engine API routes ──────────────────────

@app.route("/api/response/summary")
def api_response_summary():
    from response_engine.responder import get_response_summary
    return jsonify(get_response_summary())


@app.route("/api/response/logs")
def api_response_logs():
    from response_engine.responder import get_response_logs
    limit = int(request.args.get("limit", 100))
    return jsonify(get_response_logs(limit=limit))


@app.route("/api/response/blocked_ips")
def api_blocked_ips():
    from response_engine.firewall import get_blocked_ips
    return jsonify(get_blocked_ips())


@app.route("/api/response/unblock_ip", methods=["POST"])
def api_unblock_ip():
    data = request.json or {}
    ip   = data.get("ip", "")
    if not ip:
        return jsonify({"error": "No IP provided"}), 400
    from response_engine.firewall import unblock_ip
    from response_engine.responder import _append_log, _build_log_entry
    from core.event_model import Alert
    result = unblock_ip(ip)
    # Log this manual override
    dummy = Alert(title=f"Manual unblock: {ip}", detection="manual_override",
                  severity="LOW", hostname=ip)
    entry = _build_log_entry(dummy, "unblock_ip", "Manual Override",
                             f"Operator unblocked IP {ip}", result["success"])
    _append_log(entry)
    # Push update to dashboard
    from response_engine.responder import get_response_summary
    socketio.emit("response_update", get_response_summary())
    return jsonify(result)


@app.route("/api/response/killed_processes")
def api_killed_procs():
    from response_engine.process_killer import get_killed_processes
    return jsonify(get_killed_processes())


@app.route("/api/response/quarantined_files")
def api_quarantined():
    from response_engine.quarantine import get_quarantined_files
    return jsonify(get_quarantined_files())


@app.route("/api/response/restore_file", methods=["POST"])
def api_restore_file():
    data  = request.json or {}
    qpath = data.get("quarantine_path", "")
    if not qpath:
        return jsonify({"error": "No quarantine_path provided"}), 400
    from response_engine.quarantine import restore_file
    result = restore_file(qpath)
    from response_engine.responder import get_response_summary
    socketio.emit("response_update", get_response_summary())
    return jsonify(result)


@app.route("/api/response/clear_logs", methods=["POST"])
def api_clear_response_logs():
    from response_engine.responder import clear_response_logs
    clear_response_logs()
    return jsonify({"status": "response logs cleared"})


@app.route("/api/response/safe_mode", methods=["GET"])
def api_safe_mode_get():
    return jsonify({"safe_mode": config.SAFE_MODE})


@app.route("/api/response/safe_mode", methods=["POST"])
def api_safe_mode_set():
    data = request.json or {}
    val  = data.get("safe_mode", True)
    config.SAFE_MODE = bool(val)
    return jsonify({"safe_mode": config.SAFE_MODE})


# ── SocketIO ──────────────────────────────────────────────

@socketio.on("connect")
def on_connect():
    global _monitor_running
    _monitor_running = True
    t = threading.Thread(target=_bg_monitor, daemon=True)
    t.start()
    emit("connected", {"msg": "SOC Monitor connected"})


if __name__ == "__main__":
    print(f"  Dashboard: http://{config.FLASK_HOST}:{config.FLASK_PORT}")
    socketio.run(app, host=config.FLASK_HOST, port=config.FLASK_PORT, debug=False)
