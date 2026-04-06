#!/usr/bin/env python3
# ============================================================
#   main.py — CLI entry point for BlueTeam SOC System
# ============================================================

import sys
import os
import argparse

# Ensure project root is on path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from colorama import Fore, Style, init
init(autoreset=True)

BANNER = Fore.CYAN + Style.BRIGHT + r"""
  ____  _            _____                      ____   ___   ____
 | __ )| |_   _  __|_   _|__  __ _ _ __ ___   / ___| / _ \ / ___|
 |  _ \| | | | |/ _ \| |/ _ \/ _` | '_ ` _ \  \___ \| | | | |
 | |_) | | |_| |  __/| |  __/ (_| | | | | | |  ___) | |_| | |___
 |____/|_|\__,_|\___||_|\___|\__,_|_| |_| |_| |____/ \___/ \____|

        Unified Blue Team Threat Detection System
        Author: BlueTeam SOC Project  |  Python + Flask + Sysmon
"""


def cmd_monitor(args):
    print(BANNER)
    from core.monitor import run_monitor
    run_monitor(interval_sec=args.interval)


def cmd_simulate(args):
    print(BANNER)
    print(Fore.YELLOW + f"[SIM] Scenario: {args.scenario}  Host: {args.host}  User: {args.user}\n")
    if args.scenario == "full_chain":
        from simulations.attack_simulator import run_full_attack_chain
        run_full_attack_chain(host=args.host, user=args.user)
    else:
        from simulations.attack_simulator import ALL_SCENARIOS, _append_events
        import config
        fn = ALL_SCENARIOS.get(args.scenario)
        if not fn:
            print(Fore.RED + f"Unknown scenario '{args.scenario}'. Available: {list(ALL_SCENARIOS.keys())}")
            sys.exit(1)
        evs = fn(host=args.host, user=args.user) if "host" in fn.__code__.co_varnames else fn()
        log_path = config.SYSMON_LOG if any(
            e.get("EventID") in ("1","3","11","12","13") for e in evs
        ) else config.WINEVENT_LOG
        _append_events(log_path, evs)
        print(Fore.GREEN + f"[SIM] Injected {len(evs)} events → {log_path}")


def cmd_analyse(args):
    print(BANNER)
    from core.monitor import analyse_once
    alerts = analyse_once(verbose=True)
    print(Fore.CYAN + f"\n[ANALYSE] Total new alerts: {len(alerts)}")


def cmd_dashboard(args):
    print(BANNER)
    import config
    print(Fore.GREEN + f"  Starting SOC Dashboard on http://{config.FLASK_HOST}:{config.FLASK_PORT}")
    print(Fore.WHITE + "  Open your browser and navigate to the URL above.\n")
    from dashboard.app import socketio, app
    socketio.run(app, host=config.FLASK_HOST, port=config.FLASK_PORT, debug=False)


def cmd_report(args):
    from reports.report_generator import generate_report
    generate_report()


def cmd_clear(args):
    from core.alert_store import clear_alerts
    clear_alerts()
    print(Fore.YELLOW + "[CLEAR] All alerts have been cleared.")


def main():
    parser = argparse.ArgumentParser(
        description="BlueTeam SOC — Unified Threat Detection System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Commands:
  monitor    — Continuously watch logs and detect threats
  simulate   — Inject simulated attack events into log files
  analyse    — Run detection rules once and print alerts
  dashboard  — Start the Flask web dashboard
  report     — Generate an incident report (saved to reports/)
  clear      — Clear all stored alerts

Examples:
  python main.py simulate --scenario full_chain
  python main.py monitor --interval 5
  python main.py dashboard
  python main.py report
""")
    sub = parser.add_subparsers(dest="command")

    # monitor
    p_mon = sub.add_parser("monitor", help="Real-time log monitor")
    p_mon.add_argument("--interval", type=int, default=5, help="Poll interval in seconds")

    # simulate
    p_sim = sub.add_parser("simulate", help="Inject attack scenarios")
    p_sim.add_argument("--scenario", default="full_chain",
        help="Scenario name (full_chain, brute_force, mimikatz, c2_connection, ...)")
    p_sim.add_argument("--host", default="WORKSTATION-01")
    p_sim.add_argument("--user", default="attacker")

    # analyse
    sub.add_parser("analyse", help="Run detection rules once")

    # dashboard
    sub.add_parser("dashboard", help="Start web dashboard")

    # report
    sub.add_parser("report", help="Generate incident report")

    # clear
    sub.add_parser("clear", help="Clear all alerts")

    args = parser.parse_args()

    dispatch = {
        "monitor"  : cmd_monitor,
        "simulate" : cmd_simulate,
        "analyse"  : cmd_analyse,
        "dashboard": cmd_dashboard,
        "report"   : cmd_report,
        "clear"    : cmd_clear,
    }

    if args.command in dispatch:
        dispatch[args.command](args)
    else:
        print(BANNER)
        parser.print_help()


if __name__ == "__main__":
    main()
