# ============================================================
#   parsers/log_parser.py — Parse JSON log files into events
# ============================================================

import json
import os
import re
from typing import List
from core.event_model import SecurityEvent
import config


def load_json_log(path: str) -> list:
    if not os.path.exists(path):
        return []
    with open(path, "r") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return []


def parse_sysmon_events(raw_events: list) -> List[SecurityEvent]:
    events = []
    for r in raw_events:
        eid = str(r.get("EventID", ""))
        category = {
            "1": "process", "3": "network", "11": "file",
            "12": "registry", "13": "registry", "7": "image_load",
        }.get(eid, "generic")

        ev = SecurityEvent(
            event_id     = eid,
            source       = "sysmon",
            category     = category,
            timestamp    = r.get("TimeCreated", ""),
            hostname     = r.get("Computer", "UNKNOWN"),
            username     = r.get("User", ""),
            process_name = r.get("Image", "").split("\\")[-1].lower(),
            process_id   = int(r.get("ProcessId", 0) or 0),
            parent_proc  = r.get("ParentImage", "").split("\\")[-1].lower(),
            command_line = r.get("CommandLine", ""),
            src_ip       = r.get("SourceIp", ""),
            dst_ip       = r.get("DestinationIp", ""),
            dst_port     = int(r.get("DestinationPort", 0) or 0),
            file_path    = r.get("TargetFilename", ""),
            registry_key = r.get("TargetObject", ""),
            raw          = r,
        )
        events.append(ev)
    return events


def parse_windows_events(raw_events: list) -> List[SecurityEvent]:
    events = []
    for r in raw_events:
        eid = str(r.get("EventID", ""))
        category = {
            "4624": "login", "4625": "login", "4672": "privilege",
            "4688": "process", "4697": "service", "4720": "account",
            "4726": "account", "4732": "group", "7045": "service",
        }.get(eid, "generic")

        ev = SecurityEvent(
            event_id     = eid,
            source       = "winevent",
            category     = category,
            timestamp    = r.get("TimeCreated", ""),
            hostname     = r.get("Computer", "UNKNOWN"),
            username     = r.get("TargetUserName", r.get("SubjectUserName", "")),
            process_name = r.get("NewProcessName", "").split("\\")[-1].lower(),
            src_ip       = r.get("IpAddress", ""),
            raw          = r,
        )
        events.append(ev)
    return events


def load_all_events() -> List[SecurityEvent]:
    sysmon_raw  = load_json_log(config.SYSMON_LOG)
    winevent_raw = load_json_log(config.WINEVENT_LOG)
    return parse_sysmon_events(sysmon_raw) + parse_windows_events(winevent_raw)
