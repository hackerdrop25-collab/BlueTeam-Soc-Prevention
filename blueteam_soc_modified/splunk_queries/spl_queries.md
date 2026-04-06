# ============================================================
#   splunk_queries/spl_queries.md — Advanced SPL Reference
# ============================================================

# ─────────────────────────────────────────────────────────────
# BRUTE FORCE DETECTION
# ─────────────────────────────────────────────────────────────
# Threshold: ≥5 failures in 60 seconds per user

index=wineventlog EventCode=4625
| bin span=1m _time
| stats count by _time, Account_Name, src_ip
| where count >= 5
| sort -count
| rename Account_Name as "Targeted User", src_ip as "Source IP", count as "Failed Attempts"


# ─────────────────────────────────────────────────────────────
# SUCCESSFUL LOGIN AFTER FAILURES (Credential Stuffing)
# ─────────────────────────────────────────────────────────────

index=wineventlog (EventCode=4624 OR EventCode=4625)
| sort _time
| streamstats count(eval(EventCode=4625)) AS fail_count
             reset_on_change=true by Account_Name
| where EventCode=4624 AND fail_count >= 3
| table _time, Account_Name, src_ip, fail_count


# ─────────────────────────────────────────────────────────────
# PRIVILEGE ESCALATION
# ─────────────────────────────────────────────────────────────

index=wineventlog EventCode=4672
| stats count by Account_Name, Privilege_List, host, _time
| sort -_time


# ─────────────────────────────────────────────────────────────
# SUSPICIOUS POWERSHELL (Sysmon EventID 1)
# ─────────────────────────────────────────────────────────────

index=sysmon EventCode=1
  (Image="*powershell*" OR Image="*cmd.exe" OR Image="*wscript*")
  (CommandLine=*-enc* OR CommandLine=*-encodedcommand* OR
   CommandLine=*iex* OR CommandLine=*DownloadString* OR
   CommandLine=*bypass*)
| table _time, host, User, Image, CommandLine, ParentImage
| sort -_time


# ─────────────────────────────────────────────────────────────
# C2 NETWORK CONNECTIONS (Sysmon EventID 3)
# ─────────────────────────────────────────────────────────────

index=sysmon EventCode=3
| lookup threat_intel_ips DestinationIp OUTPUT is_malicious, threat_name
| where is_malicious=true
  OR DestinationPort IN (4444, 1337, 8888, 9999, 31337)
| table _time, host, User, Image, DestinationIp, DestinationPort, threat_name
| sort -_time


# ─────────────────────────────────────────────────────────────
# REGISTRY PERSISTENCE (Sysmon EventID 13)
# ─────────────────────────────────────────────────────────────

index=sysmon EventCode=13
  (TargetObject="*\\CurrentVersion\\Run*"
   OR TargetObject="*\\CurrentVersion\\RunOnce*"
   OR TargetObject="*\\Winlogon*"
   OR TargetObject="*\\Services\\*")
| table _time, host, User, TargetObject, Details
| sort -_time


# ─────────────────────────────────────────────────────────────
# CREDENTIAL DUMPING
# ─────────────────────────────────────────────────────────────

index=sysmon EventCode=1
  (Image="*mimikatz*" OR Image="*procdump*"
   OR CommandLine="*lsass*" OR CommandLine="*sekurlsa*"
   OR CommandLine="*logonpasswords*" OR CommandLine="*hashdump*")
| table _time, host, User, Image, CommandLine
| sort -_time


# ─────────────────────────────────────────────────────────────
# TOP ATTACKING HOSTS DASHBOARD PANEL
# ─────────────────────────────────────────────────────────────

index=wineventlog EventCode=4625
| stats count AS failures by src_ip, Account_Name
| sort -failures
| head 10


# ─────────────────────────────────────────────────────────────
# ATTACK TIMELINE (all suspicious events, last 24h)
# ─────────────────────────────────────────────────────────────

index=sysmon OR index=wineventlog earliest=-24h
  (EventCode=4625 OR EventCode=4624 OR EventCode=4672
   OR EventCode=1 OR EventCode=3 OR EventCode=13)
| eval event_type=case(
    EventCode=4625, "Failed Login",
    EventCode=4624, "Successful Login",
    EventCode=4672, "Privilege Escalation",
    EventCode=1,    "Process Creation",
    EventCode=3,    "Network Connection",
    EventCode=13,   "Registry Change",
    true(),         "Other")
| table _time, host, event_type, Account_Name, Image, DestinationIp
| sort _time


# ─────────────────────────────────────────────────────────────
# COMPOSITE RISK SCORING
# ─────────────────────────────────────────────────────────────

index=sysmon OR index=wineventlog earliest=-1h
| eval risk_score=case(
    EventCode=4625,  10,
    EventCode=4672,  80,
    (EventCode=1 AND match(CommandLine, "(?i)-enc|-bypass|iex|mimikatz")), 90,
    (EventCode=3 AND DestinationPort IN ("4444","1337","8888")), 95,
    EventCode=13,    70,
    true(), 5)
| stats sum(risk_score) AS total_risk, max(risk_score) AS peak_risk
        count AS events by host
| eval risk_level=case(
    total_risk >= 90, "CRITICAL",
    total_risk >= 70, "HIGH",
    total_risk >= 40, "MEDIUM",
    true(), "LOW")
| sort -total_risk
