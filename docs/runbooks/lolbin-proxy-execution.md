# Runbook — LOLBin proxy execution

**Applies to detections**:
- `win_sysmon_t1218.011_rundll32_unusual_parent`
- `win_sysmon_t1218.005_mshta_execution` (planned)
- `win_sysmon_t1218.010_regsvr32_remote_scriptlet` (planned)

**SLA**: triage within 30 minutes for medium severity, 10 minutes for high.

---

## 1. Validate the alert

Before acting, rule out a tuning miss.

```spl
`sysmon_process_creation` process_guid="<value-from-alert>"
| table _time host User Image CommandLine ParentImage ParentCommandLine Hashes Signed Signature
```

Checklist:

- [ ] `Image` is the legitimate Windows path (e.g., `C:\Windows\System32\rundll32.exe`)? If not, *escalate immediately* — could be a masqueraded binary
- [ ] `Signed=true` and `Signature="Microsoft Windows"`? An unsigned `rundll32.exe` is a strong incident signal
- [ ] `ParentImage` matches a known allowlisted parent? If so, add to `lookups/allowlist_rundll32.csv` and close the alert as tuning

## 2. Establish blast radius

Pull the full process tree for the same `process_guid` and walk one generation up and down.

```spl
`sysmon_process_creation` (process_guid="<guid>" OR parent_process_guid="<guid>")
| sort _time
| table _time host User Image CommandLine ProcessId ParentProcessId
```

Cross-check outbound connections during the process lifetime:

```spl
`sysmon_network_connection` process_guid="<guid>"
| table _time host Image SourceIp SourcePort DestinationIp DestinationPort DestinationHostname
```

## 3. Pivot on the asset

```spl
`cim_endpoint_indexes` host="<dest>" earliest=-1h latest=now
| stats count by sourcetype EventCode
```

Look for adjacent indicators in the last hour:

- New scheduled tasks (Sysmon EID 12-14 on `\Microsoft\Windows\Schedule\TaskCache\Tree\*`)
- New services (Windows Security EID 7045)
- Defender tampering (Windows Security EID 4688 on `Set-MpPreference`, `Add-MpPreference`)
- Account creations (Windows Security EID 4720)

## 4. Pivot on the user

```spl
`wineventlog_security` user="<user>" (EventCode=4624 OR EventCode=4625 OR EventCode=4648)
earliest=-24h latest=now
| stats count by EventCode src_ip LogonType
```

Sudden privileged logons (LogonType 2 from new IPs, LogonType 3 to atypical hosts) elevate severity.

## 5. Containment decision tree

| Condition | Action |
|---|---|
| Parent is a productivity app (Word, Outlook, Acrobat, browser) | Treat as suspected initial access. Isolate host, capture memory if possible, preserve user mailbox attachment |
| Parent is a developer tool (cmd, powershell, python) on a non-developer asset | Isolate host, interview user |
| Parent is a known admin tool, identity is privileged, time-of-day matches change window | Likely admin activity; confirm with change record, allowlist if confirmed |
| Cannot establish parent legitimacy within SLA | Escalate to L3 |

## 6. Escalation criteria

Escalate to L3 / IR on any of:

- Outbound connection from the suspect process to a non-RFC1918 IP not in `lookups/known_good_destinations.csv`
- Hashes match anything in CTI feeds
- Multiple distinct hosts firing the same detection within 1 hour
- Credential-access detections firing on the same host within 24 hours

## 7. Closure

When closing the ticket, populate:

- Verdict: `true positive` / `benign true positive` / `false positive`
- If FP: a tuning task (PR opened against `lookups/allowlist_rundll32.csv` with the parent/command pattern and a justification)
- If TP: link to the IR ticket

A ticket closed as FP without a tuning task is incomplete. Repeat noisy alerts are a *team* failure, not a tool failure.
