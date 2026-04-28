---
id: win_sysmon_t1053.005_scheduled_task_creation
title: Scheduled task created via schtasks.exe with suspicious arguments
status: testing
author: LordMonstey
created: 2026-04-28
modified: 2026-04-28
severity: medium
risk_score: 55
attack:
  - tactic: persistence
    technique: T1053.005
    sub_technique_name: Scheduled Task
data_source:
  index: sysmon
  sourcetype: XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  event_codes: [1]
mitre_data_component: Process Creation
schedule:
  cron: "*/10 * * * *"
  earliest: "-15m@m"
  latest:   "-1m@m"
references:
  - https://attack.mitre.org/techniques/T1053/005/
tags:
  - persistence
  - scheduled-task
---

## Hypothesis

`schtasks.exe /create` (or `/change`) is a routine sysadmin tool, but in the wild adversaries use it for cheap persistence — especially when paired with arguments invoking `cmd`, `powershell`, or running `SYSTEM`. Legitimate scheduled tasks tend to be created during install-time by `msiexec.exe`/`TrustedInstaller.exe`, or interactively by admins from `mmc.exe`/`taskschd.msc`.

## Logic

```spl
`sysmon_process_creation`
process_name="schtasks.exe"
| where match(CommandLine, "(?i)\s/(create|change)\b")
   AND (
       match(CommandLine, "(?i)/ru\s+system")
    OR match(CommandLine, "(?i)/tr\s+.+(powershell|cmd\.exe|wscript|cscript|mshta|rundll32|regsvr32)")
    OR match(CommandLine, "(?i)/sc\s+(onlogon|onstart|once|minute)")
   )
| eval parent_name = mvindex(split(ParentImage,"\\"), -1)
| where NOT match(parent_name, "(?i)^(mmc|taskschd|trustedinstaller|msiexec|setup)\.exe$")
| `cim_endpoint_processes_rename`
| stats count min(_time) as firstTime max(_time) as lastTime
        values(CommandLine) as commandlines
        values(parent_process_name) as parents
        by dest user process_name process_guid
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

## Known false positives

- Software updaters that schedule self-update tasks (`GoogleUpdate.exe`, `MicrosoftEdgeUpdate.exe`) — usually invoked from their own launcher, allowlist by parent
- IT scripted maintenance — track via parent and command pattern

## Tuning

- Allowlist via `(parent_process_name, task_name_prefix)` in `lookups/allowlist_schtasks.csv`
- Suppression: 6 hours per `(dest, parent_process_name)`

## Validation

- Atomic Red Team: T1053.005 #1 — At.exe Scheduled Task
- Atomic Red Team: T1053.005 #2 — schtasks /create with cmd

Manual reproduction:

```cmd
schtasks /create /tn "atomic-test" /tr "cmd.exe /c calc.exe" /sc onlogon /ru SYSTEM /f
```

Cleanup:

```cmd
schtasks /delete /tn "atomic-test" /f
```

## Response

See [`docs/runbooks/persistence-investigation.md`](../docs/runbooks/persistence-investigation.md).

1. Resolve the task's binary target (`/tr`)
2. Check the task's run-as principal — `SYSTEM` from a non-admin caller is automatic escalation territory
3. If parent is suspicious (productivity app, browser): suspected post-exploitation, isolate
4. Companion check: Win EID 4698 (task created via Security log) for cross-validation
