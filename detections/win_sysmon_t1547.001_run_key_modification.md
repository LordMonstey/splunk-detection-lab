---
id: win_sysmon_t1547.001_run_key_modification
title: Registry Run/RunOnce key modification by non-system process
status: testing
author: LordMonstey
created: 2026-04-28
modified: 2026-04-28
severity: medium
risk_score: 55
attack:
  - tactic: persistence
    technique: T1547.001
    sub_technique_name: Registry Run Keys / Startup Folder
data_source:
  index: sysmon
  sourcetype: XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  event_codes: [13]
mitre_data_component: Windows Registry
schedule:
  cron: "*/10 * * * *"
  earliest: "-15m@m"
  latest:   "-1m@m"
references:
  - https://attack.mitre.org/techniques/T1547/001/
tags:
  - persistence
  - registry
---

## Hypothesis

Run/RunOnce registry keys execute their contained binary on user logon. Adversaries write to these keys for cheap persistence. Legitimate writes to these keys are dominated by installers (`msiexec.exe`), the OS itself (`svchost.exe`), and user-driven UI events; writes from interactive shells, browsers, or office apps are anomalous.

## Logic

```spl
`sysmon_registry_event` EventID=13
TargetObject="*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run*"
   OR TargetObject="*\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce*"
   OR TargetObject="*\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run*"
| eval writer = mvindex(split(Image,"\\"), -1)
| where NOT match(writer, "(?i)^(msiexec|setup|installer|trustedinstaller|wuauclt|svchost)\.exe$")
| `cim_endpoint_processes_rename`
| stats count min(_time) as firstTime max(_time) as lastTime
        values(TargetObject) as run_keys
        values(Details) as run_values
        values(writer) as writers
        by dest user process_guid
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

## Known false positives

- Some user-installed third-party apps write their auto-start entry from a non-system parent (e.g., Spotify, Discord installer, Steam) → allowlist via writer + Details pattern in `lookups/allowlist_run_keys.csv`
- IT-deployed software via custom packagers

## Tuning

- The Details field contains the value being written; allowlist on a `(writer, Details prefix)` pair, not just `writer` alone — that protects against attackers piggybacking on a legitimate writer
- Suppression: 6 hours per `(dest, process_guid, TargetObject)`

## Validation

- Atomic Red Team: T1547.001 #1 — Reg Key Run

Manual reproduction:

```cmd
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v atomic-test /t REG_SZ /d "C:\Windows\System32\calc.exe" /f
```

Cleanup:

```cmd
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v atomic-test /f
```

## Response

See [`docs/runbooks/persistence-investigation.md`](../docs/runbooks/persistence-investigation.md).

1. Resolve the binary referenced in the Run value — file path, hash, signer
2. Pivot on `process_guid` to find the parent that wrote the key
3. If the value points to a non-program-files binary written in the last 7 days, treat as confirmed persistence attempt
4. Check companion mechanisms: scheduled tasks (T1053), services (T1543), WMI subscriptions (T1546.003)
