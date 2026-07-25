---
id: win_sysmon_t1003.001_lsass_access_suspicious
title: Suspicious access to LSASS process memory
status: production
author: LordMonstey
created: 2026-04-28
modified: 2026-07-25
severity: critical
risk_score: 90
attack:
  - tactic: credential-access
    technique: T1003.001
    sub_technique_name: LSASS Memory
data_source:
  index: sysmon
  sourcetype: XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  event_codes: [10]
mitre_data_component: Process Access
schedule:
  cron: "*/5 * * * *"
  earliest: "-10m@m"
  latest: "-1m@m"
references:
  - https://attack.mitre.org/techniques/T1003/001/
  - https://learn.microsoft.com/sysinternals/downloads/procdump
tags:
  - credential-access
  - lsass
  - critical
---

## Hypothesis

Credential-dumping tools open a handle to `lsass.exe` with memory-read rights
to extract authentication material. Legitimate LSASS accessors form a small,
stable baseline, while access masks such as `0x1010`, `0x1410`, `0x1438`,
`0x143a`, and `0x1fffff` indicate memory-read or full-access intent.

## Logic

```spl
`sysmon_process_access` EventID=10
TargetImage="*\\lsass.exe"
| eval source_name = mvindex(split(SourceImage,"\\"), -1)
| where NOT match(
    source_name,
    "(?i)^(MsMpEng|MsSense|csrss|wininit|svchost|lsass|services|TaskMgr|VsTskMgr|SgrmBroker)\.exe$"
  )
  AND (
    GrantedAccess="0x1010"
    OR GrantedAccess="0x1410"
    OR GrantedAccess="0x1438"
    OR GrantedAccess="0x143a"
    OR GrantedAccess="0x1fffff"
  )
| `cim_endpoint_processes_rename`
| stats count min(_time) as firstTime max(_time) as lastTime
        values(SourceImage) as source_images
        values(SourceCommandLine) as source_cmds
        values(GrantedAccess) as access_masks
        values(CallTrace) as call_traces
        by dest user SourceProcessGUID
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

## Known false positives

- Endpoint security agents not present in the baseline.
- System Informer or Process Hacker during approved administration sessions.
- Performance-monitoring agents that request limited process access.

New accessors must be verified by publisher signature before they are added to
`lookups/allowlist_lsass_access.csv`.

## Tuning

- Keep the access-mask filter explicit; it is the main precision control.
- Allowlist by process name and verified signer, never by process name alone.
- Do not suppress distinct process GUIDs because each handle open is actionable.

The first implementation used a regular expression for `GrantedAccess`.
Validation showed inconsistent matching in the lab version of Splunk, so the
production query uses explicit equality checks. This is both easier to review
and faster to troubleshoot.

## Validation

Validated on 2026-04-29 with Atomic Red Team
`T1003.001-1 - Dump LSASS.exe Memory using ProcDump`.

```powershell
Invoke-AtomicTest T1003.001 -TestNumbers 1
Invoke-AtomicTest T1003.001 -TestNumbers 1 -Cleanup
```

ProcDump and ProcDump64 opened LSASS with `GrantedAccess=0x1fffff`. Sysmon
recorded the process-access events and tagged the activity with the T1003
credential-dumping technique.

Evidence:

- [Atomic execution and raw events](../tests/atomic/evidence/T1003.001-lsass-procdump.png)
- [Detection results in Splunk](../tests/atomic/evidence/T1003.001-detection-fired.png)

## Response

See [`docs/runbooks/credential-access.md`](../docs/runbooks/credential-access.md).

1. Isolate the host through the EDR or a firewall control.
2. Identify privileged accounts that recently authenticated to the endpoint.
3. Preserve the source process image, hash, command line, parent, and call trace.
4. Pivot on `SourceProcessGUID` to reconstruct the process chain.
5. Search the environment for the same process hash and source image.
6. Rotate exposed privileged credentials after evidence preservation.
