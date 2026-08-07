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
`sysmon_process_access` TargetImage="*\\lsass.exe" | eval source_name = mvindex(split(SourceImage,"\\"), -1) | where NOT match(source_name, "(?i)^(wininit|svchost|lsass|services|TaskMgr|SgrmBroker)\\.exe$") AND (GrantedAccess="0x1010" OR GrantedAccess="0x1410" OR GrantedAccess="0x1438" OR GrantedAccess="0x143a" OR GrantedAccess="0x1fffff") | lookup allowlist_lsass_access source_process_name AS source_name OUTPUTNEW signer AS allowlisted_signer reason AS allowlist_reason | where isnull(allowlisted_signer) | `cim_endpoint_processes_rename` | eval user=coalesce(user, SourceUser, "unknown") | stats count min(_time) as firstTime max(_time) as lastTime values(SourceImage) as source_images values(SourceCommandLine) as source_cmds values(GrantedAccess) as access_masks values(CallTrace) as call_traces by dest user SourceProcessGUID | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

## Known false positives

- Endpoint security agents not yet present in the reviewed baseline.
- System Informer or Process Hacker during approved administration sessions.
- Performance-monitoring agents that request limited process access.

The lookup is an approval register, not a runtime signature-verification
engine. An operator must verify the publisher signature out of band before a
new source-image pattern and expected signer are committed to
`lookups/allowlist_lsass_access.csv`.

## Tuning

- Keep the access-mask filter explicit; it is the main precision control.
- Keep the small built-in Windows process baseline explicit and reviewable.
- Register additional approved accessors through `allowlist_lsass_access`,
  defined in `conf/splunk/local/transforms.conf`, after reducing `SourceImage`
  to its executable name in `source_name`.
- Never add a lookup row from the executable name alone; record the signer only
  after it has been independently verified.
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

Public evidence:

- [Aggregate live validation: 2 results, 10 events, dispatch complete](../artifacts/public/live-detection-validation-20260806.json)
- Raw events and screenshots remain in the ignored private evidence area.

## Response

See [`docs/runbooks/credential-access.md`](../docs/runbooks/credential-access.md).

1. Isolate the host through the EDR or a firewall control.
2. Identify privileged accounts that recently authenticated to the endpoint.
3. Preserve the source process image, hash, command line, parent, and call trace.
4. Pivot on `SourceProcessGUID` to reconstruct the process chain.
5. Search the environment for the same process hash and source image.
6. Rotate exposed privileged credentials after evidence preservation.
