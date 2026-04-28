---
id: win_sysmon_t1105_curl_wget_download
title: curl.exe or bitsadmin.exe downloading from external URL
status: testing
author: LordMonstey
created: 2026-04-28
modified: 2026-04-28
severity: medium
risk_score: 50
attack:
  - tactic: command-and-control
    technique: T1105
    sub_technique_name: Ingress Tool Transfer
data_source:
  index: sysmon
  sourcetype: XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  event_codes: [1]
mitre_data_component: Process Creation
schedule:
  cron: "*/5 * * * *"
  earliest: "-10m@m"
  latest:   "-1m@m"
references:
  - https://attack.mitre.org/techniques/T1105/
  - https://lolbas-project.github.io/lolbas/Binaries/Bitsadmin/
tags:
  - lolbin
  - c2
  - download
---

## Hypothesis

Windows ships `curl.exe` (since 1809) and `bitsadmin.exe` for legitimate use, but both are abused as pure downloaders by adversaries who want to avoid scripting interpreters. Legitimate workstation use is rare; build/CI systems are an exception.

## Logic

```spl
`sysmon_process_creation`
(process_name="curl.exe" OR process_name="bitsadmin.exe")
| where match(CommandLine, "(?i)https?://")
   AND NOT match(CommandLine, "(?i)https?://(127\.|localhost|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)")
| `cim_endpoint_processes_rename`
| stats count min(_time) as firstTime max(_time) as lastTime
        values(CommandLine) as commandlines
        values(parent_process_name) as parents
        by dest user process_name process_guid
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

## Known false positives

- Developer machines (curl is normal on dev workstations) — allowlist whole hostnames in `lookups/allowlist_dev_hosts.csv`
- Some setup wizards use bitsadmin to fetch components from vendor CDNs — allowlist by destination domain

## Tuning

- The RFC1918 exclusion already drops internal traffic
- Add destination-domain allowlist for known-good CDNs
- Suppression: 1 hour per `(dest, process_guid)`

## Validation

- Atomic Red Team: T1105 #2 — Bitsadmin download
- Atomic Red Team: T1105 #11 — curl download

Manual reproduction:

```cmd
curl.exe -o atomic.txt https://example.com/
del atomic.txt
```

## Response

See [`docs/runbooks/lolbin-proxy-execution.md`](../docs/runbooks/lolbin-proxy-execution.md).

1. Resolve the destination URL — VirusTotal, urlscan
2. Hash the downloaded file (the output path is in CommandLine `-o`)
3. Track via `\`sysmon_file_create\` host=<dest>` whether the file was executed
