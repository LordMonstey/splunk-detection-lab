# MITRE ATT&CK Coverage

This file is the source of truth for what this lab can detect, what it cannot, and where the gaps are. Updated alongside every detection change.

The matching ATT&CK Navigator layer is at [`navigator-layer.json`](navigator-layer.json).

Legend:

- ✅ Production — rule deployed, validated with Atomic Red Team, FPs documented
- 🟡 Testing — rule written, not yet validated end-to-end
- 🧪 Hunt — non-alerting hunt query exists in `hunting/`
- ❌ Gap — known coverage gap, deliberately not addressed yet
- 🚫 Out of scope — requires telemetry not present in this lab

## Detection inventory

| Tactic | Technique | ID | Status | Detection |
|---|---|---|---|---|
| Execution | PowerShell — encoded command | T1059.001 | 🟡 | `win_sysmon_t1059.001_powershell_encoded` |
| Execution | PowerShell — download cradle | T1059.001/T1105 | 🟡 | `win_sysmon_t1059.001_powershell_download_cradle` |
| Execution | PowerShell — AMSI bypass via 4104 | T1059.001/T1562.001 | 🟡 | `win_pwsh_t1059.001_amsi_bypass` |
| Execution | Windows Cmd — caret obfuscation | T1059.003/T1027 | 🟡 | `win_sysmon_t1059.003_cmd_obfuscation` |
| Persistence | Registry Run Keys | T1547.001 | 🟡 | `win_sysmon_t1547.001_run_key_modification` |
| Persistence | Scheduled Task | T1053.005 | 🟡 | `win_sysmon_t1053.005_scheduled_task_creation` |
| Persistence | Local Account | T1136.001 | 🟡 | `win_secevt_t1136.001_local_account_creation` |
| Persistence/Defense Evasion | IFEO / AppInit / Active Setup / Winlogon | T1546.012/T1547.014/T1112 | 🟡 | `win_sysmon_t1112_registry_persistence_helper` |
| Defense Evasion | Rundll32 unusual parent / no DLL | T1218.011 | 🟡 | `win_sysmon_t1218.011_rundll32_unusual_parent` |
| Defense Evasion | Mshta — remote/inline | T1218.005 | 🟡 | `win_sysmon_t1218.005_mshta_execution` |
| Defense Evasion | Regsvr32 — Squiblydoo | T1218.010 | 🟡 | `win_sysmon_t1218.010_regsvr32_remote` |
| Defense Evasion | PowerShell obfuscation entropy | T1027 | 🟡 | `win_sysmon_t1027_obfuscated_powershell_entropy` |
| Defense Evasion | Certutil decode/download | T1140/T1105 | 🟡 | `win_sysmon_t1140_certutil_decode` |
| Defense Evasion | Defender tampering | T1562.001 | 🟡 | `win_sysmon_t1562.001_defender_tamper` |
| Defense Evasion | icacls Everyone:F | T1222.001 | 🟡 | `win_sysmon_t1222.001_icacls_permissive` |
| Credential Access | LSASS Memory Access | T1003.001 | 🟡 | `win_sysmon_t1003.001_lsass_access_suspicious` |
| Credential Access | Brute force / spray | T1110.001/T1110.003 | 🟡 | `win_secevt_t1110.001_failed_logon_burst` |
| C2 / Ingress | curl / bitsadmin download | T1105 | 🟡 | `win_sysmon_t1105_curl_wget_download` |

## Current totals

- ✅ Production: 0
- 🟡 Testing: 18
- 🧪 Hunt: 0
- ❌ Gap: variable (see below)
- 🚫 Out of scope: see below

## Coverage gaps (deliberate)

Limited by lab scope (single Windows host, no DC, no proxy, no EDR):

- T1003.002 (Security Account Manager) — partially covered via T1003.001 LSASS rule but no SAM-specific detection
- T1021.001 (RDP lateral) — would need a second host to validate
- T1021.002 (SMB admin shares) — same
- T1071.001 (HTTP C2) — requires proxy logs
- T1090 (Proxy) — same
- T1018 (Remote system discovery) — easy to write but uninteresting in single-host lab
- T1078 (Valid accounts misuse) — needs broader auth telemetry / impossible-travel-style baselines
- T1486 (Data Encrypted for Impact) — covered by FileDelete events but needs ransomware pattern (mass file rename burst) detection — planned
- T1134 (Token Manipulation) — needs Sysmon-modular fragments enabled for token-related EIDs (currently filtered out)

## Out of scope (telemetry not collected)

- All Active Directory auth events (Kerberos, DCSync, AS-REP roasting) — no DC in lab
- Network detection (DNS tunneling, DGA, beaconing) — no proxy/Zeek

## Promotion criteria (testing → production)

A detection moves to ✅ when:

1. Atomic Red Team validation evidence committed to `tests/atomic/<technique>/`
2. At least one FP scenario observed and tuned (the lookup must have an entry)
3. Saved search exists in `conf/splunk/local/savedsearches.conf`
4. Runbook exists and is referenced from the detection's "Response" section
5. Coverage table updated to ✅ in this file
6. ATT&CK Navigator layer score updated to 100 for the technique
