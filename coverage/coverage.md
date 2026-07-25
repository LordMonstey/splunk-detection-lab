# MITRE ATT&CK Coverage

This file is the source of truth for the lab's validated coverage and known
gaps. The matching ATT&CK Navigator layer is available in
[`navigator-layer.json`](navigator-layer.json).

Status definitions:

- **Production** - deployed, validated end-to-end, and backed by evidence.
- **Testing** - implemented and deployed, but not yet promoted.
- **Hunt** - a non-alerting hunting query exists.
- **Gap** - deliberately not covered by the current telemetry.

## Detection inventory

| Tactic | Technique | ID | Status | Detection |
|---|---|---|---|---|
| Execution | PowerShell encoded command | T1059.001 | Production | `win_sysmon_t1059.001_powershell_encoded` |
| Execution | PowerShell download cradle | T1059.001/T1105 | Testing | `win_sysmon_t1059.001_powershell_download_cradle` |
| Execution | PowerShell AMSI bypass | T1059.001/T1562.001 | Testing | `win_pwsh_t1059.001_amsi_bypass` |
| Execution | Windows Cmd caret obfuscation | T1059.003/T1027 | Testing | `win_sysmon_t1059.003_cmd_obfuscation` |
| Persistence | Registry Run Keys | T1547.001 | Production | `win_sysmon_t1547.001_run_key_modification` |
| Persistence | Scheduled Task | T1053.005 | Testing | `win_sysmon_t1053.005_scheduled_task_creation` |
| Persistence | Local Account | T1136.001 | Production | `win_secevt_t1136.001_local_account_creation` |
| Persistence / Defense Evasion | IFEO, AppInit, Active Setup, Winlogon | T1546.012/T1547.014/T1112 | Testing | `win_sysmon_t1112_registry_persistence_helper` |
| Defense Evasion | Rundll32 unusual parent or no DLL | T1218.011 | Production | `win_sysmon_t1218.011_rundll32_unusual_parent` |
| Defense Evasion | Mshta remote or inline execution | T1218.005 | Production | `win_sysmon_t1218.005_mshta_execution` |
| Defense Evasion | Regsvr32 Squiblydoo | T1218.010 | Production | `win_sysmon_t1218.010_regsvr32_remote` |
| Defense Evasion | PowerShell obfuscation entropy | T1027 | Testing | `win_sysmon_t1027_obfuscated_powershell_entropy` |
| Defense Evasion | Certutil decode or download | T1140/T1105 | Production | `win_sysmon_t1140_certutil_decode` |
| Defense Evasion | Defender tampering | T1562.001 | Testing | `win_sysmon_t1562.001_defender_tamper` |
| Defense Evasion | Permissive icacls grant | T1222.001 | Testing | `win_sysmon_t1222.001_icacls_permissive` |
| Credential Access | LSASS Memory Access | T1003.001 | Production | `win_sysmon_t1003.001_lsass_access_suspicious` |
| Credential Access | Brute force or password spray | T1110.001/T1110.003 | Testing | `win_secevt_t1110.001_failed_logon_burst` |
| Command and Control / Ingress | Curl or Bitsadmin download | T1105 | Testing | `win_sysmon_t1105_curl_wget_download` |

## Current totals

- Production: **8**
- Testing: **10**
- Total deployed saved searches: **18**
- Production detections with committed evidence: **8**

## Coverage gaps

The lab is intentionally limited to a single Windows endpoint with Sysmon and
native Windows event channels.

- T1003.002 (Security Account Manager) - no SAM-specific validation.
- T1021.001 (RDP) - requires a second endpoint for lateral-movement validation.
- T1021.002 (SMB admin shares) - requires a second endpoint.
- T1071.001 (HTTP C2) - requires proxy or network telemetry.
- T1090 (Proxy) - requires proxy or NDR telemetry.
- T1078 (Valid Accounts) - requires broader identity context and baselining.
- T1486 (Data Encrypted for Impact) - requires a ransomware-pattern dataset.
- T1134 (Token Manipulation) - requires additional Sysmon telemetry.
- Active Directory techniques - no domain controller is present.

## Promotion criteria

A detection moves from **Testing** to **Production** only when:

1. Atomic Red Team or manual validation evidence is committed.
2. A false-positive scenario is documented and the tuning control is defined.
3. The saved search exists in `conf/splunk/local/savedsearches.conf`.
4. A response runbook is linked from the detection document.
5. This coverage table is updated.
6. The ATT&CK Navigator layer is updated.
