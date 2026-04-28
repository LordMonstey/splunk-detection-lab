# Atomic Red Team — Test Mapping

This file maps every detection in `detections/` to one or more Atomic Red Team test IDs. Use it as the work list for Phase 3 validation.

## Workflow per detection

1. Read the detection's `Validation` section
2. On the Windows lab VM, run the matching Atomic test:
   ```powershell
   Invoke-AtomicTest <TID>.<sub> -TestNumbers <n> -GetPrereqs
   Invoke-AtomicTest <TID>.<sub> -TestNumbers <n>
   ```
3. In Splunk, run the detection's SPL within a tight time window
4. Capture screenshot + raw event(s) → `tests/atomic/<technique>/evidence/`
5. Update `coverage/coverage.md` status to ✅
6. Update `coverage/navigator-layer.json` score to 100
7. Always cleanup: `Invoke-AtomicTest <TID>.<sub> -TestNumbers <n> -Cleanup`

## Test list

| Detection | Atomic test |
|---|---|
| win_sysmon_t1059.001_powershell_encoded | T1059.001 #2 (Mimikatz via encoded) |
| win_sysmon_t1059.001_powershell_download_cradle | T1059.001 #11, T1105 #5 |
| win_pwsh_t1059.001_amsi_bypass | T1562.001 #15, T1562.001 #28 |
| win_sysmon_t1059.003_cmd_obfuscation | T1059.003 #5 |
| win_sysmon_t1547.001_run_key_modification | T1547.001 #1 |
| win_sysmon_t1053.005_scheduled_task_creation | T1053.005 #1, T1053.005 #2 |
| win_secevt_t1136.001_local_account_creation | T1136.001 #1 |
| win_sysmon_t1112_registry_persistence_helper | T1546.012 #1, T1547.004 #1 |
| win_sysmon_t1218.011_rundll32_unusual_parent | T1218.011 #1 |
| win_sysmon_t1218.005_mshta_execution | T1218.005 #1 |
| win_sysmon_t1218.010_regsvr32_remote | T1218.010 #1 |
| win_sysmon_t1027_obfuscated_powershell_entropy | T1027 #4 |
| win_sysmon_t1140_certutil_decode | T1140 #4 |
| win_sysmon_t1562.001_defender_tamper | T1562.001 #16, T1562.001 #28 |
| win_sysmon_t1222.001_icacls_permissive | T1222.001 #1 |
| win_sysmon_t1003.001_lsass_access_suspicious | T1003.001 #1, T1003.001 #2 |
| win_secevt_t1110.001_failed_logon_burst | manual reproduction (see detection file) |
| win_sysmon_t1105_curl_wget_download | T1105 #2, T1105 #11 |

## Lab safety

This is a single-VM lab. Atomic tests can leave artifacts (binaries, registry entries, scheduled tasks). **Always run cleanup**. If an Atomic test executes a payload that doesn't cleanup well (rare but happens), revert to the VM snapshot you took before starting Phase 3.

Do not run Atomic tests on a host that holds non-lab data.
