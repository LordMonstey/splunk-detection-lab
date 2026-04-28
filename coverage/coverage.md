# MITRE ATT&CK Coverage

This file is the source of truth for what this lab can detect, what it cannot, and where the gaps are. It is updated with every new detection or deprecation.

The matching ATT&CK Navigator layer is generated at [`navigator-layer.json`](navigator-layer.json) — load it at <https://mitre-attack.github.io/attack-navigator/> to view as a heatmap.

Legend:

- ✅ Production — rule deployed, validated with Atomic Red Team, FPs documented
- 🟡 Testing — rule written, not yet validated end-to-end
- 🧪 Hunt — non-alerting hunt query exists in `hunting/`
- ❌ Gap — known coverage gap, deliberately not addressed yet
- 🚫 Out of scope — requires telemetry not present in this lab (e.g., no DC, no EDR)

| Tactic | Technique | ID | Status | Detection / Hunt |
|---|---|---|---|---|
| Execution | PowerShell | T1059.001 | 🟡 | `win_sysmon_t1059.001_powershell_encoded_command` |
| Execution | Windows Cmd | T1059.003 | ❌ | — |
| Execution | Malicious File | T1204.002 | 🧪 | `hunting/office_spawning_lolbins.spl` |
| Persistence | Registry Run Keys | T1547.001 | 🟡 | `win_sysmon_t1547.001_run_key_modification` |
| Persistence | Scheduled Task | T1053.005 | ❌ | — |
| Persistence | Local Account | T1136.001 | 🟡 | `win_secevt_t1136.001_local_account_creation` |
| Privilege Escalation | Process Injection | T1055 | 🚫 | Requires Sysmon EID 8/10 with reliable signatures (deferred) |
| Defense Evasion | Rundll32 | T1218.011 | 🟡 | `win_sysmon_t1218.011_rundll32_unusual_parent` |
| Defense Evasion | Mshta | T1218.005 | ❌ | — |
| Defense Evasion | Regsvr32 | T1218.010 | ❌ | — |
| Defense Evasion | Obfuscated Files | T1027 | 🧪 | `hunting/powershell_high_entropy.spl` |
| Defense Evasion | Deobfuscate | T1140 | ❌ | — |
| Defense Evasion | Disable Defender | T1562.001 | 🟡 | `win_sysmon_t1562.001_defender_tamper` |
| Credential Access | LSASS Memory | T1003.001 | 🟡 | `win_sysmon_t1003.001_lsass_access` |
| Credential Access | Brute Force | T1110.001 | 🟡 | `win_secevt_t1110.001_failed_logons_threshold` |
| Discovery | Account Discovery | T1087 | 🧪 | `hunting/local_account_enumeration.spl` |
| Lateral Movement | RDP | T1021.001 | ❌ | — |
| Lateral Movement | SMB/Windows Admin Shares | T1021.002 | ❌ | — |
| Impact | Data Encrypted | T1486 | 🧪 | `hunting/mass_file_rename.spl` |
| C2 | Web Protocols | T1071.001 | ❌ | Requires proxy/firewall logs (out of lab scope) |

**Current totals**: 0 ✅ / 7 🟡 / 5 🧪 / 6 ❌ / 2 🚫

Promotion criteria (testing → production):

1. Atomic Red Team validation evidence committed to `tests/atomic/`
2. At least one FP scenario documented and tuned
3. Saved search exists in `conf/splunk/local/savedsearches.conf`
4. Runbook exists in `docs/runbooks/`
5. Reviewed by another set of eyes (peer review note in PR)
