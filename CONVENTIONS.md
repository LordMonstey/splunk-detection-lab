# Conventions

This document defines the contract every contribution in this repository must follow. The goal is consistency: an analyst should be able to read any detection, lookup, or runbook in this repo and find the same structure.

---

## 1. Detection ID format

```
<platform>_<datasource>_<attck-technique>_<short-name>
```

Examples:

```
win_sysmon_t1059.001_powershell_encoded_command
win_sysmon_t1218.011_rundll3232_unusual_parent
win_secevt_t1110.001_kerberos_brute_force
```

Rules:

- `platform` — `win`, `lin`, `net`
- `datasource` — `sysmon`, `secevt`, `pwsh`, `appevt`, `firewall`
- `attck-technique` — full sub-technique ID, lowercase, with the dot
- `short-name` — kebab-case, ≤ 5 words, describes the *behavior*, not the *tool*

The detection filename is `<id>.md`. The `id` field inside the YAML front-matter must match the filename exactly.

---

## 2. Detection file format

Every file in `detections/` must contain:

1. A YAML front-matter block (see [`detections/_template.md`](detections/_template.md)) with the required fields
2. A markdown body in the documented section order: Hypothesis → Logic → False Positives → Tuning → Validation → Response

No detection is merged without a populated `validation` section pointing to a real, executed Atomic Red Team test or a documented manual procedure.

---

## 3. SPL style

### 3.1 Never hardcode `index=`

All searches reference macros from [`macros/macros.conf`](../macros/macros.conf):

```spl
`sysmon_process_creation`
| where match(CommandLine, "(?i)-enc(odedcommand)?")
```

not:

```spl
index=sysmon EventCode=1
| where match(CommandLine, "(?i)-enc(odedcommand)?")
```

### 3.2 Prefer `tstats` against accelerated data models for high-volume rules

```spl
| tstats summariesonly=t count from datamodel=Endpoint.Processes
  where Processes.process_name="powershell.exe"
  by Processes.dest Processes.user Processes.process
```

Raw-event SPL is acceptable for low-volume sources or rules that depend on fields not modeled in CIM. Justify in the detection file.

### 3.3 Field naming

CIM-aligned, lowercase, snake_case. Use `eval` to rename Sysmon-native fields when emitting results:

```spl
| eval dest=host, user=User, process=Image, process_name=mvindex(split(Image,"\\"),-1)
| table _time dest user process_name CommandLine
```

### 3.4 No wildcards on the left

```spl
NOT  CommandLine="*mimikatz*"
YES  CommandLine="mimikatz*"   OR   match(CommandLine,"(?i)mimikatz")
```

### 3.5 Time bounds

Detections must declare `earliest` and `latest` in the saved-search definition, not inside the SPL body. The SPL in the detection file shows the logic only.

---

## 4. ATT&CK mapping

- Map to the **most specific sub-technique** available
- A detection mapped to a parent technique (e.g., T1218 with no sub-id) is a smell — split it
- Multiple mappings allowed when the rule is genuinely cross-technique; list them all in `attack:` as YAML list

---

## 5. False positives

Each detection enumerates FPs as a markdown list. Acceptable phrasings:

- "Vendor X agent legitimately spawns `rundll32.exe` with this commandline pattern → allowlisted via `lookups/allowlist_rundll32.csv`"
- "Domain admin maintenance scripts on Patch Tuesday → tuned via time-of-day filter"

Unacceptable:

- "Some legitimate apps may trigger this"

If you cannot name the FP, the detection is not ready.

---

## 6. Lookups

- Filename: lowercase, snake_case, `.csv`
- Header row mandatory
- One concept per lookup (do not stuff asset + identity + allowlist into one CSV)
- Bound to a `lookups.conf` entry with a stable lookup name

---

## 7. Commits

Conventional Commits, scoped:

```
feat(detect): add t1003.001 lsass access via procexp
fix(macro): correct sysmon_network_connection eventcode filter
docs(runbook): expand triage steps for powershell encoded
test(atomic): add evidence for t1547.001 run key
```

Scopes used in this repo: `detect`, `hunt`, `macro`, `lookup`, `conf`, `dashboard`, `runbook`, `coverage`, `test`, `docs`, `ci`.
