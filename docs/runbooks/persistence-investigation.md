# Runbook — Persistence investigation

Applies to detections on Run/RunOnce keys, scheduled tasks, IFEO, Active Setup, AppInit DLLs, services. Pattern matters more than tool: regardless of mechanism, the questions are the same.

**SLA**: 30 minutes for medium severity.

## 1. What was installed

Pull the persistence payload from the event:

- Registry persistence: `Details` field holds the value written
- Scheduled task: parse `/tr` argument from CommandLine
- Service: name + ImagePath from EID 7045

Resolve the binary:

- Hash, signer, file age (creation time)
- VirusTotal lookup if accessible
- Check whether the binary was created in the last 7 days on the host: `\`sysmon_file_create\` host=<dest> file_path=<path>`

## 2. Who installed it

Pivot on the writer:

```spl
`sysmon_process_creation` process_guid="<process_guid_from_alert>"
| table _time host User Image CommandLine ParentImage Hashes
```

If the writer is `msiexec.exe`, `TrustedInstaller.exe`, or signed installer chain → benign-likely.
If the writer is `cmd.exe`, `powershell.exe`, `wmiprvse.exe`, or any user-launched process → suspect.

## 3. Companion mechanisms

Adversaries often install multiple persistence in one go. Check for any of the following on the same host within the last 24 hours:

- New scheduled tasks (`schtasks.exe /create` or Win EID 4698)
- New services (Win EID 7045)
- Run/RunOnce key writes (`sysmon_registry_event` to those keys)
- WMI subscriptions (`sysmon_wmi_event` if EID 19/20/21 are enabled)

## 4. Verdict and remediation

- Confirmed adversary persistence: remove the persistence (delete reg key, remove task, uninstall service), preserve the payload binary for IR, isolate the host
- Confirmed benign: allowlist with rationale
- Unclear: escalate to L3 with the artefact list compiled in steps 1-3
