# Validation

After the lab is built, run these checks to confirm telemetry is reaching Splunk and being normalized correctly.

## Ingestion

```spl
index=sysmon earliest=-15m | stats count by sourcetype, host
```

Expected: at least one row with sourcetype `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` and host equal to your Windows endpoint.

```spl
index=windows earliest=-15m | stats count by sourcetype
```

Expected: rows for `XmlWinEventLog:Security`, `XmlWinEventLog:System`, `XmlWinEventLog:Application`, `XmlWinEventLog:Microsoft-Windows-PowerShell/Operational`.

## Field extraction

```spl
`sysmon_process_creation`
| `cim_endpoint_processes_rename`
| head 1
| table _time dest user process_name process parent_process CommandLine
```

Expected: a row with the raw Sysmon fields plus the CIM-oriented aliases
emitted by the macro. If `CommandLine` is empty, verify XML field extraction
with `btool props list`. If aliases are empty, verify the macro definition with
`btool macros list`.

## Normalisation orientée CIM

```spl
`sysmon_process_creation`
| `cim_endpoint_processes_rename`
| head 1
| table dest user process process_name parent_process process_guid
```

Expected: the macro returns stable endpoint-oriented field names. The app ships
eventtypes, tags and a custom accelerated data model named
`Security_Telemetry_Qualification`. That model is explicitly non-CIM and does
not prove native CIM compliance. Native CIM validation still requires a
compatible `Splunk_SA_CIM` installation on the target search tier.

## Data model custom accéléré

```spl
| tstats summariesonly=t count latest(_time) as latest_event
  from datamodel=Security_Telemetry_Qualification.Security_Telemetry
```

Expected: a non-zero count after the data model acceleration summary is
complete. Compare it to the same time window over the root constraint before
accepting the model. See
[`custom-security-telemetry-data-model.md`](projects/custom-security-telemetry-data-model.md)
for the complete live gate and the explicit non-CIM boundary.

## Clock skew

```spl
index=sysmon earliest=-1h
| eval delta = round((_indextime - _time), 0)
| stats avg(delta) as avg_skew_seconds by host
```

Expected: `avg_skew_seconds` close to zero. Significantly negative means the host clock is ahead of the indexer; see [`docs/runbooks/troubleshooting-ingestion.md`](runbooks/troubleshooting-ingestion.md).

## Saved searches

```bash
sudo -u splunk /opt/splunk/bin/splunk list saved-search \
  -app splunk-detection-lab | grep "^name:" | wc -l
```

Expected: 18.
