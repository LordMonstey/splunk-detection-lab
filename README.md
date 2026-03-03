# Splunk Detection Lab

A defensive Splunk lab built to ingest Windows telemetry, normalize Sysmon events, and validate practical SPL detection use cases.

## Project Summary

This repository documents a complete single-host Splunk deployment on Debian with a Windows telemetry source using Sysmon and Splunk Universal Forwarder. The lab is designed for detection engineering, SOC validation, and interview portfolio demonstration.

The environment was validated end-to-end with successful ingestion of:

- Windows Security log
- Windows System log
- Windows Application log
- Windows PowerShell log
- Microsoft-Windows-PowerShell/Operational
- Microsoft-Windows-Sysmon/Operational

## Architecture

- **Splunk Server:** Debian 12, Splunk Enterprise / Splunk Free capable
- **Telemetry Source:** Windows VM
- **Windows Sensor Stack:** Sysmon + Splunk Universal Forwarder
- **Transport:** Splunk-to-Splunk forwarding over TCP 9997
- **Indexes:**
  - `windows`
  - `sysmon`

<img width="1489" height="869" alt="image" src="https://github.com/user-attachments/assets/e35f663b-e78a-451a-a5d6-a80219c61b67" />



## What This Project Demonstrates

- Splunk deployment and service configuration on Linux
- Windows telemetry onboarding with Universal Forwarder
- Sysmon deployment and validation
- Custom index design for telemetry separation
- SPL search development for process, network, and persistence use cases
- Practical troubleshooting of ingestion paths
- Clear documentation suitable for analyst, engineer, or detection validation roles

## Repository Layout

```text
splunk-detection-lab/
├─ README.md
├─ docs/
│  ├─ architecture.md
│  ├─ debian-splunk-install.md
│  ├─ windows-sysmon-uf-install.md
│  ├─ validation-checklist.md
│  └─ screenshots.md
├─ conf/
│  ├─ splunk/
│  │  └─ indexes.conf
│  └─ windows/
│     ├─ inputs.conf
│     └─ outputs.conf
├─ spl/
│  ├─ baseline_searches.spl
│  └─ detection_queries.spl
├─ scripts/
│  ├─ Initialize-LocalRepo.ps1
│  └─ Publish-GitHubRepo.ps1
└─ screenshots/
```

## Lab Build Highlights

### Debian Splunk Server
- Installed Splunk Enterprise on Debian 12
- Enabled systemd boot start
- Created dedicated indexes for `windows` and `sysmon`
- Enabled receiving on TCP 9997
- Exposed Splunk Web on TCP 8000

### Windows Telemetry Source
- Installed Sysmon with XML configuration
- Installed Splunk Universal Forwarder
- Configured WinEventLog stanzas for Windows and Sysmon channels
- Forwarded telemetry to the Splunk receiver at `192.168.1.113:9997`

## Validation

The following validation searches confirmed working ingestion:

```spl
index=windows OR index=sysmon
| stats count by index, sourcetype
```

```spl
index=sysmon
| stats count by sourcetype
```

Expected successful sourcetypes include:

- `XmlWinEventLog:Application`
- `XmlWinEventLog:System`
- `XmlWinEventLog:Security`
- `XmlWinEventLog:Windows PowerShell`
- `XmlWinEventLog:Microsoft-Windows-PowerShell/Operational`
- `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`

## Example Detection Searches

### Process Creation
```spl
index=sysmon EventCode=1
| table _time host Image CommandLine ParentImage User
| sort - _time
```

### Network Connections
```spl
index=sysmon EventCode=3
| table _time host Image SourceIp SourcePort DestinationIp DestinationPort Protocol
| sort - _time
```

### PowerShell Activity
```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-PowerShell/Operational"
| table _time host EventCode Message
| sort - _time
```

### Service Installation
```spl
index=windows EventCode=7045
| table _time host Service_Name ImagePath StartType Account_Name
| sort - _time
```

## Quick Start

### 1. Splunk Server
Follow the Debian installation guide in [`docs/debian-splunk-install.md`](docs/debian-splunk-install.md).

### 2. Windows Endpoint
Follow the Windows onboarding guide in [`docs/windows-sysmon-uf-install.md`](docs/windows-sysmon-uf-install.md).

### 3. Configure Files
- Splunk indexes: [`conf/splunk/indexes.conf`](conf/splunk/indexes.conf)
- Windows forwarder inputs: [`conf/windows/inputs.conf`](conf/windows/inputs.conf)
- Windows forwarder outputs: [`conf/windows/outputs.conf`](conf/windows/outputs.conf)

### 4. Validate Data
Run the checks in [`docs/validation-checklist.md`](docs/validation-checklist.md).

## Screenshots

Add your own screenshots under [`screenshots/`](screenshots/) and reference them here. Suggested captures:

- Splunk Search showing `index=windows OR index=sysmon | stats count by index, sourcetype`
- Splunk Search showing `index=sysmon | stats count by sourcetype`
- Sample `EventCode=1` process creation events
- Splunk Web search dashboard overview

See [`docs/screenshots.md`](docs/screenshots.md) for naming suggestions.

## Recommended Portfolio Positioning

This project is a strong fit for roles involving:

- SOC Analyst
- Detection Engineer
- Security Analyst
- Threat Detection / Content Engineering
- SIEM Engineering
- Blue Team lab validation

In interviews, this repo supports discussion around:

- data onboarding
- telemetry quality
- event source coverage
- SPL logic
- troubleshooting methodology
- defensive lab design

## Tools Used

- Splunk Enterprise / Splunk Free
- Splunk Universal Forwarder
- Sysmon
- PowerShell
- Debian 12
- Git
- GitHub CLI

## Notes

- This lab was built for defensive telemetry ingestion and detection validation.
- Splunk Free mode can be enabled for a permanent single-instance lab with daily ingest limits.
- lab local IPs & passwords ar dummy for the lab ofc do not take that as an exemple.


