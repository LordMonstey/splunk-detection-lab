# Architecture

## Overview

This lab uses a simple two-node design:

- **Debian 12 VM** hosting Splunk Enterprise
- **Windows VM** hosting Sysmon and Splunk Universal Forwarder

The design separates telemetry collection from indexing and search, while remaining light enough for a laptop lab or interview demo.

## Data Flow

```text
Sysmon + Windows Event Logs
        |
        v
Splunk Universal Forwarder
        |
        | TCP 9997
        v
Splunk Enterprise on Debian
        |
        +--> index=windows
        +--> index=sysmon
```

## Splunk Server Responsibilities

The Debian server is responsible for:

- running Splunk Enterprise
- providing Splunk Web on port 8000
- exposing the management interface on port 8089
- receiving forwarded data on port 9997
- storing Windows and Sysmon data in dedicated indexes

## Windows Endpoint Responsibilities

The Windows endpoint is responsible for:

- generating host telemetry
- collecting detailed process and host activity through Sysmon
- forwarding Windows Event Log channels to Splunk
- providing realistic event sources for SPL validation

## Ports

| Port | Purpose |
|---|---|
| 8000 | Splunk Web |
| 8089 | Splunk management |
| 9997 | Splunk receiver for forwarded data |

## Index Strategy

Two custom indexes are used:

- `windows` for native Windows Event Logs
- `sysmon` for Sysmon Operational events

This split keeps searches cleaner and makes detection content easier to organize.

## Why This Architecture Works Well for a Portfolio

- Simple enough to rebuild quickly
- Clear telemetry path
- Easy to explain in an interview
- Demonstrates both infrastructure and detection thinking
- Supports future expansion such as TA installation, dashboards, and saved searches
