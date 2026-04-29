# Windows Sysmon and Universal Forwarder Installation

## Goal

Install Sysmon and Splunk Universal Forwarder on the Windows telemetry source, then forward native Windows logs and Sysmon events to the Splunk server.

## Directory Convention

Use a simple working directory:

```text
C:\Tools\Sysmon
```

## Install Sysmon

Place the following files in `C:\Tools\Sysmon`:

- `Sysmon64.exe`
- your Sysmon configuration XML, for example `sysmonconfig.xml`

Then install Sysmon from an elevated PowerShell prompt:

```powershell
New-Item -ItemType Directory -Force -Path C:\Tools\Sysmon | Out-Null
cd C:\Tools\Sysmon
.\Sysmon64.exe -accepteula -i .\sysmonconfig.xml
```

## Validate Sysmon

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10 |
Select-Object TimeCreated, Id, ProviderName
```

You should see recent Sysmon events such as:

- Event ID 1 - Process creation
- Event ID 3 - Network connection
- Event ID 4 - Sysmon service state changed
- Event ID 11 - File creation

## Download and Install Universal Forwarder

Download the Windows x64 Universal Forwarder MSI, then install with PowerShell:

```powershell
$SplunkServer = "192.168.1.113:9997"
$UfAdminUser  = "admin"
$UfAdminPass  = "ChangeThisPasswordNow_123!"
$WorkDir      = "C:\Tools\Sysmon"
$MsiPath      = "$WorkDir\splunkforwarder-10.2.1-c892b66d163d-windows-x64.msi"
$LogFile      = "$WorkDir\splunk_uf_install.log"

Start-Process -FilePath "cmd.exe" `
    -ArgumentList "/D /c msiexec.exe /i `"$MsiPath`" RECEIVING_INDEXER=`"$SplunkServer`" SPLUNKUSERNAME=$UfAdminUser SPLUNKPASSWORD=$UfAdminPass AGREETOLICENSE=Yes /L*v `"$LogFile`" /quiet" `
    -Verb RunAs -Wait
```

## Universal Forwarder Config Paths

Default installation root:

```text
C:\Program Files\SplunkUniversalForwarder
```

Local configuration path:

```text
C:\Program Files\SplunkUniversalForwarder\etc\system\local
```

## Configure outputs.conf

Copy `conf/windows/outputs.conf` into the local directory or create it directly:

```powershell
$UfHome = "C:\Program Files\SplunkUniversalForwarder"
$OutDir = "$UfHome\etc\system\local"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

@'
[tcpout]
defaultGroup = default-autolb-group

[tcpout:default-autolb-group]
server = 192.168.1.113:9997

[tcpout-server://192.168.1.113:9997]
'@ | Set-Content -Path "$OutDir\outputs.conf" -Encoding ASCII -Force
```

## Configure inputs.conf

Copy `conf/windows/inputs.conf` into the local directory or create it directly:

```powershell
$UfHome = "C:\Program Files\SplunkUniversalForwarder"
$OutDir = "$UfHome\etc\system\local"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

@'
[default]
host = win10-sysmon-client

[WinEventLog://Application]
disabled = 0
index = windows
renderXml = true
start_from = oldest
current_only = 0

[WinEventLog://System]
disabled = 0
index = windows
renderXml = true
start_from = oldest
current_only = 0

[WinEventLog://Security]
disabled = 0
index = windows
renderXml = true
start_from = oldest
current_only = 0

[WinEventLog://Windows PowerShell]
disabled = 0
index = windows
renderXml = true
start_from = oldest
current_only = 0

[WinEventLog://Microsoft-Windows-PowerShell/Operational]
disabled = 0
index = windows
renderXml = true
start_from = oldest
current_only = 0

[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0
index = sysmon
renderXml = true
start_from = oldest
current_only = 0
'@ | Set-Content -Path "$OutDir\inputs.conf" -Encoding ASCII -Force
```

## Restart the Forwarder

```powershell
Restart-Service SplunkForwarder
Get-Service SplunkForwarder
```

## Validate Forwarding

```powershell
$UfHome = "C:\Program Files\SplunkUniversalForwarder"
& "$UfHome\bin\splunk.exe" list forward-server -auth admin:ChangeThisPasswordNow_123!
```

Expected result:

- the forward server is listed as **Active**
- the target is `192.168.1.113:9997`

## Troubleshooting Checks

### Confirm the service account and state

```powershell
Get-CimInstance Win32_Service -Filter "Name='SplunkForwarder'" |
Select-Object Name, StartName, State
```

### Confirm Sysmon data exists locally

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10 |
Select-Object TimeCreated, Id, ProviderName
```

### Confirm inputs are loaded

```powershell
$UfHome = "C:\Program Files\SplunkUniversalForwarder"
& "$UfHome\bin\splunk.exe" btool inputs list --debug -auth admin:ChangeThisPasswordNow_123!
```

### Review forwarder logs

```powershell
Get-Content "C:\Program Files\SplunkUniversalForwarder\var\log\splunk\splunkd.log" -Tail 200
```