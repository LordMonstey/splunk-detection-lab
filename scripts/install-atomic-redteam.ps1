[CmdletBinding()]
param(
    [string]$InstallPath = "C:\AtomicRedTeam",
    [switch]$AddDefenderExclusion
)

$ErrorActionPreference = 'Stop'

function Step($m){ Write-Host "==> $m" -ForegroundColor Cyan }
function Ok($m)  { Write-Host "    [ok] $m" -ForegroundColor Green }
function Warn($m){ Write-Host "    [!!] $m" -ForegroundColor Yellow }
function Die($m) { Write-Host "    [xx] $m" -ForegroundColor Red; exit 1 }

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Die "Run this script as Administrator."
}

Step "Set TLS 1.2 for the session"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Ok "TLS 1.2 enabled"

if ($AddDefenderExclusion) {
    Step "Add Defender exclusion for $InstallPath (lab use only)"
    Add-MpPreference -ExclusionPath $InstallPath -ErrorAction SilentlyContinue
    Ok "Exclusion added — REMOVE THIS BEFORE EXPOSING THE HOST"
}

Step "Install Invoke-AtomicRedTeam from Red Canary"
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -InstallPath $InstallPath -getAtomics -Force
Ok "Atomic Red Team installed at $InstallPath"

Step "Set up persistent module path"
$profilePath = $PROFILE.CurrentUserAllHosts
if (-not (Test-Path $profilePath)) {
    New-Item -ItemType File -Path $profilePath -Force | Out-Null
}
$line = "Import-Module `"$InstallPath\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1`" -Force"
$existing = Get-Content $profilePath -ErrorAction SilentlyContinue
if ($existing -notcontains $line) {
    Add-Content -Path $profilePath -Value $line
    Ok "Profile updated at $profilePath"
} else {
    Ok "Profile already configured"
}

Step "Validate"
Import-Module "$InstallPath\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
Get-Command Invoke-AtomicTest | Format-List Name, ModuleName, Version

Write-Host ""
Write-Host "Atomic Red Team is ready." -ForegroundColor Green
Write-Host "Try: Invoke-AtomicTest T1218.011 -ShowDetailsBrief"
