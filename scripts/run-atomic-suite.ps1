[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet(
        "T1003.001","T1027","T1053.005","T1059.001","T1059.003","T1105",
        "T1110.001","T1112","T1136.001","T1140","T1218.005","T1218.010","T1218.011",
        "T1222.001","T1546.012","T1547.001","T1547.004","T1562.001"
    )]
    [string]$Technique,

    [int[]]$TestNumbers,

    [switch]$GetPrereqs,
    [switch]$Cleanup,
    [switch]$Show
)

$ErrorActionPreference = 'Stop'
$arPath = "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1"
if (-not (Test-Path $arPath)) {
    Write-Host "Atomic Red Team not found at $arPath" -ForegroundColor Red
    Write-Host "Install with scripts/install-atomic-redteam.ps1 first." -ForegroundColor Yellow
    exit 1
}
Import-Module $arPath -Force

if ($Show) {
    if ($TestNumbers) {
        Invoke-AtomicTest $Technique -TestNumbers $TestNumbers -ShowDetails
    } else {
        Invoke-AtomicTest $Technique -ShowDetailsBrief
    }
    return
}

$args = @{ AtomicTechnique = $Technique }
if ($TestNumbers) { $args.TestNumbers = $TestNumbers }

if ($GetPrereqs) {
    Write-Host "==> GetPrereqs $Technique" -ForegroundColor Cyan
    Invoke-AtomicTest @args -GetPrereqs
    return
}

if ($Cleanup) {
    Write-Host "==> Cleanup $Technique" -ForegroundColor Yellow
    Invoke-AtomicTest @args -Cleanup
    return
}

$startTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
Write-Host "==> Run $Technique at $startTime" -ForegroundColor Cyan
Invoke-AtomicTest @args
$endTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
Write-Host ""
Write-Host "Started: $startTime" -ForegroundColor Green
Write-Host "Ended:   $endTime" -ForegroundColor Green
Write-Host ""
Write-Host "Now in Splunk Web, search the matching detection's SPL with this time window." -ForegroundColor Yellow
Write-Host "Then run with -Cleanup to remove artifacts." -ForegroundColor Yellow