param(
    [string]$Branch = "main"
)

$ErrorActionPreference = "Stop"

function Test-Command {
    param([Parameter(Mandatory)][string]$Name)
    return $null -ne (Get-Command $Name -ErrorAction SilentlyContinue)
}

if (-not (Test-Command -Name "git")) {
    throw "git is not installed or not present in PATH."
}

if (-not (Test-Path ".git")) {
    git init -b $Branch | Out-Null
}

git config core.autocrlf true
git config pull.rebase false

git add .

$hasChanges = $false
git diff --cached --quiet
if ($LASTEXITCODE -ne 0) {
    $hasChanges = $true
}

if ($hasChanges) {
    git commit -m "Initial commit - Splunk Detection Lab" | Out-Host
} else {
    Write-Host "No staged changes to commit."
}

Write-Host "Local repository initialized successfully."
