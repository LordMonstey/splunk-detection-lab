param(
    [string]$RepoName = "splunk-detection-lab",
    [string]$Description = "Defensive Splunk lab for Windows telemetry ingestion, Sysmon onboarding, and SPL detection validation.",
    [ValidateSet("public","private")]
    [string]$Visibility = "public",
    [string]$Branch = "main",
    [string]$Owner
)

$ErrorActionPreference = "Stop"

function Test-Command {
    param([Parameter(Mandatory)][string]$Name)
    return $null -ne (Get-Command $Name -ErrorAction SilentlyContinue)
}

if (-not (Test-Command -Name "git")) {
    throw "git is not installed or not present in PATH."
}

if (-not (Test-Command -Name "gh")) {
    throw "GitHub CLI (gh) is not installed or not present in PATH."
}

gh auth status | Out-Null

if (-not $Owner) {
    $Owner = gh api user --jq ".login"
}

$FullRepoName = "$Owner/$RepoName"

if (-not (Test-Path ".git")) {
    git init -b $Branch | Out-Null
}

$currentBranch = git branch --show-current
if (-not $currentBranch) {
    git checkout -b $Branch | Out-Null
} elseif ($currentBranch -ne $Branch) {
    git checkout -B $Branch | Out-Null
}

git add .

git diff --cached --quiet
if ($LASTEXITCODE -ne 0) {
    git commit -m "Initial commit - Splunk Detection Lab" | Out-Host
} else {
    Write-Host "No staged changes to commit."
}

$remoteExists = $false
git remote get-url origin *> $null
if ($LASTEXITCODE -eq 0) {
    $remoteExists = $true
}

$repoExists = $false
gh repo view $FullRepoName *> $null
if ($LASTEXITCODE -eq 0) {
    $repoExists = $true
}

if (-not $repoExists) {
    gh repo create $FullRepoName --$Visibility --source . --remote origin --push --description $Description | Out-Host
} else {
    if (-not $remoteExists) {
        git remote add origin "https://github.com/$FullRepoName.git"
    }

    git push -u origin $Branch | Out-Host
}

Write-Host "Repository published successfully: https://github.com/$FullRepoName"
