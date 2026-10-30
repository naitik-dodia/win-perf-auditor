<#
.SYNOPSIS
    Restores Windows 10/11 services to their exact original StartupType and running state from backup JSON snapshots.

.DESCRIPTION
    By default, loads all `services_backup_*.json` snapshots in `..\backups\` chronologically (oldest-first)
    so the earliest true pre-change state for every modified service is restored across single or multiple runs.
    You can also pass `-BackupFile` to restore from one specific snapshot.

.EXAMPLE
    # Preview rollback without modifying the system:
    powershell -ExecutionPolicy Bypass -File .\scripts\restore-services.ps1 -DryRun

    # Perform rollback (Run PowerShell as Administrator):
    powershell -ExecutionPolicy Bypass -File .\scripts\restore-services.ps1
#>
[CmdletBinding()]
param(
    [string]$BackupFile,
    [string]$BackupDirectory = "",
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'

$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }
$repoRoot  = Split-Path -Parent $scriptDir
if ([string]::IsNullOrWhiteSpace($BackupDirectory)) {
    $BackupDirectory = Join-Path $repoRoot "backups"
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not $DryRun -and -not (Test-IsAdministrator)) {
    Write-Host "[ERROR] Administrator privileges are required to restore Windows services." -ForegroundColor Red
    Write-Host "        Right-click PowerShell -> 'Run as administrator', or pass -DryRun to preview rollback." -ForegroundColor Yellow
    exit 1
}

$servicesToRestore = @{}

if (-not [string]::IsNullOrWhiteSpace($BackupFile)) {
    if (-not (Test-Path -LiteralPath $BackupFile)) {
        Write-Host "[ERROR] Backup file does not exist: $BackupFile" -ForegroundColor Red
        exit 1
    }
    $filesToLoad = @(Get-Item -LiteralPath $BackupFile)
} else {
    if (-not (Test-Path -LiteralPath $BackupDirectory)) {
        Write-Host "[ERROR] Backup directory not found: $BackupDirectory" -ForegroundColor Red
        exit 1
    }
    $filesToLoad = @(Get-ChildItem -LiteralPath $BackupDirectory -Filter "services_backup_*.json" |
                     Sort-Object LastWriteTime)
    if ($filesToLoad.Count -eq 0) {
        Write-Host "[ERROR] No services_backup_*.json files found in $BackupDirectory" -ForegroundColor Red
        exit 1
    }
}

foreach ($f in $filesToLoad) {
    Write-Host "Loading service backup snapshot: $($f.FullName)" -ForegroundColor Cyan
    $rawJson = [System.IO.File]::ReadAllText($f.FullName, [System.Text.Encoding]::UTF8)
    $snapshot = $rawJson | ConvertFrom-Json
    foreach ($rec in $snapshot.Services) {
        $key = $rec.Name.ToLowerInvariant()
        if (-not $servicesToRestore.ContainsKey($key)) {
            $servicesToRestore[$key] = $rec
        }
    }
}

foreach ($rec in $servicesToRestore.Values) {
    $name = $rec.Name
    $origMode = $rec.OriginalStartMode
    $origDelayed = [bool]$rec.OriginalDelayedAutoStart
    $origState = $rec.OriginalState

    $psStartupType = switch ($origMode) {
        'Auto'     { 'Automatic' }
        'Manual'   { 'Manual' }
        'Disabled' { 'Disabled' }
        default    { 'Manual' }
    }

    if ($DryRun) {
        Write-Host "[DRY-RUN] Restore $name -> StartupType=$psStartupType (Delayed=$origDelayed), OriginalState=$origState" -ForegroundColor Yellow
        continue
    }

    try {
        if ($origMode -eq 'Auto' -and $origDelayed) {
            & sc.exe config "$name" start= delayed-auto | Out-Null
        } else {
            Set-Service -Name $name -StartupType $psStartupType -ErrorAction Stop
        }

        if ($origState -eq 'Running' -and $psStartupType -ne 'Disabled') {
            Start-Service -Name $name -ErrorAction SilentlyContinue
        }
        Write-Host "[RESTORED] $name -> $psStartupType (State target: $origState)" -ForegroundColor Green
    } catch {
        Write-Host "[WARN] Could not restore '$name': $($_.Exception.Message)" -ForegroundColor DarkYellow
    }
}

Write-Host "Rollback operation completed." -ForegroundColor Cyan
