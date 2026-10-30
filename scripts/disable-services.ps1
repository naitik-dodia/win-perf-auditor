<#
.SYNOPSIS
    Generic, CSV-repository-driven Windows 10/11 background service optimizer.

.DESCRIPTION
    Reads community-curated service rules from the CSV repositories in ..\data\:
      - core_protected_services.csv   (Hard safety blocklist -- never modified)
      - tier1_safe_to_disable.csv     (Applied by default: Stop + StartupType = Disabled)
      - tier3_set_to_manual.csv       (Applied by default: Automatic -> Manual, unless -SkipManualOptimization)
      - tier2_conditional_disable.csv (Opt-in ONLY via -IncludeConditional for human review/intervention)

    Safety mechanisms:
      - Automatic pre-change JSON backup in ..\backups\services_backup_<timestamp>.json
      - Optional Windows System Restore Point creation
      - Reverse-dependency check (refuses to disable a service required by an active protected service)
      - Topological stop ordering (stops dependent services before parent services)
      - -DryRun mode to preview every planned change without Administrator privileges

.EXAMPLE
    # Preview default optimizations (Tier 1 Safe-to-Disable + Tier 3 Auto -> Manual):
    powershell -ExecutionPolicy Bypass -File .\scripts\disable-services.ps1 -DryRun

    # Preview default + Tier 2 Conditional services:
    powershell -ExecutionPolicy Bypass -File .\scripts\disable-services.ps1 -DryRun -IncludeConditional

    # Apply default optimizations (Run PowerShell as Administrator):
    powershell -ExecutionPolicy Bypass -File .\scripts\disable-services.ps1

    # Apply default + Tier 2 Conditional, while excluding specific services or selecting feature groups:
    powershell -ExecutionPolicy Bypass -File .\scripts\disable-services.ps1 -IncludeConditional -ExcludeServices WSearch,Spooler
#>
[CmdletBinding()]
param(
    [switch]$DryRun,
    [switch]$IncludeConditional,
    [string[]]$OnlyFeatureGroups = @(),
    [string[]]$ExcludeFeatureGroups = @(),
    [string[]]$ExcludeServices = @(),
    [switch]$SkipManualOptimization,
    [switch]$SkipRestorePoint,
    [string]$DataDirectory = "",
    [string]$BackupDirectory = ""
)

$ErrorActionPreference = 'Stop'

$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }
$repoRoot  = Split-Path -Parent $scriptDir
if ([string]::IsNullOrWhiteSpace($DataDirectory)) {
    $DataDirectory = Join-Path $repoRoot "data"
}
if ([string]::IsNullOrWhiteSpace($BackupDirectory)) {
    $BackupDirectory = Join-Path $repoRoot "backups"
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-IsPerUserServiceInstance {
    param($CimService)
    if ($CimService.Name -match '^(.+?)_([0-9a-fA-F]{4,16})$') {
        $hex = $Matches[2]
        if ($CimService.DisplayName -match "_$hex$") {
            return $true
        }
    }
    return $false
}

function Test-RuleMatch {
    param(
        [string]$ServiceName,
        [string]$RulePattern,
        [string]$MatchType
    )
    if ($MatchType -eq 'wildcard') {
        return ($ServiceName -like $RulePattern)
    }
    return ($ServiceName -ieq $RulePattern)
}

# Validate required CSV repository files exist
$protectedCsv = Join-Path $DataDirectory "core_protected_services.csv"
$tier1Csv     = Join-Path $DataDirectory "tier1_safe_to_disable.csv"
$tier2Csv     = Join-Path $DataDirectory "tier2_conditional_disable.csv"
$tier3Csv     = Join-Path $DataDirectory "tier3_set_to_manual.csv"

foreach ($reqFile in @($protectedCsv, $tier1Csv, $tier2Csv, $tier3Csv)) {
    if (-not (Test-Path -LiteralPath $reqFile)) {
        Write-Host "[ERROR] Missing CSV repository file: $reqFile" -ForegroundColor Red
        exit 1
    }
}

$isAdmin = Test-IsAdministrator
if (-not $DryRun -and -not $isAdmin) {
    Write-Host "[ERROR] Administrator privileges are required to modify Windows services." -ForegroundColor Red
    Write-Host "        Right-click PowerShell -> 'Run as administrator', or pass -DryRun to preview changes." -ForegroundColor Yellow
    exit 1
}

Write-Host "=========================================================================" -ForegroundColor Cyan
if ($DryRun) {
    Write-Host " Windows Service Optimizer -- DRY RUN PREVIEW (No changes will be made)" -ForegroundColor Yellow
} else {
    Write-Host " Windows Service Optimizer -- LIVE EXECUTION" -ForegroundColor Green
}
Write-Host " Repository Path: $DataDirectory" -ForegroundColor DarkCyan
Write-Host "=========================================================================" -ForegroundColor Cyan

# Load CSV repositories
$protectedRows = @(Import-Csv -LiteralPath $protectedCsv)
$protectedSet = @{}
foreach ($r in $protectedRows) {
    if ($r.service_name) {
        $protectedSet[$r.service_name.Trim().ToLowerInvariant()] = $true
    }
}

$excludeSvcSet = @{}
foreach ($rawEx in $ExcludeServices) {
    foreach ($ex in ($rawEx -split ',')) {
        if (-not [string]::IsNullOrWhiteSpace($ex)) {
            $excludeSvcSet[$ex.Trim().ToLowerInvariant()] = $true
        }
    }
}

$onlyGroupsLower = @($OnlyFeatureGroups | ForEach-Object { $_ -split ',' } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_.Trim().ToLowerInvariant() })
$excludeGroupsLower = @($ExcludeFeatureGroups | ForEach-Object { $_ -split ',' } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_.Trim().ToLowerInvariant() })

$tier1Rules = @(Import-Csv -LiteralPath $tier1Csv)
$tier2Rules = @(Import-Csv -LiteralPath $tier2Csv)
$tier3Rules = @(Import-Csv -LiteralPath $tier3Csv)

# Query installed services on this machine
$allCimServices = @(Get-CimInstance Win32_Service)
$scMap = @{}
foreach ($s in (Get-Service -ErrorAction SilentlyContinue)) {
    $scMap[$s.Name.ToLowerInvariant()] = $s
}

# Match installed services against CSV rules
$rawCandidates = @{}

foreach ($svc in $allCimServices) {
    $sname = $svc.Name
    $skey = $sname.ToLowerInvariant()

    if (Test-IsPerUserServiceInstance -CimService $svc) { continue }
    if ($excludeSvcSet.ContainsKey($skey)) {
        Write-Host "[EXCLUDED] Skipping user-excluded service: $sname" -ForegroundColor DarkGray
        continue
    }
    if ($protectedSet.ContainsKey($skey)) { continue }

    # 1. Check Tier 1
    $matchedT1 = $null
    foreach ($r in $tier1Rules) {
        $mt = if ($r.match_type) { $r.match_type.Trim().ToLowerInvariant() } else { 'exact' }
        if (Test-RuleMatch -ServiceName $sname -RulePattern $r.service_name.Trim() -MatchType $mt) {
            $matchedT1 = $r
            break
        }
    }
    if ($matchedT1) {
        if ($svc.StartMode -eq 'Disabled' -and $svc.State -ne 'Running') { continue }
        $rawCandidates[$skey] = @{
            CimService      = $svc
            TargetStartMode = 'Disabled'
            StopRunning     = $true
            Tier            = 'Tier1-SafeDisable'
            Note            = $matchedT1.rationale
        }
        continue
    }

    # 2. Check Tier 2 (only if -IncludeConditional)
    if ($IncludeConditional) {
        $matchedT2 = $null
        foreach ($r in $tier2Rules) {
            $mt = if ($r.match_type) { $r.match_type.Trim().ToLowerInvariant() } else { 'exact' }
            if (Test-RuleMatch -ServiceName $sname -RulePattern $r.service_name.Trim() -MatchType $mt) {
                $matchedT2 = $r
                break
            }
        }
        if ($matchedT2) {
            $fg = if ($matchedT2.feature_group) { $matchedT2.feature_group.Trim() } else { 'General' }
            $fgLow = $fg.ToLowerInvariant()
            if ($onlyGroupsLower.Count -gt 0 -and ($onlyGroupsLower -notcontains $fgLow)) { continue }
            if ($excludeGroupsLower -contains $fgLow) { continue }
            if ($svc.StartMode -eq 'Disabled' -and $svc.State -ne 'Running') { continue }

            $rawCandidates[$skey] = @{
                CimService      = $svc
                TargetStartMode = 'Disabled'
                StopRunning     = $true
                Tier            = "Tier2-Conditional[$fg]"
                Note            = $matchedT2.disable_condition
            }
            continue
        }
    }

    # 3. Check Tier 3 (unless -SkipManualOptimization)
    if (-not $SkipManualOptimization) {
        $matchedT3 = $null
        foreach ($r in $tier3Rules) {
            $mt = if ($r.match_type) { $r.match_type.Trim().ToLowerInvariant() } else { 'exact' }
            if (Test-RuleMatch -ServiceName $sname -RulePattern $r.service_name.Trim() -MatchType $mt) {
                $matchedT3 = $r
                break
            }
        }
        if ($matchedT3) {
            # Only change services currently configured as Auto
            if ($svc.StartMode -ne 'Auto') { continue }
            $rawCandidates[$skey] = @{
                CimService      = $svc
                TargetStartMode = 'Manual'
                StopRunning     = $false
                Tier            = 'Tier3-SetManual'
                Note            = $matchedT3.rationale
            }
            continue
        }
    }
}

# Reverse-dependency safety guard & topological stop ordering
$safeCandidates = @{}
foreach ($skey in $rawCandidates.Keys) {
    $cand = $rawCandidates[$skey]
    $svcName = $cand.CimService.Name

    if ($cand.TargetStartMode -eq 'Disabled' -and $scMap.ContainsKey($skey)) {
        $blockingDeps = @()
        try {
            foreach ($dep in $scMap[$skey].DependentServices) {
                $depKey = $dep.Name.ToLowerInvariant()
                if ($dep.Status -eq 'Running') {
                    if ($protectedSet.ContainsKey($depKey) -or (-not $rawCandidates.ContainsKey($depKey)) -or ($rawCandidates[$depKey].TargetStartMode -ne 'Disabled')) {
                        $blockingDeps += $dep.Name
                    }
                }
            }
        } catch {}

        if ($blockingDeps.Count -gt 0) {
            Write-Host "[SAFETY GUARD] Skipping '$svcName' -- active dependent service(s) require it: $($blockingDeps -join ', ')" -ForegroundColor DarkYellow
            continue
        }
    }
    $safeCandidates[$skey] = $cand
}

# Topological sort so dependent services stop before the services they depend on
$visited = @{}
$validPlan = New-Object System.Collections.Generic.List[object]

function Add-TopologicalCandidate {
    param([string]$Key)
    if ($visited.ContainsKey($Key)) { return }
    $visited[$Key] = $true
    if ($scMap.ContainsKey($Key)) {
        try {
            foreach ($dep in $scMap[$Key].DependentServices) {
                $depKey = $dep.Name.ToLowerInvariant()
                if ($safeCandidates.ContainsKey($depKey)) {
                    Add-TopologicalCandidate -Key $depKey
                }
            }
        } catch {}
    }
    $validPlan.Add($safeCandidates[$Key])
}

foreach ($k in ($safeCandidates.Keys | Sort-Object)) {
    Add-TopologicalCandidate -Key $k
}

if ($validPlan.Count -eq 0) {
    Write-Host "No installed services require optimization under the selected flags." -ForegroundColor Green
    exit 0
}

# Build backup snapshot records
$backupRecords = New-Object System.Collections.Generic.List[object]
foreach ($entry in $validPlan) {
    $c = $entry.CimService
    $backupRecords.Add(@{
        Name                     = $c.Name
        DisplayName              = $c.DisplayName
        OriginalStartMode        = $c.StartMode
        OriginalDelayedAutoStart = [bool]$c.DelayedAutoStart
        OriginalState            = $c.State
        TargetStartMode          = $entry.TargetStartMode
        Tier                     = $entry.Tier
    })
}

if (-not $DryRun) {
    if (-not (Test-Path -LiteralPath $BackupDirectory)) {
        New-Item -ItemType Directory -Path $BackupDirectory -Force | Out-Null
    }
    $ts = Get-Date -Format "yyyyMMdd_HHmmss"
    $backupPath = Join-Path $BackupDirectory "services_backup_$ts.json"
    $backupPayload = @{
        CreatedAt = (Get-Date).ToString("o")
        Computer  = $env:COMPUTERNAME
        Services  = $backupRecords
    } | ConvertTo-Json -Depth 6
    [System.IO.File]::WriteAllText($backupPath, $backupPayload, (New-Object System.Text.UTF8Encoding($false)))
    Write-Host "[BACKUP] Saved pre-change service snapshot to: $backupPath" -ForegroundColor Cyan

    if (-not $SkipRestorePoint) {
        try {
            Checkpoint-Computer -Description "Before win-perf-auditor Service Optimization" -RestorePointType "MODIFY_SETTINGS" -ErrorAction Stop | Out-Null
            Write-Host "[RESTORE POINT] Created Windows System Restore Point." -ForegroundColor Cyan
        } catch {
            Write-Host "[INFO] Skipped System Restore Point (System Protection disabled or 24h cooldown active): $($_.Exception.Message)" -ForegroundColor DarkYellow
        }
    }
}

Write-Host ""
$changedCount = 0
$protectedFailCount = 0

foreach ($entry in $validPlan) {
    $c = $entry.CimService
    $name = $c.Name
    $disp = $c.DisplayName
    $curState = $c.State
    $curStart = $c.StartMode
    $targetStart = $entry.TargetStartMode
    $tier = $entry.Tier

    if ($DryRun) {
        $stopMsg = if ($entry.StopRunning -and $curState -eq 'Running') { "Stop + " } else { "" }
        Write-Host "[DRY-RUN][$tier] $name ($disp): $curState/$curStart -> $($stopMsg)StartupType=$targetStart" -ForegroundColor Yellow
        $changedCount++
        continue
    }

    try {
        if ($entry.StopRunning -and $curState -eq 'Running') {
            Write-Host "[STOPPING] $name ($disp)..." -ForegroundColor Cyan
            Stop-Service -Name $name -Force -ErrorAction Stop
        }
        Write-Host "[CONFIG]   $name -> StartupType = $targetStart" -ForegroundColor Green
        Set-Service -Name $name -StartupType $targetStart -ErrorAction Stop
        $changedCount++
    } catch {
        $protectedFailCount++
        Write-Host "[PROTECTED / ACCESS DENIED] Could not modify '$name' ($disp): $($_.Exception.Message)" -ForegroundColor DarkYellow
        Write-Host "   -> Note: Third-party security/antivirus services often enforce kernel tamper-protection and must be removed via Windows Installed Apps." -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "=========================================================================" -ForegroundColor Cyan
if ($DryRun) {
    Write-Host " Dry-run complete: $changedCount installed service(s) would be optimized." -ForegroundColor Yellow
} else {
    Write-Host " Optimization complete: $changedCount service(s) updated, $protectedFailCount protected/skipped." -ForegroundColor Green
    Write-Host " To roll back changes at any time, run: .\scripts\restore-services.ps1" -ForegroundColor Cyan
}
Write-Host "=========================================================================" -ForegroundColor Cyan
