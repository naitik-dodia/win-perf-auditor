param(
    [Parameter(Mandatory = $true)]
    [string]$OutputPath,

    [int]$CounterSamples = 3
)

$ErrorActionPreference = 'SilentlyContinue'

function Get-ExecutableFromPathName {
    param([string]$PathName)
    if ([string]::IsNullOrWhiteSpace($PathName)) { return $null }
    $trimmed = $PathName.Trim()
    if ($trimmed.StartsWith('"')) {
        $endQuote = $trimmed.IndexOf('"', 1)
        if ($endQuote -gt 1) {
            return [Environment]::ExpandEnvironmentVariables($trimmed.Substring(1, $endQuote - 1))
        }
    }
    # Unquoted path: match up to .exe
    if ($trimmed -match '^([a-zA-Z]:\\[^"]*?\.exe)\b') {
        return [Environment]::ExpandEnvironmentVariables($Matches[1])
    }
    $firstToken = ($trimmed -split '\s+')[0]
    return [Environment]::ExpandEnvironmentVariables($firstToken)
}

# 1. System, OS, CPU, Battery, Disks
$os = Get-CimInstance Win32_OperatingSystem
$cs = Get-CimInstance Win32_ComputerSystem
$cpus = @(Get-CimInstance Win32_Processor)
$batteries = @(Get-CimInstance Win32_Battery)
$disks = @(Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3")

$uptimeSec = 0
$lastBootIso = $null
if ($os -and $os.LastBootUpTime) {
    $uptimeSec = [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalSeconds, 1)
    $lastBootIso = $os.LastBootUpTime.ToString("o")
}

$systemInfo = @{
    Manufacturer          = $cs.Manufacturer
    Model                 = $cs.Model
    OSCaption             = $os.Caption
    OSVersion             = $os.Version
    OSBuild               = $os.BuildNumber
    LastBootUpTime        = $lastBootIso
    UptimeSeconds         = $uptimeSec
    TotalVisibleMemoryKB  = [int64]$os.TotalVisibleMemorySize
    FreePhysicalMemoryKB  = [int64]$os.FreePhysicalMemory
    TotalVirtualMemoryKB  = [int64]$os.TotalVirtualMemorySize
    FreeVirtualMemoryKB   = [int64]$os.FreeVirtualMemory
    Processors            = @($cpus | ForEach-Object {
        @{
            Name                      = $_.Name
            NumberOfCores             = $_.NumberOfCores
            NumberOfLogicalProcessors = $_.NumberOfLogicalProcessors
            MaxClockSpeedMHz          = $_.MaxClockSpeed
            CurrentClockSpeedMHz      = $_.CurrentClockSpeed
            LoadPercentage            = $_.LoadPercentage
        }
    })
    Batteries             = @($batteries | ForEach-Object {
        @{
            Name                     = $_.Name
            BatteryStatus            = $_.BatteryStatus
            EstimatedChargeRemaining = $_.EstimatedChargeRemaining
        }
    })
    Disks                 = @($disks | ForEach-Object {
        @{
            DeviceID   = $_.DeviceID
            VolumeName = $_.VolumeName
            SizeBytes  = [int64]$_.Size
            FreeBytes  = [int64]$_.FreeSpace
        }
    })
}

# 2. Power Plan & Processor Throttle Configuration
$activeSchemeRaw = (powercfg /getactivescheme 2>$null) -join " "
$procMaxOut = (powercfg /q SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMAX 2>$null) -join "`n"
$procMinOut = (powercfg /q SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMIN 2>$null) -join "`n"
$boostOut   = (powercfg /q SCHEME_CURRENT SUB_PROCESSOR PERFBOOSTMODE 2>$null) -join "`n"

function Parse-PowerCfgAcDc {
    param([string]$Text)
    $ac = $null
    $dc = $null
    if ($Text -match 'Current AC Power Setting Index:\s*0x([0-9a-fA-F]+)') {
        $ac = [Convert]::ToInt32($Matches[1], 16)
    }
    if ($Text -match 'Current DC Power Setting Index:\s*0x([0-9a-fA-F]+)') {
        $dc = [Convert]::ToInt32($Matches[1], 16)
    }
    return @{ AC = $ac; DC = $dc }
}

# Check Windows 11 Power Mode overlay in Registry
$powerOverlayAc = $null
$powerOverlayDc = $null
try {
    $powerReg = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes" -ErrorAction SilentlyContinue
    if ($powerReg) {
        $activeOverlayAc = $powerReg.ActiveOverlayAcPowerScheme
        $activeOverlayDc = $powerReg.ActiveOverlayDcPowerScheme
        $powerOverlayAc = $activeOverlayAc
        $powerOverlayDc = $activeOverlayDc
    }
} catch {}

$powerInfo = @{
    ActiveScheme      = $activeSchemeRaw
    ProcThrottleMax   = Parse-PowerCfgAcDc -Text $procMaxOut
    ProcThrottleMin   = Parse-PowerCfgAcDc -Text $procMinOut
    PerfBoostMode     = Parse-PowerCfgAcDc -Text $boostOut
    OverlayAcGuid     = $powerOverlayAc
    OverlayDcGuid     = $powerOverlayDc
}

# 3. Windows Performance Counters
$counterPaths = @(
    '\Processor Information(_Total)\% Processor Performance',
    '\Processor Information(_Total)\% Processor Utility',
    '\Processor(_Total)\% Processor Time',
    '\Processor(_Total)\% Privileged Time',
    '\Processor(_Total)\% DPC Time',
    '\Processor(_Total)\% Interrupt Time',
    '\Memory\Pages/sec',
    '\Memory\Page Reads/sec',
    '\Memory\Committed Bytes',
    '\Memory\Commit Limit',
    '\PhysicalDisk(_Total)\% Idle Time',
    '\PhysicalDisk(_Total)\Current Disk Queue Length',
    '\PhysicalDisk(_Total)\Avg. Disk sec/Read',
    '\PhysicalDisk(_Total)\Avg. Disk sec/Write'
)

$counterSummary = @{}
try {
    $samples = Get-Counter -Counter $counterPaths -SampleInterval 1 -MaxSamples $CounterSamples -ErrorAction SilentlyContinue
    $grouped = @{}
    foreach ($sampleSet in $samples) {
        foreach ($csItem in $sampleSet.CounterSamples) {
            $p = $csItem.Path
            # Strip \\COMPUTERNAME prefix
            if ($p -match '^\\\\[^\\]+(\\.*)$') {
                $p = $Matches[1]
            }
            if (-not $grouped.ContainsKey($p)) {
                $grouped[$p] = New-Object System.Collections.Generic.List[double]
            }
            $grouped[$p].Add([double]$csItem.CookedValue)
        }
    }
    foreach ($k in $grouped.Keys) {
        $vals = $grouped[$k]
        if ($vals.Count -gt 0) {
            $avg = ($vals | Measure-Object -Average).Average
            $max = ($vals | Measure-Object -Maximum).Maximum
            $min = ($vals | Measure-Object -Minimum).Minimum
            $counterSummary[$k] = @{
                Avg     = [math]::Round($avg, 4)
                Max     = [math]::Round($max, 4)
                Min     = [math]::Round($min, 4)
                Samples = $vals.Count
            }
        }
    }
} catch {}

# 4. Recent Event Log Signals (Last 48 hours)
$since = (Get-Date).AddHours(-48)
$eventSignals = @{
    ProcessorThrottleEvents = @()
    MemoryExhaustionEvents  = @()
    DiskWarningEvents       = @()
    AppHangCrashCount48h    = 0
    TopCrashingApps         = @()
}

try {
    $throttleEvts = @(Get-WinEvent -FilterHashtable @{
        LogName      = 'System'
        ProviderName = 'Microsoft-Windows-Kernel-Processor-Power'
        Id           = 37
        StartTime    = $since
    } -MaxEvents 20 -ErrorAction SilentlyContinue)
    $eventSignals.ProcessorThrottleEvents = @($throttleEvts | ForEach-Object {
        @{
            TimeCreated = $_.TimeCreated.ToString("o")
            Id          = $_.Id
            Message     = ($_.Message -replace '\s+', ' ').Trim()
        }
    })
} catch {}

try {
    $memEvts = @(Get-WinEvent -FilterHashtable @{
        LogName      = 'System'
        ProviderName = 'Microsoft-Windows-Resource-Exhaustion-Detector'
        StartTime    = $since
    } -MaxEvents 20 -ErrorAction SilentlyContinue)
    $eventSignals.MemoryExhaustionEvents = @($memEvts | ForEach-Object {
        @{
            TimeCreated = $_.TimeCreated.ToString("o")
            Id          = $_.Id
            Message     = ($_.Message -replace '\s+', ' ').Trim()
        }
    })
} catch {}

try {
    $diskEvts = @(Get-WinEvent -FilterHashtable @{
        LogName   = 'System'
        Level     = @(1, 2, 3)
        StartTime = $since
    } -MaxEvents 300 -ErrorAction SilentlyContinue | Where-Object {
        $_.ProviderName -match 'disk|stor|nvme|ntfs|volsnap'
    } | Select-Object -First 20)
    $eventSignals.DiskWarningEvents = @($diskEvts | ForEach-Object {
        @{
            TimeCreated  = $_.TimeCreated.ToString("o")
            ProviderName = $_.ProviderName
            Id           = $_.Id
            Level        = $_.LevelDisplayName
            Message      = ($_.Message -replace '\s+', ' ').Trim()
        }
    })
} catch {}

try {
    $appEvts = @(Get-WinEvent -FilterHashtable @{
        LogName   = 'Application'
        Id        = @(1000, 1002)
        StartTime = $since
    } -MaxEvents 100 -ErrorAction SilentlyContinue)
    $eventSignals.AppHangCrashCount48h = $appEvts.Count
    if ($appEvts.Count -gt 0) {
        $topApps = @($appEvts | ForEach-Object {
            if ($_.Message -match 'Faulting application name:\s*([^\s,]+)') { $Matches[1] }
            elseif ($_.Message -match 'program\s+([^\s]+\.exe)') { $Matches[1] }
            else { 'Unknown' }
        } | Group-Object | Sort-Object Count -Descending | Select-Object -First 5 | ForEach-Object {
            @{ App = $_.Name; Count = $_.Count }
        })
        $eventSignals.TopCrashingApps = $topApps
    }
} catch {}

# 5. Services Inventory + Dependencies + Binary Metadata
$cimServices = @(Get-CimInstance Win32_Service)
$scMap = @{}
foreach ($s in (Get-Service -ErrorAction SilentlyContinue)) {
    $scMap[$s.Name] = $s
}

$exeMetaCache = @{}
$servicesList = New-Object System.Collections.Generic.List[object]

foreach ($svc in $cimServices) {
    $exePath = Get-ExecutableFromPathName -PathName $svc.PathName
    $company = $null
    $product = $null
    $fileDesc = $null

    if ($exePath) {
        $key = $exePath.ToLowerInvariant()
        if (-not $exeMetaCache.ContainsKey($key)) {
            $meta = @{ Company = $null; Product = $null; FileDesc = $null }
            if (Test-Path -LiteralPath $exePath) {
                try {
                    $vi = (Get-Item -LiteralPath $exePath -ErrorAction SilentlyContinue).VersionInfo
                    if ($vi) {
                        $meta.Company  = $vi.CompanyName
                        $meta.Product  = $vi.ProductName
                        $meta.FileDesc = $vi.FileDescription
                    }
                } catch {}
            }
            $exeMetaCache[$key] = $meta
        }
        $cached = $exeMetaCache[$key]
        $company  = $cached.Company
        $product  = $cached.Product
        $fileDesc = $cached.FileDesc
    }

    # Check ServiceDll for svchost services
    $serviceDll = $null
    if ($exePath -and ($exePath -match 'svchost\.exe$')) {
        try {
            $paramKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$($svc.Name)\Parameters"
            $pObj = Get-ItemProperty -LiteralPath $paramKey -Name ServiceDll -ErrorAction SilentlyContinue
            if ($pObj -and $pObj.ServiceDll) {
                $serviceDll = $pObj.ServiceDll
            }
        } catch {}
    }

    $depServices = @()
    $activeDepServices = @()
    $reqServices = @()
    if ($scMap.ContainsKey($svc.Name)) {
        $scObj = $scMap[$svc.Name]
        try {
            foreach ($d in $scObj.DependentServices) {
                $depServices += $d.Name
                if ($d.Status -eq 'Running') {
                    $activeDepServices += $d.Name
                }
            }
        } catch {}
        try {
            foreach ($r in $scObj.ServicesDependedOn) {
                $reqServices += $r.Name
            }
        } catch {}
    }

    $servicesList.Add(@{
        Name                    = $svc.Name
        DisplayName             = $svc.DisplayName
        State                   = $svc.State
        StartMode               = $svc.StartMode
        DelayedAutoStart        = [bool]$svc.DelayedAutoStart
        ProcessId               = [int]$svc.ProcessId
        PathName                = $svc.PathName
        ExecutablePath          = $exePath
        ServiceDll              = $serviceDll
        CompanyName             = $company
        ProductName             = $product
        FileDescription         = $fileDesc
        ServiceType             = $svc.ServiceType
        StartName               = $svc.StartName
        Description             = $svc.Description
        DependentServices       = $depServices
        ActiveDependentServices = $activeDepServices
        RequiredServices        = $reqServices
    })
}

# 6. Startup Items & Non-Microsoft Scheduled Tasks
$startupItems = @(Get-CimInstance Win32_StartupCommand -ErrorAction SilentlyContinue | ForEach-Object {
    @{
        Name     = $_.Name
        Command  = $_.Command
        Location = $_.Location
        User     = $_.User
    }
})

$scheduledTasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
    $_.State -eq 'Running' -or ($_.State -eq 'Ready' -and $_.TaskPath -notlike '\Microsoft\*')
} | ForEach-Object {
    @{
        TaskName    = $_.TaskName
        TaskPath    = $_.TaskPath
        State       = $_.State.ToString()
        Author      = $_.Author
        Description = $_.Description
    }
})

$payload = @{
    CollectedAt      = (Get-Date).ToString("o")
    System           = $systemInfo
    Power            = $powerInfo
    PerfCounters     = $counterSummary
    EventSignals     = $eventSignals
    Services         = $servicesList
    StartupItems     = $startupItems
    ScheduledTasks   = $scheduledTasks
}

$parentDir = Split-Path -Parent $OutputPath
if ($parentDir -and -not (Test-Path -LiteralPath $parentDir)) {
    New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
}

$json = $payload | ConvertTo-Json -Depth 8 -Compress
[System.IO.File]::WriteAllText($OutputPath, $json, (New-Object System.Text.UTF8Encoding($false)))

