"""Generic, hardware-agnostic root-cause analysis engine for Windows 10/11 performance slowdowns."""

from __future__ import annotations

import os
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .collectors import ProcessMetrics, TelemetryBundle
from .service_discovery import WindowsServiceRecord

# Generic multi-vendor Antivirus / EDR service detection map
AV_VENDOR_SIGNATURES: dict[str, set[str]] = {
    "Microsoft Defender": {"windefend"},
    "McAfee": {"mcapexe", "mfemms", "mfevtp", "mcshield"},
    "Norton / Symantec": {"nortonsecurity", "ns", "sepasterservice", "ccsvchst", "symantec antivirus"},
    "Avast": {"avast! antivirus", "aswbidsagent"},
    "AVG": {"avg antivirus", "avgsvca"},
    "Bitdefender": {"vsserv", "bdredline"},
    "Kaspersky": {"avp", "kes"},
    "Malwarebytes": {"mbamservice"},
    "ESET": {"ekrn"},
    "Trend Micro": {"amasvc", "ntrtscan"},
    "Webroot": {"wrsvc"},
    "CrowdStrike Falcon": {"csagent", "csfalconservice"},
    "SentinelOne": {"sentinelagent"},
}

BROWSER_EXES = {"chrome.exe", "msedge.exe", "opera.exe", "brave.exe", "firefox.exe", "vivaldi.exe", "arc.exe"}
GAME_LAUNCHER_EXES = {
    "steam.exe",
    "epicgameslauncher.exe",
    "ealauncher.exe",
    "battle.net.exe",
    "galaxyclient.exe",
    "upc.exe",
    "ubisoftconnect.exe",
    "riotclientservices.exe",
}
HEAVY_RESIDENT_EXES = {
    "vmmemwsl": "WSL2 Linux Utility VM",
    "vmmem": "Hyper-V / Docker Utility VM",
    "com.docker.backend.exe": "Docker Desktop Backend",
    "virtualboxvm.exe": "Oracle VirtualBox VM",
    "vmware-vmx.exe": "VMware Workstation VM",
    "phoneexperiencehost.exe": "Microsoft Phone Link Host",
}


@dataclass
class RootCauseFinding:
    """A single prioritized, evidence-backed root-cause finding."""

    id: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    title: str
    subsystem: str
    summary: str
    evidence: list[str] = field(default_factory=list)
    remediation_steps: list[str] = field(default_factory=list)


@dataclass
class ProcessFamilySummary:
    """Aggregated resource consumption grouped by executable name."""

    exe_name: str
    instance_count: int = 0
    live_cpu_avg_raw_pct: float = 0.0
    live_cpu_peak_raw_pct: float = 0.0
    cpu_total_seconds: float = 0.0
    working_set_mb: float = 0.0
    private_mb: float = 0.0
    io_total_mb: float = 0.0
    hosted_services: list[str] = field(default_factory=list)


@dataclass
class RootCauseReport:
    """Structured output of the generic root-cause diagnostic engine."""

    verdict_headline: str
    cpu_hypothesis_assessment: str
    findings: list[RootCauseFinding]
    top_process_families_by_cpu: list[ProcessFamilySummary]
    top_process_families_by_ram: list[ProcessFamilySummary]
    top_services_by_cpu: list[WindowsServiceRecord]
    top_services_by_ram: list[WindowsServiceRecord]
    top_services_by_io: list[WindowsServiceRecord]
    startup_bloat_items: list[dict[str, Any]]
    key_metrics: dict[str, Any]


def _aggregate_process_families(
    processes_by_pid: dict[int, ProcessMetrics],
    exclude_self_python: bool = True,
) -> list[ProcessFamilySummary]:
    self_pid = os.getpid()
    grouped: dict[str, ProcessFamilySummary] = {}
    for p in processes_by_pid.values():
        if exclude_self_python and (p.pid == self_pid or (p.name.lower() == "python.exe" and p.age_seconds < 45)):
            continue
        key = p.name.lower()
        fam = grouped.get(key)
        if fam is None:
            fam = ProcessFamilySummary(exe_name=p.name)
            grouped[key] = fam
        fam.instance_count += 1
        fam.live_cpu_avg_raw_pct = round(fam.live_cpu_avg_raw_pct + p.cpu_avg_raw_pct, 2)
        fam.live_cpu_peak_raw_pct = round(fam.live_cpu_peak_raw_pct + p.cpu_peak_raw_pct, 2)
        fam.cpu_total_seconds = round(fam.cpu_total_seconds + p.cpu_total_seconds, 2)
        fam.working_set_mb = round(fam.working_set_mb + p.working_set_mb, 2)
        fam.private_mb = round(fam.private_mb + p.private_mb, 2)
        fam.io_total_mb = round(fam.io_total_mb + p.io_total_mb, 2)
        for s in p.hosted_services:
            if s not in fam.hosted_services:
                fam.hosted_services.append(s)
    return list(grouped.values())


def _get_counter_avg(counters: dict[str, Any], suffix: str) -> float | None:
    suf_l = suffix.lower()
    for k, v in counters.items():
        if k.lower().endswith(suf_l) and isinstance(v, dict):
            return float(v.get("Avg", 0.0))
    return None


def _extract_exe_basename(command: str) -> str | None:
    m = re.search(r"([a-zA-Z0-9_.\-]+\.exe)", command, re.IGNORECASE)
    return m.group(1).lower() if m else None


def analyze_root_causes(
    bundle: TelemetryBundle,
    services: list[WindowsServiceRecord],
) -> RootCauseReport:
    """Evaluate collected telemetry to determine the primary root causes of slowdown on any Windows PC."""
    raw = bundle.windows_raw
    sys_info = raw.get("System", {}) or {}
    power_info = raw.get("Power", {}) or {}
    counters = raw.get("PerfCounters", {}) or {}
    events = raw.get("EventSignals", {}) or {}
    startup_items: list[dict[str, Any]] = list(raw.get("StartupItems") or [])

    uptime_sec = max(1.0, float(sys_info.get("UptimeSeconds") or 1.0))
    uptime_min = round(uptime_sec / 60.0, 1)
    uptime_hr = round(uptime_sec / 3600.0, 2)

    families = _aggregate_process_families(bundle.processes_by_pid)
    top_fam_cpu = sorted(families, key=lambda f: f.cpu_total_seconds, reverse=True)[:15]
    top_fam_ram = sorted(families, key=lambda f: f.working_set_mb, reverse=True)[:15]

    running_svcs = [s for s in services if s.state.lower() == "running"]
    top_svc_cpu = sorted(running_svcs, key=lambda s: s.cpu_total_seconds, reverse=True)[:15]
    top_svc_ram = sorted(running_svcs, key=lambda s: s.working_set_mb, reverse=True)[:15]
    top_svc_io = sorted(running_svcs, key=lambda s: s.io_total_mb, reverse=True)[:15]

    findings: list[RootCauseFinding] = []
    finding_seq = 1

    def _next_id() -> str:
        nonlocal finding_seq
        fid = f"RC-{finding_seq:02d}"
        finding_seq += 1
        return fid

    # --- Detector 1: Multi-Antivirus Contention & High-Churn Background Services (Indexer / AV / Update) ---
    active_av_vendors: dict[str, list[WindowsServiceRecord]] = {}
    for s in running_svcs:
        b_low = s.base_name.lower()
        for vendor_label, sig_names in AV_VENDOR_SIGNATURES.items():
            if b_low in sig_names:
                active_av_vendors.setdefault(vendor_label, []).append(s)

    svc_by_base = {s.base_name.lower(): s for s in services}
    wsearch = svc_by_base.get("wsearch")
    sysmain = svc_by_base.get("sysmain")

    high_io_indexer = bool(
        wsearch
        and wsearch.state.lower() == "running"
        and (wsearch.io_total_mb > 4096 or (wsearch.io_total_mb / max(1.0, uptime_min)) > 150.0)
    )
    high_cpu_svcs = [
        s for s in running_svcs
        if s.cpu_lifetime_core_pct >= 5.0 or s.cpu_avg_raw_pct >= 10.0
    ]

    if len(active_av_vendors) >= 2 or high_io_indexer or high_cpu_svcs:
        ev1: list[str] = []
        steps1: list[str] = []
        title_parts: list[str] = []
        sev1 = "MEDIUM"

        if len(active_av_vendors) >= 2:
            sev1 = "CRITICAL"
            vendor_summaries = [
                f"**{v}** ({', '.join(f'`{x.name}`' for x in svs)})"
                for v, svs in active_av_vendors.items()
            ]
            title_parts.append(f"Concurrent Antivirus Contention ({' + '.join(active_av_vendors.keys())})")
            ev1.append(
                f"Multiple real-time security engines are running simultaneously: {'; '.join(vendor_summaries)}. "
                f"Concurrent filesystem and process filter hooks intercept every file open and DLL load twice."
            )
            steps1.append(
                "Keep only **one** active real-time antivirus engine. If an OEM trial antivirus is leftover alongside "
                "Microsoft Defender, uninstall the secondary antivirus via **Windows Settings -> Apps -> Installed apps** "
                "(or disable its services via `scripts\\disable-services.ps1 -IncludeConditional`)."
            )

        for s in sorted(high_cpu_svcs, key=lambda x: x.cpu_total_seconds, reverse=True)[:4]:
            if sev1 == "MEDIUM" and s.cpu_lifetime_core_pct >= 8.0:
                sev1 = "HIGH"
            ev1.append(
                f"Service `{s.name}` ({s.display_name}, PID {s.pid}) burned **{s.cpu_total_seconds:,.1f} CPU seconds** "
                f"({s.cpu_lifetime_core_pct:.1f}% of a core continuously; live avg {s.cpu_avg_raw_pct:.1f}%), "
                f"**{s.working_set_mb:.1f} MB RAM**, and **{s.io_total_mb:,.1f} MB Disk I/O** over {uptime_min} min uptime."
            )

        if high_io_indexer and wsearch is not None:
            if sev1 != "CRITICAL":
                sev1 = "HIGH"
            title_parts.append("Heavy Windows Search Indexer Disk/CPU Churn")
            ev1.append(
                f"Windows Search (`WSearch` / `SearchIndexer.exe`, PID {wsearch.pid}) generated "
                f"**{wsearch.io_total_mb:,.1f} MB ({wsearch.io_total_mb / 1024:.2f} GB) of Disk I/O** and "
                f"**{wsearch.cpu_total_seconds:,.1f} CPU seconds** in {uptime_min} minutes — amplifying real-time antivirus scanning."
            )
            steps1.append(
                "Open **Windows Settings -> Privacy & Security -> Searching Windows** and exclude high-churn developer, "
                "cache, and VM directories (e.g., `%USERPROFILE%\\.cache`, `.gradle`, `node_modules`, VM folders), or "
                "disable `WSearch` via `scripts\\disable-services.ps1 -IncludeConditional` if instant file-content search is unneeded."
            )

        crashing_apps = list(events.get("TopCrashingApps") or [])
        if crashing_apps:
            crash_str = ", ".join(f"`{c.get('App')}` ({c.get('Count')}x)" for c in crashing_apps[:3])
            ev1.append(f"Application Event Log recorded recent background crashes/hangs (last 48h): {crash_str}.")

        if not title_parts:
            title_parts.append("Elevated Background Service CPU & I/O Utilization")
        if not steps1:
            steps1.append(
                "Run `scripts\\disable-services.ps1` (Administrator PowerShell) to disable Tier 1 telemetry/legacy services "
                "and switch Tier 3 auto-updaters to `Manual`."
            )

        findings.append(
            RootCauseFinding(
                id=_next_id(),
                severity=sev1,
                title=" & ".join(title_parts),
                subsystem="Background Services, Security Filters & Indexing",
                summary=(
                    "Background system services are generating sustained CPU and filesystem filter activity, "
                    "reducing responsiveness for foreground applications."
                ),
                evidence=ev1,
                remediation_steps=steps1,
            )
        )

    # --- Detector 2: Startup Storm & Resident Process Bloat ---
    total_procs = len(bundle.processes_by_pid)
    auto_svcs_count = sum(1 for s in services if s.start_mode.lower() == "auto")
    mem_used_gb = float(bundle.psutil_mem_summary.get("used_gb") or 0.0)
    mem_pct = float(bundle.psutil_mem_summary.get("percent") or 0.0)
    sys_cpu_avg = round(sum(bundle.system_cpu_samples_pct) / max(1, len(bundle.system_cpu_samples_pct)), 2)
    sys_cpu_peak = max(bundle.system_cpu_samples_pct) if bundle.system_cpu_samples_pct else 0.0

    startup_exes = [
        _extract_exe_basename(str(item.get("Command") or ""))
        for item in startup_items
    ]
    exe_counts = Counter(e for e in startup_exes if e)
    duplicate_startups = {exe: cnt for exe, cnt in exe_counts.items() if cnt > 1}
    auto_browsers = sorted({e for e in startup_exes if e in BROWSER_EXES})
    auto_launchers = sorted({e for e in startup_exes if e in GAME_LAUNCHER_EXES})

    heavy_residents: list[str] = []
    for p in sorted(bundle.processes_by_pid.values(), key=lambda x: x.working_set_mb, reverse=True):
        label = HEAVY_RESIDENT_EXES.get(p.name.lower())
        if label and p.working_set_mb >= 250.0:
            heavy_residents.append(
                f"{label} (`{p.name}`, PID {p.pid}) holding **{p.working_set_mb:,.1f} MB RAM** "
                f"and **{p.cpu_total_seconds:,.1f}s CPU**"
            )

    if len(startup_items) >= 12 or total_procs >= 240:
        sev2 = "HIGH" if (len(startup_items) >= 20 or total_procs >= 300) else "MEDIUM"
        ev2 = [
            f"**{total_procs} active processes**, **{len(running_svcs)} running services** ({auto_svcs_count} `Automatic`), "
            f"and **{len(startup_items)} startup entries** are active ({mem_used_gb:.2f} GB RAM used / {mem_pct:.1f}%; "
            f"sampled system CPU avg **{sys_cpu_avg:.1f}%**, peak **{sys_cpu_peak:.1f}%** across {bundle.logical_cpu_count} logical CPUs)."
        ]
        if auto_browsers or auto_launchers:
            parts = []
            if auto_browsers:
                parts.append(f"{len(auto_browsers)} browser(s) ({', '.join(f'`{b}`' for b in auto_browsers)})")
            if auto_launchers:
                parts.append(f"{len(auto_launchers)} game launcher(s) ({', '.join(f'`{g}`' for g in auto_launchers)})")
            ev2.append(f"Auto-launching at Windows login: {' and '.join(parts)}.")
        if duplicate_startups:
            dup_str = ", ".join(f"`{k}` ({v}x)" for k, v in duplicate_startups.items())
            ev2.append(f"Duplicate startup registrations across registry/folder locations: {dup_str}.")
        if heavy_residents:
            ev2.append(f"Heavy background resident subsystems: {'; '.join(heavy_residents[:4])}.")

        findings.append(
            RootCauseFinding(
                id=_next_id(),
                severity=sev2,
                title=f"Startup & Background Process Bloat ({len(startup_items)} Startup Entries, {total_procs} Active Processes)",
                subsystem="Windows Startup Registry/Folders & Auto-Start Daemons",
                summary=(
                    "A large number of auto-starting applications, background updaters, and resident daemons launch "
                    "at login, increasing memory footprint, context switching, and background CPU bursts."
                ),
                evidence=ev2,
                remediation_steps=[
                    "Run `scripts\\disable-services.ps1` as Administrator to disable Tier 1 bloatware/telemetry services "
                    "and switch Tier 3 background updaters and VM daemons from `Automatic` to `Manual`.",
                    "Open **Task Manager -> Startup apps** (`Ctrl + Shift + Esc`) and disable non-essential auto-launchers "
                    "(game launchers, archive preloaders, P2P engines, and background browser pre-launchers).",
                ],
            )
        )

    # --- Detector 3: CPU Throttling, Power Policy & DPC Driver Latency ---
    throttle_evts = list(events.get("ProcessorThrottleEvents") or [])
    proc_min_ac = (power_info.get("ProcThrottleMin") or {}).get("AC")
    proc_max_ac = (power_info.get("ProcThrottleMax") or {}).get("AC")
    proc_max_dc = (power_info.get("ProcThrottleMax") or {}).get("DC")
    active_scheme = str(power_info.get("ActiveScheme") or "Unknown")
    perf_pct = _get_counter_avg(counters, "% processor performance")
    dpc_pct = _get_counter_avg(counters, "% dpc time")

    batteries = list(sys_info.get("Batteries") or [])
    on_battery = any(int(b.get("BatteryStatus") or 2) == 1 for b in batteries)

    is_max_capped = (
        (not on_battery and proc_max_ac is not None and int(proc_max_ac) < 100)
        or (on_battery and proc_max_dc is not None and int(proc_max_dc) < 100)
    )
    is_min_locked_100 = (not on_battery and proc_min_ac is not None and int(proc_min_ac) >= 100)
    is_perf_throttled = perf_pct is not None and perf_pct < 85.0
    is_high_dpc = dpc_pct is not None and dpc_pct >= 2.5

    if throttle_evts or is_max_capped or (is_min_locked_100 and batteries) or is_perf_throttled or is_high_dpc:
        ev3: list[str] = []
        steps3: list[str] = []
        sev3 = "MEDIUM"
        title3_parts: list[str] = []

        if throttle_evts:
            sev3 = "HIGH"
            throttled_cpus: set[int] = set()
            max_dur = 0
            for ev in throttle_evts:
                msg = str(ev.get("Message") or "")
                m_c = re.search(r"processor\s+(\d+)", msg, re.IGNORECASE)
                if m_c:
                    throttled_cpus.add(int(m_c.group(1)))
                m_d = re.search(r"for\s+(\d+)\s+seconds", msg, re.IGNORECASE)
                if m_d:
                    max_dur = max(max_dur, int(m_d.group(1)))
            cpu_str = ", ".join(str(c) for c in sorted(throttled_cpus)) or "multiple cores"
            is_hybrid = (
                bundle.physical_cpu_count > 4
                and bundle.logical_cpu_count != bundle.physical_cpu_count * 2
                and bundle.logical_cpu_count != bundle.physical_cpu_count
            )
            hybrid_note = (
                " (including Efficiency cores where Windows Thread Director routes background tasks)"
                if is_hybrid
                else ""
            )
            title3_parts.append("Firmware/Thermal CPU Speed Throttling (Event ID 37)")
            ev3.append(
                f"System Event Log (`Microsoft-Windows-Kernel-Processor-Power`, Event ID `37`) recorded "
                f"**{len(throttle_evts)} firmware speed-limiting warnings** on logical processor(s) **{cpu_str}**"
                f"{hybrid_note} lasting up to **{max_dur:,} seconds**."
            )
            steps3.append(
                "Check CPU cooling vents, fan curves, and thermal headroom so system firmware does not cap processor P-states."
            )

        if is_max_capped:
            sev3 = "HIGH"
            capped_val = proc_max_dc if on_battery else proc_max_ac
            mode_lbl = "Battery (DC)" if on_battery else "Plugged-In (AC)"
            title3_parts.append(f"Capped Maximum Processor State ({capped_val}%)")
            ev3.append(
                f"Active power plan (`{active_scheme}`) caps **Maximum Processor State ({mode_lbl}) = {capped_val}%** "
                f"(setting `< 100%` disables CPU Turbo Boost on Windows, sharply reducing single-core speed)."
            )
            flag_cmd = "/setdcvalueindex" if on_battery else "/setacvalueindex"
            steps3.append(
                f"Restore 100% Maximum Processor State to re-enable Turbo Boost: "
                f"`powercfg {flag_cmd} SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMAX 100` then `powercfg /setactive SCHEME_CURRENT`."
            )

        if is_min_locked_100 and batteries:
            title3_parts.append("Locked 100% Minimum CPU Power Policy")
            ev3.append(
                f"Active power plan (`{active_scheme}`) sets **Minimum Processor State (AC) = {proc_min_ac}%** on a battery-equipped "
                f"laptop, preventing idle cores from downclocking/cooling and reducing thermal headroom."
            )
            steps3.append(
                "Lower Minimum Processor State on AC from `100%` to `5%` (while keeping Maximum at `100%`): "
                "`powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMIN 5` then `powercfg /setactive SCHEME_CURRENT`."
            )

        if is_perf_throttled and perf_pct is not None:
            sev3 = "HIGH"
            title3_parts.append(f"Reduced Live CPU Clock ({perf_pct:.1f}% of Base)")
            ev3.append(
                f"`\\Processor Information(_Total)\\% Processor Performance` averaged only **{perf_pct:.1f}%** of base clock."
            )

        if is_high_dpc and dpc_pct is not None:
            sev3 = "HIGH"
            title3_parts.append(f"Elevated Kernel Driver DPC Latency ({dpc_pct:.2f}%)")
            ev3.append(
                f"`\\Processor(_Total)\\% DPC Time` averaged **{dpc_pct:.2f}%** (`>= 2.5%` indicates a kernel driver "
                f"stalling CPU interrupts and causing UI/audio micro-stutters)."
            )
            steps3.append(
                "Update network, GPU, and storage controller drivers, or profile offending `.sys` drivers with LatencyMon / WPR."
            )

        findings.append(
            RootCauseFinding(
                id=_next_id(),
                severity=sev3,
                title=" & ".join(title3_parts) or "Processor Power & Thermal Configuration Issue",
                subsystem="CPU Power Management, Firmware & Kernel Interrupts",
                summary=(
                    "Processor frequency scaling, power plan thresholds, or firmware thermal limits are constraining "
                    "effective CPU throughput."
                ),
                evidence=ev3,
                remediation_steps=steps3,
            )
        )

    # --- Detector 4: Storage Capacity, Disk I/O Queue Saturation & Disk Errors ---
    disks = list(sys_info.get("Disks") or [])
    sys_drive = os.environ.get("SystemDrive", "C:").upper()
    disk_idle = _get_counter_avg(counters, "% idle time")
    disk_queue = _get_counter_avg(counters, "current disk queue length") or 0.0
    disk_read_ms = (_get_counter_avg(counters, "avg. disk sec/read") or 0.0) * 1000.0
    disk_write_ms = (_get_counter_avg(counters, "avg. disk sec/write") or 0.0) * 1000.0
    disk_evts = list(events.get("DiskWarningEvents") or [])

    low_space_drives: list[tuple[str, float, float, float]] = []
    ample_drives: list[str] = []
    for d in disks:
        dev = str(d.get("DeviceID") or "").upper()
        size_b = int(d.get("SizeBytes") or 0)
        free_b = int(d.get("FreeBytes") or 0)
        if size_b <= 0:
            continue
        free_pct = (free_b / size_b) * 100.0
        free_gb = free_b / (1024**3)
        size_gb = size_b / (1024**3)
        if free_pct < 10.0:
            low_space_drives.append((dev, free_pct, free_gb, size_gb))
        elif free_gb >= 100.0:
            ample_drives.append(f"`{dev}` ({free_gb:.0f} GB free)")

    is_disk_saturated = (disk_idle is not None and disk_idle < 50.0) or disk_queue >= 2.0 or disk_read_ms >= 20.0 or disk_write_ms >= 20.0

    if low_space_drives or is_disk_saturated or disk_evts:
        ev4: list[str] = []
        steps4: list[str] = []
        sev4 = "MEDIUM"
        title4_parts: list[str] = []

        if disk_evts:
            sev4 = "CRITICAL"
            title4_parts.append(f"Storage Controller / Disk Warnings ({len(disk_evts)} Events)")
            ev4.append(
                f"System Event Log recorded **{len(disk_evts)} disk/storage warning or error event(s)** in the last 48 hours "
                f"(latest: `{disk_evts[0].get('ProviderName')}` ID `{disk_evts[0].get('Id')}`)."
            )
            steps4.append("Check drive SMART health immediately (`Get-PhysicalDisk | Get-StorageReliabilityCounter`) and verify backups.")

        if is_disk_saturated:
            if sev4 != "CRITICAL":
                sev4 = "HIGH"
            title4_parts.append("Active Storage I/O Bottleneck")
            ev4.append(
                f"Live PhysicalDisk counters indicate heavy I/O pressure: Idle Time = **{(disk_idle or 0.0):.1f}%**, "
                f"Queue Length = **{disk_queue:.2f}**, Avg Read = **{disk_read_ms:.1f} ms**, Avg Write = **{disk_write_ms:.1f} ms**."
            )

        for dev, fpct, fgb, sgb in low_space_drives:
            if dev == sys_drive and fpct < 5.0 and sev4 == "MEDIUM":
                sev4 = "HIGH"
            title4_parts.append(f"Drive `{dev}` Near Capacity ({fpct:.1f}% Free -- {fgb:.1f} GB of {sgb:.1f} GB)")
            alt_note = f" (other local volume(s) with ample space: {', '.join(ample_drives)})" if ample_drives else ""
            ev4.append(
                f"Volume `{dev}` has only **{fgb:.2f} GB free** out of **{sgb:.2f} GB** (**{100.0 - fpct:.1f}% full**){alt_note}. "
                f"SSDs below 10% free space suffer reduced SLC write-cache headroom during paging, updates, and indexing."
            )
            steps4.append(
                f"Reclaim free space on `{dev}` (aim for `> 12-15%` free) via Windows Storage Sense / `cleanmgr`, clearing `%TEMP%`, "
                f"pruning package/build caches, or moving large archives/VMs to another volume."
            )

        if not is_disk_saturated and not disk_evts:
            ev4.append(
                f"Hardware I/O latency is currently healthy (Idle Time **{(disk_idle or 0.0):.1f}%**, "
                f"Read **{disk_read_ms:.2f} ms**, Write **{disk_write_ms:.2f} ms**, `0` disk errors in System log)."
            )

        findings.append(
            RootCauseFinding(
                id=_next_id(),
                severity=sev4,
                title=" & ".join(title4_parts),
                subsystem="Storage Capacity & Disk I/O Subsystem",
                summary="Storage capacity pressure or sustained disk I/O contention is impacting system responsiveness.",
                evidence=ev4,
                remediation_steps=steps4,
            )
        )

    # --- Detector 5: Physical Memory Exhaustion & Swap Thrashing ---
    pages_per_sec = _get_counter_avg(counters, "pages/sec") or 0.0
    mem_evts = list(events.get("MemoryExhaustionEvents") or [])
    if mem_pct >= 85.0 or pages_per_sec >= 50.0 or mem_evts:
        sev5 = "CRITICAL" if (mem_pct >= 92.0 or mem_evts) else "HIGH"
        ev5 = [
            f"Physical RAM utilization is **{mem_pct:.1f}%** (**{mem_used_gb:.2f} GB** used of "
            f"**{bundle.psutil_mem_summary.get('total_gb')} GB**); hard page fault rate (`Pages/sec`) = **{pages_per_sec:.1f}/s**."
        ]
        if mem_evts:
            ev5.append(
                f"Windows `Resource-Exhaustion-Detector` logged **{len(mem_evts)} low-virtual-memory warning(s)** in the past 48 hours."
            )
        findings.append(
            RootCauseFinding(
                id=_next_id(),
                severity=sev5,
                title=f"Memory Pressure & Pagefile Thrashing ({mem_pct:.1f}% RAM Used)",
                subsystem="Virtual Memory & Paging",
                summary="High physical RAM saturation is forcing Windows to page memory to disk, causing severe UI stalls.",
                evidence=ev5,
                remediation_steps=[
                    "Close high-memory process families listed in Section 4 (browser tab clusters, idle VMs/WSL2 via `wsl --shutdown`).",
                    "Disable unneeded background services via `scripts\\disable-services.ps1` and ensure Windows system-managed pagefile is enabled.",
                ],
            )
        )

    # Sort findings by severity
    sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings.sort(key=lambda x: sev_rank.get(x.severity, 9))
    for idx, f in enumerate(findings, start=1):
        f.id = f"RC-{idx:02d}"

    # Build dynamic verdict
    if not findings:
        verdict_headline = "No Critical System Bottlenecks Detected During Sampling Window."
        cpu_hypothesis_assessment = (
            f"Sampled CPU load averaged **{sys_cpu_avg:.1f}%** (peak **{sys_cpu_peak:.1f}%**) with healthy clock performance, "
            f"low disk latency, and `{mem_pct:.1f}%` memory usage. Review the generated services catalog to trim any optional "
            f"background telemetry or auto-updaters."
        )
    else:
        top_titles = "; ".join(f"[{f.severity}] {f.title}" for f in findings[:3])
        verdict_headline = f"Detected {len(findings)} Performance Bottleneck(s): {top_titles}"
        cpu_hypothesis_assessment = (
            f"Across `{bundle.logical_cpu_count}` logical processors, live background CPU averaged **{sys_cpu_avg:.1f}%** "
            f"(peaking at **{sys_cpu_peak:.1f}%**) with **{total_procs} active processes** and **{len(running_svcs)} running services** "
            f"consuming **{mem_used_gb:.2f} GB RAM ({mem_pct:.1f}%)** after **{uptime_min} minutes** of uptime. "
            f"The diagnostic engine cross-checked cumulative CPU burn, Disk I/O amplification, startup bloat, power/thermal "
            f"throttling, DPC driver latency, and storage headroom to isolate the exact root causes below."
        )

    key_metrics = {
        "manufacturer": sys_info.get("Manufacturer") or "Unknown",
        "model": sys_info.get("Model") or "PC",
        "os_caption": sys_info.get("OSCaption") or "Windows",
        "os_build": sys_info.get("OSBuild") or "Unknown",
        "cpu_name": ((sys_info.get("Processors") or [{}])[0]).get("Name") or "Processor",
        "logical_cpus": bundle.logical_cpu_count,
        "physical_cpus": bundle.physical_cpu_count,
        "uptime_hours": uptime_hr,
        "uptime_minutes": uptime_min,
        "total_processes": total_procs,
        "total_services": len(services),
        "running_services": len(running_svcs),
        "auto_services": auto_svcs_count,
        "startup_items_count": len(startup_items),
        "ram_used_gb": mem_used_gb,
        "ram_total_gb": bundle.psutil_mem_summary.get("total_gb", 0.0),
        "ram_used_pct": mem_pct,
        "sampled_cpu_avg_pct": sys_cpu_avg,
        "sampled_cpu_peak_pct": sys_cpu_peak,
        "cpu_perf_pct_of_base": perf_pct,
        "dpc_time_pct": dpc_pct,
    }

    return RootCauseReport(
        verdict_headline=verdict_headline,
        cpu_hypothesis_assessment=cpu_hypothesis_assessment,
        findings=findings,
        top_process_families_by_cpu=top_fam_cpu,
        top_process_families_by_ram=top_fam_ram,
        top_services_by_cpu=top_svc_cpu,
        top_services_by_ram=top_svc_ram,
        top_services_by_io=top_svc_io,
        startup_bloat_items=startup_items,
        key_metrics=key_metrics,
    )
