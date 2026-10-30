"""System, process, and Windows WMI/CIM telemetry collectors."""

from __future__ import annotations

import json
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import psutil


@dataclass
class ProcessMetrics:
    """Aggregated live and cumulative metrics for a single Windows process."""

    pid: int
    name: str
    exe: str | None = None
    cmdline: str | None = None
    username: str | None = None
    status: str | None = None
    ppid: int = 0
    create_time: float = 0.0
    age_seconds: float = 0.0

    # Live sampled CPU (% across logical processors; 100% = 1 full logical core)
    cpu_avg_raw_pct: float = 0.0
    cpu_peak_raw_pct: float = 0.0
    # Normalized to total system CPU capacity (0..100%)
    cpu_avg_system_pct: float = 0.0
    cpu_peak_system_pct: float = 0.0

    # Cumulative CPU burned since process start
    cpu_total_seconds: float = 0.0
    cpu_user_seconds: float = 0.0
    cpu_kernel_seconds: float = 0.0
    cpu_lifetime_core_pct: float = 0.0  # (cpu_total_seconds / age_seconds) * 100

    # Memory
    working_set_mb: float = 0.0
    private_mb: float = 0.0
    page_faults: int = 0

    # Disk I/O since process start
    io_read_mb: float = 0.0
    io_write_mb: float = 0.0
    io_total_mb: float = 0.0
    io_read_ops: int = 0
    io_write_ops: int = 0

    # Concurrency & handles
    num_threads: int = 0
    num_handles: int = 0

    # Hosted Windows service names (populated by service_discovery)
    hosted_services: list[str] = field(default_factory=list)


@dataclass
class TelemetryBundle:
    """Combined telemetry from Windows CIM/PerfCounters and Python psutil profiling."""

    windows_raw: dict[str, Any]
    processes_by_pid: dict[int, ProcessMetrics]
    logical_cpu_count: int
    physical_cpu_count: int
    sample_count: int
    sample_interval_sec: float
    system_cpu_samples_pct: list[float]
    per_core_peak_pct: list[float]
    per_core_avg_pct: list[float]
    psutil_mem_summary: dict[str, float]


def collect_all_telemetry(
    project_root: Path,
    sample_count: int = 8,
    sample_interval: float = 1.0,
) -> TelemetryBundle:
    """Run PowerShell CIM/PerfCounter collection in parallel with multi-sample psutil profiling."""
    ps_script = project_root / "scripts" / "collect_windows_telemetry.ps1"
    raw_json_path = project_root / "reports" / "_raw_windows_telemetry.json"
    raw_json_path.parent.mkdir(parents=True, exist_ok=True)

    ps_cmd = [
        "powershell.exe",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(ps_script),
        "-OutputPath",
        str(raw_json_path),
        "-CounterSamples",
        str(max(3, min(sample_count, 5))),
    ]
    ps_proc = subprocess.Popen(
        ps_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    logical_cpus = psutil.cpu_count(logical=True) or 1
    physical_cpus = psutil.cpu_count(logical=False) or logical_cpus

    # Prime psutil CPU percent counters
    psutil.cpu_percent(interval=None, percpu=True)
    tracked_procs: dict[int, psutil.Process] = {}
    cpu_samples_by_pid: dict[int, list[float]] = {}

    for proc in psutil.process_iter():
        try:
            if proc.pid == 0:  # Skip Windows System Idle Process (PID 0)
                continue
            proc.cpu_percent(interval=None)
            tracked_procs[proc.pid] = proc
            cpu_samples_by_pid[proc.pid] = []
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    system_cpu_samples: list[float] = []
    per_core_history: list[list[float]] = []

    for _ in range(sample_count):
        time.sleep(sample_interval)
        per_core = psutil.cpu_percent(interval=None, percpu=True)
        per_core_history.append(per_core)
        sys_avg = sum(per_core) / len(per_core) if per_core else 0.0
        system_cpu_samples.append(round(sys_avg, 2))

        # Check existing and newly spawned processes
        current_pids = set(psutil.pids()) - {0}
        new_pids = current_pids - set(tracked_procs.keys())
        for npid in new_pids:
            try:
                nproc = psutil.Process(npid)
                nproc.cpu_percent(interval=None)
                tracked_procs[npid] = nproc
                cpu_samples_by_pid[npid] = []
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        for pid, proc in list(tracked_procs.items()):
            try:
                val = proc.cpu_percent(interval=None)
                cpu_samples_by_pid[pid].append(val)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                tracked_procs.pop(pid, None)

    now = time.time()
    processes_by_pid: dict[int, ProcessMetrics] = {}

    for pid, proc in tracked_procs.items():
        try:
            with proc.oneshot():
                name = proc.name()
                ppid = proc.ppid()
                status = proc.status()
                ctime = proc.create_time()
                age = max(1.0, now - ctime) if ctime > 0 else 1.0

                try:
                    exe = proc.exe()
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    exe = None

                try:
                    cmdline_list = proc.cmdline()
                    cmdline = " ".join(cmdline_list) if cmdline_list else None
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    cmdline = None

                try:
                    username = proc.username()
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    username = None

                try:
                    ctimes = proc.cpu_times()
                    u_sec = float(ctimes.user)
                    k_sec = float(ctimes.system)
                    tot_sec = u_sec + k_sec
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    u_sec = k_sec = tot_sec = 0.0

                try:
                    mem = proc.memory_info()
                    wset_mb = mem.rss / (1024 * 1024)
                    priv_bytes = getattr(mem, "private", mem.rss)
                    priv_mb = priv_bytes / (1024 * 1024)
                    pfaults = int(getattr(mem, "num_page_faults", 0))
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    wset_mb = priv_mb = 0.0
                    pfaults = 0

                try:
                    io = proc.io_counters()
                    r_mb = io.read_bytes / (1024 * 1024)
                    w_mb = io.write_bytes / (1024 * 1024)
                    r_ops = int(io.read_count)
                    w_ops = int(io.write_count)
                except (psutil.AccessDenied, psutil.NoSuchProcess, AttributeError):
                    r_mb = w_mb = 0.0
                    r_ops = w_ops = 0

                try:
                    n_threads = proc.num_threads()
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    n_threads = 0

                try:
                    n_handles = proc.num_handles() if hasattr(proc, "num_handles") else 0
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    n_handles = 0

            samples = cpu_samples_by_pid.get(pid, [])
            avg_raw = (sum(samples) / len(samples)) if samples else 0.0
            peak_raw = max(samples) if samples else 0.0

            processes_by_pid[pid] = ProcessMetrics(
                pid=pid,
                name=name,
                exe=exe,
                cmdline=cmdline,
                username=username,
                status=status,
                ppid=ppid,
                create_time=ctime,
                age_seconds=round(age, 1),
                cpu_avg_raw_pct=round(avg_raw, 2),
                cpu_peak_raw_pct=round(peak_raw, 2),
                cpu_avg_system_pct=round(avg_raw / logical_cpus, 2),
                cpu_peak_system_pct=round(peak_raw / logical_cpus, 2),
                cpu_total_seconds=round(tot_sec, 2),
                cpu_user_seconds=round(u_sec, 2),
                cpu_kernel_seconds=round(k_sec, 2),
                cpu_lifetime_core_pct=round((tot_sec / age) * 100.0, 2),
                working_set_mb=round(wset_mb, 2),
                private_mb=round(priv_mb, 2),
                page_faults=pfaults,
                io_read_mb=round(r_mb, 2),
                io_write_mb=round(w_mb, 2),
                io_total_mb=round(r_mb + w_mb, 2),
                io_read_ops=r_ops,
                io_write_ops=w_ops,
                num_threads=n_threads,
                num_handles=n_handles,
            )
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    # Per-core averages and peaks
    per_core_avg: list[float] = []
    per_core_peak: list[float] = []
    if per_core_history:
        num_c = len(per_core_history[0])
        for c_idx in range(num_c):
            col = [row[c_idx] for row in per_core_history if c_idx < len(row)]
            per_core_avg.append(round(sum(col) / len(col), 2) if col else 0.0)
            per_core_peak.append(round(max(col), 2) if col else 0.0)

    vm = psutil.virtual_memory()
    sm = psutil.swap_memory()
    mem_summary = {
        "total_gb": round(vm.total / (1024**3), 2),
        "available_gb": round(vm.available / (1024**3), 2),
        "used_gb": round((vm.total - vm.available) / (1024**3), 2),
        "percent": round(vm.percent, 1),
        "swap_total_gb": round(sm.total / (1024**3), 2),
        "swap_used_gb": round(sm.used / (1024**3), 2),
        "swap_percent": round(sm.percent, 1),
    }

    # Wait for PowerShell telemetry collector
    _, stderr = ps_proc.communicate(timeout=60)
    if ps_proc.returncode != 0 and not raw_json_path.exists():
        raise RuntimeError(f"PowerShell telemetry collector failed: {stderr}")

    windows_raw = json.loads(raw_json_path.read_text(encoding="utf-8-sig"))

    return TelemetryBundle(
        windows_raw=windows_raw,
        processes_by_pid=processes_by_pid,
        logical_cpu_count=logical_cpus,
        physical_cpu_count=physical_cpus,
        sample_count=sample_count,
        sample_interval_sec=sample_interval,
        system_cpu_samples_pct=system_cpu_samples,
        per_core_peak_pct=per_core_peak,
        per_core_avg_pct=per_core_avg,
        psutil_mem_summary=mem_summary,
    )

