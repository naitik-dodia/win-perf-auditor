"""Generators for Markdown, CSV, and JSON audit reports."""

from __future__ import annotations

import csv
import dataclasses
import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from .recommendation_engine import (
    TIER_ALREADY_DISABLED,
    TIER_CONDITIONAL_DISABLE,
    TIER_KEEP,
    TIER_SAFE_DISABLE,
    TIER_SET_MANUAL,
)
from .root_cause_analyzer import RootCauseReport
from .service_discovery import WindowsServiceRecord


def _md_escape(text: str | None) -> str:
    if not text:
        return ""
    return text.replace("|", "\\|").replace("\r", " ").replace("\n", " ").strip()


def generate_root_cause_markdown(report: RootCauseReport, output_path: Path) -> None:
    """Write the executive and technical root-cause analysis report to Markdown."""
    km = report.key_metrics
    perf_val = km.get("cpu_perf_pct_of_base")
    perf_str = f"`{perf_val:.1f}%` of base clock" if perf_val is not None else "N/A"
    dpc_val = km.get("dpc_time_pct")
    dpc_str = f"`{dpc_val:.2f}%`" if dpc_val is not None else "N/A"
    dpc_status = "Healthy (`< 2.5%`)" if (dpc_val is None or dpc_val < 2.5) else "Elevated (`>= 2.5%` driver ISR/DPC latency)"

    lines: list[str] = [
        "# Windows Performance Slowdown — Root-Cause Diagnostic Report",
        "",
        f"**Generated**: `{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`  ",
        f"**System**: `{km.get('manufacturer')} {km.get('model')}` | `{km.get('os_caption')} (Build {km.get('os_build')})`  ",
        f"**Processor**: `{km.get('cpu_name')}` (`{km.get('physical_cpus')}C / {km.get('logical_cpus')}T`)  ",
        f"**Uptime at Audit**: `{km.get('uptime_minutes')} minutes ({km.get('uptime_hours')} hours)`",
        "",
        "---",
        "",
        "## 1. Executive Verdict",
        "",
        f"**Headline**: {report.verdict_headline}",
        "",
        f"{report.cpu_hypothesis_assessment}",
        "",
        "### System Telemetry Snapshot",
        "",
        "| Metric | Measured Value | Context |",
        "| :--- | :--- | :--- |",
        f"| **Sampled System CPU Load** | Avg `{km.get('sampled_cpu_avg_pct')}%` / Peak `{km.get('sampled_cpu_peak_pct')}%` | Across `{km.get('logical_cpus')}` logical processors |",
        f"| **CPU Clock Performance** | {perf_str} | `> 100%` indicates active Turbo Boost; `< 85%` indicates throttling |",
        f"| **Kernel DPC Latency** | {dpc_str} | {dpc_status} |",
        f"| **Physical Memory (RAM)** | `{km.get('ram_used_gb')} GB` / `{km.get('ram_total_gb')} GB` (`{km.get('ram_used_pct')}%`) | Live physical memory utilization |",
        f"| **Active Processes** | `{km.get('total_processes')}` processes | Active user and system processes |",
        f"| **Windows Services** | `{km.get('running_services')}` Running / `{km.get('auto_services')}` Auto (`{km.get('total_services')}` total) | Audited against CSV repositories in `data/` |",
        f"| **Startup Auto-Launch Items** | `{km.get('startup_items_count')}` entries | Registry `Run` keys and Startup folders |",
        "",
        "---",
        "",
        "## 2. Prioritized Root-Cause Findings",
        "",
    ]

    if not report.findings:
        lines.append("_No critical or high-severity performance bottlenecks were detected during this audit window._")
        lines.append("")
    else:
        for f in report.findings:
            lines.append(f"### [{f.id}] ({f.severity}) {f.title}")
            lines.append(f"- **Subsystem**: `{f.subsystem}`")
            lines.append(f"- **Summary**: {f.summary}")
            lines.append("- **Empirical Evidence**:")
            for ev in f.evidence:
                lines.append(f"  - {ev}")
            lines.append("- **Recommended Fixes**:")
            for step in f.remediation_steps:
                lines.append(f"  1. {step}")
            lines.append("")

    lines.extend([
        "---",
        "",
        "## 3. Top Process Families by Cumulative CPU Burn Since Boot",
        "",
        "| Process Family | Instances | Cumulative CPU (sec) | Sampled Live CPU % (Raw) | RAM Working Set (MB) | Disk I/O Since Boot (MB) | Hosted Windows Services |",
        "| :--- | :---: | ---: | ---: | ---: | ---: | :--- |",
    ])
    for fam in report.top_process_families_by_cpu:
        svcs_str = ", ".join(f"`{s}`" for s in fam.hosted_services[:5])
        if len(fam.hosted_services) > 5:
            svcs_str += f" (+{len(fam.hosted_services) - 5} more)"
        lines.append(
            f"| `{_md_escape(fam.exe_name)}` | {fam.instance_count} | **{fam.cpu_total_seconds:,.1f}s** | "
            f"{fam.live_cpu_avg_raw_pct:.1f}% (peak {fam.live_cpu_peak_raw_pct:.1f}%) | "
            f"{fam.working_set_mb:,.1f} MB | {fam.io_total_mb:,.1f} MB | {svcs_str or '—'} |"
        )

    lines.extend([
        "",
        "## 4. Top Process Families by Memory (RAM) Consumption",
        "",
        "| Process Family | Instances | RAM Working Set (MB) | Private Memory (MB) | Cumulative CPU (sec) | Hosted Windows Services |",
        "| :--- | :---: | ---: | ---: | ---: | :--- |",
    ])
    for fam in report.top_process_families_by_ram:
        svcs_str = ", ".join(f"`{s}`" for s in fam.hosted_services[:5])
        if len(fam.hosted_services) > 5:
            svcs_str += f" (+{len(fam.hosted_services) - 5} more)"
        lines.append(
            f"| `{_md_escape(fam.exe_name)}` | {fam.instance_count} | **{fam.working_set_mb:,.1f} MB** | "
            f"{fam.private_mb:,.1f} MB | {fam.cpu_total_seconds:,.1f}s | {svcs_str or '—'} |"
        )

    lines.extend([
        "",
        "## 5. Top Running Windows Services by Resource Usage",
        "",
        "| Service Name | Display Name | PID | CPU Burn (sec) | Live CPU % | RAM (MB) | Disk I/O (MB) | Recommendation |",
        "| :--- | :--- | :---: | ---: | ---: | ---: | ---: | :--- |",
    ])
    seen_cpu_pids: set[int] = set()
    for s in report.top_services_by_cpu:
        shared_note = f" *(shared x{s.shared_pid_service_count})*" if s.shared_pid_service_count > 1 else ""
        if s.pid in seen_cpu_pids and s.shared_pid_service_count > 1:
            continue
        seen_cpu_pids.add(s.pid)
        lines.append(
            f"| `{s.name}` | {_md_escape(s.display_name)}{shared_note} | {s.pid} | **{s.cpu_total_seconds:,.1f}s** | "
            f"{s.cpu_avg_raw_pct:.1f}% | {s.working_set_mb:.1f} MB | {s.io_total_mb:,.1f} MB | `{s.recommendation_tier}` |"
        )

    lines.extend([
        "",
        "## 6. Windows Startup Auto-Launch Audit (`Win32_StartupCommand`)",
        "",
        "| Startup Entry Name | Registry / Folder Location | User | Launch Command |",
        "| :--- | :--- | :--- | :--- |",
    ])
    for item in report.startup_bloat_items:
        lines.append(
            f"| **{_md_escape(str(item.get('Name')))}** | `{_md_escape(str(item.get('Location')))}` | "
            f"`{_md_escape(str(item.get('User')))}` | `{_md_escape(str(item.get('Command')))}` |"
        )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def generate_services_catalog_markdown(
    services: list[WindowsServiceRecord],
    output_path: Path,
) -> None:
    """Write the complete categorized Windows background services catalog and explanations."""
    tier_counts = defaultdict(int)
    for s in services:
        tier_counts[s.recommendation_tier] += 1

    safe_list = sorted(
        [s for s in services if s.recommendation_tier == TIER_SAFE_DISABLE],
        key=lambda x: (-x.cpu_total_seconds, -x.working_set_mb, x.name.lower()),
    )
    cond_list = sorted(
        [s for s in services if s.recommendation_tier == TIER_CONDITIONAL_DISABLE],
        key=lambda x: ((x.feature_group or "").lower(), -x.cpu_total_seconds, x.name.lower()),
    )
    manual_list = sorted(
        [s for s in services if s.recommendation_tier == TIER_SET_MANUAL],
        key=lambda x: (-x.cpu_total_seconds, -x.working_set_mb, x.name.lower()),
    )

    lines: list[str] = [
        "# Windows Background Services Catalog & Disabling Guide",
        "",
        f"**Total Installed Services Audited**: `{len(services)}`  ",
        f"- **Tier 1 — Safe to Entirely Disable (`{TIER_SAFE_DISABLE}`)**: `{len(safe_list)}` active/enabled matches (from `data/tier1_safe_to_disable.csv`)  ",
        f"- **Tier 2 — Conditionally Safe to Disable (`{TIER_CONDITIONAL_DISABLE}`)**: `{len(cond_list)}` matches requiring human review (from `data/tier2_conditional_disable.csv`)  ",
        f"- **Tier 3 — Switch Automatic -> Manual (`{TIER_SET_MANUAL}`)**: `{len(manual_list)}` matches (from `data/tier3_set_to_manual.csv`)  ",
        f"- **Already Disabled (`{TIER_ALREADY_DISABLED}`)**: `{tier_counts[TIER_ALREADY_DISABLED]}` services  ",
        f"- **Tier 4 — Keep / Protected (`{TIER_KEEP}`)**: `{tier_counts[TIER_KEEP]}` services",
        "",
        "---",
        "",
        "## 1. Tier 1 — Services Safe to Entirely Turn Off & Disable (`SAFE_TO_DISABLE`)",
        "",
        "Matched from `data/tier1_safe_to_disable.csv` and verified to have zero non-Tier-1 active dependent services. Applied by default when running `.\\scripts\\disable-services.ps1`.",
        "",
        "| Service Name | Display Name | State / StartMode | CPU / RAM | What It Does | Why It Can Be Disabled |",
        "| :--- | :--- | :--- | :--- | :--- | :--- |",
    ]
    if not safe_list:
        lines.append("| _None remaining_ | — | — | — | All Tier 1 services on this machine are already disabled. | — |")
    else:
        for s in safe_list:
            lines.append(
                f"| `{s.name}` | {_md_escape(s.display_name)} | `{s.state}` / `{s.start_mode}` | "
                f"{s.cpu_total_seconds:.1f}s / {s.working_set_mb:.1f} MB | "
                f"{_md_escape(s.plain_english_purpose)} | {_md_escape(s.recommendation_reason)} |"
            )

    lines.extend([
        "",
        "---",
        "",
        "## 2. Tier 2 — Conditionally Safe to Disable (`CONDITIONAL_DISABLE`)",
        "",
        "Matched from `data/tier2_conditional_disable.csv`. Protected behind `-IncludeConditional` (plus optional `-ExcludeServices` / `-OnlyFeatureGroups`) so a human can verify feature usage before disabling.",
        "",
        "| Feature Group | Service Name | Display Name | State / StartMode | CPU / RAM / Disk I/O | Condition to Safely Disable | What It Does |",
        "| :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
    ])
    if not cond_list:
        lines.append("| — | _None_ | — | — | — | — | — |")
    else:
        for s in cond_list:
            lines.append(
                f"| `{_md_escape(s.feature_group or 'General')}` | `{s.name}` | {_md_escape(s.display_name)} | "
                f"`{s.state}` / `{s.start_mode}` | "
                f"{s.cpu_total_seconds:.1f}s / {s.working_set_mb:.1f} MB / {s.io_total_mb:,.0f} MB | "
                f"**{_md_escape(s.disable_condition)}** | {_md_escape(s.plain_english_purpose)} |"
            )

    lines.extend([
        "",
        "---",
        "",
        "## 3. Tier 3 — Switch from `Automatic` to `Manual` (`SET_TO_MANUAL`)",
        "",
        "Matched from `data/tier3_set_to_manual.csv`. Switching from `Automatic` to `Manual` prevents 24/7 boot bloat while keeping parent applications functional on demand.",
        "",
        "| Service Name | Display Name | State / StartMode | CPU / RAM | What It Does | Why Switch to `Manual` |",
        "| :--- | :--- | :--- | :--- | :--- | :--- |",
    ])
    if not manual_list:
        lines.append("| _None remaining_ | — | — | — | All matched Tier 3 services on this machine are already set to `Manual`. | — |")
    else:
        for s in manual_list:
            lines.append(
                f"| `{s.name}` | {_md_escape(s.display_name)} | `{s.state}` / `{s.start_mode}` | "
                f"{s.cpu_total_seconds:.1f}s / {s.working_set_mb:.1f} MB | "
                f"{_md_escape(s.plain_english_purpose)} | {_md_escape(s.recommendation_reason)} |"
            )

    lines.extend([
        "",
        "---",
        "",
        "## 4. Complete Active & Auto-Start Background Services Catalog (By Category)",
        "",
        "Every service currently **Running** or configured as **Automatic** on this machine, grouped by subsystem.",
        "",
    ])

    active_or_auto = [
        s for s in services
        if s.state.lower() == "running" or s.start_mode.lower() == "auto"
    ]
    by_cat: dict[str, list[WindowsServiceRecord]] = defaultdict(list)
    for s in active_or_auto:
        by_cat[s.category].append(s)

    for cat in sorted(by_cat.keys()):
        cat_svcs = sorted(by_cat[cat], key=lambda x: x.name.lower())
        lines.append(f"### {cat} (`{len(cat_svcs)}` services)")
        lines.append("")
        lines.append("| Service Name | Display Name | State | StartMode | RAM (MB) | CPU (s) | Recommendation | What This Service Does |")
        lines.append("| :--- | :--- | :--- | :--- | ---: | ---: | :--- | :--- |")
        for s in cat_svcs:
            lines.append(
                f"| `{s.name}` | {_md_escape(s.display_name)} | `{s.state}` | `{s.start_mode}` | "
                f"{s.working_set_mb:.1f} | {s.cpu_total_seconds:.1f} | `{s.recommendation_tier}` | "
                f"{_md_escape(s.plain_english_purpose)} |"
            )
        lines.append("")

    inactive_svcs = sorted(
        [s for s in services if s.state.lower() != "running" and s.start_mode.lower() != "auto"],
        key=lambda x: x.name.lower(),
    )
    lines.extend([
        "---",
        "",
        f"## 5. Inactive (`Stopped` + `Manual` / `Disabled`) Services Reference (`{len(inactive_svcs)}` services)",
        "",
        "| Service Name | Display Name | StartMode | Category | Recommendation | What This Service Does |",
        "| :--- | :--- | :--- | :--- | :--- | :--- |",
    ])
    for s in inactive_svcs:
        lines.append(
            f"| `{s.name}` | {_md_escape(s.display_name)} | `{s.start_mode}` | "
            f"{_md_escape(s.category)} | `{s.recommendation_tier}` | {_md_escape(s.plain_english_purpose)} |"
        )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def export_services_csv_and_json(
    services: list[WindowsServiceRecord],
    report: RootCauseReport,
    csv_path: Path,
    json_path: Path,
) -> None:
    """Export machine-readable CSV and JSON audit datasets."""
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "name",
        "display_name",
        "category",
        "feature_group",
        "vendor_group",
        "state",
        "start_mode",
        "delayed_auto_start",
        "pid",
        "cpu_avg_raw_pct",
        "cpu_total_seconds",
        "working_set_mb",
        "io_total_mb",
        "recommendation_tier",
        "recommendation_action",
        "disable_condition",
        "plain_english_purpose",
        "recommendation_reason",
        "executable_path",
    ]
    with csv_path.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for s in sorted(services, key=lambda x: x.name.lower()):
            row = {k: getattr(s, k) for k in fieldnames}
            writer.writerow(row)

    payload = {
        "generated_at": datetime.now().isoformat(),
        "key_metrics": report.key_metrics,
        "verdict_headline": report.verdict_headline,
        "cpu_hypothesis_assessment": report.cpu_hypothesis_assessment,
        "findings": [dataclasses.asdict(fd) for fd in report.findings],
        "services": [dataclasses.asdict(s) for s in sorted(services, key=lambda x: x.name.lower())],
    }
    json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
