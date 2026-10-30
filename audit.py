"""Main CLI entry point for the open-source Windows Performance & Background Service Auditor."""

from __future__ import annotations

import argparse
import platform
import sys
from collections import Counter
from pathlib import Path

from colorama import Fore, Style, init as colorama_init

from src.recommendation_engine import (
    TIER_ALREADY_DISABLED,
    TIER_CONDITIONAL_DISABLE,
    TIER_KEEP,
    TIER_SAFE_DISABLE,
    TIER_SET_MANUAL,
    classify_service_recommendations,
)
from src.report_generator import (
    export_services_csv_and_json,
    generate_root_cause_markdown,
    generate_services_catalog_markdown,
)
from src.repository_loader import load_and_validate_repository
from src.service_knowledge_base import enrich_service_explanations


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Audit Windows 10/11 slowdown root causes and classify background services using open-source CSV repositories."
    )
    parser.add_argument(
        "--samples",
        type=int,
        default=8,
        help="Number of live CPU/PerfCounter intervals to sample (default: 8).",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=1.0,
        help="Seconds between live telemetry samples (default: 1.0).",
    )
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=None,
        help="Path to CSV service repository directory (default: ./data).",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Directory where audit reports will be written (default: ./reports).",
    )
    parser.add_argument(
        "--validate-repo",
        action="store_true",
        help="Validate CSV repository schemas and safety constraints in ./data and exit.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    colorama_init(autoreset=True)
    args = build_arg_parser().parse_args(argv)
    project_root = Path(__file__).resolve().parent
    data_dir = (args.data_dir or (project_root / "data")).resolve()
    reports_dir = (args.output_dir or (project_root / "reports")).resolve()

    repo, errors = load_and_validate_repository(data_dir)
    if errors:
        print(f"{Fore.RED}{Style.BRIGHT}[ERROR] CSV Repository validation failed in {data_dir}:")
        for err in errors:
            print(f"  {Fore.RED}- {err}")
        return 1

    if args.validate_repo:
        print(f"{Fore.GREEN}{Style.BRIGHT}[OK] Validated CSV service repositories in {data_dir}:")
        print(f"  Core Protected Services : {len(repo.protected)}")
        print(f"  Tier 1 (Safe Disable)   : {len(repo.tier1)}")
        print(f"  Tier 2 (Conditional)    : {len(repo.tier2)}")
        print(f"  Tier 3 (Set to Manual)  : {len(repo.tier3)}")
        print(f"  Catalog Reference       : {len(repo.catalog_ref)}")
        return 0

    if platform.system().lower() != "windows":
        print(
            f"{Fore.RED}[ERROR] Live system auditing requires Windows (WMI/CIM & Service Control Manager). "
            f"Use --validate-repo on non-Windows platforms."
        )
        return 1

    from src.collectors import collect_all_telemetry
    from src.root_cause_analyzer import analyze_root_causes
    from src.service_discovery import discover_and_correlate_services

    print(f"{Fore.CYAN}{Style.BRIGHT}=======================================================================")
    print(f"{Fore.CYAN}{Style.BRIGHT}  Windows Performance & Background Service Auditor (win-perf-auditor)")
    print(f"{Fore.CYAN}{Style.BRIGHT}=======================================================================")
    print(
        f"{Fore.CYAN}  Loaded CSV Repositories: "
        f"{len(repo.protected)} protected | {len(repo.tier1)} Tier 1 | {len(repo.tier2)} Tier 2 | {len(repo.tier3)} Tier 3"
    )
    print(
        f"{Fore.YELLOW}[1/5] Collecting live Windows CIM, PerfCounters, Event Logs & psutil samples "
        f"({args.samples} x {args.interval:.1f}s)..."
    )

    bundle = collect_all_telemetry(
        project_root=project_root,
        sample_count=max(2, args.samples),
        sample_interval=max(0.25, args.interval),
    )

    print(f"{Fore.YELLOW}[2/5] Discovering Windows services and correlating active PIDs...")
    services = discover_and_correlate_services(bundle)

    print(f"{Fore.YELLOW}[3/5] Matching services against CSV repositories & 4-tier safety rules...")
    enrich_service_explanations(services, repo)
    classify_service_recommendations(services, repo)

    print(f"{Fore.YELLOW}[4/5] Running generic slowdown root-cause analysis...")
    rc_report = analyze_root_causes(bundle, services)

    rc_md_path = reports_dir / "root_cause_report.md"
    cat_md_path = reports_dir / "background_services_catalog.md"
    cat_csv_path = reports_dir / "background_services_catalog.csv"
    audit_json_path = reports_dir / "services_audit_data.json"
    disable_ps_path = project_root / "scripts" / "disable-services.ps1"
    restore_ps_path = project_root / "scripts" / "restore-services.ps1"

    print(f"{Fore.YELLOW}[5/5] Writing audit reports to {reports_dir}...")
    generate_root_cause_markdown(rc_report, rc_md_path)
    generate_services_catalog_markdown(services, cat_md_path)
    export_services_csv_and_json(services, rc_report, cat_csv_path, audit_json_path)

    counts = Counter(s.recommendation_tier for s in services)
    km = rc_report.key_metrics

    print()
    print(f"{Fore.GREEN}{Style.BRIGHT}=== AUDIT SUMMARY ===")
    print(
        f"  System       : {km.get('manufacturer')} {km.get('model')} | {km.get('os_caption')} (Build {km.get('os_build')})"
    )
    print(
        f"  CPU & RAM    : {km.get('cpu_name')} | Sampled CPU Avg {km.get('sampled_cpu_avg_pct')}% "
        f"(Peak {km.get('sampled_cpu_peak_pct')}%) | RAM {km.get('ram_used_gb')}/{km.get('ram_total_gb')} GB ({km.get('ram_used_pct')}%)"
    )
    print(
        f"  Footprint    : {km.get('total_processes')} processes | {km.get('running_services')} running services "
        f"({km.get('total_services')} total) | {km.get('startup_items_count')} startup entries"
    )
    print()
    print(f"{Fore.CYAN}{Style.BRIGHT}=== DETECTED ROOT CAUSES ({len(rc_report.findings)}) ===")
    if not rc_report.findings:
        print(f"  {Fore.GREEN}No critical or high-severity bottlenecks detected.")
    for f in rc_report.findings:
        sev_color = Fore.RED if f.severity == "CRITICAL" else (Fore.YELLOW if f.severity == "HIGH" else Fore.CYAN)
        print(f"  {sev_color}[{f.id}][{f.severity}]{Style.RESET_ALL} {f.title}")

    print()
    print(f"{Fore.CYAN}{Style.BRIGHT}=== SERVICE CLASSIFICATION BREAKDOWN ===")
    print(f"  {Fore.GREEN}Tier 1 - Safe to Entirely Disable ({TIER_SAFE_DISABLE})      : {counts[TIER_SAFE_DISABLE]}")
    print(f"  {Fore.YELLOW}Tier 2 - Conditionally Safe to Disable ({TIER_CONDITIONAL_DISABLE}): {counts[TIER_CONDITIONAL_DISABLE]}")
    print(f"  {Fore.CYAN}Tier 3 - Switch Automatic -> Manual ({TIER_SET_MANUAL})        : {counts[TIER_SET_MANUAL]}")
    print(f"  {Fore.WHITE}Already Disabled ({TIER_ALREADY_DISABLED})                     : {counts[TIER_ALREADY_DISABLED]}")
    print(f"  {Fore.WHITE}Tier 4 - Protected / Keep ({TIER_KEEP})                   : {counts[TIER_KEEP]}")

    print()
    print(f"{Fore.GREEN}{Style.BRIGHT}=== REPORTS & SCRIPTS ===")
    print(f"  Root-Cause Report    : {rc_md_path}")
    print(f"  Services Catalog (MD): {cat_md_path}")
    print(f"  Services CSV Export  : {cat_csv_path}")
    print(f"  Audit JSON Dataset   : {audit_json_path}")
    print(f"  Disable Script (PS1) : {disable_ps_path}")
    print(f"  Restore Script (PS1) : {restore_ps_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
