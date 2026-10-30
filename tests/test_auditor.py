"""Comprehensive unit and integration tests for the open-source Windows Performance & Service Auditor."""

from __future__ import annotations

import csv
import io
import json
import os
import platform
import shutil
import subprocess
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from typing import Any

import audit
from src.collectors import ProcessMetrics, TelemetryBundle
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
from src.repository_loader import load_and_validate_repository, load_repository
from src.root_cause_analyzer import analyze_root_causes
from src.service_discovery import WindowsServiceRecord, discover_and_correlate_services
from src.service_knowledge_base import enrich_service_explanations

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"


def _make_svc(
    name: str,
    base_name: str | None = None,
    state: str = "Running",
    start_mode: str = "Auto",
    is_per_user: bool = False,
    deps: list[str] | None = None,
    active_deps: list[str] | None = None,
    cpu_total_seconds: float = 0.0,
    cpu_lifetime_core_pct: float = 0.0,
    cpu_avg_raw_pct: float = 0.0,
    working_set_mb: float = 10.0,
    io_total_mb: float = 0.0,
) -> WindowsServiceRecord:
    return WindowsServiceRecord(
        name=name,
        base_name=base_name or name,
        is_per_user_instance=is_per_user,
        display_name=name,
        state=state,
        start_mode=start_mode,
        delayed_auto_start=False,
        pid=1234 if state == "Running" else 0,
        path_name=None,
        executable_path=None,
        service_dll=None,
        company_name=None,
        product_name=None,
        file_description=None,
        service_type="Own Process",
        start_name="LocalSystem",
        scm_description="Test description",
        dependent_services=deps or [],
        active_dependent_services=active_deps or [],
        cpu_total_seconds=cpu_total_seconds,
        cpu_lifetime_core_pct=cpu_lifetime_core_pct,
        cpu_avg_raw_pct=cpu_avg_raw_pct,
        working_set_mb=working_set_mb,
        io_total_mb=io_total_mb,
    )


def _make_telemetry_bundle(
    windows_raw: dict[str, Any] | None = None,
    processes: list[ProcessMetrics] | None = None,
    cpu_samples: list[float] | None = None,
    mem_pct: float = 45.0,
    mem_used_gb: float = 14.4,
    mem_total_gb: float = 32.0,
    logical_cpus: int = 16,
    physical_cpus: int = 10,
) -> TelemetryBundle:
    proc_map = {p.pid: p for p in (processes or [])}
    samples = cpu_samples if cpu_samples is not None else [8.0, 10.0, 9.0]
    return TelemetryBundle(
        windows_raw=windows_raw or {},
        processes_by_pid=proc_map,
        logical_cpu_count=logical_cpus,
        physical_cpu_count=physical_cpus,
        sample_count=len(samples),
        sample_interval_sec=0.5,
        system_cpu_samples_pct=samples,
        per_core_peak_pct=[20.0] * logical_cpus,
        per_core_avg_pct=[9.0] * logical_cpus,
        psutil_mem_summary={
            "total_gb": mem_total_gb,
            "available_gb": round(mem_total_gb - mem_used_gb, 2),
            "used_gb": mem_used_gb,
            "percent": mem_pct,
            "swap_total_gb": 8.0,
            "swap_used_gb": 0.2,
            "swap_percent": 2.5,
        },
    )


class TestCsvRepositoryAndClassifier(unittest.TestCase):
    def test_shipped_csv_repositories_are_valid(self) -> None:
        repo, errors = load_and_validate_repository(DATA_DIR)
        self.assertEqual(errors, [], f"CSV validation errors: {errors}")
        self.assertGreater(len(repo.protected), 50)
        self.assertGreater(len(repo.tier1), 10)
        self.assertGreater(len(repo.tier2), 20)
        self.assertGreater(len(repo.tier3), 10)
        self.assertGreater(len(repo.catalog_ref), 30)

    def test_protected_collision_in_pr_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            for csv_file in DATA_DIR.glob("*.csv"):
                shutil.copy2(csv_file, tmp_dir / csv_file.name)

            t1_path = tmp_dir / "tier1_safe_to_disable.csv"
            with t1_path.open("a", encoding="utf-8", newline="") as f:
                f.write("RpcSs,exact,Core,Microsoft,RPC runtime,Bad PR rule\n")

            _, errors = load_and_validate_repository(tmp_dir)
            self.assertTrue(
                any("collides with protected core service" in e for e in errors),
                f"Expected protected collision error, got: {errors}",
            )
            with self.assertRaises(ValueError):
                load_repository(tmp_dir)

    def test_duplicate_across_tiers_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            for csv_file in DATA_DIR.glob("*.csv"):
                shutil.copy2(csv_file, tmp_dir / csv_file.name)

            t3_path = tmp_dir / "tier3_set_to_manual.csv"
            with t3_path.open("a", encoding="utf-8", newline="") as f:
                f.write("RetailDemo,exact,Kiosk,Microsoft,Retail demo,Duplicate rule\n")

            _, errors = load_and_validate_repository(tmp_dir)
            self.assertTrue(
                any("Duplicate rule" in e for e in errors),
                f"Expected duplicate rule error, got: {errors}",
            )

    def test_broad_or_malformed_wildcards_and_invalid_match_type_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            for csv_file in DATA_DIR.glob("*.csv"):
                shutil.copy2(csv_file, tmp_dir / csv_file.name)

            t3_path = tmp_dir / "tier3_set_to_manual.csv"
            with t3_path.open("a", encoding="utf-8", newline="") as f:
                f.write("Ab*,wildcard,Test,Vendor,Too short wildcard,Bad wildcard\n")
                f.write("NoStarPattern,wildcard,Test,Vendor,Missing star,Bad wildcard\n")
                f.write("BadMatchSvc,regex,Test,Vendor,Invalid match type,Bad match_type\n")

            _, errors = load_and_validate_repository(tmp_dir)
            self.assertTrue(any("dangerously broad" in e for e in errors), errors)
            self.assertTrue(any("contains no '*' or '?'" in e for e in errors), errors)
            self.assertTrue(any("Invalid match_type 'regex'" in e for e in errors), errors)

    def test_audit_cli_validate_repo_exit_codes(self) -> None:
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc_ok = audit.main(["--validate-repo", "--data-dir", str(DATA_DIR)])
        self.assertEqual(rc_ok, 0)
        self.assertIn("[OK]", buf.getvalue())

        with tempfile.TemporaryDirectory() as empty_tmp:
            buf_err = io.StringIO()
            with redirect_stdout(buf_err):
                rc_fail = audit.main(["--validate-repo", "--data-dir", empty_tmp])
            self.assertEqual(rc_fail, 1)
            self.assertIn("Missing required CSV repository file", buf_err.getvalue())

    def test_core_protected_services_never_disabled(self) -> None:
        repo = load_repository(DATA_DIR)
        critical = [_make_svc(name) for name in ("RpcSs", "DcomLaunch", "WinDefend", "WlanSvc", "Audiosrv")]
        classify_service_recommendations(critical, repo)
        for s in critical:
            self.assertEqual(s.recommendation_tier, TIER_KEEP)

    def test_safe_to_disable_dependency_checks_and_tier1_co_dependents(self) -> None:
        repo = load_repository(DATA_DIR)
        # Blocked when active dependent is protected / non-Tier-1
        svc_blocked = _make_svc("InventorySvc", active_deps=["RpcSs"])
        svc_rpc = _make_svc("RpcSs")
        classify_service_recommendations([svc_blocked, svc_rpc], repo)
        self.assertEqual(svc_blocked.recommendation_tier, TIER_KEEP)

        # Allowed when active dependent is ALSO a Tier 1 service
        svc_t1_parent = _make_svc("InventorySvc", active_deps=["RetailDemo"])
        svc_t1_child = _make_svc("RetailDemo")
        classify_service_recommendations([svc_t1_parent, svc_t1_child], repo)
        self.assertEqual(svc_t1_parent.recommendation_tier, TIER_SAFE_DISABLE)
        self.assertEqual(svc_t1_child.recommendation_tier, TIER_SAFE_DISABLE)

    def test_per_user_and_already_disabled_and_manual_tier3_states(self) -> None:
        repo = load_repository(DATA_DIR)
        per_user = _make_svc("cbdhsvc_7a4e1", base_name="cbdhsvc", is_per_user=True)
        disabled_t1 = _make_svc("RetailDemo", state="Stopped", start_mode="Disabled")
        disabled_t2 = _make_svc("Fax", state="Stopped", start_mode="Disabled")
        disabled_other = _make_svc("CustomStoppedSvc", state="Stopped", start_mode="Disabled")
        already_manual_t3 = _make_svc("GoogleUpdaterService130.0", state="Stopped", start_mode="Manual")

        svcs = [per_user, disabled_t1, disabled_t2, disabled_other, already_manual_t3]
        classify_service_recommendations(svcs, repo)

        self.assertEqual(per_user.recommendation_tier, TIER_KEEP)
        self.assertIn("Per-User Session Instance", per_user.recommendation_action)
        self.assertEqual(disabled_t1.recommendation_tier, TIER_ALREADY_DISABLED)
        self.assertEqual(disabled_t2.recommendation_tier, TIER_ALREADY_DISABLED)
        self.assertEqual(disabled_other.recommendation_tier, TIER_ALREADY_DISABLED)
        self.assertEqual(already_manual_t3.recommendation_tier, TIER_KEEP)

    def test_wildcard_tier3_and_tier2_feature_groups_and_tier1_match(self) -> None:
        repo = load_repository(DATA_DIR)
        g_upd = _make_svc("GoogleUpdaterService199.0.9999.0", state="Stopped", start_mode="Auto")
        w_search = _make_svc("WSearch", state="Running", start_mode="Auto")
        inv = _make_svc("InventorySvc", state="Running", start_mode="Auto")
        svcs = [g_upd, w_search, inv]
        enrich_service_explanations(svcs, repo)
        classify_service_recommendations(svcs, repo)

        self.assertEqual(g_upd.recommendation_tier, TIER_SET_MANUAL)
        self.assertEqual(w_search.recommendation_tier, TIER_CONDITIONAL_DISABLE)
        self.assertEqual(w_search.feature_group, "Search & Indexing")
        self.assertTrue(bool(w_search.disable_condition))
        self.assertEqual(inv.recommendation_tier, TIER_SAFE_DISABLE)

    def test_ai_guidance_and_skill_files_conform_to_conventions_and_csv_headers(self) -> None:
        claude_md = PROJECT_ROOT / "CLAUDE.md"
        gemini_md = PROJECT_ROOT / "GEMINI.md"
        root_skill_md = PROJECT_ROOT / "SKILL.md"
        agent_skill_md = PROJECT_ROOT / ".agents" / "skills" / "identify-windows-services" / "SKILL.md"
        forensic_script = PROJECT_ROOT / "scripts" / "find_uncataloged_services.py"

        for path in (claude_md, gemini_md, root_skill_md, agent_skill_md, forensic_script):
            self.assertTrue(path.is_file(), f"Missing expected AI discovery file: {path}")

        for rule_file in (claude_md, gemini_md):
            text = rule_file.read_text(encoding="utf-8")
            self.assertFalse(
                text.lstrip().startswith("---"),
                f"{rule_file.name} must not start with YAML frontmatter.",
            )
        self.assertLess(
            gemini_md.stat().st_size,
            24_000,
            "GEMINI.md must remain under the 24,000-byte workspace rule limit.",
        )

        root_skill_text = root_skill_md.read_text(encoding="utf-8")
        agent_skill_text = agent_skill_md.read_text(encoding="utf-8")
        self.assertEqual(
            root_skill_text,
            agent_skill_text,
            "Root SKILL.md and .agents/skills/identify-windows-services/SKILL.md should stay identical.",
        )
        self.assertTrue(root_skill_text.startswith("---\n"), "SKILL.md must begin with YAML frontmatter.")
        parts = root_skill_text.split("---", 2)
        self.assertGreaterEqual(len(parts), 3, "SKILL.md YAML frontmatter is not properly closed.")
        frontmatter = parts[1]
        self.assertIn("name: identify-windows-services", frontmatter)
        self.assertIn("description:", frontmatter)

        # Verify every actual CSV header in data/*.csv is documented verbatim inside SKILL.md
        for csv_path in DATA_DIR.glob("*.csv"):
            first_line = csv_path.read_text(encoding="utf-8-sig").splitlines()[0].strip()
            self.assertIn(
                first_line,
                root_skill_text,
                f"CSV header '{first_line}' from {csv_path.name} is out of sync with SKILL.md!",
            )


class TestServiceDiscoveryAndKnowledgeBase(unittest.TestCase):
    def test_luid_normalization_svchost_correlation_and_fallbacks(self) -> None:
        p_svchost = ProcessMetrics(
            pid=900,
            name="svchost.exe",
            exe=r"C:\Windows\System32\svchost.exe",
            cpu_avg_raw_pct=4.5,
            cpu_total_seconds=42.0,
            working_set_mb=64.0,
            io_total_mb=120.0,
        )
        raw_services = [
            {
                "Name": "cbdhsvc",
                "DisplayName": "Clipboard User Service",
                "State": "Stopped",
                "StartMode": "Manual",
                "ProcessId": 0,
                "ExecutablePath": r"C:\Windows\System32\svchost.exe",
                "ServiceDll": r"C:\Windows\System32\cbdhsvc.dll",
                "CompanyName": "Microsoft Corporation",
            },
            {
                "Name": "cbdhsvc_7a4e1",
                "DisplayName": "Clipboard User Service_7a4e1",
                "State": "Running",
                "StartMode": "Manual",
                "ProcessId": 900,
                "ExecutablePath": r"C:\Windows\System32\svchost.exe",
                "ServiceDll": r"C:\Windows\System32\cbdhsvc.dll",
                "CompanyName": "Microsoft Corporation",
            },
            {
                "Name": "CDPUserSvc_7a4e1",
                "DisplayName": "Connected Devices Platform User Service_7a4e1",
                "State": "Running",
                "StartMode": "Auto",
                "ProcessId": 900,
                "ExecutablePath": r"C:\Windows\System32\svchost.exe",
                "ServiceDll": r"C:\Windows\System32\cdpusersvc.dll",
                "CompanyName": "Microsoft Corporation",
            },
            {
                "Name": "vmictimesync",
                "DisplayName": "Hyper-V Time Synchronization Service",
                "State": "Stopped",
                "StartMode": "Manual",
                "ProcessId": 0,
                "ExecutablePath": r"C:\Windows\System32\svchost.exe",
                "CompanyName": "Microsoft Corporation",
            },
            {
                "Name": "vmiccustomext",
                "DisplayName": "Hyper-V Custom Integration Extension",
                "State": "Stopped",
                "StartMode": "Manual",
                "ProcessId": 0,
                "ExecutablePath": r"C:\Windows\System32\svchost.exe",
                "CompanyName": "Microsoft Corporation",
            },
            {
                "Name": "CustomAsusHelper_badf",
                "DisplayName": "ASUS Custom Helper",  # DisplayName does NOT end in _badf -> not a LUID service
                "State": "Stopped",
                "StartMode": "Manual",
                "ProcessId": 0,
                "ExecutablePath": r"C:\Program Files\ASUS\Helper.exe",
                "CompanyName": "ASUSTeK COMPUTER INC.",
                "ProductName": "ASUS System Control",
                "FileDescription": "ASUS Hotkey Daemon",
                "Description": "@%SystemRoot%\\System32\\unexpanded.dll,-100",
            },
        ]
        bundle = _make_telemetry_bundle(windows_raw={"Services": raw_services}, processes=[p_svchost])
        records = discover_and_correlate_services(bundle)
        by_name = {r.name: r for r in records}

        # LUID per-user instance normalized
        cbd_inst = by_name["cbdhsvc_7a4e1"]
        self.assertTrue(cbd_inst.is_per_user_instance)
        self.assertEqual(cbd_inst.base_name, "cbdhsvc")
        self.assertTrue(cbd_inst.is_svchost)
        self.assertEqual(cbd_inst.shared_pid_service_count, 2)
        self.assertEqual(cbd_inst.co_hosted_services, ["CDPUserSvc_7a4e1"])
        self.assertEqual(cbd_inst.cpu_total_seconds, 42.0)
        self.assertEqual(p_svchost.hosted_services, ["CDPUserSvc_7a4e1", "cbdhsvc_7a4e1"])

        # Non-LUID service ending in 4 hex letters after underscore must NOT strip suffix
        asus_rec = by_name["CustomAsusHelper_badf"]
        self.assertFalse(asus_rec.is_per_user_instance)
        self.assertEqual(asus_rec.base_name, "CustomAsusHelper_badf")
        self.assertEqual(asus_rec.vendor_group, "OEM Utility (ASUS)")

        # Enrich explanations (catalog match + vmic heuristic + @dll resource fallback)
        repo = load_repository(DATA_DIR)
        enrich_service_explanations(records, repo)
        self.assertIn("Hyper-V Time Synchronization", by_name["vmictimesync"].plain_english_purpose)
        self.assertIn("Hyper-V guest integration", by_name["vmiccustomext"].plain_english_purpose)
        self.assertIn("ASUS System Control", asus_rec.plain_english_purpose)


class TestRootCauseAnalyzerAndReportGenerator(unittest.TestCase):
    def test_healthy_baseline_reports_zero_bottlenecks(self) -> None:
        raw = {
            "System": {
                "Manufacturer": "GenericCorp",
                "Model": "Workstation",
                "OSCaption": "Microsoft Windows 11 Pro",
                "OSBuild": "26100",
                "UptimeSeconds": 3600,
                "Disks": [{"DeviceID": "C:", "SizeBytes": 1000 * (1024**3), "FreeBytes": 600 * (1024**3)}],
            },
            "Power": {"ActiveScheme": "Balanced", "ProcThrottleMin": {"AC": 5}, "ProcThrottleMax": {"AC": 100}},
            "PerfCounters": {
                r"\Processor Information(_Total)\% Processor Performance": {"Avg": 115.0},
                r"\Processor(_Total)\% DPC Time": {"Avg": 0.4},
                r"\PhysicalDisk(_Total)\% Idle Time": {"Avg": 98.0},
                r"\Memory\Pages/sec": {"Avg": 1.0},
            },
            "EventSignals": {},
            "StartupItems": [{"Name": "SecurityHealth", "Command": "SecurityHealthSystray.exe"}],
        }
        bundle = _make_telemetry_bundle(windows_raw=raw, mem_pct=40.0)
        services = [_make_svc("WinDefend")]
        report = analyze_root_causes(bundle, services)
        self.assertEqual(report.findings, [])
        self.assertIn("No Critical System Bottlenecks Detected", report.verdict_headline)

    def test_all_five_slowdown_detectors_and_report_exports(self) -> None:
        startup_items = [
            {"Name": "ChromeAuto", "Location": "HKCU\\Run", "User": "User", "Command": "chrome.exe --background"},
            {"Name": "SteamAuto", "Location": "HKCU\\Run", "User": "User", "Command": "steam.exe -silent"},
            {"Name": "SteamDup", "Location": "Startup", "User": "User", "Command": "steam.exe -silent"},
        ] + [
            {"Name": f"Helper{i}", "Location": "HKCU\\Run", "User": "User", "Command": f"helper{i}.exe"}
            for i in range(10)
        ]

        raw = {
            "System": {
                "Manufacturer": "TestVendor",
                "Model": "Laptop | PipeEdition",
                "OSCaption": "Microsoft Windows 11 Home",
                "OSBuild": "26100",
                "UptimeSeconds": 1800,
                "Batteries": [{"BatteryStatus": 2}],
                "Disks": [
                    {"DeviceID": "C:", "SizeBytes": 500 * (1024**3), "FreeBytes": 20 * (1024**3)},
                    {"DeviceID": "D:", "SizeBytes": 1000 * (1024**3), "FreeBytes": 800 * (1024**3)},
                ],
            },
            "Power": {
                "ActiveScheme": "High Performance",
                "ProcThrottleMin": {"AC": 100},
                "ProcThrottleMax": {"AC": 80},
            },
            "PerfCounters": {
                r"\Processor Information(_Total)\% Processor Performance": {"Avg": 75.0},
                r"\Processor(_Total)\% DPC Time": {"Avg": 4.2},
                r"\PhysicalDisk(_Total)\% Idle Time": {"Avg": 35.0},
                r"\PhysicalDisk(_Total)\Current Disk Queue Length": {"Avg": 3.5},
                r"\Memory\Pages/sec": {"Avg": 120.0},
            },
            "EventSignals": {
                "ProcessorThrottleEvents": [
                    {"Id": 37, "Message": "The speed of processor 4 in group 0 is being limited by system firmware for 75 seconds."}
                ],
                "DiskWarningEvents": [{"ProviderName": "disk", "Id": 153}],
                "MemoryExhaustionEvents": [{"Id": 2004}],
                "TopCrashingApps": [{"App": "BadUpdater.exe", "Count": 4}],
            },
            "StartupItems": startup_items,
        }
        p_wsl = ProcessMetrics(
            pid=4444,
            name="vmmemWSL",
            working_set_mb=4096.0,
            private_mb=4096.0,
            cpu_total_seconds=120.0,
            cpu_avg_raw_pct=15.0,
        )
        bundle = _make_telemetry_bundle(
            windows_raw=raw,
            processes=[p_wsl],
            mem_pct=93.5,
            mem_used_gb=29.9,
            mem_total_gb=32.0,
        )

        repo = load_repository(DATA_DIR)
        services = [
            _make_svc("WinDefend", cpu_total_seconds=90.0, cpu_lifetime_core_pct=6.0, working_set_mb=280.0),
            _make_svc("mcshield", cpu_total_seconds=140.0, cpu_lifetime_core_pct=9.5, working_set_mb=350.0),
            _make_svc("WSearch", cpu_total_seconds=85.0, io_total_mb=8192.0, working_set_mb=150.0),
            _make_svc("DiagTrack", cpu_total_seconds=15.0, working_set_mb=30.0),
            _make_svc("GoogleUpdaterService140.0", state="Stopped", start_mode="Auto"),
        ]
        enrich_service_explanations(services, repo)
        classify_service_recommendations(services, repo)

        report = analyze_root_causes(bundle, services)
        self.assertEqual(len(report.findings), 5, f"Expected all 5 detectors to fire, got: {report.findings}")
        severities = [f.severity for f in report.findings]
        self.assertEqual(severities, sorted(severities, key=lambda s: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}[s]))
        self.assertTrue(any("Concurrent Antivirus Contention" in f.title for f in report.findings))
        self.assertTrue(any("Startup & Background Process Bloat" in f.title for f in report.findings))
        self.assertTrue(any("Event ID 37" in f.title for f in report.findings))
        self.assertTrue(any("Storage Controller / Disk Warnings" in f.title for f in report.findings))
        self.assertTrue(any("Memory Pressure & Pagefile Thrashing" in f.title for f in report.findings))

        # Test all report exports (Markdown + CSV + JSON) in a temporary directory
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp)
            rc_md = out_dir / "root_cause_report.md"
            cat_md = out_dir / "background_services_catalog.md"
            cat_csv = out_dir / "background_services_catalog.csv"
            audit_json = out_dir / "services_audit_data.json"

            generate_root_cause_markdown(report, rc_md)
            generate_services_catalog_markdown(services, cat_md)
            export_services_csv_and_json(services, report, cat_csv, audit_json)

            self.assertTrue(rc_md.is_file())
            self.assertIn("RC-01", rc_md.read_text(encoding="utf-8"))
            self.assertTrue(cat_md.is_file())
            cat_text = cat_md.read_text(encoding="utf-8")
            self.assertIn("DiagTrack", cat_text)
            self.assertIn("WSearch", cat_text)
            self.assertIn("GoogleUpdaterService140.0", cat_text)

            with cat_csv.open("r", encoding="utf-8-sig", newline="") as f:
                rows = list(csv.DictReader(f))
            self.assertEqual(len(rows), 5)

            parsed_json = json.loads(audit_json.read_text(encoding="utf-8"))
            self.assertEqual(len(parsed_json["findings"]), 5)
            self.assertEqual(len(parsed_json["services"]), 5)


@unittest.skipUnless(platform.system().lower() == "windows", "PowerShell integration tests require Windows")
class TestPowerShellSuiteIntegration(unittest.TestCase):
    def test_powershell_scripts_parse_cleanly_without_syntax_errors(self) -> None:
        ps_check = r"""
        $scripts = @(
            'scripts\collect_windows_telemetry.ps1',
            'scripts\disable-services.ps1',
            'scripts\restore-services.ps1'
        )
        foreach ($rel in $scripts) {
            $errors = $null
            $full = Join-Path $PWD $rel
            [System.Management.Automation.Language.Parser]::ParseFile($full, [ref]$null, [ref]$errors) | Out-Null
            if ($errors.Count -gt 0) {
                Write-Error "Parse error in ${rel}: $($errors[0].Message)"
                exit 1
            }
        }
        """
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_check],
            cwd=str(PROJECT_ROOT),
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, f"PowerShell syntax check failed:\n{proc.stderr}\n{proc.stdout}")

    def test_disable_services_dry_run_and_feature_group_filters(self) -> None:
        script_path = PROJECT_ROOT / "scripts" / "disable-services.ps1"
        proc = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(script_path),
                "-DryRun",
                "-IncludeConditional",
                "-ExcludeServices",
                "WSearch,Spooler",
                "-OnlyFeatureGroups",
                "Printing,Smart Cards",
            ],
            cwd=str(PROJECT_ROOT),
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, f"disable-services.ps1 -DryRun failed:\n{proc.stderr}\n{proc.stdout}")
        self.assertIn("DRY RUN PREVIEW", proc.stdout)

    def test_restore_services_dry_run_merges_snapshots_oldest_first(self) -> None:
        restore_script = PROJECT_ROOT / "scripts" / "restore-services.ps1"
        with tempfile.TemporaryDirectory() as tmp:
            bdir = Path(tmp)
            snap1 = bdir / "services_backup_20260101_100000.json"
            snap2 = bdir / "services_backup_20260101_110000.json"

            # Older snapshot recorded DiagTrack as Auto / Running
            snap1.write_text(
                json.dumps({
                    "CreatedAt": "2026-01-01T10:00:00",
                    "Computer": "TEST-PC",
                    "Services": [
                        {
                            "Name": "DiagTrack",
                            "DisplayName": "Connected User Experiences and Telemetry",
                            "OriginalStartMode": "Auto",
                            "OriginalDelayedAutoStart": True,
                            "OriginalState": "Running",
                            "TargetStartMode": "Disabled",
                            "Tier": "Tier1-SafeDisable",
                        }
                    ],
                }),
                encoding="utf-8",
            )
            # Ensure snap2 has a strictly newer LastWriteTime
            os.utime(snap1, (time.time() - 120, time.time() - 120))

            # Newer snapshot saw DiagTrack already Disabled and also added Fax (Manual / Stopped)
            snap2.write_text(
                json.dumps({
                    "CreatedAt": "2026-01-01T11:00:00",
                    "Computer": "TEST-PC",
                    "Services": [
                        {
                            "Name": "DiagTrack",
                            "DisplayName": "Connected User Experiences and Telemetry",
                            "OriginalStartMode": "Disabled",
                            "OriginalDelayedAutoStart": False,
                            "OriginalState": "Stopped",
                            "TargetStartMode": "Disabled",
                            "Tier": "Tier1-SafeDisable",
                        },
                        {
                            "Name": "Fax",
                            "DisplayName": "Fax",
                            "OriginalStartMode": "Manual",
                            "OriginalDelayedAutoStart": False,
                            "OriginalState": "Stopped",
                            "TargetStartMode": "Disabled",
                            "Tier": "Tier1-SafeDisable",
                        },
                    ],
                }),
                encoding="utf-8",
            )

            proc = subprocess.run(
                [
                    "powershell.exe",
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    str(restore_script),
                    "-BackupDirectory",
                    str(bdir),
                    "-DryRun",
                ],
                cwd=str(PROJECT_ROOT),
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, f"restore-services.ps1 -DryRun failed:\n{proc.stderr}\n{proc.stdout}")
            # Must restore DiagTrack to Automatic (Delayed=True), OriginalState=Running from oldest snapshot!
            self.assertIn(
                "Restore DiagTrack -> StartupType=Automatic (Delayed=True), OriginalState=Running",
                proc.stdout,
            )
            self.assertIn(
                "Restore Fax -> StartupType=Manual (Delayed=False), OriginalState=Stopped",
                proc.stdout,
            )


if __name__ == "__main__":
    unittest.main()
