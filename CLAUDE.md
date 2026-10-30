# CLAUDE.md — `win-perf-auditor` Guide for Claude Code

`win-perf-auditor` is an open-source, CSV-repository-driven Windows 10/11 performance diagnostics and background service optimization toolkit. Both the Python audit engine (`audit.py`) and the PowerShell remediation script (`scripts/disable-services.ps1`) consume the CSV service rule repositories in `data/`.

---

## Quick Command Reference

```powershell
# 1. Discover uncataloged Windows services + top non-service background processes (with Authenticode signatures):
python scripts/find_uncataloged_services.py
python scripts/find_uncataloged_services.py --include-stopped --format json

# 2. Run a full read-only Windows slowdown & background service audit:
python audit.py --samples 6 --interval 1.0

# 3. Validate all CSV repositories (schemas, wildcards, duplicates, protected-service collisions):
python audit.py --validate-repo

# 4. Run unit & CSV repository-integrity tests:
python -m unittest discover -s tests -v

# 5. Preview PowerShell service optimizations safely (no Administrator elevation required):
powershell -ExecutionPolicy Bypass -File .\scripts\disable-services.ps1 -DryRun
powershell -ExecutionPolicy Bypass -File .\scripts\disable-services.ps1 -DryRun -IncludeConditional
```

---

## Architecture Overview

- **`audit.py`**: Main CLI entry point (`--samples`, `--interval`, `--data-dir`, `--output-dir`, `--validate-repo`).
- **`data/*.csv`** *(Single Source of Truth)*:
  - `data/core_protected_services.csv` — Hard safety blocklist (RPC, DCOM, security, networking, audio, display, Windows Update/Installer). Never disabled; blocks colliding PR rules in CI.
  - `data/tier1_safe_to_disable.csv` — **Tier 1**: 100% universally safe to disable across standard personal/developer Windows 10/11 PCs (pure telemetry uploaders, retail demo kiosk, legacy Fax/NetBIOS).
  - `data/tier2_conditional_disable.csv` — **Tier 2**: Feature-dependent services gated behind `-IncludeConditional` for human intervention (`feature_group` + `disable_condition`).
  - `data/tier3_set_to_manual.csv` — **Tier 3**: Legitimate `Automatic` app/updater/VM daemons safely switched to `Manual` (on-demand).
  - `data/service_catalog_reference.csv` — Informational plain-English descriptions for legitimate services that remain untouched.
- **`src/`**:
  - `collectors.py` — Parallel multi-sample `psutil` profiler + `scripts/collect_windows_telemetry.ps1` (WMI/CIM, PerfCounters, `powercfg`, Event Logs).
  - `repository_loader.py` — CSV parser, wildcard matcher, and PR integrity/collision validator.
  - `service_discovery.py` — `Win32_Service` discovery, per-user `_<hex>` LUID normalization (`cbdhsvc_7a4e1` -> `cbdhsvc`), `ServiceDll` resolution, and PID correlation.
  - `service_knowledge_base.py` & `recommendation_engine.py` — Plain-English enrichment and dependency-aware 4-tier classifier.
  - `root_cause_analyzer.py` — Hardware-agnostic slowdown detector (multi-AV contention, indexer churn, startup bloat, firmware thermal/power throttling & DPC latency, disk headroom, memory paging).
  - `report_generator.py` — Writes `reports/root_cause_report.md`, `reports/background_services_catalog.{md,csv}`, and `reports/services_audit_data.json`.
- **`scripts/`**:
  - `find_uncataloged_services.py` — AI forensic discovery helper (extracts Authenticode X.509 signatures, PE `VersionInfo`, `ServiceDll`, dependency trees, and CPU/RAM/I/O footprints).
  - `collect_windows_telemetry.ps1` — Read-only Windows CIM/PerfCounter/EventLog collector.
  - `disable-services.ps1` — Elevated CSV-driven service optimizer with JSON state snapshots (`backups/`) and Windows System Restore Point creation.
  - `restore-services.ps1` — Chronological multi-snapshot rollback script.

---

## Accelerating Identification of Unknown Services & Processes

Whenever a user asks what unknown services or background processes on their PC are doing—or wants to add new services from their machine to `data/*.csv`—follow the forensic workflow in **`SKILL.md`** (also mirrored at `.agents/skills/identify-windows-services/SKILL.md`):

1. **Extract Evidence First**: Run `python scripts/find_uncataloged_services.py` (add `--include-stopped` to sweep stopped third-party/OEM services). Never guess a service's behavior solely from its short name.
2. **Verify Authenticode & Path Trust**:
   - Inspect `authenticode_status`, `signer_subject`, and `executable_path` / `service_dll`.
   - **Security Gate**: If a process or service runs from `%TEMP%`, `%APPDATA%`, or `C:\Users\Public` without a valid vendor signature—or masquerades as a core Windows executable (`svchost.exe`, `lsass.exe`, `csrss.exe`) outside `C:\Windows\System32` / `SysWOW64` / `WinSxS`—stop optimization classification and alert the user to a potential malware/persistence indicator.
3. **Check Dependencies & Connectivity Impact**:
   - Check `dependent_services` and `active_dependent_services`. Never place a service with non-Tier-1 dependents into `tier1_safe_to_disable.csv`.
   - Never auto-disable the user's sole active antivirus, active VPN tunnels (`Tailscale`, `WireGuard`, `OpenVPNService`), or active software KVM input tools (`barriers`, `InputLeap`, `Synergy`).
   - Distinguish **Windows SCM services** (managed via `data/*.csv` and `disable-services.ps1`) from **non-service background processes** (managed via Startup Apps / `Win32_StartupCommand`, Task Scheduler, or `.wslconfig`).
4. **Classify Conservatively**:
   - Normalize per-user services to their base template name (strip trailing `_<hex>`).
   - Use `match_type=wildcard` (minimum 4 literal characters, e.g., `GoogleUpdaterService*`) only for version-suffixed service names.
   - **When in doubt between Tier 1 and Tier 2, always choose Tier 2 (`data/tier2_conditional_disable.csv`)** with an explicit `"Disable ONLY if ..."` `disable_condition` so human intervention remains required via `-IncludeConditional`.

---

## Project Invariants & Coding Standards

1. **Human-in-the-Loop Tier 2 Safety**: Never enable Tier 2 (`data/tier2_conditional_disable.csv`) by default in `disable-services.ps1`. It must remain gated behind `-IncludeConditional` (with `-ExcludeServices`, `-OnlyFeatureGroups`, and `-ExcludeFeatureGroups` filtering).
2. **Open-Source Privacy Hygiene**:
   - Never commit files inside `reports/` or `backups/` (except `.gitkeep`).
   - Never introduce machine-specific usernames, hostnames, serial numbers, or local user paths into `src/`, `scripts/`, `data/*.csv`, `tests/`, or Markdown documentation.
3. **Windows PowerShell 5.1 Compatibility**:
   - Built-in `powershell.exe` on Windows 10/11 is PowerShell 5.1, which reads BOM-less UTF-8 `.ps1` files as Windows-1252. Use plain ASCII `--` instead of UTF-8 em-dashes inside `.ps1` files to prevent quote-parsing corruption.
   - Do not evaluate `$PSScriptRoot` inside `param()` default expressions; resolve default paths immediately after `param()`.
   - Normalize `[string[]]` CLI parameters with `$_ -split ','` so `powershell.exe -File ... -ExcludeServices A,B` works seamlessly.
4. **Mandatory Verification Before Completion**:
   - Run `python audit.py --validate-repo` and `python -m unittest discover -s tests -v` after any CSV or Python edit.

