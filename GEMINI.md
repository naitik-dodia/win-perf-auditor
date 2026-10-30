# GEMINI.md — Workspace Rules for Gemini CLI & Google Antigravity

`win-perf-auditor` is an open-source, CSV-repository-driven diagnostic and background service optimization toolkit for Windows 10 and Windows 11.

---

## 1. AI-Assisted Service & Process Discovery Workflow

When asked to identify unfamiliar Windows services, investigate background CPU/RAM/disk hogs, or add newly discovered services to this repository:

1. **Activate the Workspace Skill**: Read and follow `.agents/skills/identify-windows-services/SKILL.md` (also available at the repository root as `SKILL.md`).
2. **Run Forensic Discovery First**:
   - Active/Automatic uncataloged services + top non-service background processes:
     `python scripts/find_uncataloged_services.py`
   - Full sweep including stopped Manual/Disabled services:
     `python scripts/find_uncataloged_services.py --include-stopped`
   - Machine-readable JSON output:
     `python scripts/find_uncataloged_services.py --include-stopped --format json`
3. **Inspect Before Classifying**:
   - Verify `authenticode_status`, `signer_subject`, `executable_path` / `service_dll`, `company_name`, `scm_description`, and `dependent_services` / `active_dependent_services`.
   - **Security Triage**: Flag unsigned or masquerading binaries executing from `%TEMP%`, `%APPDATA%`, or `C:\Users\Public` immediately as potential persistence/security risks rather than cataloging them as normal services.
   - Differentiate **Windows SCM services** (`Win32_Service`, cataloged in `data/*.csv`) from **non-service user/background processes** (managed via `Win32_StartupCommand`, Task Scheduler, or app settings).

---

## 2. CSV Service Repository Architecture (`data/`)

All service explanations and optimization rules live in five UTF-8 CSV repositories consumed by both Python (`src/repository_loader.py`) and PowerShell (`scripts/disable-services.ps1`):

| Repository File | Purpose & Safety Contract |
| :--- | :--- |
| `data/core_protected_services.csv` | **Hard Blocklist**: Critical OS, RPC, DCOM, security, networking, audio, display, and Windows Update/Installer services. Never disabled; blocks colliding rules in CI. |
| `data/tier1_safe_to_disable.csv` | **Tier 1 (Default Disable)**: 100% universally safe to disable on personal/developer Windows 10/11 PCs (pure telemetry uploaders, retail showroom demo, legacy Fax/NetBIOS). |
| `data/tier2_conditional_disable.csv` | **Tier 2 (Human Intervention Required)**: Feature-dependent services (Printing, Windows Search, Smart Cards, Xbox, OEM utilities, secondary AV). Untouched unless `-IncludeConditional` is explicitly passed. Requires `feature_group` and `disable_condition`. |
| `data/tier3_set_to_manual.csv` | **Tier 3 (Default Manual)**: Legitimate `Automatic` updaters, game launchers, and developer/VM daemons that work on-demand when switched from `Automatic` -> `Manual`. |
| `data/service_catalog_reference.csv` | **Informational Catalog**: Plain-English descriptions for legitimate services that should remain in their default state. |

### Classification Rules
- **Conservative Tier Placement**: Whenever a service disables an optional hardware peripheral, OEM laptop hotkey/thermal utility, VPN, KVM tool, or desktop feature, place it in **Tier 2 (`data/tier2_conditional_disable.csv`)**, never Tier 1.
- **Name Normalization**: Strip per-user Windows `_<hex>` LUID suffixes (catalog `cbdhsvc`, not `cbdhsvc_7a4e1`). Use `match_type=wildcard` (at least 4 literal characters, e.g., `GoogleUpdaterService*`) only for versioned service names.
- **CSV Quoting**: Wrap any field containing commas in double quotes (`"..."`).

---

## 3. Safety, Privacy & Compatibility Invariants

- **Zero Personal Telemetry in Git**: Never commit generated files under `reports/` or `backups/`, and never write machine-specific usernames, hostnames, hardware serials, or personal file paths into tracked code, CSVs, tests, or docs.
- **Keep Tier 2 Gated**: Preserve `-IncludeConditional`, `-ExcludeServices`, `-OnlyFeatureGroups`, and `-ExcludeFeatureGroups` in `scripts/disable-services.ps1` so human intervention is always respected.
- **Windows PowerShell 5.1 Compatibility**:
  - Use ASCII `--` instead of UTF-8 em-dashes inside `.ps1` scripts (PowerShell 5.1 parses BOM-less UTF-8 `.ps1` files as Windows-1252).
  - Resolve `$PSScriptRoot`-relative default paths outside `param()` blocks and split `[string[]]` arguments on commas (`$_ -split ','`) for `powershell.exe -File` compatibility.

---

## 4. Mandatory Validation Commands

Run all three checks after modifying `data/*.csv`, `src/`, or `scripts/`:

```powershell
python audit.py --validate-repo
python -m unittest discover -s tests -v
powershell -ExecutionPolicy Bypass -File .\scripts\disable-services.ps1 -DryRun -IncludeConditional
```

