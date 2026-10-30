# Windows Performance & Background Service Auditor (`win-perf-auditor`)

An open-source, CSV-repository-driven diagnostic and service optimization toolkit for **Windows 10 & Windows 11**.

`win-perf-auditor` helps you find out *why* a Windows PC feels slower than expected, explains every installed background service in plain English, classifies services against community-curated CSV repositories, and provides safe, reversible PowerShell scripts with one-command rollback.

---

## Key Features

1. **Multi-Dimensional Slowdown Root-Cause Engine**:
   - **Live & Cumulative CPU Profiling**: Multi-sample `psutil` process/core profiling combined with cumulative CPU seconds burned since boot.
   - **Antivirus & Indexer Contention Detection**: Flags concurrent multi-antivirus hook conflicts and high-churn `WSearch` / background indexing loops.
   - **CPU Throttling, Power Policy & DPC Latency**: Inspects Windows Performance Counters (`% Processor Performance`, `% DPC Time`), `powercfg` AC/DC processor limits (e.g., disabled Turbo Boost or locked 100% idle states), and `Kernel-Processor-Power` Event ID `37` firmware thermal throttling logs.
   - **Memory, Startup & Storage Pressure**: Audits `Win32_StartupCommand` auto-launch bloat, heavy VM/container residents (`vmmemWSL`, Docker, VirtualBox), swap paging (`Pages/sec`), SSD free-space headroom, and disk latency/error events.
2. **Service-to-PID Correlation**:
   - Maps all installed `Win32_Service` entries (including split/shared `svchost.exe` hosts and per-user `_<LUID>` services) to live CPU, RAM, Disk I/O, binary publisher metadata, and dependency graphs.
3. **Open-Source CSV Rule Repositories ([`data/`](./data))**:
   - Community-extensible CSV files power **both** the Python audit reports and the PowerShell optimizer—no code changes required to add new services.
4. **AI-Ready Forensic Discovery (`CLAUDE.md`, `GEMINI.md`, `SKILL.md`)**:
   - Pre-configured workspace rules and an agent skill let **Claude Code**, **Gemini CLI**, **Google Antigravity**, and Agent Skills-compatible tools automatically extract Authenticode signatures, `ServiceDll` metadata, dependency graphs, and resource footprints via `scripts/find_uncataloged_services.py` to explain unfamiliar processes and classify new services rapidly.
5. **Human-in-the-Loop Safety & One-Command Rollback**:
   - Enforces a hardcoded Core OS Protected Blocklist (`data/core_protected_services.csv`) and active reverse-dependency checks.
   - Keeps feature-dependent **Tier 2** services safely gated behind `-IncludeConditional` (plus `-ExcludeServices` / `-OnlyFeatureGroups`) for human intervention.
   - Automatically saves pre-change JSON snapshots to `backups/` and supports full multi-snapshot rollback via `scripts\restore-services.ps1`.

---

## Repository Structure

```text
win-perf-auditor/
├── audit.py                           # Main CLI entry point & CSV repository validator
├── CLAUDE.md                          # Workspace guide & invariants for Claude Code
├── GEMINI.md                          # Workspace rules for Gemini CLI & Google Antigravity
├── SKILL.md                           # Reusable AI skill runbook for service/process identification
├── .agents/skills/
│   └── identify-windows-services/
│       └── SKILL.md                   # Auto-discovered workspace skill for AI agents
├── requirements.txt                   # Python dependencies (psutil, colorama)
├── CONTRIBUTING.md                    # Guide for adding services to the CSV repositories
├── data/                              # Open-source CSV service rule repositories
│   ├── core_protected_services.csv    # Hard safety blocklist (never disabled)
│   ├── tier1_safe_to_disable.csv      # Tier 1: Universally safe to disable (telemetry/kiosk/legacy)
│   ├── tier2_conditional_disable.csv  # Tier 2: Feature-dependent (requires -IncludeConditional)
│   ├── tier3_set_to_manual.csv        # Tier 3: Switch Automatic -> Manual (on-demand)
│   └── service_catalog_reference.csv  # Additional plain-English service descriptions
├── src/
│   ├── collectors.py                  # Parallel Python psutil + PowerShell CIM/PerfCounter collectors
│   ├── repository_loader.py           # CSV loader, wildcard matcher & PR safety validator
│   ├── service_discovery.py           # Win32_Service discovery, LUID normalization & PID correlation
│   ├── service_knowledge_base.py      # Enriches services with plain-English explanations
│   ├── recommendation_engine.py       # Dependency-aware 4-tier safety classifier
│   ├── root_cause_analyzer.py         # Generic Windows slowdown root-cause analyzer
│   └── report_generator.py            # Markdown, CSV, and JSON report generators
├── scripts/
│   ├── find_uncataloged_services.py   # Forensic Authenticode & footprint discovery helper for AI tools
│   ├── collect_windows_telemetry.ps1  # Read-only WMI/CIM, PerfCounter, PowerCfg & EventLog helper
│   ├── disable-services.ps1           # CSV-driven Administrator service optimizer
│   └── restore-services.ps1           # Chronological multi-snapshot rollback script
├── tests/
│   └── test_auditor.py                # Unit & CSV repository integrity tests
├── reports/                           # Local generated audit reports (git-ignored)
└── backups/                           # Local service state JSON backups (git-ignored)
```

---

## Quick Start

### 1. Install Requirements
Requires **Windows 10 or Windows 11**, **Python 3.10+**, and **Windows PowerShell 5.1+** (built into Windows):

```powershell
git clone https://github.com/<your-username>/win-perf-auditor.git
cd win-perf-auditor
pip install -r requirements.txt
```

### 2. Run a Read-Only System & Service Audit
```powershell
python audit.py --samples 8 --interval 1.0
```
This performs a 100% read-only audit of your PC and generates local reports inside `./reports/` (which are excluded via `.gitignore` so personal machine telemetry is never committed):
- `reports/root_cause_report.md` — Prioritized slowdown root causes, CPU/RAM process breakdowns, and startup audit.
- `reports/background_services_catalog.md` — Plain-English explanations and safety classifications for every installed service.
- `reports/background_services_catalog.csv` & `reports/services_audit_data.json` — Machine-readable exports.

### 3. Preview Service Optimizations (`-DryRun`)
No Administrator privileges are required for `-DryRun`:

```powershell
# Preview default optimizations (Tier 1 Safe-to-Disable + Tier 3 Automatic -> Manual):
powershell -ExecutionPolicy Bypass -File .\scripts\disable-services.ps1 -DryRun

# Also preview Tier 2 feature-dependent conditional services:
powershell -ExecutionPolicy Bypass -File .\scripts\disable-services.ps1 -DryRun -IncludeConditional
```

### 4. Apply Optimizations (Run PowerShell as Administrator)
Before changing any service, `disable-services.ps1` automatically backs up your exact original `StartMode`, `DelayedAutoStart`, and `State` to `.\backups\services_backup_<timestamp>.json` and attempts to create a Windows System Restore Point.

```powershell
# Apply safe defaults (Tier 1 Disabled + Tier 3 Automatic -> Manual):
powershell -ExecutionPolicy Bypass -File .\scripts\disable-services.ps1
```

#### Human Intervention for Tier 2 (`-IncludeConditional`)
Tier 2 services (`data/tier2_conditional_disable.csv`) are intentionally **not** disabled by default because they power optional hardware or features (such as Printing, Windows Search, Smart Cards, Xbox/Game Pass, or OEM laptop utilities). After reviewing `reports/background_services_catalog.md`, you can selectively apply Tier 2:

```powershell
# Option A: Apply Tier 2 while excluding specific services you use (e.g., keep Printing and Windows Search):
powershell -ExecutionPolicy Bypass -File .\scripts\disable-services.ps1 -IncludeConditional -ExcludeServices Spooler,PrintNotify,WSearch

# Option B: Target ONLY specific Tier 2 feature groups (alongside Tier 1 & Tier 3):
powershell -ExecutionPolicy Bypass -File .\scripts\disable-services.ps1 -IncludeConditional -OnlyFeatureGroups "Smart Cards","Windows Insider","External Drive Utilities"
```

### 5. Roll Back Anytime (Run PowerShell as Administrator)
```powershell
# Preview rollback:
powershell -ExecutionPolicy Bypass -File .\scripts\restore-services.ps1 -DryRun

# Restore original service startup modes and running states:
powershell -ExecutionPolicy Bypass -File .\scripts\restore-services.ps1
```

---

## AI-Assisted Service & Process Discovery (`CLAUDE.md`, `GEMINI.md`, `SKILL.md`)

Every PC has unique OEM drivers, peripheral daemons, and third-party background utilities. This repository ships built-in AI context and skill files so tools like **Claude Code**, **Gemini CLI**, and **Google Antigravity** can immediately investigate unknown services and processes on your machine:

- [`CLAUDE.md`](./CLAUDE.md) — Project architecture, safety invariants, and discovery instructions for Claude Code.
- [`GEMINI.md`](./GEMINI.md) — Always-on workspace rules for Gemini CLI and Google Antigravity.
- [`SKILL.md`](./SKILL.md) & [`.agents/skills/identify-windows-services/SKILL.md`](./.agents/skills/identify-windows-services/SKILL.md) — Step-by-step 6-signal forensic evaluation protocol and 5-tier CSV classification rubric.

You (or your AI assistant) can run the forensic discovery helper directly:

```powershell
# Inspect active/automatic uncataloged services + top non-service background processes:
python scripts/find_uncataloged_services.py

# Sweep ALL uncataloged services (including stopped Manual services) in JSON format:
python scripts/find_uncataloged_services.py --include-stopped --format json
```

Example prompt to give Claude, Gemini, or Antigravity inside this repo:
> *"Find any uncataloged Windows services and heavy background processes on my PC, verify their Authenticode signatures, explain what each one does, and add safe classification entries to `data/*.csv`."*

---

## Contributing New Services

We welcome community Pull Requests adding Windows, OEM (ASUS, Dell, Lenovo, HP, MSI, Razer), and third-party background services to [`data/`](./data)!

1. Edit the appropriate CSV repository in [`data/`](./data) following [`CONTRIBUTING.md`](./CONTRIBUTING.md).
2. Validate your changes locally:
   ```powershell
   python audit.py --validate-repo
   python -m unittest discover -s tests -v
   ```
3. Open a Pull Request!
