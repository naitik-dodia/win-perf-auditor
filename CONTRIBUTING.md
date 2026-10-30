# Contributing to `win-perf-auditor`

Thank you for helping grow the open-source Windows service optimization knowledge base!

Both the Python audit engine (`audit.py`) and the PowerShell remediation script (`scripts\disable-services.ps1`) read directly from the CSV repositories inside [`data/`](./data). Adding or improving a Windows, OEM, or third-party service rule requires **no Python or PowerShell code changes**—simply submit a Pull Request updating the appropriate CSV file.

---

## Fast-Track Discovery with AI Tools (`CLAUDE.md`, `GEMINI.md`, `SKILL.md`)

To rapidly discover and research services on your Windows PC that are not yet in [`data/`](./data):

1. Run the read-only forensic discovery script:
   ```powershell
   python scripts/find_uncataloged_services.py
   # Or include stopped Manual services:
   python scripts/find_uncataloged_services.py --include-stopped
   ```
   This extracts `ServiceDll` / binary paths, Authenticode X.509 digital signatures, PE `VersionInfo`, dependency graphs, and CPU/RAM/Disk I/O footprints.
2. Open the repository in **Claude Code** ([`CLAUDE.md`](./CLAUDE.md)), **Gemini CLI**, or **Google Antigravity** ([`GEMINI.md`](./GEMINI.md) + [`.agents/skills/identify-windows-services/SKILL.md`](./.agents/skills/identify-windows-services/SKILL.md) / [`SKILL.md`](./SKILL.md)) and ask your AI assistant to evaluate the uncataloged services using the 6-signal forensic rubric and append validated rows to `data/*.csv`.

---

## 1. Choosing the Right CSV Repository

| CSV File | When to Add a Service Here | Applied by Default? |
| :--- | :--- | :--- |
| [`data/tier1_safe_to_disable.csv`](./data/tier1_safe_to_disable.csv) | **100% universally safe to disable** on standard personal/developer Windows 10/11 PCs (pure telemetry uploaders, retail showroom kiosk mode, obsolete dial-up Fax/NetBIOS). Must **never** break hardware, printing, gaming, networking, or user apps. | **Yes** (`Stop` + `Disabled`) |
| [`data/tier2_conditional_disable.csv`](./data/tier2_conditional_disable.csv) | **Feature-dependent services** that are safe to disable *only if* the user does not use a specific hardware peripheral or OS feature (e.g., Printing, Smart Cards, Xbox/Game Pass, Windows Search, OEM touchpad helpers, Secondary/Trial AV). | **No** — gated behind `-IncludeConditional` for human intervention |
| [`data/tier3_set_to_manual.csv`](./data/tier3_set_to_manual.csv) | **Legitimate app/updater/VM daemons** that install themselves as `Automatic` (running 24/7 from boot), which work properly on-demand when switched from `Automatic` → `Manual`. | **Yes** (`Automatic` → `Manual` unless `-SkipManualOptimization`) |
| [`data/core_protected_services.csv`](./data/core_protected_services.csv) | **Critical OS, RPC, Security, Networking, Audio, or Display services** that must **never** be disabled. Any rule in Tiers 1–3 that collides with this file will fail CI validation. | **Hard Blocklist** |
| [`data/service_catalog_reference.csv`](./data/service_catalog_reference.csv) | Informational plain-English explanations for standard services that should remain untouched. | Informational only |

---

## 2. CSV Schemas

Always wrap text fields containing commas in double quotes (`"..."`).

### `data/tier1_safe_to_disable.csv` & `data/tier3_set_to_manual.csv`
```csv
service_name,match_type,category,vendor,purpose,rationale
MapsBroker,exact,Telemetry & Diagnostics,Microsoft,"Downloaded Maps Manager — background updater for offline Bing Maps.","Wastes startup checks unless offline Bing Maps are downloaded."
GoogleUpdaterService*,wildcard,Third-Party Updaters & Daemons,Google,"Google Updater Service — auto-updates Chrome and Google apps.","Setting to Manual avoids boot-time spikes while Chrome updates when opened."
```

### `data/tier2_conditional_disable.csv`
Includes `feature_group` and `disable_condition` so users can safely review or filter features before intervening:
```csv
service_name,match_type,feature_group,category,vendor,disable_condition,purpose,rationale
Spooler,exact,Printing,Printing & Scanning,Microsoft,"Disable ONLY if you never print to physical printers and do not use 'Microsoft Print to PDF'","Print Spooler — queues print jobs to physical and virtual printers.","Frees permanent boot RAM when printing is unused."
```

### `match_type` Rules
- `exact`: Case-insensitive exact match against the service's base name (automatically normalizes Windows per-user `_<hex>` LUID suffixes during auditing).
- `wildcard`: Supports `*` and `?` wildcards (e.g., `GoogleUpdaterService*` for versioned service names). Wildcards must contain at least **4 literal characters** so overly broad patterns cannot pass CI.

---

## 3. Validating Your Pull Request Locally

Before opening a Pull Request, run the built-in repository validator and unit test suite:

```bash
python audit.py --validate-repo
python -m unittest discover -s tests -v
```

The validator checks:
1. All required CSV columns are present and non-empty.
2. `match_type` values and wildcard lengths are safe and well-formed.
3. **Zero collisions** exist between `core_protected_services.csv` and Tiers 1–3.
4. **Zero duplicate rules** exist across Tier 1, Tier 2, and Tier 3.

