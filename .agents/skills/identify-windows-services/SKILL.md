---
name: identify-windows-services
description: >-
  Identifies, researches, and classifies uncataloged Windows background services
  and high-resource processes into the win-perf-auditor CSV repositories.
  Activate when a user wants to find out what unknown Windows services or
  background processes do, diagnose unfamiliar CPU/RAM consumers, or contribute
  new service rules to data/*.csv.
---

# Identify & Classify Windows Services and Background Processes

This skill provides a repeatable forensic workflow for AI coding assistants (Claude Code, Gemini CLI, Google Antigravity, and Agent Skills-compatible tools) to rapidly discover uncataloged Windows background services and processes, verify their authenticity, explain their purpose in plain English, and classify them safely into `data/*.csv`.

---

## When to Use This Skill

Activate this workflow whenever the user asks to:
1. Find and explain unknown or uncataloged services running on their Windows 10/11 PC.
2. Determine what unfamiliar background `.exe` processes or `svchost.exe` instances are doing.
3. Expand the open-source CSV repositories (`data/tier1_safe_to_disable.csv`, `data/tier2_conditional_disable.csv`, `data/tier3_set_to_manual.csv`, `data/core_protected_services.csv`, or `data/service_catalog_reference.csv`) with newly discovered Microsoft, OEM (ASUS, Dell, Lenovo, HP, MSI, Razer, Acer), or third-party services.

---

## Step 1: Run Automated Forensic Discovery

Do **not** guess what a service or process does from its short name alone. Run the built-in read-only forensic discovery helper first:

```powershell
# Inspect active/automatic uncataloged services + top 15 non-service background processes:
python scripts/find_uncataloged_services.py

# Include stopped Manual/Disabled services as well (full machine sweep):
python scripts/find_uncataloged_services.py --include-stopped

# Emit structured JSON for programmatic analysis:
python scripts/find_uncataloged_services.py --include-stopped --top-processes 25 --format json
```

### What `find_uncataloged_services.py` Extracts Automatically
- **Service Metadata**: `service_name`, normalized `base_name` (strips per-user `_<hex>` LUID suffixes), `display_name`, `state`, `start_mode`, `delayed_auto_start`, and `scm_description`.
- **Binary & `ServiceDll` Resolution**: Resolves both standalone executables and shared `svchost.exe` registry `Parameters\ServiceDll` paths.
- **Authenticode Digital Signatures**: Batch-verifies `Get-AuthenticodeSignature` (`Valid`, `NotSigned`, `HashMismatch`, etc.) and extracts the X.509 `SignerSubject` alongside PE `VersionInfo` (`CompanyName`, `ProductName`, `FileDescription`).
- **Dependency Graph**: Lists upstream `required_services`, downstream `dependent_services`, and currently running `active_dependent_services`.
- **Live Resource Footprint**: Captures cumulative CPU seconds burned since boot, live CPU %, Working Set RAM (MB), and Disk I/O (MB).
- **Non-Service Background Processes**: Ranks heavy background processes that are *not* Windows SCM services (e.g., startup tray utilities, updaters, WSL/VM hosts, helper daemons).

If you need deeper inspection on a specific service `<Name>`, run these read-only PowerShell queries:
```powershell
Get-CimInstance Win32_Service -Filter "Name='<Name>'" | Format-List *
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\<Name>"
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\<Name>\Parameters" -ErrorAction SilentlyContinue
```

---

## Step 2: Six-Signal Forensic Evaluation Protocol

Evaluate every discovered service or process across all six signals before recommending an action or adding a CSV row:

### 1. Authenticode Signature & Security Triage (Check First!)
- **`authenticode_status == "Valid"`**: Confirm `signer_subject` matches the expected vendor (e.g., `Microsoft Windows`, `NVIDIA Corporation`, `ASUSTeK COMPUTER INC.`, `Google LLC`).
- **`NotSigned` / `HashMismatch` / Suspicious Path**:
  - Legitimate open-source tools installed by developers sometimes ship unsigned binaries under `C:\Program Files\`. Verify with the user before classifying.
  - **CRITICAL SECURITY GATE**: If a service or process runs from `%TEMP%`, `%APPDATA%`, `%LOCALAPPDATA%\Temp`, or `C:\Users\Public`, OR mimics a core Windows binary name (such as `svchost.exe`, `lsass.exe`, `csrss.exe`, `explorer.exe`) outside `C:\Windows\System32` / `C:\Windows\SysWOW64` / `C:\Windows\WinSxS`, **DO NOT** simply add it to a CSV repository. Immediately warn the user of potential malware or unauthorized persistence.

### 2. Binary / `ServiceDll` Location
- `C:\Windows\System32\*.dll` (via `svchost.exe`): Built-in Windows OS service. Always analyze the `service_dll` filename and description, never `svchost.exe` itself.
- `C:\Windows\System32\DriverStore\FileRepository\...`: Hardware driver companion service (GPU display/telemetry, Wi-Fi/Bluetooth helper, audio DSP, chipset/thermal framework, OEM hotkey controller). Disabling driver-store services can break hardware features or power management.
- `C:\Program Files\...` or `C:\Program Files (x86)\...`: Third-party application, cloud sync client, VPN daemon, updater, anti-cheat service, or OEM utility suite.

### 3. Reverse Dependency Graph (`dependent_services` & `active_dependent_services`)
- Check `dependent_services` and `active_dependent_services` in the dossier.
- **Hard Rule**: Never classify a service into `tier1_safe_to_disable.csv` if any core Windows component or non-Tier-1 service depends on it.

### 4. Per-User LUID & Versioned Service Name Normalization
- **Per-User Services**: Windows appends a session-specific `_<hex>` suffix at runtime (e.g., `cbdhsvc_7a4e1`, `CDPUserSvc_7a4e1`, `WpnUserService_7a4e1`). Always record the **template `base_name`** (`cbdhsvc`, `CDPUserSvc`, `WpnUserService`) with `match_type=exact`.
- **Versioned Third-Party Services**: Updaters frequently embed version numbers in the service name (e.g., `GoogleUpdaterService145.0.7632.16`, `MicrosoftEdgeElevationService131.0`). Use `match_type=wildcard` with a specific prefix of **at least 4 literal characters** (e.g., `GoogleUpdaterService*`). Never use overly broad wildcards like `Asus*` or `Win*` that could match critical driver or OS services.

### 5. Active Connectivity, Input, or Security Role
- Never recommend automatically disabling:
  - The system's **sole active antivirus / endpoint protection** service.
  - **Active VPN or mesh-network tunnels** (`Tailscale`, `WireGuardTunnel$*`, `OpenVPNService`, `ZeroTierOneService`) — disabling cuts remote/VPN connectivity immediately.
  - **Active software KVM / mouse-keyboard sharing daemons** (`barriers`, `InputLeap`, `Synergy`) — disabling freezes input across linked computers.
- If optional, catalog these in `service_catalog_reference.csv` (Keep) or `tier2_conditional_disable.csv` with a clear `disable_condition` warning.

### 6. Non-Service Background Processes (`HostedServices == []`)
- `scripts\disable-services.ps1` manages Windows Service Control Manager (`Win32_Service`) entries only.
- When Section 2 of `find_uncataloged_services.py` surfaces a heavy non-service `.exe` (e.g., OEM RGB lighting apps, browser background helpers, Electron tray apps, `vmmemWSL`), explain to the user *how* it launches:
  - **Startup Registry / Folder**: Inspect via `Get-CimInstance Win32_StartupCommand` or Task Manager -> **Startup apps**.
  - **Task Scheduler**: Inspect via `Get-ScheduledTask | Where-Object State -ne 'Disabled'`.
  - **WSL / Hyper-V**: Managed via `wsl --shutdown` and `%USERPROFILE%\.wslconfig`.

---

## Step 3: Five-Repository Classification Rubric

Assign each newly identified **Windows Service** to **exactly one** CSV repository under `data/`:

| Target CSV File | Strict Inclusion Criteria | Default Script Behavior |
| :--- | :--- | :--- |
| `data/core_protected_services.csv` | Critical OS kernel/user-mode plumbing (RPC, DCOM, PlugPlay, LSM), Windows Defender/Firewall, core TCP/IP/DNS/DHCP/Wi-Fi networking, primary Audio/Display stacks, Windows Installer, or Windows Update engine. | **Hard Blocklist** — never modified; blocks colliding PRs in CI. |
| `data/tier1_safe_to_disable.csv` | **100% universally safe to disable** across standard home, gaming, and developer Windows 10/11 PCs. Restricted to pure telemetry/diagnostic uploaders, retail showroom demo mode, obsolete legacy protocols (Fax, NetBIOS-over-TCP/IP helper when unused), or dead legacy features. Must **never** break hardware, printing, audio, gaming, or networking. | **Stopped & Disabled** by default. |
| `data/tier2_conditional_disable.csv` | **Feature-dependent services** safe to disable *only when* the user confirms they do not use that hardware or feature (e.g., Printing, Scanners/Webcams, Smart Cards, Xbox/Game Pass, Windows Insider, Windows Search indexing, OEM laptop hotkeys/armoury bloatware, secondary/trial Antivirus, Hyper-V/Containers). | **Untouched by default** — requires `-IncludeConditional` (human intervention). |
| `data/tier3_set_to_manual.csv` | Legitimate app updaters, browser elevation helpers, game anti-cheat/launcher services, or developer/VM services that install themselves as `Automatic` (running 24/7 from boot) even though they work properly on-demand when set to `Manual`. | Switched from **`Automatic` -> `Manual`** (not disabled). |
| `data/service_catalog_reference.csv` | Legitimate OS, driver, security, VPN, or user-application services that should remain in their default startup configuration, added so audit reports explain them in plain English instead of falling back to generic heuristics. | **Informational only** — never modified by scripts. |

> **Golden Rule**: When torn between **Tier 1** and **Tier 2**, **always choose Tier 2 (`data/tier2_conditional_disable.csv`)**. Tier 2 keeps human intervention in the loop via `-IncludeConditional`, `-ExcludeServices`, and `-OnlyFeatureGroups`.

---

## Step 4: CSV Schemas & Formatting Rules

- Encode files as **UTF-8** (no machine-specific usernames, serial numbers, or local user paths in descriptions).
- Wrap any field containing commas in standard double quotes (`"..."`). Escape literal double quotes inside a quoted CSV field by doubling them (`""`).
- Use clear, neutral plain English:
  - `purpose`: **What the service is and what it actually does** (e.g., `"ASUS System Analysis — background hardware telemetry and diagnostic helper bundled with MyASUS."`).
  - `rationale`: **Why it belongs in this tier and the performance/safety trade-off** (e.g., `"Runs continuously on boot and polls WMI sensors; safe to disable if you do not use MyASUS diagnostics."`).

### Schema A: `data/core_protected_services.csv`
```csv
service_name,category,purpose
RpcSs,Core OS & Kernel Infrastructure,"Remote Procedure Call (RPC) — foundational inter-process communication broker; disabling prevents Windows from booting."
```

### Schema B: `data/tier1_safe_to_disable.csv` & `data/tier3_set_to_manual.csv`
```csv
service_name,match_type,category,vendor,purpose,rationale
DiagTrack,exact,Telemetry & Diagnostics,Microsoft,"Connected User Experiences and Telemetry — collects diagnostic and usage telemetry in the background.","Safe to disable to reduce background CPU, disk I/O, and network telemetry chatter."
GoogleUpdaterService*,wildcard,Third-Party Updaters & Daemons,Google,"Google Updater Service — background auto-updater for Chrome and Google desktop apps.","Switching from Automatic to Manual eliminates boot-time updater spikes while allowing on-demand updates."
```

### Schema C: `data/tier2_conditional_disable.csv`
Requires `feature_group` (short group label used by `-OnlyFeatureGroups` / `-ExcludeFeatureGroups`) and `disable_condition` (actionable `"Disable ONLY if ..."` human checklist):
```csv
service_name,match_type,feature_group,category,vendor,disable_condition,purpose,rationale
Spooler,exact,Printing,Printing & Scanning,Microsoft,"Disable ONLY if you never print to physical printers and do not use 'Microsoft Print to PDF'","Print Spooler — manages print queues for physical and virtual PDF/XPS printers.","Frees permanent boot RAM and closes historical spooler attack surface when printing is unused."
```
*(Reuse existing `feature_group` names where appropriate—check existing values in `data/tier2_conditional_disable.csv` first so `-OnlyFeatureGroups` stays clean and consistent.)*

### Schema D: `data/service_catalog_reference.csv`
```csv
service_name,match_type,category,purpose
Tailscale,exact,Networking & Connectivity,"Tailscale VPN Daemon — maintains encrypted WireGuard mesh VPN connectivity."
```

---

## Step 5: Mandatory Validation Checklist

After adding or editing any row in `data/*.csv`, you **must** run all three checks before finishing:

```powershell
# 1. Validate CSV schemas, wildcard lengths, duplicate rules, and zero protected-service collisions:
python audit.py --validate-repo

# 2. Run the automated unit & repository-integrity test suite:
python -m unittest discover -s tests -v

# 3. Verify PowerShell CSV parsing and dry-run matching (read-only, no Admin required):
powershell -ExecutionPolicy Bypass -File .\scripts\disable-services.ps1 -DryRun -IncludeConditional
```

All three commands must exit with code `0` before committing or presenting changes as complete.

