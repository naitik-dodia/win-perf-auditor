"""Forensic discovery helper for AI agents (Claude, Gemini, Antigravity) to identify uncataloged Windows services & processes."""

from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.repository_loader import load_repository


_PS_FORENSIC_SNIPPET = r"""
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'SilentlyContinue'
$jsonFile = $env:WIN_PERF_FORENSIC_PATHS
if ([string]::IsNullOrWhiteSpace($jsonFile) -or -not (Test-Path -LiteralPath $jsonFile)) {
    '{}'
    exit 0
}
$raw = Get-Content -LiteralPath $jsonFile -Raw -Encoding UTF8
if ([string]::IsNullOrWhiteSpace($raw)) {
    '{}'
    exit 0
}
$parsed = ConvertFrom-Json -InputObject $raw
$results = @{}
foreach ($item in $parsed) {
    $p = [string]$item
    if ([string]::IsNullOrWhiteSpace($p)) { continue }
    $expanded = [Environment]::ExpandEnvironmentVariables($p)
    if (-not (Test-Path -LiteralPath $expanded)) { continue }
    $sigStatus = 'Unknown'
    $signer = $null
    try {
        $sig = Get-AuthenticodeSignature -LiteralPath $expanded -ErrorAction SilentlyContinue
        if ($sig) {
            $sigStatus = $sig.Status.ToString()
            if ($sig.SignerCertificate) {
                $signer = $sig.SignerCertificate.Subject
            }
        }
    } catch {}
    $viObj = $null
    try {
        $vi = (Get-Item -LiteralPath $expanded -ErrorAction SilentlyContinue).VersionInfo
        if ($vi) {
            $viObj = @{
                CompanyName     = $vi.CompanyName
                ProductName     = $vi.ProductName
                FileDescription = $vi.FileDescription
                FileVersion     = $vi.FileVersion
            }
        }
    } catch {}
    $results[$p] = @{
        AuthenticodeStatus = $sigStatus
        SignerSubject      = $signer
        VersionInfo        = $viObj
    }
}
$results | ConvertTo-Json -Depth 5 -Compress
"""


def _inspect_binaries_authenticode(paths: list[str]) -> dict[str, dict[str, Any]]:
    """Batch-inspect Authenticode signatures and VersionInfo for unique binary/DLL paths."""
    unique_paths = sorted({p for p in paths if p})
    if not unique_paths:
        return {}

    tmp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", encoding="utf-8", delete=False
        ) as tmp:
            json.dump(unique_paths, tmp)
            tmp_path = Path(tmp.name)

        env = os.environ.copy()
        env["WIN_PERF_FORENSIC_PATHS"] = str(tmp_path)
        proc = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                _PS_FORENSIC_SNIPPET,
            ],
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=45,
            check=False,
        )
    finally:
        if tmp_path and tmp_path.exists():
            try:
                tmp_path.unlink()
            except OSError:
                pass

    out = (proc.stdout or "").strip()
    if not out:
        return {}
    try:
        parsed = json.loads(out)
        return parsed if isinstance(parsed, dict) else {}
    except json.JSONDecodeError:
        return {}


def discover_uncataloged(
    include_stopped: bool = False,
    top_processes_limit: int = 20,
    sample_seconds: float = 1.5,
) -> dict[str, Any]:
    """Return structured forensic dossiers for uncataloged services and top non-service background processes."""
    if platform.system().lower() != "windows":
        raise RuntimeError("Live Windows service & process discovery requires a Windows host.")

    from src.collectors import collect_all_telemetry
    from src.service_discovery import discover_and_correlate_services

    repo = load_repository(PROJECT_ROOT / "data")
    bundle = collect_all_telemetry(
        project_root=PROJECT_ROOT,
        sample_count=2,
        sample_interval=max(0.5, sample_seconds / 2.0),
    )
    services = discover_and_correlate_services(bundle)

    uncataloged_svcs = []
    paths_to_verify: list[str] = []

    for s in services:
        if s.is_per_user_instance:
            # Check whether base template is already cataloged
            if repo.lookup_explanation(s.base_name) is not None:
                continue
        else:
            if repo.lookup_explanation(s.base_name) is not None:
                continue

        if not include_stopped and s.state.lower() != "running" and s.start_mode.lower() != "auto":
            continue

        uncataloged_svcs.append(s)
        if s.executable_path:
            paths_to_verify.append(s.executable_path)
        if s.service_dll:
            paths_to_verify.append(s.service_dll)

    # Identify top background/non-service processes (excluding core Windows system binaries and self)
    self_pid = os.getpid()
    core_win_exes = {
        "system",
        "registry",
        "smss.exe",
        "csrss.exe",
        "wininit.exe",
        "services.exe",
        "lsass.exe",
        "svchost.exe",
        "winlogon.exe",
        "dwm.exe",
        "explorer.exe",
        "sihost.exe",
        "fontdrvhost.exe",
        "taskhostw.exe",
        "runtimebroker.exe",
        "conhost.exe",
        "dllhost.exe",
        "ctfmon.exe",
        "memcompression",
    }

    candidate_procs = []
    for p in bundle.processes_by_pid.values():
        if p.pid == self_pid or p.hosted_services:
            continue
        if p.name.lower() in core_win_exes:
            continue
        if p.name.lower() in {"python.exe", "powershell.exe"} and p.age_seconds < 30:
            continue
        candidate_procs.append(p)

    # Rank non-service processes by combined CPU burn + RAM weight
    candidate_procs.sort(
        key=lambda x: (x.cpu_total_seconds * 2.0 + x.working_set_mb * 0.1 + x.cpu_avg_raw_pct * 5.0),
        reverse=True,
    )

    seen_proc_exes: set[str] = set()
    top_procs = []
    for p in candidate_procs:
        dedup_key = (p.exe or p.name).lower()
        if dedup_key in seen_proc_exes:
            continue
        seen_proc_exes.add(dedup_key)
        top_procs.append(p)
        if p.exe:
            paths_to_verify.append(p.exe)
        if len(top_procs) >= top_processes_limit:
            break

    forensics = _inspect_binaries_authenticode(paths_to_verify)

    svc_dossiers = []
    for s in sorted(uncataloged_svcs, key=lambda x: (-x.cpu_total_seconds, -x.working_set_mb, x.name.lower())):
        target_bin = s.service_dll if (s.is_svchost and s.service_dll) else s.executable_path
        f_info = forensics.get(target_bin or "", {})
        svc_dossiers.append({
            "service_name": s.name,
            "base_name": s.base_name,
            "display_name": s.display_name,
            "state": s.state,
            "start_mode": s.start_mode,
            "delayed_auto_start": s.delayed_auto_start,
            "is_svchost": s.is_svchost,
            "executable_path": s.executable_path,
            "service_dll": s.service_dll,
            "authenticode_status": f_info.get("AuthenticodeStatus", "Unknown"),
            "signer_subject": f_info.get("SignerSubject"),
            "company_name": s.company_name or (f_info.get("VersionInfo") or {}).get("CompanyName"),
            "product_name": s.product_name or (f_info.get("VersionInfo") or {}).get("ProductName"),
            "file_description": s.file_description or (f_info.get("VersionInfo") or {}).get("FileDescription"),
            "scm_description": s.scm_description,
            "required_services": s.required_services,
            "dependent_services": s.dependent_services,
            "active_dependent_services": s.active_dependent_services,
            "cpu_total_seconds": s.cpu_total_seconds,
            "cpu_avg_raw_pct": s.cpu_avg_raw_pct,
            "working_set_mb": s.working_set_mb,
            "io_total_mb": s.io_total_mb,
        })

    proc_dossiers = []
    for p in top_procs:
        f_info = forensics.get(p.exe or "", {})
        v_info = f_info.get("VersionInfo") or {}
        proc_dossiers.append({
            "pid": p.pid,
            "name": p.name,
            "exe": p.exe,
            "cmdline": p.cmdline,
            "username": p.username,
            "authenticode_status": f_info.get("AuthenticodeStatus", "Unknown"),
            "signer_subject": f_info.get("SignerSubject"),
            "company_name": v_info.get("CompanyName"),
            "product_name": v_info.get("ProductName"),
            "file_description": v_info.get("FileDescription"),
            "cpu_total_seconds": p.cpu_total_seconds,
            "cpu_avg_raw_pct": p.cpu_avg_raw_pct,
            "working_set_mb": p.working_set_mb,
            "io_total_mb": p.io_total_mb,
            "num_threads": p.num_threads,
        })

    return {
        "total_installed_services": len(services),
        "uncataloged_service_count": len(svc_dossiers),
        "include_stopped": include_stopped,
        "uncataloged_services": svc_dossiers,
        "top_non_service_processes": proc_dossiers,
    }


def _format_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# Uncataloged Windows Services & Background Processes Dossier",
        "",
        f"- **Total Installed Services**: `{payload['total_installed_services']}`",
        f"- **Uncataloged Services Found** (`include_stopped={payload['include_stopped']}`): `{payload['uncataloged_service_count']}`",
        "",
        "## 1. Uncataloged Windows Services (Candidates for `data/*.csv`)",
        "",
    ]
    svcs = payload["uncataloged_services"]
    if not svcs:
        lines.append("_All active/automatic services on this machine are already cataloged in `data/*.csv`! Pass `--include-stopped` to inspect stopped manual services._")
        lines.append("")
    else:
        for s in svcs:
            bin_shown = s["service_dll"] if (s["is_svchost"] and s["service_dll"]) else s["executable_path"]
            lines.extend([
                f"### `{s['base_name']}` ({s['display_name']})",
                f"- **State / StartMode**: `{s['state']}` / `{s['start_mode']}` (Delayed={s['delayed_auto_start']})",
                f"- **Binary / ServiceDll**: `{bin_shown}` (svchost={s['is_svchost']})",
                f"- **Authenticode Signature**: `{s['authenticode_status']}` — `{s['signer_subject'] or 'Unsigned / Unknown'}`",
                f"- **Vendor / Product**: `{s['company_name'] or 'Unknown'}` | `{s['product_name'] or 'Unknown'}` | `{s['file_description'] or ''}`",
                f"- **SCM Description**: {s['scm_description'] or '_None_'}",
                f"- **Dependencies**: Requires={s['required_services']} | Dependents={s['dependent_services']} (Active={s['active_dependent_services']})",
                f"- **Footprint**: CPU `{s['cpu_total_seconds']}s` (live `{s['cpu_avg_raw_pct']}%`) | RAM `{s['working_set_mb']} MB` | Disk I/O `{s['io_total_mb']} MB`",
                "",
            ])

    lines.extend([
        "## 2. Top Non-Service Background & User Processes",
        "",
        "| Process | PID | CPU (s) | Live CPU % | RAM (MB) | Authenticode | Publisher / Description | Path |",
        "| :--- | :---: | ---: | ---: | ---: | :--- | :--- | :--- |",
    ])
    for p in payload["top_non_service_processes"]:
        pub = " — ".join(x for x in [p["company_name"], p["file_description"]] if x) or "Unknown"
        lines.append(
            f"| `{p['name']}` | {p['pid']} | {p['cpu_total_seconds']:.1f}s | {p['cpu_avg_raw_pct']:.1f}% | "
            f"{p['working_set_mb']:.1f} | `{p['authenticode_status']}` | {pub} | `{p['exe'] or ''}` |"
        )
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Discover uncataloged Windows services and top background processes with Authenticode forensics."
    )
    parser.add_argument(
        "--include-stopped",
        action="store_true",
        help="Also include stopped Manual/Disabled services not yet present in data/*.csv.",
    )
    parser.add_argument(
        "--top-processes",
        type=int,
        default=15,
        help="Number of top unique non-service processes to inspect (default: 15).",
    )
    parser.add_argument(
        "--format",
        choices=["markdown", "json"],
        default="markdown",
        help="Output format for AI agent consumption (default: markdown).",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Optional file path to write output (defaults to stdout).",
    )
    args = parser.parse_args(argv)

    payload = discover_uncataloged(
        include_stopped=args.include_stopped,
        top_processes_limit=max(1, args.top_processes),
    )
    rendered = json.dumps(payload, indent=2) if args.format == "json" else _format_markdown(payload)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
        print(f"Wrote forensic discovery output to: {args.output}")
    else:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        print(rendered)
    return 0


if __name__ == "__main__":
    sys.exit(main())
