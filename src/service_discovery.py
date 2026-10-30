"""Windows Service discovery, LUID normalization, vendor fingerprinting, and PID correlation."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .collectors import ProcessMetrics, TelemetryBundle

_LUID_SUFFIX_RE = re.compile(r"^(.+?)_([0-9a-fA-F]{4,16})$")


@dataclass
class WindowsServiceRecord:
    """Enriched Windows Service record correlated with live process telemetry."""

    name: str
    base_name: str
    is_per_user_instance: bool
    display_name: str
    state: str
    start_mode: str
    delayed_auto_start: bool
    pid: int
    path_name: str | None
    executable_path: str | None
    service_dll: str | None
    company_name: str | None
    product_name: str | None
    file_description: str | None
    service_type: str | None
    start_name: str | None
    scm_description: str | None
    dependent_services: list[str] = field(default_factory=list)
    active_dependent_services: list[str] = field(default_factory=list)
    required_services: list[str] = field(default_factory=list)

    # Vendor & hosting classification
    vendor_group: str = "Unknown"
    is_svchost: bool = False
    shared_pid_service_count: int = 1
    co_hosted_services: list[str] = field(default_factory=list)

    # Correlated Process Metrics (0 if stopped)
    process_name: str | None = None
    cpu_avg_raw_pct: float = 0.0
    cpu_peak_raw_pct: float = 0.0
    cpu_total_seconds: float = 0.0
    cpu_lifetime_core_pct: float = 0.0
    working_set_mb: float = 0.0
    private_mb: float = 0.0
    io_read_mb: float = 0.0
    io_write_mb: float = 0.0
    io_total_mb: float = 0.0
    num_threads: int = 0
    num_handles: int = 0

    # Enriched by CSV repository & recommendation engine
    category: str = ""
    feature_group: str | None = None
    plain_english_purpose: str = ""
    recommendation_tier: str = ""
    recommendation_action: str = ""
    recommendation_reason: str = ""
    disable_condition: str | None = None


def _classify_vendor_group(
    exe_path: str | None,
    company: str | None,
    product: str | None,
    name: str,
) -> str:
    exe_l = (exe_path or "").lower()
    comp_l = (company or "").lower()
    prod_l = (product or "").lower()
    name_l = name.lower()

    # OEM PC Manufacturers
    oem_keywords = {
        "asus": "OEM Utility (ASUS)",
        "armoury": "OEM Utility (ASUS)",
        "rog ": "OEM Utility (ASUS)",
        "micro-star": "OEM Utility (MSI)",
        "msi ": "OEM Utility (MSI)",
        "lenovo": "OEM Utility (Lenovo)",
        "dell ": "OEM Utility (Dell)",
        "alienware": "OEM Utility (Dell/Alienware)",
        "hewlett-packard": "OEM Utility (HP)",
        "hp inc": "OEM Utility (HP)",
        "acer ": "OEM Utility (Acer)",
        "razer": "OEM Utility (Razer)",
        "gigabyte": "OEM Utility (Gigabyte)",
        "samsung": "OEM Utility (Samsung)",
    }
    if name_l.startswith("asus") or "armourycrate" in name_l:
        return "OEM Utility (ASUS)"
    for kw, label in oem_keywords.items():
        if kw in comp_l or kw in prod_l or kw in exe_l:
            return label

    # Silicon / Hardware Driver Services
    if name_l.startswith("nvdisplay") or name_l.startswith("nvcontainer") or "nvcontainer" in exe_l:
        return "Hardware / Driver (NVIDIA)"
    if name_l.startswith("intelaudio") or name_l in {"cplspcon", "dptftcs", "igccservice", "ipfsvc", "jhi_service", "rstmwservice", "wmiregistrationservice", "pieservicenew"}:
        return "Hardware / Driver (Intel)"
    if name_l.startswith("rtkaudio"):
        return "Hardware / Driver (Realtek)"
    hw_keywords = {
        "intel": "Hardware / Driver (Intel)",
        "nvidia": "Hardware / Driver (NVIDIA)",
        "advanced micro devices": "Hardware / Driver (AMD)",
        "realtek": "Hardware / Driver (Realtek)",
        "dolby": "Hardware / Driver (Audio/Dolby)",
        "waves": "Hardware / Driver (Audio/Waves)",
        "nahimic": "Hardware / Driver (Audio/Nahimic)",
        "dts": "Hardware / Driver (Audio/DTS)",
        "mediatek": "Hardware / Driver (MediaTek)",
        "qualcomm": "Hardware / Driver (Qualcomm)",
        "killer": "Hardware / Driver (Killer Networking)",
        "synaptics": "Hardware / Driver (Synaptics)",
        "elan": "Hardware / Driver (ELAN)",
        "thunderbolt": "Hardware / Driver (Thunderbolt)",
    }
    for kw, label in hw_keywords.items():
        if kw in comp_l or kw in prod_l or kw in exe_l:
            return label

    # Microsoft Security / Defender
    if (
        "windows defender" in exe_l
        or "microsoft defender" in prod_l
        or name_l in {"windefend", "wdnisdrv", "wdnissvc", "mpssvc", "securityhealthservice", "sense", "mdcoresvc", "webthreatdefsvc", "webthreatdefusersvc"}
    ):
        return "Microsoft Security & Defender"

    # Microsoft Edge / Store / Xbox / Office
    if "microsoft edge" in exe_l or "microsoft\\copilot" in exe_l or name_l.startswith("edgeupdate") or "microsoftedge" in name_l or "copilot" in name_l:
        return "Microsoft Edge / Copilot"
    if (
        name_l.startswith("xbox")
        or name_l.startswith("xbl")
        or "gamingservices" in name_l
        or "gameinput" in name_l
        or "microsoft gameinput" in exe_l
    ):
        return "Microsoft Xbox & Gaming"
    if "clicktorun" in exe_l or "microsoft office" in exe_l:
        return "Microsoft Office"

    # Core Microsoft Windows OS
    if (
        "microsoft" in comp_l
        or exe_l.startswith("c:\\windows\\")
    ):
        return "Microsoft Windows OS"

    if exe_l:
        return f"Third-Party ({company.strip()})" if company and company.strip() else "Third-Party Software"
    return "Microsoft Windows OS"


def discover_and_correlate_services(bundle: TelemetryBundle) -> list[WindowsServiceRecord]:
    """Build enriched WindowsServiceRecord list and cross-link PIDs with ProcessMetrics."""
    raw_services: list[dict[str, Any]] = bundle.windows_raw.get("Services", []) or []
    all_names_lower = {str(s.get("Name", "")).lower() for s in raw_services}

    known_per_user_prefixes = {
        "aaragent",
        "bcastdvruserservice",
        "bluetoothuserservice",
        "captureservice",
        "cbdhsvc",
        "cdpusersvc",
        "consentuxusersvc",
        "credentialenrollmentmanagerusersvc",
        "deviceassociationbrokersvc",
        "devicepickerusersvc",
        "devicesflowusersvc",
        "messagingservice",
        "npsmsvc",
        "onesyncsvc",
        "penservice",
        "pimindexmaintenancesvc",
        "printworkflowusersvc",
        "udkusersvc",
        "unistoresvc",
        "userdatasvc",
        "webaccountmanagersvc",
        "wpnuserservice",
    }

    # Count services sharing each active PID
    pid_to_service_names: dict[int, list[str]] = {}
    for s in raw_services:
        pid = int(s.get("ProcessId") or 0)
        sname = str(s.get("Name") or "")
        if pid > 0 and sname:
            pid_to_service_names.setdefault(pid, []).append(sname)

    # Populate hosted_services on ProcessMetrics
    for pid, s_names in pid_to_service_names.items():
        p_metric: ProcessMetrics | None = bundle.processes_by_pid.get(pid)
        if p_metric is not None:
            p_metric.hosted_services = sorted(s_names)

    records: list[WindowsServiceRecord] = []
    for s in raw_services:
        name = str(s.get("Name") or "").strip()
        if not name:
            continue

        base_name = name
        is_per_user = False
        disp_raw = str(s.get("DisplayName") or name).strip()
        m = _LUID_SUFFIX_RE.match(name)
        if m:
            candidate_base, hex_suffix = m.group(1), m.group(2)
            if (
                candidate_base.lower() in all_names_lower
                or candidate_base.lower() in known_per_user_prefixes
                or disp_raw.lower().endswith("_" + hex_suffix.lower())
            ):
                base_name = candidate_base
                is_per_user = True

        pid = int(s.get("ProcessId") or 0)
        exe_path = s.get("ExecutablePath")
        is_svchost = bool(exe_path and exe_path.lower().endswith("svchost.exe"))
        company = s.get("CompanyName")
        product = s.get("ProductName")

        co_hosted = [n for n in pid_to_service_names.get(pid, []) if n != name] if pid > 0 else []
        shared_count = len(pid_to_service_names.get(pid, [])) if pid > 0 else 1

        p_metric = bundle.processes_by_pid.get(pid) if pid > 0 else None

        rec = WindowsServiceRecord(
            name=name,
            base_name=base_name,
            is_per_user_instance=is_per_user,
            display_name=str(s.get("DisplayName") or name).strip(),
            state=str(s.get("State") or "Unknown").strip(),
            start_mode=str(s.get("StartMode") or "Unknown").strip(),
            delayed_auto_start=bool(s.get("DelayedAutoStart", False)),
            pid=pid,
            path_name=s.get("PathName"),
            executable_path=exe_path,
            service_dll=s.get("ServiceDll"),
            company_name=company,
            product_name=product,
            file_description=s.get("FileDescription"),
            service_type=s.get("ServiceType"),
            start_name=s.get("StartName"),
            scm_description=(str(s.get("Description")).strip() if s.get("Description") else None),
            dependent_services=list(s.get("DependentServices") or []),
            active_dependent_services=list(s.get("ActiveDependentServices") or []),
            required_services=list(s.get("RequiredServices") or []),
            vendor_group=_classify_vendor_group(exe_path, company, product, base_name),
            is_svchost=is_svchost,
            shared_pid_service_count=max(1, shared_count),
            co_hosted_services=co_hosted,
            process_name=p_metric.name if p_metric else None,
            cpu_avg_raw_pct=p_metric.cpu_avg_raw_pct if p_metric else 0.0,
            cpu_peak_raw_pct=p_metric.cpu_peak_raw_pct if p_metric else 0.0,
            cpu_total_seconds=p_metric.cpu_total_seconds if p_metric else 0.0,
            cpu_lifetime_core_pct=p_metric.cpu_lifetime_core_pct if p_metric else 0.0,
            working_set_mb=p_metric.working_set_mb if p_metric else 0.0,
            private_mb=p_metric.private_mb if p_metric else 0.0,
            io_read_mb=p_metric.io_read_mb if p_metric else 0.0,
            io_write_mb=p_metric.io_write_mb if p_metric else 0.0,
            io_total_mb=p_metric.io_total_mb if p_metric else 0.0,
            num_threads=p_metric.num_threads if p_metric else 0,
            num_handles=p_metric.num_handles if p_metric else 0,
        )
        records.append(rec)

    return records
