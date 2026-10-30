"""CSV-repository-driven, dependency-aware 4-tier safety classification engine for Windows services."""

from __future__ import annotations

from .repository_loader import ServiceRepository
from .service_discovery import WindowsServiceRecord

# Tier constants
TIER_SAFE_DISABLE = "SAFE_TO_DISABLE"
TIER_CONDITIONAL_DISABLE = "CONDITIONAL_DISABLE"
TIER_SET_MANUAL = "SET_TO_MANUAL"
TIER_ALREADY_DISABLED = "ALREADY_DISABLED"
TIER_KEEP = "DO_NOT_DISABLE"


def classify_service_recommendations(
    services: list[WindowsServiceRecord],
    repo: ServiceRepository,
) -> None:
    """Assign 4-tier safety recommendations to all discovered Windows services using CSV repositories."""
    by_name = {s.name.lower(): s for s in services}

    for svc in services:
        # 0. Per-user dynamic session instances (_<LUID>) cannot be modified directly via Set-Service
        if svc.is_per_user_instance:
            svc.recommendation_tier = TIER_KEEP
            svc.recommendation_action = "Keep (Per-User Session Instance)"
            svc.recommendation_reason = (
                f"Dynamic per-user session instance of `{svc.base_name}` managed automatically by Windows login."
            )
            continue

        # 1. Core Protected Blocklist (data/core_protected_services.csv) always wins
        prot = repo.match_protected(svc.base_name)
        if prot is not None:
            svc.recommendation_tier = TIER_KEEP
            svc.recommendation_action = "Keep Enabled (Protected Core OS / Security / Driver)"
            svc.recommendation_reason = (
                "Listed in `data/core_protected_services.csv`; required for OS stability, security, networking, audio, or display."
            )
            continue

        # 2. Tier 1: Safe to Disable (data/tier1_safe_to_disable.csv)
        t1 = repo.match_tier1(svc.base_name)
        if t1 is not None:
            if svc.start_mode.lower() == "disabled" and svc.state.lower() != "running":
                svc.recommendation_tier = TIER_ALREADY_DISABLED
                svc.recommendation_action = "Already Disabled"
                svc.recommendation_reason = t1.rationale
                continue

            # Ensure no non-Tier-1 active dependent services rely on this service
            blocking_deps: list[str] = []
            for dep_name in svc.active_dependent_services:
                dep_rec = by_name.get(dep_name.lower())
                dep_base = dep_rec.base_name if dep_rec else dep_name
                if repo.match_tier1(dep_base) is None:
                    blocking_deps.append(dep_name)

            if blocking_deps:
                svc.recommendation_tier = TIER_KEEP
                svc.recommendation_action = "Keep (Active Dependents)"
                svc.recommendation_reason = (
                    f"Blocked from disabling because active dependent services rely on it: {', '.join(blocking_deps)}."
                )
            else:
                svc.recommendation_tier = TIER_SAFE_DISABLE
                svc.recommendation_action = "Stop & Set StartupType = Disabled"
                svc.recommendation_reason = t1.rationale
            continue

        # 3. Tier 2: Conditional Disable (data/tier2_conditional_disable.csv)
        t2 = repo.match_tier2(svc.base_name)
        if t2 is not None:
            svc.feature_group = t2.feature_group
            svc.disable_condition = t2.disable_condition
            if svc.start_mode.lower() == "disabled" and svc.state.lower() != "running":
                svc.recommendation_tier = TIER_ALREADY_DISABLED
                svc.recommendation_action = "Already Disabled"
                svc.recommendation_reason = t2.rationale
            else:
                svc.recommendation_tier = TIER_CONDITIONAL_DISABLE
                svc.recommendation_action = f"Optional ({t2.feature_group}): Disable if unused"
                svc.recommendation_reason = t2.rationale
            continue

        # 4. Tier 3: Set Automatic -> Manual (data/tier3_set_to_manual.csv)
        t3 = repo.match_tier3(svc.base_name)
        if t3 is not None:
            if svc.start_mode.lower() == "auto":
                svc.recommendation_tier = TIER_SET_MANUAL
                svc.recommendation_action = "Change StartupType: Automatic -> Manual"
                svc.recommendation_reason = t3.rationale
            else:
                svc.recommendation_tier = TIER_KEEP
                svc.recommendation_action = f"Keep ({svc.start_mode})"
                svc.recommendation_reason = "Already configured for on-demand (`Manual`) startup."
            continue

        # 5. Services already disabled outside Tiers 1-3
        if svc.start_mode.lower() == "disabled" and svc.state.lower() != "running":
            svc.recommendation_tier = TIER_ALREADY_DISABLED
            svc.recommendation_action = "Already Disabled"
            svc.recommendation_reason = "Previously disabled on this system."
            continue

        # 6. Default: Keep as-is
        svc.recommendation_tier = TIER_KEEP
        if svc.state.lower() == "stopped" and svc.start_mode.lower() == "manual":
            svc.recommendation_action = "Keep as Manual (Stopped / 0 CPU)"
            svc.recommendation_reason = (
                "Currently stopped (0% CPU, 0 MB RAM); Windows starts it only on demand when requested."
            )
        else:
            svc.recommendation_action = f"Keep ({svc.start_mode})"
            svc.recommendation_reason = (
                "Standard OS, driver, or active user application service; not flagged for disabling."
            )
