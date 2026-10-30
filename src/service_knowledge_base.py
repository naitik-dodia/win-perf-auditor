"""Enriches discovered Windows services with categories and plain-English explanations from CSV repositories."""

from __future__ import annotations

from .repository_loader import ServiceRepository
from .service_discovery import WindowsServiceRecord


def enrich_service_explanations(
    services: list[WindowsServiceRecord],
    repo: ServiceRepository,
) -> None:
    """Populate `category` and `plain_english_purpose` on every service record using CSV repositories."""
    for svc in services:
        found = repo.lookup_explanation(svc.base_name)
        if found is not None:
            svc.category, svc.plain_english_purpose = found
            continue

        b_low = svc.base_name.lower()
        if b_low.startswith("vmic"):
            svc.category = "Virtualization & Containers"
            svc.plain_english_purpose = (
                f"Hyper-V guest integration service ({svc.display_name}); used only when Windows runs inside a Hyper-V VM."
            )
            continue

        # Fallback category inference for unlisted services
        vg = svc.vendor_group
        if "Security" in vg:
            cat = "Security & Firewall"
        elif "Xbox" in vg:
            cat = "Gaming & Xbox Ecosystem"
        elif "NVIDIA" in vg or "Audio" in vg or "Realtek" in vg:
            cat = "Audio & Display Drivers"
        elif "Hardware" in vg or "OEM" in vg:
            cat = "Hardware & Platform Drivers"
        elif vg.startswith("Third-Party") or "Edge" in vg or "Office" in vg:
            cat = "Third-Party Updaters & Daemons"
        else:
            cat = "Core OS & Kernel Infrastructure"
        svc.category = cat

        # Fallback plain-English purpose from Windows SCM description or binary metadata
        desc = (svc.scm_description or "").strip()
        if desc and not desc.startswith("@"):
            first_sentence = desc.split(". ")[0].strip()
            if not first_sentence.endswith("."):
                first_sentence += "."
            svc.plain_english_purpose = first_sentence
        elif svc.file_description or svc.product_name:
            parts = [p for p in [svc.product_name, svc.file_description] if p]
            svc.plain_english_purpose = f"Background service for {' — '.join(dict.fromkeys(parts))}."
        else:
            svc.plain_english_purpose = f"Windows background service ({svc.display_name})."
