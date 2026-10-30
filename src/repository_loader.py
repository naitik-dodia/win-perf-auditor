"""Loader and schema/safety validator for the open-source CSV service repositories."""

from __future__ import annotations

import csv
import fnmatch
from dataclasses import dataclass, field
from pathlib import Path

VALID_MATCH_TYPES = {"exact", "wildcard"}


@dataclass(frozen=True)
class ProtectedServiceRule:
    service_name: str
    category: str
    purpose: str


@dataclass(frozen=True)
class Tier1Rule:
    service_name: str
    match_type: str
    category: str
    vendor: str
    purpose: str
    rationale: str


@dataclass(frozen=True)
class Tier2Rule:
    service_name: str
    match_type: str
    feature_group: str
    category: str
    vendor: str
    disable_condition: str
    purpose: str
    rationale: str


@dataclass(frozen=True)
class Tier3Rule:
    service_name: str
    match_type: str
    category: str
    vendor: str
    purpose: str
    rationale: str


@dataclass(frozen=True)
class CatalogReferenceRule:
    service_name: str
    match_type: str
    category: str
    purpose: str


def _matches_pattern(candidate_base_lower: str, pattern: str, match_type: str) -> bool:
    pat_l = pattern.lower()
    if match_type == "wildcard":
        return fnmatch.fnmatchcase(candidate_base_lower, pat_l)
    return candidate_base_lower == pat_l


@dataclass
class ServiceRepository:
    """In-memory index of all CSV service repositories in `data/`."""

    data_dir: Path
    protected: dict[str, ProtectedServiceRule] = field(default_factory=dict)
    tier1: list[Tier1Rule] = field(default_factory=list)
    tier2: list[Tier2Rule] = field(default_factory=list)
    tier3: list[Tier3Rule] = field(default_factory=list)
    catalog_ref: list[CatalogReferenceRule] = field(default_factory=list)

    def match_protected(self, base_name: str) -> ProtectedServiceRule | None:
        return self.protected.get(base_name.lower())

    def match_tier1(self, base_name: str) -> Tier1Rule | None:
        b_low = base_name.lower()
        for r in self.tier1:
            if _matches_pattern(b_low, r.service_name, r.match_type):
                return r
        return None

    def match_tier2(self, base_name: str) -> Tier2Rule | None:
        b_low = base_name.lower()
        for r in self.tier2:
            if _matches_pattern(b_low, r.service_name, r.match_type):
                return r
        return None

    def match_tier3(self, base_name: str) -> Tier3Rule | None:
        b_low = base_name.lower()
        for r in self.tier3:
            if _matches_pattern(b_low, r.service_name, r.match_type):
                return r
        return None

    def lookup_explanation(self, base_name: str) -> tuple[str, str] | None:
        """Look up (category, purpose) across all CSV repositories."""
        p = self.match_protected(base_name)
        if p:
            return (p.category, p.purpose)
        t1 = self.match_tier1(base_name)
        if t1:
            return (t1.category, t1.purpose)
        t2 = self.match_tier2(base_name)
        if t2:
            return (t2.category, t2.purpose)
        t3 = self.match_tier3(base_name)
        if t3:
            return (t3.category, t3.purpose)
        b_low = base_name.lower()
        for c in self.catalog_ref:
            if _matches_pattern(b_low, c.service_name, c.match_type):
                return (c.category, c.purpose)
        return None


def _read_csv_rows(path: Path, required_columns: list[str], errors: list[str]) -> list[dict[str, str]]:
    if not path.exists():
        errors.append(f"Missing required CSV repository file: {path}")
        return []
    rows: list[dict[str, str]] = []
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames or []
        missing_cols = [c for c in required_columns if c not in fieldnames]
        if missing_cols:
            errors.append(f"{path.name}: Missing required columns: {', '.join(missing_cols)}")
            return []
        for idx, raw_row in enumerate(reader, start=2):
            cleaned = {k: (v or "").strip() for k, v in raw_row.items() if k is not None}
            # Skip completely blank lines
            if not any(cleaned.values()):
                continue
            for col in required_columns:
                if not cleaned.get(col):
                    errors.append(f"{path.name} line {idx}: Empty required column '{col}'")
            rows.append(cleaned)
    return rows


def _validate_match_rule(
    file_label: str,
    service_name: str,
    match_type: str,
    errors: list[str],
) -> None:
    if match_type not in VALID_MATCH_TYPES:
        errors.append(
            f"{file_label} ('{service_name}'): Invalid match_type '{match_type}' (must be 'exact' or 'wildcard')."
        )
    if match_type == "wildcard":
        if "*" not in service_name and "?" not in service_name:
            errors.append(
                f"{file_label} ('{service_name}'): match_type is 'wildcard' but pattern contains no '*' or '?'."
            )
        literal_chars = service_name.replace("*", "").replace("?", "").strip()
        if len(literal_chars) < 4:
            errors.append(
                f"{file_label} ('{service_name}'): Wildcard pattern is dangerously broad (< 4 literal chars)."
            )


def load_and_validate_repository(data_dir: Path) -> tuple[ServiceRepository, list[str]]:
    """Load all CSV files from `data_dir` and return `(ServiceRepository, validation_errors)`."""
    errors: list[str] = []
    repo = ServiceRepository(data_dir=data_dir)

    # 1. Core Protected Services
    prot_rows = _read_csv_rows(
        data_dir / "core_protected_services.csv",
        ["service_name", "category", "purpose"],
        errors,
    )
    for r in prot_rows:
        sname = r["service_name"]
        key = sname.lower()
        if key in repo.protected:
            errors.append(f"core_protected_services.csv: Duplicate service_name '{sname}'.")
        repo.protected[key] = ProtectedServiceRule(
            service_name=sname,
            category=r["category"],
            purpose=r["purpose"],
        )

    seen_tier_patterns: dict[str, str] = {}

    def _register_tier_pattern(source_csv: str, sname: str, mtype: str) -> None:
        _validate_match_rule(source_csv, sname, mtype, errors)
        key = sname.lower()
        if key in seen_tier_patterns:
            errors.append(
                f"{source_csv}: Duplicate rule '{sname}' already defined in {seen_tier_patterns[key]}."
            )
        else:
            seen_tier_patterns[key] = source_csv

        # Ensure rule never matches any protected service
        for prot_key, prot_rule in repo.protected.items():
            if _matches_pattern(prot_key, sname, mtype):
                errors.append(
                    f"{source_csv}: Rule '{sname}' collides with protected core service '{prot_rule.service_name}'!"
                )

    # 2. Tier 1: Safe to Disable
    t1_rows = _read_csv_rows(
        data_dir / "tier1_safe_to_disable.csv",
        ["service_name", "match_type", "category", "vendor", "purpose", "rationale"],
        errors,
    )
    for r in t1_rows:
        mtype = r["match_type"].lower() or "exact"
        _register_tier_pattern("tier1_safe_to_disable.csv", r["service_name"], mtype)
        repo.tier1.append(
            Tier1Rule(
                service_name=r["service_name"],
                match_type=mtype,
                category=r["category"],
                vendor=r["vendor"],
                purpose=r["purpose"],
                rationale=r["rationale"],
            )
        )

    # 3. Tier 2: Conditional Disable
    t2_rows = _read_csv_rows(
        data_dir / "tier2_conditional_disable.csv",
        [
            "service_name",
            "match_type",
            "feature_group",
            "category",
            "vendor",
            "disable_condition",
            "purpose",
            "rationale",
        ],
        errors,
    )
    for r in t2_rows:
        mtype = r["match_type"].lower() or "exact"
        _register_tier_pattern("tier2_conditional_disable.csv", r["service_name"], mtype)
        repo.tier2.append(
            Tier2Rule(
                service_name=r["service_name"],
                match_type=mtype,
                feature_group=r["feature_group"],
                category=r["category"],
                vendor=r["vendor"],
                disable_condition=r["disable_condition"],
                purpose=r["purpose"],
                rationale=r["rationale"],
            )
        )

    # 4. Tier 3: Set to Manual
    t3_rows = _read_csv_rows(
        data_dir / "tier3_set_to_manual.csv",
        ["service_name", "match_type", "category", "vendor", "purpose", "rationale"],
        errors,
    )
    for r in t3_rows:
        mtype = r["match_type"].lower() or "exact"
        _register_tier_pattern("tier3_set_to_manual.csv", r["service_name"], mtype)
        repo.tier3.append(
            Tier3Rule(
                service_name=r["service_name"],
                match_type=mtype,
                category=r["category"],
                vendor=r["vendor"],
                purpose=r["purpose"],
                rationale=r["rationale"],
            )
        )

    # 5. Service Catalog Reference (optional informational explanations)
    ref_path = data_dir / "service_catalog_reference.csv"
    if ref_path.exists():
        ref_rows = _read_csv_rows(
            ref_path,
            ["service_name", "match_type", "category", "purpose"],
            errors,
        )
        seen_ref: set[str] = set()
        for r in ref_rows:
            mtype = r["match_type"].lower() or "exact"
            _validate_match_rule("service_catalog_reference.csv", r["service_name"], mtype, errors)
            rkey = r["service_name"].lower()
            if rkey in seen_ref:
                errors.append(f"service_catalog_reference.csv: Duplicate service_name '{r['service_name']}'.")
            seen_ref.add(rkey)
            repo.catalog_ref.append(
                CatalogReferenceRule(
                    service_name=r["service_name"],
                    match_type=mtype,
                    category=r["category"],
                    purpose=r["purpose"],
                )
            )

    return repo, errors


def load_repository(data_dir: Path) -> ServiceRepository:
    """Load CSV service repository and raise ValueError if any schema or safety check fails."""
    repo, errors = load_and_validate_repository(data_dir)
    if errors:
        joined = "\n  - ".join(errors)
        raise ValueError(f"Service CSV repository validation failed:\n  - {joined}")
    return repo

