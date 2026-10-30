"""Unit and repository-integrity tests for the open-source Windows Service Auditor."""

from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from src.recommendation_engine import (
    TIER_CONDITIONAL_DISABLE,
    TIER_KEEP,
    TIER_SAFE_DISABLE,
    TIER_SET_MANUAL,
    classify_service_recommendations,
)
from src.repository_loader import load_and_validate_repository, load_repository
from src.service_discovery import WindowsServiceRecord
from src.service_knowledge_base import enrich_service_explanations

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"


def _make_svc(
    name: str,
    base_name: str | None = None,
    state: str = "Running",
    start_mode: str = "Auto",
    is_per_user: bool = False,
    deps: list[str] | None = None,
    active_deps: list[str] | None = None,
) -> WindowsServiceRecord:
    return WindowsServiceRecord(
        name=name,
        base_name=base_name or name,
        is_per_user_instance=is_per_user,
        display_name=name,
        state=state,
        start_mode=start_mode,
        delayed_auto_start=False,
        pid=1234 if state == "Running" else 0,
        path_name=None,
        executable_path=None,
        service_dll=None,
        company_name=None,
        product_name=None,
        file_description=None,
        service_type="Own Process",
        start_name="LocalSystem",
        scm_description="Test description",
        dependent_services=deps or [],
        active_dependent_services=active_deps or [],
    )


class TestCsvRepositoryAndClassifier(unittest.TestCase):
    def test_shipped_csv_repositories_are_valid(self) -> None:
        repo, errors = load_and_validate_repository(DATA_DIR)
        self.assertEqual(errors, [], f"CSV validation errors: {errors}")
        self.assertGreater(len(repo.protected), 50)
        self.assertGreater(len(repo.tier1), 10)
        self.assertGreater(len(repo.tier2), 20)
        self.assertGreater(len(repo.tier3), 10)

    def test_protected_collision_in_pr_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            for csv_file in DATA_DIR.glob("*.csv"):
                shutil.copy2(csv_file, tmp_dir / csv_file.name)

            # Simulate a dangerous PR adding RpcSs to tier1_safe_to_disable.csv
            t1_path = tmp_dir / "tier1_safe_to_disable.csv"
            with t1_path.open("a", encoding="utf-8", newline="") as f:
                f.write("RpcSs,exact,Core,Microsoft,RPC runtime,Bad PR rule\n")

            _, errors = load_and_validate_repository(tmp_dir)
            self.assertTrue(
                any("collides with protected core service" in e for e in errors),
                f"Expected protected collision error, got: {errors}",
            )

    def test_duplicate_across_tiers_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            for csv_file in DATA_DIR.glob("*.csv"):
                shutil.copy2(csv_file, tmp_dir / csv_file.name)

            # Simulate duplicate service added to Tier 3 that already exists in Tier 1
            t3_path = tmp_dir / "tier3_set_to_manual.csv"
            with t3_path.open("a", encoding="utf-8", newline="") as f:
                f.write("RetailDemo,exact,Kiosk,Microsoft,Retail demo,Duplicate rule\n")

            _, errors = load_and_validate_repository(tmp_dir)
            self.assertTrue(
                any("Duplicate rule" in e for e in errors),
                f"Expected duplicate rule error, got: {errors}",
            )

    def test_core_protected_services_never_disabled(self) -> None:
        repo = load_repository(DATA_DIR)
        critical = [_make_svc(name) for name in ("RpcSs", "DcomLaunch", "WinDefend", "WlanSvc", "Audiosrv")]
        classify_service_recommendations(critical, repo)
        for s in critical:
            self.assertEqual(s.recommendation_tier, TIER_KEEP)

    def test_safe_to_disable_blocked_if_non_tier1_active_dependent(self) -> None:
        repo = load_repository(DATA_DIR)
        svc_a = _make_svc("InventorySvc", active_deps=["RpcSs"])
        svc_rpc = _make_svc("RpcSs")
        classify_service_recommendations([svc_a, svc_rpc], repo)
        self.assertEqual(svc_a.recommendation_tier, TIER_KEEP)

    def test_wildcard_tier3_and_tier2_feature_groups(self) -> None:
        repo = load_repository(DATA_DIR)
        g_upd = _make_svc("GoogleUpdaterService199.0.9999.0", state="Stopped", start_mode="Auto")
        w_search = _make_svc("WSearch", state="Running", start_mode="Auto")
        svcs = [g_upd, w_search]
        enrich_service_explanations(svcs, repo)
        classify_service_recommendations(svcs, repo)

        self.assertEqual(g_upd.recommendation_tier, TIER_SET_MANUAL)
        self.assertEqual(w_search.recommendation_tier, TIER_CONDITIONAL_DISABLE)
        self.assertEqual(w_search.feature_group, "Search & Indexing")
        self.assertTrue(bool(w_search.disable_condition))

    def test_tier1_match(self) -> None:
        repo = load_repository(DATA_DIR)
        inv = _make_svc("InventorySvc", state="Running", start_mode="Auto")
        classify_service_recommendations([inv], repo)
        self.assertEqual(inv.recommendation_tier, TIER_SAFE_DISABLE)


if __name__ == "__main__":
    unittest.main()
