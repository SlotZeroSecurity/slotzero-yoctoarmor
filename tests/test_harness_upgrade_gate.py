"""Synthetic release-gate arithmetic; never treated as qualification evidence."""

from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from check_harness_upgrade import compare


class HarnessUpgradeGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def summaries(self, name: str, *, recall: float, precision: float, runtime: float = 100,
                  tokens: int = 1000, safe_high: int = 0) -> list[Path]:
        paths = []
        for number in range(3):
            path = self.root / f"{name}-{number}.json"
            path.write_text(json.dumps({
                "schema_version": 2, "gate_profile": "near-auditor-l4-v2", "run_id": f"{name}-{number}",
                "configuration_hash": name, "dataset_hash": "dataset", "target_manifest_hash": "targets",
                "scorer_hash": "scorer", "track": "smart-contracts", "discovery_passes_planned": 3,
                "metrics": {"severity_weighted_recall": recall, "precision": precision,
                            "recall_by_severity": {"critical": 1.0, "high": 0.9},
                            "safe_critical_high_false_positives": safe_high,
                            "safe_medium_plus_false_positives_per_10kloc": 0.0,
                            "total_runtime_seconds": runtime, "total_input_tokens": tokens,
                            "all_predictions_human_adjudicated": True},
            }))
            paths.append(path)
        return paths

    def test_quality_gain_within_budget_passes(self) -> None:
        old = self.summaries("old", recall=0.85, precision=0.80)
        new = self.summaries("new", recall=0.86, precision=0.80, runtime=119, tokens=1190)
        self.assertTrue(compare(old, new, 0.20)["release_gate_passed"])

    def test_equal_quality_or_regression_fails(self) -> None:
        old = self.summaries("old", recall=0.85, precision=0.80)
        equal = self.summaries("equal", recall=0.85, precision=0.80)
        self.assertFalse(compare(old, equal, 0.20)["release_gate_passed"])
        worse = self.summaries("worse", recall=0.86, precision=0.79)
        self.assertFalse(compare(old, worse, 0.20)["release_gate_passed"])

    def test_cost_and_high_false_positive_gates(self) -> None:
        old = self.summaries("old", recall=0.85, precision=0.80)
        slow = self.summaries("slow", recall=0.86, precision=0.80, runtime=121)
        self.assertFalse(compare(old, slow, 0.20)["release_gate_passed"])
        unsafe = self.summaries("unsafe", recall=0.86, precision=0.80, safe_high=1)
        self.assertFalse(compare(old, unsafe, 0.20)["release_gate_passed"])


if __name__ == "__main__":
    unittest.main()
