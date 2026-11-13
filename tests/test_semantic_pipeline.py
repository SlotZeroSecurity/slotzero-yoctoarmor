#!/usr/bin/env python3
"""Regression tests for semantic extraction, feedback, and the informed pass."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from support import run


SKILL = Path(__file__).resolve().parent.parent
SCRIPTS = SKILL / "scripts"
FIXTURE = Path(__file__).resolve().parent / "fixtures" / "semantic-near"


def candidate(candidate_id: str = "cand-1") -> dict[str, object]:
    return {
        "schema_version": 2,
        "candidate_id": candidate_id,
        "role_id": "async-state-explorer",
        "origin_role": "async-state-explorer",
        "origin_level": "L3",
        "discovery_technique": "async_schedule",
        "pattern_id": "NA-ASYNC-002",
        "root_cause_fingerprint": "sha256:" + "a" * 64,
        "root_cause": "Pending withdrawal is not restored on failed receipt.",
        "broken_invariant": "Every withdrawal reaches one terminal accounting state.",
        "intent_invariant_ids": ["INV-SETTLE-1"],
        "attacker": "ordinary account",
        "preconditions": ["receiver receipt fails"],
        "receipt_trace": ["withdraw", "transfer", "on_withdraw"],
        "defenses_checked": ["private callback"],
        "locations": [{"path": "src/lib.rs", "function": "withdraw", "start": 10}],
    }


class SemanticPipelineTest(unittest.TestCase):
    def test_semantic_ir_extracts_near_relationships(self) -> None:
        result = run("python3", str(SCRIPTS / "build_semantic_ir.py"), str(FIXTURE))
        payload = json.loads(result.stdout)
        exports = {row["name"] for row in payload["exports"]}
        self.assertIn("withdraw", exports)
        self.assertIn("rotate_owner", exports)
        self.assertTrue(any(row["field"] == "pending" and row["access"] == "write" for row in payload["state_accesses"]))
        self.assertTrue(any(row["from_symbol"].endswith("::withdraw") for row in payload["receipt_edges"]))
        authorities = {row["authority"] for row in payload["authority_edges"]}
        self.assertTrue({"predecessor", "signer", "private_macro"} <= authorities)
        self.assertGreaterEqual(payload["coverage"]["symbols"], 3)

    def test_driver_initializes_hash_bound_schema_v7_run(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "run"
            result = run(
                "python3", str(SCRIPTS / "near_audit.py"), "run", str(FIXTURE), "--loop", "1",
                "--run-dir", str(run_dir), "--worker-capacity", "4", "--runtime-capacity", "4",
            )
            payload = json.loads(result.stdout)
            self.assertIn("NEAR MULTI-AGENT SECURITY SCANNER", result.stderr)
            self.assertNotIn("Traceback", result.stderr)
            manifest = json.loads((run_dir / "run-manifest.json").read_text())
            self.assertEqual(manifest["schema_version"], 7)
            self.assertEqual(manifest["feedback_policy"], "metrics_only")
            self.assertEqual(manifest["second_pass_mode"], "targeted_verified_seed")
            self.assertEqual(manifest["worker_capacity"], 4)
            self.assertEqual(manifest["runtime_capacity"], 4)
            self.assertEqual(manifest["capacity_semantics"], "spawned_workers_excluding_primary")
            self.assertTrue(manifest["semantic_ir_hash"].startswith("sha256:"))
            self.assertGreater(payload["work_packets"], 0)
            status = json.loads(run("python3", str(SCRIPTS / "near_audit.py"), "status", str(run_dir)).stdout)
            self.assertEqual(status["current_phase"], "l0-model")
            incomplete = run("python3", str(SCRIPTS / "check_run_artifacts.py"), str(run_dir), check=False)
            self.assertIn("intent-model.json", incomplete.stderr)

            intent = {
                "schema_version": 1,
                **{name: [] for name in (
                    "actors", "assets", "entrypoints", "receipt_state_machines", "standards",
                    "trust_boundaries", "invariants", "unresolved_intent", "upgrade_dependencies",
                    "account_key_capabilities", "yield_resume_flows", "global_contract_dependencies",
                    "cross_chain_routes", "version_claims",
                )},
            }
            (run_dir / "intent-model.json").write_text(json.dumps(intent), encoding="utf-8")
            resumed = json.loads(run("python3", str(SCRIPTS / "near_audit.py"), "resume", str(run_dir)).stdout)
            self.assertEqual(resumed["current_phase"], "isolated-l1-l2")
            persisted = json.loads((run_dir / "run-state.json").read_text())
            self.assertEqual(persisted["schema_version"], 4)
            self.assertEqual(persisted["current_phase"], "isolated-l1-l2")

    def test_schema_v7_validator_rejects_semantic_ir_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "run"
            run("python3", str(SCRIPTS / "near_audit.py"), "run", str(FIXTURE), "--loop", "1", "--run-dir", str(run_dir))
            semantic = json.loads((run_dir / "semantic-ir.json").read_text())
            semantic["unresolved_edges"].append({"kind": "tampered"})
            (run_dir / "semantic-ir.json").write_text(json.dumps(semantic), encoding="utf-8")
            result = run("python3", str(SCRIPTS / "check_run_artifacts.py"), str(run_dir), check=False)
            self.assertNotEqual(result.returncode, 0)
        self.assertIn("content differs", result.stderr)

    def test_offline_near_scenarios_route_to_relevant_lenses(self) -> None:
        root = SKILL / "tests/fixtures/near-scenarios"
        cases = json.loads((root / "manifest.json").read_text())["cases"]
        index = json.loads((SKILL / "references/attack-lenses-index.json").read_text())["cards"]
        self.assertEqual(4, len(cases))
        for case in cases:
            folder = root / case["name"]
            self.assertTrue((root / case["vulnerable"]).is_file())
            self.assertTrue((root / case["safe"]).is_file())
            self.assertLessEqual(set(case["patterns"]), set(index))
            result = run("python3", str(SCRIPTS / "map_surface.py"), str(folder))
            surface = json.loads(result.stdout)
            self.assertTrue(surface["selected_pattern_categories"])
            for pattern in case["patterns"]:
                self.assertIn(index[pattern]["category"], surface["selected_pattern_categories"], case["name"])


if __name__ == "__main__":
    unittest.main()
