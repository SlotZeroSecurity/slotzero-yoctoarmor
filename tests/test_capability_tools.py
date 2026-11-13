#!/usr/bin/env python3
"""Regression tests for L0-L4 artifacts, scoring, and attestation."""

from __future__ import annotations

import json
import hashlib
import subprocess
import tempfile
import unittest
from pathlib import Path


SKILL = Path(__file__).resolve().parent.parent
SCRIPTS = SKILL / "scripts"
FIXTURE = Path(__file__).resolve().parent / "fixtures" / "nep-surface"
NEP_PIN = json.loads((SKILL / "references" / "nep-registry.json").read_text(encoding="utf-8"))[
    "source"
]["commit"]
OFFICIAL_REGISTRY = SKILL / "references" / "official-docs-registry.json"
OFFICIAL_PIN = json.loads(OFFICIAL_REGISTRY.read_text(encoding="utf-8"))["source"]["commit"]
MUTATION_FAMILIES = (
    "identity-substitution",
    "access-macro-removal",
    "late-reservation",
    "promise-result-semantics",
    "callback-gas",
    "refund-cap",
    "storage-accounting",
    "terminal-promise",
    "arithmetic-rounding",
    "migration-layout",
    "key-capability",
    "yield-resume-binding",
    "refund-principal",
    "transfer-call-polarity",
    "route-finality",
    "serializer-mismatch",
    "deployed-code-identity",
)


def run(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, check=check, text=True, capture_output=True)


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


def canonical_hash(value: object) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def make_run_artifacts(root: Path) -> None:
    surface_result = run("python3", str(SCRIPTS / "map_surface.py"), str(FIXTURE))
    (root / "surface.json").write_text(surface_result.stdout, encoding="utf-8")
    surface = json.loads(surface_result.stdout)
    write_json(
        root / "run-manifest.json",
        {
            "schema_version": 2,
            "target": str(FIXTURE),
            "target_revision": "fixture",
            "dirty_tree": False,
            "scope": ["lib.rs"],
            "exclusions": [],

            "toolchain": {"rust": "fixture"},
            "sdk_versions": {"near-sdk": "fixture"},
            "nep_source_commit": NEP_PIN,
            "official_docs_source_commit": OFFICIAL_PIN,
            "official_docs_registry_hash": hashlib.sha256(OFFICIAL_REGISTRY.read_bytes()).hexdigest(),
            "corpus_hash": "sha256:" + "a" * 64,
            "models": {"orchestrator": "fixture"},
            "prompt_hashes": {"L0": "sha256:" + "b" * 64},
            "tool_versions": {"python": "3"},
            "worker_capacity": 8,
            "started_at": "2026-08-27T00:00:00Z",
        },
    )
    write_json(
        root / "intent-model.json",
        {
            "schema_version": 1,
            "actors": [],
            "assets": [],
            "entrypoints": [],
            "receipt_state_machines": [],
            "standards": [],
            "trust_boundaries": [],
            "invariants": [{"invariant_id": "INV-SETTLE-ONCE-1", "statement": "settle once"}],
            "unresolved_intent": [],
            "upgrade_dependencies": [],
            "account_key_capabilities": [],
            "yield_resume_flows": [],
            "global_contract_dependencies": [],
            "cross_chain_routes": [],
            "version_claims": [],
        },
    )
    write_jsonl(
        root / "level-coverage.jsonl",
        [
            {
                "schema_version": 1,
                "level": level,
                "status": "complete",
                "roles": [role],
                "inputs": ["fixture"],
                "artifacts": ["fixture"],
                "model_and_prompt_hashes": ["sha256:" + "c" * 64],
                "started_at": "2026-08-27T00:00:00Z",
                "completed_at": "2026-08-27T00:01:00Z",
                "cost": {"tokens": 1},
                "blockers": [],
            }
            for level, role in (
                ("L0", "protocol-modeler"),
                ("L1", "pattern-matcher"),
                ("L2", "intent-reasoner"),
                ("L3", "specialists"),
            )
        ],
    )
    write_jsonl(
        root / "invariant-ledger.jsonl",
        [
            {
                "schema_version": 1,
                "invariant_id": "INV-SETTLE-ONCE-1",
                "statement": "settle once",
                "scope": ["fixture"],
                "assets": ["token"],
                "writers": ["withdraw"],
                "readers": ["resolve"],
                "receipt_boundaries": ["R1", "R2"],
                "test_class": "structural",
                "execution_status": "structural",
                "candidate_ids": [],
            }
        ],
    )
    inventory = json.loads((SKILL / "references/mutation-operators.json").read_text())["families"]
    citation = {"path": "lib.rs", "start": 1, "end": 1, "quote": (FIXTURE / "lib.rs").read_text().splitlines()[0]}
    write_jsonl(root / "mutation-results.jsonl", [
        {"schema_version": 2, "operator_family": family, "applicability": "not_applicable",
         "mutations_total": 0, "killed": 0, "survived": 0, "blocked": 0, "candidate_ids": [],
         "rationale": "Inert validation fixture; no mutations executed.", "operators": [
             {"operator_id": op["operator_id"], "applicability": "not_applicable",
              "rationale": "Synthetic coverage disposition, not a target audit.",
              "target_evidence": [citation], "locations": [], "outcomes": []} for op in operators]}
        for family, operators in inventory.items()])
    write_jsonl(
        root / "async-schedules.jsonl",
        [
            {
                "schema_version": 1,
                "operation_id": "withdraw-1",
                "state_machine_id": "withdraw",
                "initiating_export": "withdraw",
                "receipts": ["R1", "R2"],
                "reserved_state": ["balance"],
                "terminal_states": ["succeeded", "compensated"],
                "coverage": {"success": True, "failure": True, "pending_interleaving": True},
                "candidate_ids": [],
            }
        ],
    )
    write_jsonl(
        root / "nep-differential.jsonl",
        [
            {
                "schema_version": 1,
                "status": "complete",
                "evidence": ["fixture oracle"],
                "candidate_ids": [],
            }
        ],
    )
    write_jsonl(
        root / "official-guidance-coverage.jsonl",
        [
            {
                "schema_version": 1,
                "card_id": card_id,
                "applicability": "applicable",
                "version_evidence": ["fixture version"],
                "target_evidence": ["fixture signal"],
                "checks_performed": ["safe structural check"],
                "test_status": "structural",
                "candidate_ids": [],
                "advisory_observations": [],
                "disposition": "conformant",
                "rationale": "Fixture supplies a complete safe disposition.",
            }
            for card_id in surface["selected_attacker_cards"]
        ],
    )
    (root / "unresolved-assumptions.jsonl").write_text("", encoding="utf-8")
    write_json(
        root / "rescan-summary.json",
        {
            "schema_version": 2,
            "iteration": 1,
            "status": "complete",
            "input_count": 0,
            "new_candidate_ids": [],
        },
    )


def benchmark_rows() -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    ground: list[dict[str, object]] = []
    predictions: list[dict[str, object]] = []
    severities = ("critical", "high", "medium", "low")
    for index in range(30):
        root_id = f"gt-{index:02d}"
        severity = severities[index % len(severities)]
        benchmark_type = "mutation" if index < 10 else "historical"
        ground.append(
            {
                "schema_version": 1,
                "root_cause_id": root_id,
                "project_id": f"project-{index % 10}",
                "track": "smart-contracts",
                "severity": severity,
                "benchmark_type": benchmark_type,
                "vulnerable_revision": "bad",
                "fixed_revision": "good",
                "mechanism": f"mechanism {index}",
                "affected_path": f"src/{index}.rs",
                "exploit_preconditions": ["attacker"],
                "source_provenance": "public fixture",
                "mutation_class": "authorization" if index % 2 == 0 else "settlement",
            }
        )
        predictions.append(
            {
                "schema_version": 1,
                "prediction_id": f"prediction-{index:02d}",
                "project_id": f"project-{index % 10}",
                "candidate_id": f"candidate-{index:02d}",
                "matched_root_cause_ids": [root_id],
                "final_status": "accepted",
                "mechanism_match": True,
                "path_match": True,
                "human_adjudicated": True,
                "origin_level": "L3",
            }
        )
    return ground, predictions


def benchmark_v2(root: Path) -> tuple[Path, Path, Path]:
    ground: list[dict[str, object]] = []
    predictions: list[dict[str, object]] = []
    severities = ("critical", "high", "medium", "low")
    for index in range(50):
        root_id = f"v2-gt-{index:02d}"
        severity = severities[index % len(severities)]
        ground.append(
            {
                "schema_version": 2,
                "root_cause_id": root_id,
                "project_id": f"project-{index % 12}",
                "track": "smart-contracts",
                "severity": severity,
                "benchmark_type": "mutation" if index < 12 else "historical",
                "vulnerable_revision": "bad",
                "fixed_revision": "good",
                "safe_twin_id": f"safe-{index % 10}",
                "mechanism": f"mechanism {index}",
                "affected_path": f"src/{index}.rs",
                "exploit_preconditions": ["attacker"],
                "source_provenance": "held-out fixture",
                "mutation_class": "authorization" if index % 2 == 0 else "settlement",
            }
        )
        predictions.append(
            {
                "schema_version": 2,
                "prediction_id": f"v2-prediction-{index:02d}",
                "target_kind": "vulnerable",
                "pass_origin": "informed" if index == 48 else "blind",
                "discovery_pass": None if index == 48 else 1,
                "project_id": f"project-{index % 12}",
                "candidate_id": f"v2-candidate-{index:02d}",
                "matched_root_cause_ids": [root_id],
                "final_status": "accepted",
                "predicted_severity": severity,
                "mechanism_match": True,
                "path_match": True,
                "human_adjudicated": True,
                "origin_level": "L3",
            }
        )
    negatives = [
        {
            "target_id": f"safe-{index}",
            "kind": "safe_twin",
            "project_id": f"project-{index}",
            "revision": "safe",
            "source_hash": "sha256:" + f"{index:064x}",
            "kloc": 10,
        }
        for index in range(10)
    ]
    ground_path = root / "ground-v2.jsonl"
    predictions_path = root / "predictions-v2.jsonl"
    review_path = root / "review-v2.json"
    write_jsonl(ground_path, ground)
    write_jsonl(predictions_path, predictions)
    components = {
        "models": {"orchestrator": "fixed-model"},
        "prompt_hashes": {"L0": "sha256:" + "1" * 64},
        "role_topology_hash": "sha256:" + "2" * 64,
        "corpus_hash": "sha256:" + "3" * 64,
        "nep_registry_hash": "sha256:" + "4" * 64,
        "official_docs_registry_hash": "sha256:" + "5" * 64,
        "semantic_extractor_hash": "sha256:" + "6" * 64,
        "driver_hash": "sha256:" + "7" * 64,
        "thresholds_hash": "sha256:" + "8" * 64,
        "discovery_pass_plan_hash": canonical_hash({"planned": 1, "mode": "independent_blind_l2_l3"}),
    }
    target_manifest = {
        "ground_truth": sorted(ground, key=lambda row: str(row["root_cause_id"])),
        "negative_targets": sorted(negatives, key=lambda row: str(row["target_id"])),
    }
    telemetry = [
        {
            "schema_version": 1,
            "telemetry_id": "blind-pass",
            "pass_origin": "blind",
            "discovery_pass": 1,
            "wall_clock_seconds": 100,
            "input_tokens": 100_000,
            "measurement_source": "orchestrator_runtime_usage_export",
        },
        {
            "schema_version": 1,
            "telemetry_id": "informed-pass",
            "pass_origin": "informed",
            "wall_clock_seconds": 10,
            "input_tokens": 10_000,
            "measurement_source": "orchestrator_runtime_usage_export",
        },
    ]
    for row in telemetry:
        row["record_hash"] = canonical_hash(row)
    write_json(
        review_path,
        {
            "schema_version": 2,
            "run_id": "v2-run",
            "configuration_hash": canonical_hash(components),
            "configuration_components": components,
            "dataset_hash": "sha256:" + hashlib.sha256(ground_path.read_bytes()).hexdigest(),
            "target_manifest_hash": canonical_hash(target_manifest),
            "track": "smart-contracts",
            "discovery_passes_planned": 1,
            "discovery_passes_completed": 1,
            "negative_targets": negatives,
            "project_kloc": {f"project-{index}": 10 for index in range(12)},
            "review_minutes": 300,
            "invariants_declared": 100,
            "invariants_executed": 90,
            "async_value_chains_total": 10,
            "async_value_chains_complete": 10,
            "informed_enabled": True,
            "telemetry_records": telemetry,
            "blind_runtime_seconds": 100,
            "total_runtime_seconds": 110,
            "blind_input_tokens": 100_000,
            "total_input_tokens": 110_000,
        },
    )
    return ground_path, predictions_path, review_path


class CapabilityToolsTest(unittest.TestCase):

    def test_complete_run_artifacts_pass(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            make_run_artifacts(root)
            result = run("python3", str(SCRIPTS / "check_run_artifacts.py"), str(root), "--final")
            self.assertTrue(json.loads(result.stdout)["complete"])

    def test_missing_level_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            make_run_artifacts(root)
            rows = [json.loads(line) for line in (root / "level-coverage.jsonl").read_text().splitlines()]
            write_jsonl(root / "level-coverage.jsonl", rows[:-1])
            result = run(
                "python3", str(SCRIPTS / "check_run_artifacts.py"), str(root), "--final", check=False
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("expected", result.stderr)


    def test_benchmark_cannot_qualify_after_missing_critical(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ground, predictions = benchmark_rows()
            predictions[0]["final_status"] = "rejected"
            predictions[0]["mechanism_match"] = False
            predictions[0]["path_match"] = False
            predictions[0]["matched_root_cause_ids"] = []
            write_jsonl(root / "ground.jsonl", ground)
            write_jsonl(root / "predictions.jsonl", predictions)
            write_json(
                root / "review.json",
                {
                    "schema_version": 1,
                    "run_id": "missed-critical",
                    "configuration_hash": "sha256:" + "d" * 64,
                    "track": "smart-contracts",
                    "project_kloc": {f"project-{index}": 10 for index in range(10)},
                    "review_minutes": 300,
                    "invariants_declared": 100,
                    "invariants_executed": 90,
                    "async_value_chains_total": 10,
                    "async_value_chains_complete": 10,
                },
            )
            result = run(
                "python3",
                str(SCRIPTS / "score_benchmark.py"),
                str(root / "ground.jsonl"),
                str(root / "predictions.jsonl"),
                str(root / "review.json"),
            )
            payload = json.loads(result.stdout)
            self.assertFalse(payload["qualified"])
            self.assertFalse(payload["gates"]["critical_recall"])



    def test_benchmark_v2_rejects_configuration_hash_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ground, predictions, review = benchmark_v2(root)
            payload = json.loads(review.read_text())
            payload["configuration_hash"] = "sha256:" + "f" * 64
            write_json(review, payload)
            result = run("python3", str(SCRIPTS / "score_benchmark.py"), str(ground), str(predictions), str(review), check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("configuration_hash", result.stderr)




    def test_benchmark_v2_rejects_telemetry_aggregate_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ground, predictions, review = benchmark_v2(root)
            payload = json.loads(review.read_text())
            payload["total_runtime_seconds"] = 111
            write_json(review, payload)
            result = run("python3", str(SCRIPTS / "score_benchmark.py"), str(ground), str(predictions), str(review), check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("telemetry records", result.stderr)


if __name__ == "__main__":
    unittest.main()
