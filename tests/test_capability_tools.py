#!/usr/bin/env python3
"""Regression tests for L0-L4 artifacts, scoring, and attestation."""

from __future__ import annotations

import json
import hashlib
import tempfile
import unittest
from pathlib import Path

from support import run, write_json, write_jsonl, make_run_artifacts


SKILL = Path(__file__).resolve().parent.parent
SCRIPTS = SKILL / "scripts"


def canonical_hash(value: object) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(raw).hexdigest()


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
