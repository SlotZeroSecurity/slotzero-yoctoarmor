#!/usr/bin/env python3
"""Score one isolated NEAR L4 benchmark repetition.

Schema 1 is retained for reproducible v2 baselines. Schema 2 is the release gate:
it binds the full configuration, scores safe twins, and measures whether one
verified-TP informed pass adds useful recall within a bounded cost envelope.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path
from typing import Any


WEIGHTS = {"critical": 8, "high": 4, "medium": 2, "low": 1}
SEVERITIES = {*WEIGHTS, "informational"}
BENCHMARK_TYPES = {"historical", "fixture", "mutation", "async", "nep", "upgrade"}
FINAL_STATUSES = {"accepted", "rejected", "blocked"}
ORIGIN_LEVELS = {"L1", "L2", "L3"}
TARGET_KINDS = {"vulnerable", "safe_twin", "clean"}
PASS_ORIGINS = {"blind", "informed"}
CONFIG_COMPONENTS = {
    "models",
    "prompt_hashes",
    "role_topology_hash",
    "corpus_hash",
    "nep_registry_hash",
    "official_docs_registry_hash",
    "semantic_extractor_hash",
    "driver_hash",
    "thresholds_hash",
    "discovery_pass_plan_hash",
}


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path}: invalid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected object")
    return value


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path}:{line_no}: invalid JSON: {exc}") from exc
        if not isinstance(value, dict):
            raise ValueError(f"{path}:{line_no}: expected object")
        rows.append(value)
    return rows


def require(row: dict[str, Any], fields: tuple[str, ...], label: str) -> None:
    missing = [field for field in fields if row.get(field) is None or row.get(field) == ""]
    if missing:
        raise ValueError(f"{label}: missing fields {missing}")


def ratio(numerator: int | float, denominator: int | float) -> float:
    return 0.0 if denominator == 0 else float(numerator) / float(denominator)


def canonical_hash(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def file_hash(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def validate_project_metrics(review: dict[str, Any], projects: set[str]) -> tuple[float, float]:
    project_kloc = review["project_kloc"]
    if not isinstance(project_kloc, dict) or not project_kloc or not all(
        isinstance(value, (int, float)) and value > 0 for value in project_kloc.values()
    ):
        raise ValueError("review metrics: project_kloc must map projects to positive numbers")
    if projects - set(project_kloc):
        raise ValueError("review metrics: project_kloc omits benchmark projects")
    total_kloc = sum(float(project_kloc[item]) for item in projects)
    review_minutes = float(review["review_minutes"])
    if review_minutes < 0:
        raise ValueError("review metrics: review_minutes cannot be negative")
    return total_kloc, review_minutes * 10.0 / total_kloc


def common_coverage(review: dict[str, Any]) -> tuple[float, float]:
    declared = int(review["invariants_declared"])
    executed = int(review["invariants_executed"])
    async_total = int(review["async_value_chains_total"])
    async_complete = int(review["async_value_chains_complete"])
    if not 0 <= executed <= declared:
        raise ValueError("review metrics: invalid invariant counts")
    if not 0 <= async_complete <= async_total:
        raise ValueError("review metrics: invalid async counts")
    return ratio(executed, declared), ratio(async_complete, async_total)


def load_ground(rows: list[dict[str, Any]], review: dict[str, Any], schema: int) -> dict[str, dict[str, Any]]:
    required = (
        "schema_version", "root_cause_id", "project_id", "track", "severity",
        "benchmark_type", "vulnerable_revision", "fixed_revision", "mechanism",
        "affected_path", "exploit_preconditions", "source_provenance",
    ) + (("safe_twin_id",) if schema == 2 else ())
    ground: dict[str, dict[str, Any]] = {}
    for row in rows:
        require(row, required, "ground truth row")
        root_id = str(row["root_cause_id"])
        if root_id in ground:
            raise ValueError(f"ground truth: duplicate root_cause_id {root_id}")
        if row["schema_version"] != schema:
            raise ValueError(f"ground truth {root_id}: schema_version must be {schema}")
        if row["track"] != review["track"]:
            raise ValueError(f"ground truth {root_id}: track differs from review metrics")
        if row["severity"] not in WEIGHTS:
            raise ValueError(f"ground truth {root_id}: invalid severity")
        if row["benchmark_type"] not in BENCHMARK_TYPES:
            raise ValueError(f"ground truth {root_id}: invalid benchmark_type")
        ground[root_id] = row
    return ground


def root_metrics(ground: dict[str, dict[str, Any]], detected: set[str]) -> dict[str, Any]:
    totals = {severity: 0 for severity in WEIGHTS}
    hits = {severity: 0 for severity in WEIGHTS}
    for root_id, row in ground.items():
        severity = str(row["severity"])
        totals[severity] += 1
        if root_id in detected:
            hits[severity] += 1
    total_weight = sum(WEIGHTS[str(row["severity"])] for row in ground.values())
    hit_weight = sum(WEIGHTS[str(ground[root_id]["severity"])] for root_id in detected)
    return {
        "severity_weighted_recall": ratio(hit_weight, total_weight),
        "recall_by_severity": {severity: ratio(hits[severity], totals[severity]) for severity in WEIGHTS},
        "severity_totals": totals,
        "false_negative_rate": 1.0 - ratio(len(detected), len(ground)),
    }


def mutation_metrics(ground: dict[str, dict[str, Any]], detected: set[str]) -> tuple[set[str], set[str], float, float]:
    mutations = {root_id for root_id, row in ground.items() if row["benchmark_type"] == "mutation"}
    critical = {
        root_id for root_id, row in ground.items()
        if row["benchmark_type"] == "mutation"
        and row["severity"] in {"critical", "high"}
        and row.get("mutation_class") in {"authorization", "settlement"}
    }
    return mutations, critical, ratio(len(detected & mutations), len(mutations)), ratio(len(detected & critical), len(critical))


def score_v1(ground_rows: list[dict[str, Any]], prediction_rows: list[dict[str, Any]], review: dict[str, Any]) -> dict[str, Any]:
    ground = load_ground(ground_rows, review, 1)
    seen: set[str] = set()
    detected: set[str] = set()
    accepted_matches = 0
    accepted = rejected = 0
    all_adjudicated = True
    for row in prediction_rows:
        require(row, ("schema_version", "prediction_id", "project_id", "candidate_id", "matched_root_cause_ids", "final_status", "mechanism_match", "path_match", "human_adjudicated", "origin_level"), "prediction row")
        prediction_id = str(row["prediction_id"])
        if prediction_id in seen:
            raise ValueError(f"predictions: duplicate prediction_id {prediction_id}")
        seen.add(prediction_id)
        if row["schema_version"] != 1:
            raise ValueError(f"prediction {prediction_id}: schema_version must be 1")
        if row["final_status"] not in FINAL_STATUSES or row["origin_level"] not in ORIGIN_LEVELS:
            raise ValueError(f"prediction {prediction_id}: invalid status or origin level")
        matches = row["matched_root_cause_ids"]
        if not isinstance(matches, list) or not all(isinstance(item, str) for item in matches):
            raise ValueError(f"prediction {prediction_id}: matched_root_cause_ids must be a string list")
        unknown = sorted(set(matches) - set(ground))
        if unknown:
            raise ValueError(f"prediction {prediction_id}: unknown root causes {unknown}")
        if any(ground[item]["project_id"] != row["project_id"] for item in matches):
            raise ValueError(f"prediction {prediction_id}: project/root-cause mismatch")
        qualifies = row["final_status"] == "accepted" and row["human_adjudicated"] is True and row["mechanism_match"] is True and row["path_match"] is True and bool(matches)
        if qualifies:
            accepted_matches += 1
            detected.update(matches)
        accepted += row["final_status"] == "accepted"
        rejected += row["final_status"] == "rejected"
        all_adjudicated &= row["human_adjudicated"] is True

    projects = {str(row["project_id"]) for row in ground.values()}
    _, triage = validate_project_metrics(review, projects)
    invariant_coverage, async_coverage = common_coverage(review)
    roots = root_metrics(ground, detected)
    mutations, critical_mutations, mutation_rate, critical_mutation_rate = mutation_metrics(ground, detected)
    metrics = {
        "root_causes": len(ground), "projects": len(projects),
        "severity_weighted_recall": roots["severity_weighted_recall"],
        "recall_by_severity": roots["recall_by_severity"],
        "precision": ratio(accepted_matches, accepted),
        "false_negative_rate": roots["false_negative_rate"],
        "accepted_candidates": accepted, "rejected_candidates": rejected,
        "rejected_per_accepted": ratio(rejected, accepted),
        "review_minutes_per_10kloc": triage, "mutation_kill_rate": mutation_rate,
        "critical_high_auth_settlement_mutation_kill_rate": critical_mutation_rate,
        "invariant_execution_coverage": invariant_coverage, "async_complete_coverage": async_coverage,
        "all_predictions_human_adjudicated": all_adjudicated,
    }
    totals = roots["severity_totals"]
    gates = {
        "minimum_root_causes": len(ground) >= 30, "minimum_projects": len(projects) >= 10,
        "weighted_recall": metrics["severity_weighted_recall"] >= 0.85,
        "critical_recall": totals["critical"] > 0 and metrics["recall_by_severity"]["critical"] == 1.0,
        "high_recall": totals["high"] > 0 and metrics["recall_by_severity"]["high"] >= 0.90,
        "mutation_kill_rate": bool(mutations) and mutation_rate >= 0.85,
        "critical_high_auth_settlement_mutations": bool(critical_mutations) and critical_mutation_rate == 1.0,
        "invariant_coverage": int(review["invariants_declared"]) > 0 and invariant_coverage >= 0.90,
        "async_coverage": int(review["async_value_chains_total"]) > 0 and async_coverage == 1.0,
        "triage_time": triage <= 60.0, "rejected_volume": accepted > 0 and ratio(rejected, accepted) <= 3.0,
        "human_adjudication": all_adjudicated,
    }
    return {"schema_version": 1, "run_id": review["run_id"], "configuration_hash": review["configuration_hash"], "track": review["track"], "metrics": metrics, "gates": gates, "qualified": all(gates.values())}


def validate_v2_identity(ground_path: Path, ground_rows: list[dict[str, Any]], review: dict[str, Any]) -> tuple[str, str]:
    require(review, ("dataset_hash", "target_manifest_hash", "configuration_components", "negative_targets", "informed_enabled", "telemetry_records", "blind_runtime_seconds", "total_runtime_seconds", "blind_input_tokens", "total_input_tokens"), "review metrics v2")
    components = review["configuration_components"]
    planned = review.get("discovery_passes_planned")
    completed = review.get("discovery_passes_completed")
    if type(planned) is not int or not 1 <= planned <= 10 or completed != planned:
        raise ValueError("review metrics: all planned blind discovery passes must complete")
    if not isinstance(components, dict) or set(components) != CONFIG_COMPONENTS:
        raise ValueError(f"review metrics: configuration_components must contain exactly {sorted(CONFIG_COMPONENTS)}")
    if not isinstance(components["models"], dict) or not components["models"]:
        raise ValueError("review metrics: configuration models must be a non-empty object")
    if not isinstance(components["prompt_hashes"], dict) or not components["prompt_hashes"]:
        raise ValueError("review metrics: prompt_hashes must be a non-empty object")
    if not all(
        isinstance(value, str) and value.startswith("sha256:")
        for value in components["prompt_hashes"].values()
    ):
        raise ValueError("review metrics: every prompt hash must be a SHA-256 identity")
    for name in CONFIG_COMPONENTS - {"models", "prompt_hashes"}:
        value = components[name]
        if not isinstance(value, str) or not value.startswith("sha256:"):
            raise ValueError(f"review metrics: {name} must be a SHA-256 identity")
    if components["discovery_pass_plan_hash"] != canonical_hash({"planned": planned, "mode": "independent_blind_l2_l3"}):
        raise ValueError("review metrics: discovery pass plan hash differs from planned count")
    reconstructed = canonical_hash(components)
    if review["configuration_hash"] != reconstructed:
        raise ValueError("review metrics: configuration_hash does not match configuration_components")
    dataset_hash = file_hash(ground_path)
    if review["dataset_hash"] != dataset_hash:
        raise ValueError("review metrics: dataset_hash does not match ground truth bytes")
    negatives = review["negative_targets"]
    if not isinstance(negatives, list):
        raise ValueError("review metrics: negative_targets must be a list")
    manifest = {
        "ground_truth": sorted(ground_rows, key=lambda row: str(row.get("root_cause_id"))),
        "negative_targets": sorted(negatives, key=lambda row: str(row.get("target_id"))),
    }
    target_hash = canonical_hash(manifest)
    if review["target_manifest_hash"] != target_hash:
        raise ValueError("review metrics: target_manifest_hash does not match targets")
    return dataset_hash, target_hash


def validate_telemetry(review: dict[str, Any]) -> tuple[float, float, int, int]:
    records = review["telemetry_records"]
    if not isinstance(records, list) or not records:
        raise ValueError("review metrics: telemetry_records must be a non-empty list")
    seen: set[str] = set()
    runtime = {origin: 0.0 for origin in PASS_ORIGINS}
    tokens = {origin: 0 for origin in PASS_ORIGINS}
    observed_blind_passes: set[int] = set()
    for row in records:
        if not isinstance(row, dict):
            raise ValueError("review metrics: telemetry record must be an object")
        require(row, ("schema_version", "telemetry_id", "pass_origin", "wall_clock_seconds", "input_tokens", "measurement_source", "record_hash"), "telemetry record")
        telemetry_id = str(row["telemetry_id"])
        if telemetry_id in seen:
            raise ValueError(f"review metrics: duplicate telemetry record {telemetry_id}")
        seen.add(telemetry_id)
        origin = row["pass_origin"]
        if row["schema_version"] != 1 or origin not in PASS_ORIGINS:
            raise ValueError(f"telemetry {telemetry_id}: invalid schema or pass origin")
        if origin == "blind":
            number = row.get("discovery_pass")
            if number is not None and (type(number) is not int or not 1 <= number <= review["discovery_passes_planned"]):
                raise ValueError(f"telemetry {telemetry_id}: invalid blind discovery pass")
            if number is not None:
                observed_blind_passes.add(number)
        elif row.get("discovery_pass") is not None:
            raise ValueError(f"telemetry {telemetry_id}: informed telemetry cannot claim a blind discovery pass")
        if row["measurement_source"] not in {"orchestrator_runtime_usage_export", "model_api_usage_export"}:
            raise ValueError(f"telemetry {telemetry_id}: unsupported measurement source")
        seconds = row["wall_clock_seconds"]
        input_tokens = row["input_tokens"]
        if not isinstance(seconds, (int, float)) or seconds <= 0 or not isinstance(input_tokens, int) or input_tokens <= 0:
            raise ValueError(f"telemetry {telemetry_id}: runtime and input tokens must be positive")
        unhashed = dict(row)
        claimed = unhashed.pop("record_hash")
        if claimed != canonical_hash(unhashed):
            raise ValueError(f"telemetry {telemetry_id}: record hash mismatch")
        runtime[str(origin)] += float(seconds)
        tokens[str(origin)] += input_tokens
    if runtime["blind"] <= 0 or runtime["informed"] <= 0:
        raise ValueError("review metrics: telemetry requires blind and informed records")
    if observed_blind_passes != set(range(1, review["discovery_passes_planned"] + 1)):
        raise ValueError("review metrics: missing measured blind discovery pass")
    blind_runtime = runtime["blind"]
    total_runtime = sum(runtime.values())
    blind_tokens = tokens["blind"]
    total_tokens = sum(tokens.values())
    if (
        not math.isclose(float(review["blind_runtime_seconds"]), blind_runtime, rel_tol=0.0, abs_tol=1e-9)
        or not math.isclose(float(review["total_runtime_seconds"]), total_runtime, rel_tol=0.0, abs_tol=1e-9)
        or int(review["blind_input_tokens"]) != blind_tokens
        or int(review["total_input_tokens"]) != total_tokens
    ):
        raise ValueError("review metrics: aggregate runtime/token totals differ from telemetry records")
    return blind_runtime, total_runtime, blind_tokens, total_tokens


def score_v2(ground_path: Path, ground_rows: list[dict[str, Any]], prediction_rows: list[dict[str, Any]], review: dict[str, Any]) -> dict[str, Any]:
    dataset_hash, target_hash = validate_v2_identity(ground_path, ground_rows, review)
    ground = load_ground(ground_rows, review, 2)
    negatives: dict[str, dict[str, Any]] = {}
    for row in review["negative_targets"]:
        if not isinstance(row, dict):
            raise ValueError("review metrics: each negative target must be an object")
        require(row, ("target_id", "kind", "project_id", "revision", "source_hash", "kloc"), "negative target")
        target_id = str(row["target_id"])
        if target_id in negatives:
            raise ValueError(f"review metrics: duplicate negative target {target_id}")
        if row["kind"] not in {"safe_twin", "clean"} or not isinstance(row["kloc"], (int, float)) or row["kloc"] <= 0:
            raise ValueError(f"negative target {target_id}: invalid kind or kloc")
        negatives[target_id] = row

    predictions: dict[str, dict[str, Any]] = {}
    detected = {origin: set() for origin in PASS_ORIGINS}
    accepted_by_pass = {origin: 0 for origin in PASS_ORIGINS}
    true_by_pass = {origin: 0 for origin in PASS_ORIGINS}
    informed_incremental_candidates = 0
    negative_accepted: list[dict[str, Any]] = []
    duplicate_count = rejected = blocked = 0
    claimed_roots: set[str] = set()
    all_adjudicated = True
    for row in prediction_rows:
        require(row, ("schema_version", "prediction_id", "target_kind", "pass_origin", "project_id", "candidate_id", "matched_root_cause_ids", "final_status", "predicted_severity", "mechanism_match", "path_match", "human_adjudicated", "origin_level"), "prediction row")
        prediction_id = str(row["prediction_id"])
        if prediction_id in predictions:
            raise ValueError(f"predictions: duplicate prediction_id {prediction_id}")
        predictions[prediction_id] = row
        if row["schema_version"] != 2 or row["target_kind"] not in TARGET_KINDS or row["pass_origin"] not in PASS_ORIGINS:
            raise ValueError(f"prediction {prediction_id}: invalid schema, target kind, or pass origin")
        number = row.get("discovery_pass")
        if row["pass_origin"] == "blind" and (number is not None and
                (type(number) is not int or not 1 <= number <= review["discovery_passes_planned"])):
            raise ValueError(f"prediction {prediction_id}: invalid discovery pass")
        if row["pass_origin"] == "informed" and number is not None:
            raise ValueError(f"prediction {prediction_id}: informed origin cannot claim a blind discovery pass")
        if row["final_status"] not in FINAL_STATUSES or row["origin_level"] not in ORIGIN_LEVELS or row["predicted_severity"] not in SEVERITIES:
            raise ValueError(f"prediction {prediction_id}: invalid status, level, or severity")
        matches = row["matched_root_cause_ids"]
        if not isinstance(matches, list) or not all(isinstance(item, str) for item in matches):
            raise ValueError(f"prediction {prediction_id}: matched_root_cause_ids must be a string list")
        unknown = sorted(set(matches) - set(ground))
        if unknown:
            raise ValueError(f"prediction {prediction_id}: unknown root causes {unknown}")
        origin = str(row["pass_origin"])
        if row["target_kind"] != "vulnerable":
            require(row, ("target_id",), f"prediction {prediction_id}")
            target_id = str(row["target_id"])
            if target_id not in negatives or negatives[target_id]["kind"] != row["target_kind"]:
                raise ValueError(f"prediction {prediction_id}: unknown or mismatched negative target")
            if matches:
                raise ValueError(f"prediction {prediction_id}: negative target cannot match a root cause")
        elif any(ground[item]["project_id"] != row["project_id"] for item in matches):
            raise ValueError(f"prediction {prediction_id}: project/root-cause mismatch")
        is_accepted = row["final_status"] == "accepted"
        all_adjudicated &= row["human_adjudicated"] is True
        rejected += row["final_status"] == "rejected"
        blocked += row["final_status"] == "blocked"
        if not is_accepted:
            continue
        accepted_by_pass[origin] += 1
        if row["target_kind"] != "vulnerable":
            negative_accepted.append(row)
            continue
        qualifies = row["human_adjudicated"] is True and row["mechanism_match"] is True and row["path_match"] is True and bool(matches)
        if qualifies:
            true_by_pass[origin] += 1
            matched = set(matches)
            if origin == "informed" and matched - detected["blind"]:
                informed_incremental_candidates += 1
            if row.get("duplicate_of") or bool(matched & claimed_roots):
                duplicate_count += 1
            claimed_roots.update(matched)
            detected[origin].update(matched)

    blind_detected = detected["blind"]
    overall_detected = blind_detected | detected["informed"]
    projects = {str(row["project_id"]) for row in ground.values()}
    _, triage = validate_project_metrics(review, projects)
    invariant_coverage, async_coverage = common_coverage(review)
    overall_roots = root_metrics(ground, overall_detected)
    blind_roots = root_metrics(ground, blind_detected)
    mutations, critical_mutations, mutation_rate, critical_mutation_rate = mutation_metrics(ground, overall_detected)
    accepted = sum(accepted_by_pass.values())
    true_accepted = sum(true_by_pass.values())
    safe_kloc = sum(float(row["kloc"]) for row in negatives.values())
    safe_ch = sum(row["predicted_severity"] in {"critical", "high"} for row in negative_accepted)
    safe_medium_plus = sum(row["predicted_severity"] in {"critical", "high", "medium"} for row in negative_accepted)
    blind_runtime, total_runtime, blind_tokens, total_tokens = validate_telemetry(review)
    metrics = {
        "root_causes": len(ground), "projects": len(projects), "negative_targets": len(negatives),
        "severity_weighted_recall": overall_roots["severity_weighted_recall"],
        "blind_severity_weighted_recall": blind_roots["severity_weighted_recall"],
        "informed_weighted_recall_delta": overall_roots["severity_weighted_recall"] - blind_roots["severity_weighted_recall"],
        "recall_by_severity": overall_roots["recall_by_severity"],
        "precision": ratio(true_accepted, accepted), "blind_precision": ratio(true_by_pass["blind"], accepted_by_pass["blind"]),
        "informed_incremental_precision": ratio(informed_incremental_candidates, accepted_by_pass["informed"]),
        "false_negative_rate": overall_roots["false_negative_rate"],
        "accepted_candidates": accepted, "rejected_candidates": rejected, "blocked_candidates": blocked,
        "rejected_per_accepted": ratio(rejected, accepted), "duplicate_rate": ratio(duplicate_count, accepted),
        "safe_critical_high_false_positives": safe_ch,
        "safe_medium_plus_false_positives_per_10kloc": ratio(safe_medium_plus * 10.0, safe_kloc),
        "review_minutes_per_10kloc": triage, "mutation_kill_rate": mutation_rate,
        "critical_high_auth_settlement_mutation_kill_rate": critical_mutation_rate,
        "invariant_execution_coverage": invariant_coverage, "async_complete_coverage": async_coverage,
        "runtime_overhead": total_runtime / blind_runtime - 1.0, "input_token_overhead": total_tokens / blind_tokens - 1.0,
        "total_runtime_seconds": total_runtime, "total_input_tokens": total_tokens,
        "all_predictions_human_adjudicated": all_adjudicated,
    }
    totals = overall_roots["severity_totals"]
    safe_ids = {str(row["safe_twin_id"]) for row in ground.values()}
    gates = {
        "minimum_root_causes": len(ground) >= 50, "minimum_projects": len(projects) >= 12,
        "minimum_negative_targets": len(negatives) >= 10, "safe_twin_coverage": safe_ids <= set(negatives),
        "weighted_recall": metrics["severity_weighted_recall"] >= 0.85,
        "critical_recall": totals["critical"] > 0 and metrics["recall_by_severity"]["critical"] == 1.0,
        "high_recall": totals["high"] > 0 and metrics["recall_by_severity"]["high"] >= 0.90,
        "precision": metrics["precision"] >= 0.80, "safe_critical_high_zero": safe_ch == 0,
        "safe_medium_plus_rate": metrics["safe_medium_plus_false_positives_per_10kloc"] <= 0.20,
        "duplicate_rate": metrics["duplicate_rate"] <= 0.10,
        "mutation_kill_rate": bool(mutations) and mutation_rate >= 0.85,
        "critical_high_auth_settlement_mutations": bool(critical_mutations) and critical_mutation_rate == 1.0,
        "invariant_coverage": int(review["invariants_declared"]) > 0 and invariant_coverage >= 0.90,
        "async_coverage": int(review["async_value_chains_total"]) > 0 and async_coverage == 1.0,
        "triage_time": triage <= 60.0, "rejected_volume": accepted > 0 and ratio(rejected, accepted) <= 3.0,
        "human_adjudication": all_adjudicated, "informed_enabled": review["informed_enabled"] is True,
        "informed_recall_lift": metrics["informed_weighted_recall_delta"] >= 0.03,
        "informed_incremental_precision": metrics["informed_incremental_precision"] >= 0.70,
        "precision_non_regression": metrics["precision"] >= metrics["blind_precision"] - 0.02,
        "runtime_overhead": metrics["runtime_overhead"] <= 0.20,
        "input_token_overhead": metrics["input_token_overhead"] <= 0.20,
    }
    return {
        "schema_version": 2, "gate_profile": "near-auditor-l4-v2", "run_id": review["run_id"],
        "configuration_hash": review["configuration_hash"], "dataset_hash": dataset_hash,
        "discovery_passes_planned": review["discovery_passes_planned"],
        "discovery_passes_completed": review["discovery_passes_completed"],
        "target_manifest_hash": target_hash, "scorer_hash": file_hash(Path(__file__)),
        "track": review["track"], "metrics": metrics, "gates": gates, "qualified": all(gates.values()),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("ground_truth", type=Path)
    parser.add_argument("predictions", type=Path)
    parser.add_argument("review_metrics", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    ground_rows = load_jsonl(args.ground_truth)
    prediction_rows = load_jsonl(args.predictions)
    review = load_json(args.review_metrics)
    require(review, ("schema_version", "run_id", "configuration_hash", "track", "project_kloc", "review_minutes", "invariants_declared", "invariants_executed", "async_value_chains_total", "async_value_chains_complete"), "review metrics")
    if review["schema_version"] == 1:
        summary = score_v1(ground_rows, prediction_rows, review)
    elif review["schema_version"] == 2:
        summary = score_v2(args.ground_truth, ground_rows, prediction_rows, review)
    else:
        raise ValueError("review metrics: schema_version must be 1 or 2")
    rendered = json.dumps(summary, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
