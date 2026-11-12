#!/usr/bin/env python3
"""Compare three measured, adjudicated before/after benchmark repetitions."""

from __future__ import annotations

import argparse
import json
import statistics
from pathlib import Path


def load_group(paths: list[Path]) -> tuple[list[dict], dict]:
    if len(paths) != 3:
        raise ValueError("exactly three repetitions are required per configuration")
    rows = [json.loads(path.read_text(encoding="utf-8")) for path in paths]
    if any(not isinstance(row, dict) or row.get("schema_version") != 2 for row in rows):
        raise ValueError("release comparison requires schema-2 benchmark summaries")
    identities = {(row.get("dataset_hash"), row.get("target_manifest_hash"), row.get("scorer_hash"),
                   row.get("gate_profile"), row.get("track"), row.get("discovery_passes_planned")) for row in rows}
    if len(identities) != 1 or len({row.get("configuration_hash") for row in rows}) != 1:
        raise ValueError("repetitions must share dataset, targets, scorer, track, pass count, and configuration")
    if len({row.get("run_id") for row in rows}) != 3:
        raise ValueError("repetitions need distinct run IDs")
    required = ("severity_weighted_recall", "precision", "safe_critical_high_false_positives",
                "safe_medium_plus_false_positives_per_10kloc", "total_runtime_seconds", "total_input_tokens")
    for row in rows:
        metrics = row.get("metrics", {})
        if not metrics.get("all_predictions_human_adjudicated") or any(name not in metrics for name in required):
            raise ValueError("release comparison requires adjudicated quality and measured usage")
        if metrics["total_runtime_seconds"] <= 0 or metrics["total_input_tokens"] <= 0:
            raise ValueError("runtime and input tokens must be positive measurements")
    return rows, dict(zip(("dataset_hash", "target_manifest_hash", "scorer_hash", "gate_profile", "track",
                           "discovery_passes_planned"), next(iter(identities))))


def median(rows: list[dict], key: str) -> float:
    return float(statistics.median(row["metrics"][key] for row in rows))


def compare(baseline: list[Path], candidate: list[Path], max_overhead: float) -> dict:
    old, identity = load_group(baseline)
    new, current_identity = load_group(candidate)
    if identity != current_identity:
        raise ValueError("baseline and candidate dataset, targets, scorer, track, or pass count differ")
    if old[0]["configuration_hash"] == new[0]["configuration_hash"]:
        raise ValueError("candidate configuration must differ from baseline")
    quality_keys = ("severity_weighted_recall", "precision", "safe_critical_high_false_positives",
                    "safe_medium_plus_false_positives_per_10kloc")
    old_metrics = {key: median(old, key) for key in (*quality_keys, "total_runtime_seconds", "total_input_tokens")}
    new_metrics = {key: median(new, key) for key in old_metrics}
    old_severity = {severity: float(statistics.median(row["metrics"]["recall_by_severity"][severity] for row in old))
                    for severity in ("critical", "high")}
    new_severity = {severity: float(statistics.median(row["metrics"]["recall_by_severity"][severity] for row in new))
                    for severity in ("critical", "high")}
    eps = 1e-12
    quality_holds = (new_metrics["severity_weighted_recall"] + eps >= old_metrics["severity_weighted_recall"]
                     and new_metrics["precision"] + eps >= old_metrics["precision"]
                     and all(row["metrics"]["safe_critical_high_false_positives"] == 0 for row in new)
                     and new_metrics["safe_medium_plus_false_positives_per_10kloc"] <= old_metrics["safe_medium_plus_false_positives_per_10kloc"] + eps
                     and all(min(row["metrics"]["recall_by_severity"][name] for row in new) + eps >=
                             min(row["metrics"]["recall_by_severity"][name] for row in old)
                             for name in old_severity))
    quality_improves = (new_metrics["severity_weighted_recall"] >= old_metrics["severity_weighted_recall"] + 0.01 - eps
                        or new_metrics["precision"] >= old_metrics["precision"] + 0.01 - eps
                        or new_metrics["safe_critical_high_false_positives"] < old_metrics["safe_critical_high_false_positives"]
                        or new_metrics["safe_medium_plus_false_positives_per_10kloc"] + eps < old_metrics["safe_medium_plus_false_positives_per_10kloc"])
    runtime_overhead = new_metrics["total_runtime_seconds"] / old_metrics["total_runtime_seconds"] - 1
    token_overhead = new_metrics["total_input_tokens"] / old_metrics["total_input_tokens"] - 1
    passes = quality_holds and quality_improves and runtime_overhead <= max_overhead and token_overhead <= max_overhead
    return {"schema_version": 1, "comparable": True, "identity": identity,
            "baseline_configuration_hash": old[0]["configuration_hash"],
            "candidate_configuration_hash": new[0]["configuration_hash"],
            "baseline_medians": old_metrics, "candidate_medians": new_metrics,
            "baseline_severity_recall": old_severity, "candidate_severity_recall": new_severity,
            "quality_nonregression": quality_holds, "measured_quality_improvement": quality_improves,
            "runtime_overhead": runtime_overhead, "input_token_overhead": token_overhead,
            "max_overhead": max_overhead, "release_gate_passed": passes}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline", nargs=3, type=Path, required=True)
    parser.add_argument("--candidate", nargs=3, type=Path, required=True)
    parser.add_argument("--max-overhead", type=float, default=0.20)
    args = parser.parse_args()
    if args.max_overhead < 0:
        parser.error("--max-overhead cannot be negative")
    result = compare(args.baseline, args.candidate, args.max_overhead)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["release_gate_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
