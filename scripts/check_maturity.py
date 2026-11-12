#!/usr/bin/env python3
"""Create an L4 attestation from three equivalent qualifying benchmark runs."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def load_summary(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path}: invalid JSON: {exc}") from exc
    if not isinstance(value, dict) or value.get("schema_version") not in {1, 2}:
        raise ValueError(f"{path}: expected benchmark summary schema 1 or 2")
    for field in ("run_id", "configuration_hash", "track", "metrics", "gates", "qualified"):
        if value.get(field) is None:
            raise ValueError(f"{path}: missing {field}")
    if not isinstance(value["metrics"], dict) or not isinstance(value["gates"], dict):
        raise ValueError(f"{path}: metrics and gates must be objects")
    if value["schema_version"] == 2:
        for field in ("gate_profile", "dataset_hash", "target_manifest_hash", "scorer_hash",
                      "discovery_passes_planned", "discovery_passes_completed"):
            if not value.get(field):
                raise ValueError(f"{path}: schema 2 summary missing {field}")
        if value["gate_profile"] != "near-auditor-l4-v2":
            raise ValueError(f"{path}: unsupported gate_profile")
    return value


def canonical_hash(value: dict[str, object]) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("summaries", nargs=3, type=Path)
    parser.add_argument("--issued-at", required=True, help="Explicit ISO-8601 issue time")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    summaries = [load_summary(path) for path in args.summaries]
    run_ids = [str(item["run_id"]) for item in summaries]
    if len(set(run_ids)) != 3:
        raise ValueError("maturity attestation requires three distinct run IDs")
    schemas = {int(item["schema_version"]) for item in summaries}
    if len(schemas) != 1:
        raise ValueError("benchmark summaries must use one schema version")
    schema = next(iter(schemas))
    tracks = {str(item["track"]) for item in summaries}
    configurations = {str(item["configuration_hash"]) for item in summaries}
    if len(tracks) != 1 or len(configurations) != 1:
        raise ValueError("benchmark summaries must use one track and configuration hash")
    benchmark_identity: dict[str, object] = {}
    if schema == 2:
        for field in ("gate_profile", "dataset_hash", "target_manifest_hash", "scorer_hash"):
            values = {str(item[field]) for item in summaries}
            if len(values) != 1:
                raise ValueError(f"benchmark summaries must use one {field}")
            benchmark_identity[field] = next(iter(values))
        counts = {int(item["discovery_passes_planned"]) for item in summaries}
        if len(counts) != 1 or any(item["discovery_passes_completed"] != item["discovery_passes_planned"] for item in summaries):
            raise ValueError("benchmark summaries require one complete discovery pass plan")
        benchmark_identity["discovery_passes_planned"] = next(iter(counts))
    if not all(item["qualified"] is True and all(item["gates"].values()) for item in summaries):
        raise ValueError("all three benchmark summaries must pass every L4 gate")

    metric_names = (
        "severity_weighted_recall",
        "mutation_kill_rate",
        "critical_high_auth_settlement_mutation_kill_rate",
        "invariant_execution_coverage",
        "async_complete_coverage",
    )
    worst_case = {
        name: min(float(item["metrics"][name]) for item in summaries) for name in metric_names
    }
    worst_case["critical_recall"] = min(
        float(item["metrics"]["recall_by_severity"]["critical"]) for item in summaries
    )
    worst_case["high_recall"] = min(
        float(item["metrics"]["recall_by_severity"]["high"]) for item in summaries
    )
    worst_case["review_minutes_per_10kloc"] = max(
        float(item["metrics"]["review_minutes_per_10kloc"]) for item in summaries
    )
    worst_case["rejected_per_accepted"] = max(
        float(item["metrics"]["rejected_per_accepted"]) for item in summaries
    )
    if schema == 2:
        for name in (
            "precision",
            "informed_weighted_recall_delta",
            "informed_incremental_precision",
        ):
            worst_case[name] = min(float(item["metrics"][name]) for item in summaries)
        for name in (
            "duplicate_rate",
            "safe_medium_plus_false_positives_per_10kloc",
            "runtime_overhead",
            "input_token_overhead",
        ):
            worst_case[name] = max(float(item["metrics"][name]) for item in summaries)
        worst_case["safe_critical_high_false_positives"] = max(
            int(item["metrics"]["safe_critical_high_false_positives"]) for item in summaries
        )

    summary_hashes = [f"sha256:{canonical_hash(item)}" for item in summaries]
    identity = {
        "summary_schema": schema,
        "track": next(iter(tracks)),
        "configuration_hash": next(iter(configurations)),
        "run_ids": run_ids,
        "summary_hashes": summary_hashes,
        **benchmark_identity,
    }
    attestation_id = f"sha256:{canonical_hash(identity)}"
    attestation = {
        "schema_version": 2 if schema == 2 else 1,
        "attestation_id": attestation_id,
        "capability_level": "L4",
        "track": next(iter(tracks)),
        "configuration_hash": next(iter(configurations)),
        "issued_at": args.issued_at,
        "run_ids": run_ids,
        "summary_hashes": summary_hashes,
        **benchmark_identity,
        "worst_case_metrics": worst_case,
        "human_adjudication_required": True,
        "qualified": True,
    }
    rendered = json.dumps(attestation, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
