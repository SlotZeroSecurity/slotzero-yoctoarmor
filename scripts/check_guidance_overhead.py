#!/usr/bin/env python3
"""Validate three-run runtime and input-token overhead."""

from __future__ import annotations

import argparse
import json
import statistics
from pathlib import Path


def load(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or value.get("schema_version") != 2:
        raise ValueError(f"{path}: expected schema-version-2 object; older measurements need their original package")
    if "mode" in value:
        raise ValueError(f"{path}: obsolete scan selector")
    rows = value.get("runs")
    if not isinstance(rows, list) or len(rows) < 3:
        raise ValueError(f"{path}: at least three equivalent runs are required")
    fixture_ids: set[str] = set()
    run_ids: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError(f"{path}: invalid run row")
        fixture_id = row.get("fixture_id")
        run_id = row.get("run_id")
        runtime = row.get("runtime_seconds")
        tokens = row.get("input_tokens")
        if not isinstance(fixture_id, str) or not fixture_id or not isinstance(run_id, str) or not run_id:
            raise ValueError(f"{path}: every row needs fixture_id and run_id")
        if run_id in run_ids:
            raise ValueError(f"{path}: duplicate run_id {run_id}")
        if not isinstance(runtime, (int, float)) or runtime <= 0:
            raise ValueError(f"{path}: runtime_seconds must be positive")
        if not isinstance(tokens, int) or tokens <= 0:
            raise ValueError(f"{path}: input_tokens must be a positive integer")
        run_ids.add(run_id)
        fixture_ids.add(fixture_id)
    value["_fixture_ids"] = fixture_ids
    return value


def medians(value: dict[str, object]) -> tuple[float, float]:
    rows = value["runs"]
    assert isinstance(rows, list)
    return (
        float(statistics.median(row["runtime_seconds"] for row in rows)),
        float(statistics.median(row["input_tokens"] for row in rows)),
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("baseline", type=Path)
    parser.add_argument("candidate", type=Path)
    parser.add_argument("--max-overhead", type=float, default=0.20)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.max_overhead < 0:
        parser.error("--max-overhead cannot be negative")

    baseline = load(args.baseline)
    candidate = load(args.candidate)
    if baseline["_fixture_ids"] != candidate["_fixture_ids"]:
        raise ValueError("baseline and candidate fixture sets differ")
    if baseline.get("audit_config_id") != candidate.get("audit_config_id"):
        raise ValueError("baseline and candidate audit_config_id differ")

    base_runtime, base_tokens = medians(baseline)
    candidate_runtime, candidate_tokens = medians(candidate)
    runtime_overhead = candidate_runtime / base_runtime - 1
    token_overhead = candidate_tokens / base_tokens - 1
    complete = runtime_overhead <= args.max_overhead and token_overhead <= args.max_overhead
    result = {
        "schema_version": 2,
        "audit_config_id": baseline.get("audit_config_id"),
        "fixtures": sorted(baseline["_fixture_ids"]),
        "run_count": min(len(baseline["runs"]), len(candidate["runs"])),
        "baseline_median_runtime_seconds": base_runtime,
        "candidate_median_runtime_seconds": candidate_runtime,
        "runtime_overhead": runtime_overhead,
        "baseline_median_input_tokens": base_tokens,
        "candidate_median_input_tokens": candidate_tokens,
        "input_token_overhead": token_overhead,
        "max_overhead": args.max_overhead,
        "complete": complete,
    }
    rendered = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0 if complete else 1


if __name__ == "__main__":
    raise SystemExit(main())
