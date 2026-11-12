#!/usr/bin/env python3
"""Record human TP/FP dispositions as local metrics-only audit feedback."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path

from run_integrity import (
    atomic_write_json, atomic_write_jsonl, require_current_run, run_lock, validate_bindings,
)

LABELS = {"TP", "FP", "DUPLICATE", "UNRESOLVED"}


def canonical_hash(value: object) -> str:
    """Hash normalized JSON content, independent of formatting and object key order."""
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def load_json(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected object")
    return value


def require_mutable_run(run_dir: Path) -> None:
    """Manifestless directories are standalone fixtures; legacy runs are read-only."""
    manifest_path = run_dir / "run-manifest.json"
    if not manifest_path.exists():
        if (run_dir / "run-state.json").exists():
            raise ValueError("run-state exists without run-manifest")
        return
    manifest = require_current_run(run_dir)
    state = load_json(run_dir / "run-state.json")
    if state.get("schema_version") != 4:
        raise ValueError("mutation requires run-state v4")
    if not manifest.get("run_id") or state.get("run_id") != manifest["run_id"]:
        raise ValueError("run-state identity differs from run-manifest")
    validate_bindings(run_dir)
    from run_journal import load as load_run_state
    if load_run_state(run_dir, repair_snapshot=True).get("run_id") != manifest["run_id"]:
        raise ValueError("run event journal identity differs from run-manifest")


def load_jsonl(path: Path, *, missing_ok: bool = False) -> list[dict[str, object]]:
    if not path.exists() and missing_ok:
        return []
    rows: list[dict[str, object]] = []
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


def candidate_index(run_dir: Path, *, required: bool = True) -> dict[str, dict[str, object]]:
    indexed: dict[str, dict[str, object]] = {}
    primary = "deduplicated.jsonl" if (run_dir / "deduplicated.jsonl").exists() else "raw-candidates.jsonl"
    for filename in (primary, "informed-rescan-candidates.jsonl"):
        source_ids: set[str] = set()
        for row in load_jsonl(run_dir / filename, missing_ok=filename != primary or not required):
            candidate_id = row.get("candidate_id")
            if not isinstance(candidate_id, str) or not candidate_id:
                raise ValueError(f"{filename}: missing candidate_id")
            if candidate_id in source_ids:
                raise ValueError(f"{filename}: duplicate candidate {candidate_id}")
            source_ids.add(candidate_id)
            if filename == "informed-rescan-candidates.jsonl" and candidate_pass(row) != "informed":
                raise ValueError(f"informed candidate {candidate_id}: invalid pass attribution")
            if candidate_id in indexed and canonical_hash(indexed[candidate_id]) != canonical_hash(row):
                raise ValueError(f"candidate {candidate_id}: conflicting row content across ledgers")
            indexed[candidate_id] = row
    return indexed


def string_values(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    return []


def candidate_pass(candidate: dict[str, object]) -> str:
    return "informed" if "verified_seed_variant" in string_values(candidate.get("discovery_technique")) else "blind"


def population_hashes(candidates: dict[str, dict[str, object]]) -> dict[str, str]:
    return {key: canonical_hash(row) for key, row in sorted(candidates.items())}


def blind_hashes(candidates: dict[str, dict[str, object]]) -> dict[str, str]:
    return population_hashes({key: row for key, row in candidates.items() if candidate_pass(row) == "blind"})


def validate_label(row: dict[str, object], candidates: dict[str, dict[str, object]], *, bound: bool) -> dict[str, object]:
    candidate_id = row.get("candidate_id")
    if not isinstance(candidate_id, str) or candidate_id not in candidates:
        raise ValueError(f"feedback references unknown candidate {candidate_id!r}")
    if row.get("schema_version") != 1 or row.get("label") not in LABELS:
        raise ValueError(f"feedback {candidate_id}: invalid schema or label")
    for field in ("reason_code", "reviewer", "reviewed_at"):
        if not isinstance(row.get(field), str) or not row[field].strip():
            raise ValueError(f"feedback {candidate_id}: missing {field}")
    inferred_pass = candidate_pass(candidates[candidate_id])
    if row.get("pass_origin", None if bound else inferred_pass) != inferred_pass:
        raise ValueError(f"feedback {candidate_id}: pass_origin differs from candidate attribution")
    content_hash = canonical_hash(candidates[candidate_id])
    if (bound or "candidate_hash" in row) and row.get("candidate_hash") != content_hash:
        raise ValueError(f"feedback {candidate_id}: candidate content drift (hash differs)")
    return {
        "schema_version": 1,
        "candidate_id": candidate_id,
        "candidate_hash": content_hash,
        "label": row["label"],
        "reason_code": row["reason_code"],
        "notes": row.get("notes", ""),
        "reviewer": row["reviewer"],
        "reviewed_at": row["reviewed_at"],
        "pass_origin": inferred_pass,
    }


def summarize(rows: list[dict[str, object]], candidates: dict[str, dict[str, object]]) -> dict[str, object]:
    labels = Counter(str(row["label"]) for row in rows)
    by_role: dict[str, Counter[str]] = defaultdict(Counter)
    by_pattern: dict[str, Counter[str]] = defaultdict(Counter)
    by_pass: dict[str, Counter[str]] = defaultdict(Counter)
    reason_codes: dict[str, Counter[str]] = defaultdict(Counter)
    for row in rows:
        candidate = candidates.get(str(row["candidate_id"]), {})
        label = str(row["label"])
        for role in string_values(candidate.get("origin_role") or candidate.get("role_id")):
            by_role[role][label] += 1
        for pattern in string_values(candidate.get("pattern_id")) + string_values(candidate.get("corpus_ids")):
            by_pattern[pattern][label] += 1
        by_pass[str(row["pass_origin"])][label] += 1
        reason_codes[label][str(row["reason_code"])] += 1
    decided = labels["TP"] + labels["FP"]
    return {
        "schema_version": 1,
        "status": "complete" if candidates else "skipped",
        "feedback_policy": "metrics_only",
        "automatic_learning": False,
        "total_rows": len(rows),
        "label_counts": dict(sorted(labels.items())),
        "precision": labels["TP"] / decided if decided else None,
        "by_role": {key: dict(sorted(value.items())) for key, value in sorted(by_role.items())},
        "by_pattern": {key: dict(sorted(value.items())) for key, value in sorted(by_pattern.items())},
        "by_pass": {key: dict(sorted(value.items())) for key, value in sorted(by_pass.items())},
        "reason_codes": {
            key: dict(sorted(value.items())) for key, value in sorted(reason_codes.items())
        },
        "corpus_changed": False,
        "prompts_changed": False,
        "routing_changed": False,
        "mutations_changed": False,
        "candidate_hashes": population_hashes(candidates),
        "reviewed_population_hash": canonical_hash(population_hashes(candidates)),
        "blind_candidate_hashes": blind_hashes(candidates),
        "feedback_hash": canonical_hash(sorted(rows, key=lambda row: str(row["candidate_id"]))),
        "blind_feedback_hash": canonical_hash(sorted(
            [row for row in rows if row["pass_origin"] == "blind"],
            key=lambda row: str(row["candidate_id"]),
        )),
    }


def _validate_feedback(run_dir: Path, *, require_complete: bool, allow_unreviewed_informed: bool = False) -> dict:
    summary_path = run_dir / "feedback-summary.json"
    summary = load_json(summary_path) if summary_path.exists() else {"status": "not_run"}
    rows = load_jsonl(run_dir / "finding-feedback.jsonl", missing_ok=True)
    status = summary.get("status")
    if status not in {"not_run", "pending", "complete", "skipped"}:
        raise ValueError("feedback-summary: invalid status")
    candidates = candidate_index(run_dir, required=status in {"complete", "skipped"})
    if status in {"not_run", "pending"}:
        if rows:
            raise ValueError("feedback-summary: pending review must not contain uncommitted labels")
        if summary_path.exists():
            empty = summarize([], {})
            for key in ("schema_version", "feedback_policy", "automatic_learning", "total_rows", "label_counts",
                        "corpus_changed", "prompts_changed", "routing_changed", "mutations_changed"):
                if summary.get(key) != empty[key]:
                    raise ValueError(f"feedback-summary: pending {key} differs from empty review")
        if require_complete:
            raise ValueError("feedback requires complete human review")
        return summary
    if not (run_dir / "finding-feedback.jsonl").is_file():
        raise ValueError("completed feedback requires finding-feedback.jsonl")
    indexed: dict[str, dict[str, object]] = {}
    for row in rows:
        normalized = validate_label(row, candidates, bound=True)
        candidate_id = str(normalized["candidate_id"])
        if candidate_id in indexed:
            raise ValueError(f"duplicate feedback candidate {candidate_id}")
        indexed[candidate_id] = normalized
    omitted = set(candidates) - set(indexed)
    if allow_unreviewed_informed:
        omitted = {key for key in omitted if candidate_pass(candidates[key]) != "informed"}
    if omitted:
        raise ValueError(f"feedback must disposition every review candidate; omitted {sorted(omitted)}")
    reviewed = {key: candidates[key] for key in indexed}
    expected = summarize(list(indexed.values()), reviewed)
    if summary.get("blind_candidate_hashes") != blind_hashes(candidates):
        raise ValueError("feedback: frozen blind population content drift")
    for key, value in expected.items():
        if summary.get(key) != value:
            raise ValueError(f"feedback-summary: {key} differs from reviewed ledger")
    return summary


def validate_feedback(run_dir: Path, *, require_complete: bool = False) -> dict:
    """Read-only gate: validate exact IDs, row hashes, attribution and all metrics.

    Callers coordinating concurrent writes should hold run_lock. This validator
    deliberately does not acquire the non-reentrant lock used by helper commands.
    """
    return _validate_feedback(run_dir, require_complete=require_complete)


def reviewed_blind_population(run_dir: Path) -> dict[str, dict[str, object]]:
    """Validate frozen review while allowing newly produced informed rows awaiting review."""
    _validate_feedback(run_dir, require_complete=True, allow_unreviewed_informed=True)
    return {key: row for key, row in candidate_index(run_dir).items() if candidate_pass(row) == "blind"}


def record_feedback(run_dir: Path, labels: Path) -> dict:
    """Commit a complete review. Mutating callers must hold run_lock."""
    require_mutable_run(run_dir)
    candidates = candidate_index(run_dir)
    indexed: dict[str, dict[str, object]] = {}
    for row in load_jsonl(labels):
        normalized = validate_label(row, candidates, bound=False)
        candidate_id = str(normalized["candidate_id"])
        if candidate_id in indexed:
            raise ValueError(f"duplicate feedback candidate {candidate_id}")
        indexed[candidate_id] = normalized
    omitted = sorted(set(candidates) - set(indexed))
    if omitted:
        raise ValueError(f"feedback must disposition every review candidate; omitted {omitted}")
    previous_path = run_dir / "feedback-summary.json"
    if previous_path.exists():
        previous = load_json(previous_path)
        frozen = previous.get("blind_candidate_hashes")
        if previous.get("status") in {"complete", "skipped"} and frozen != blind_hashes(candidates):
            raise ValueError("feedback: frozen blind population content drift; cannot reseed")
    rows = [indexed[key] for key in sorted(indexed)]
    summary = summarize(rows, candidates)
    informed_path = run_dir / "informed-rescan-summary.json"
    if informed_path.exists():
        informed = load_json(informed_path)
        if informed.get("status") in {"prepared", "complete", "skipped", "blocked"}:
            if informed.get("blind_feedback_hash") != summary["blind_feedback_hash"]:
                raise ValueError("blind feedback is frozen after informed preparation; cannot reseed")
    # Commit the summary last. A crash between replacements fails validation.
    atomic_write_jsonl(run_dir / "finding-feedback.jsonl", rows)
    atomic_write_json(run_dir / "feedback-summary.json", summary)
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("run_dir", type=Path)
    parser.add_argument("labels", type=Path, help="Human-authored feedback JSONL")
    args = parser.parse_args()
    run_dir = args.run_dir.resolve()
    if (run_dir / "run-manifest.json").exists():
        require_current_run(run_dir)
    run_dir.mkdir(parents=True, exist_ok=True)
    with run_lock(run_dir):
        result = record_feedback(run_dir, args.labels.resolve())
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
