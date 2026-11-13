#!/usr/bin/env python3
"""Prepare or complete one TP-seeded, same-target informed rescan."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from record_feedback import (
    require_mutable_run, reviewed_blind_population, validate_feedback,
    string_values as values,
)
from run_integrity import (
    atomic_write_json, atomic_write_jsonl, require_current_run, run_lock,
    canonical_hash, load_json_object as load_json, load_jsonl_objects,
)

MAX_EDGE_ROWS = 120
MAX_RELATED_SYMBOLS = 80

def load_jsonl(path: Path, *, missing_ok: bool = False) -> list[dict[str, object]]:
    return [] if missing_ok and not path.exists() else load_jsonl_objects(path, contextual_errors=False)


def affected_symbols(candidate: dict[str, object], semantic: dict[str, object]) -> list[str]:
    matches: set[str] = set()
    locations = candidate.get("locations", [])
    if not isinstance(locations, list):
        return []
    for location in locations:
        if not isinstance(location, dict):
            continue
        path = location.get("path")
        function = location.get("function")
        for symbol in semantic.get("symbols", []):
            if not isinstance(symbol, dict):
                continue
            if symbol.get("path") == path and symbol.get("name") == function:
                matches.add(str(symbol["symbol_id"]))
    return sorted(matches)


def graph_neighborhood(symbol_ids: list[str], semantic: dict[str, object]) -> dict[str, object]:
    affected = set(symbol_ids)
    related: set[str] = set(symbol_ids)
    state_fields = {
        str(row["field"])
        for row in semantic.get("state_accesses", [])
        if isinstance(row, dict) and row.get("symbol_id") in affected
    }
    state_edges = [
        row
        for row in semantic.get("state_accesses", [])
        if isinstance(row, dict) and row.get("field") in state_fields
    ]
    related.update(str(row["symbol_id"]) for row in state_edges)
    call_edges = []
    for row in semantic.get("call_edges", []):
        if not isinstance(row, dict):
            continue
        if row.get("caller") in affected or row.get("to_symbol") in affected:
            call_edges.append(row)
            if isinstance(row.get("caller"), str):
                related.add(str(row["caller"]))
            if isinstance(row.get("to_symbol"), str):
                related.add(str(row["to_symbol"]))
    affected_names = {
        str(row.get("name"))
        for row in semantic.get("symbols", [])
        if isinstance(row, dict) and row.get("symbol_id") in affected
    }
    receipt_edges = [
        row
        for row in semantic.get("receipt_edges", [])
        if isinstance(row, dict)
        and (row.get("from_symbol") in affected or row.get("callback") in affected_names)
    ]
    related.update(
        str(row["from_symbol"])
        for row in receipt_edges
        if isinstance(row.get("from_symbol"), str)
    )
    authority_kinds = {
        str(row["authority"])
        for row in semantic.get("authority_edges", [])
        if isinstance(row, dict) and row.get("symbol_id") in affected
    }
    authority_edges = [
        row
        for row in semantic.get("authority_edges", [])
        if isinstance(row, dict) and row.get("authority") in authority_kinds
    ]
    related.update(str(row["symbol_id"]) for row in authority_edges)
    flow_kinds = {
        str(row["flow_kind"])
        for row in semantic.get("value_flows", [])
        if isinstance(row, dict) and row.get("symbol_id") in affected
    }
    value_flows = [
        row
        for row in semantic.get("value_flows", [])
        if isinstance(row, dict) and row.get("flow_kind") in flow_kinds
    ]
    related.update(str(row["symbol_id"]) for row in value_flows)
    edge_sets = {
        "state_edges": state_edges,
        "call_edges": call_edges,
        "receipt_edges": receipt_edges,
        "authority_edges": authority_edges,
        "value_flows": value_flows,
    }
    truncated = {
        name: max(0, len(rows) - MAX_EDGE_ROWS)
        for name, rows in edge_sets.items()
    }
    related_rows = sorted(related - affected)
    truncated["related_symbols"] = max(0, len(related_rows) - MAX_RELATED_SYMBOLS)
    return {
        "affected_symbols": sorted(affected),
        "related_symbols": related_rows[:MAX_RELATED_SYMBOLS],
        "shared_state_fields": sorted(state_fields),
        **{name: rows[:MAX_EDGE_ROWS] for name, rows in edge_sets.items()},
        "truncated_rows": truncated,
        "limits": {"edge_rows_per_kind": MAX_EDGE_ROWS, "related_symbols": MAX_RELATED_SYMBOLS},
    }


def prepare(run_dir: Path) -> dict[str, object]:
    """Prepare once after human review; mutating callers must hold run_lock."""
    require_mutable_run(run_dir)
    summary_path = run_dir / "informed-rescan-summary.json"
    if summary_path.exists():
        previous = load_json(summary_path)
        if previous.get("status") in {"prepared", "complete", "skipped", "blocked"}:
            raise ValueError("informed rescan was already prepared; exactly one iteration is allowed")
    reviewed = validate_feedback(run_dir)
    if reviewed.get("status") not in {"complete", "skipped"}:
        if any((run_dir / name).exists() for name in (
            "verified-seeds.jsonl", "informed-rescan-candidates.jsonl", "informed-rescan-packet.json",
        )):
            raise ValueError("pending review cannot defer with existing seed or informed artifacts")
        summary = {
            "schema_version": 1,
            "iteration": 1,
            "status": "deferred",
            "reason": "human feedback is not complete",
            "seed_count": 0,
            "new_candidate_ids": [],
            "rediscovery_candidate_ids": [],
        }
        atomic_write_json(summary_path, summary)
        return summary
    candidates = reviewed_blind_population(run_dir)
    feedback = load_jsonl(run_dir / "finding-feedback.jsonl")
    tp_rows = [row for row in feedback if row.get("label") == "TP" and row.get("pass_origin") == "blind"]
    semantic = load_json(run_dir / "semantic-ir.json") if tp_rows else {}
    seeds: list[dict[str, object]] = []
    for feedback_row in tp_rows:
        candidate_id = str(feedback_row["candidate_id"])
        candidate = candidates.get(candidate_id)
        if candidate is None:
            raise ValueError(f"TP feedback has no candidate payload: {candidate_id}")
        symbols = affected_symbols(candidate, semantic)
        locations = candidate.get("locations", [])
        seed = {
            "schema_version": 1,
            "seed_id": f"seed-{candidate_id}",
            "source_candidate_id": candidate_id,
            "source_candidate_hash": feedback_row["candidate_hash"],
            "source_fingerprint": candidate.get("root_cause_fingerprint"),
            "root_cause": candidate.get("root_cause"),
            "broken_invariant": candidate.get("broken_invariant"),
            "intent_invariant_ids": values(candidate.get("intent_invariant_ids")),
            "attacker_capability": candidate.get("attacker"),
            "preconditions": candidate.get("preconditions", []),
            "receipt_trace": candidate.get("receipt_trace", []),
            "defenses_checked": candidate.get("defenses_checked", []),
            "affected_symbols": symbols,
            "excluded_locations": locations,
            "search_neighborhood": graph_neighborhood(symbols, semantic),
            "forbidden_fields_removed": ["severity", "recommendation", "fix", "report_title"],
        }
        seed["seed_hash"] = canonical_hash(seed)
        seeds.append(seed)
    seeds.sort(key=lambda row: str(row["seed_id"]))
    atomic_write_jsonl(run_dir / "verified-seeds.jsonl", seeds)
    if not seeds:
        summary = {
            "schema_version": 1,
            "iteration": 1,
            "status": "skipped",
            "reason": "no manually labelled blind TP seeds",
            "seed_count": 0,
            "new_candidate_ids": [],
            "rediscovery_candidate_ids": [],
            "blind_candidate_hashes": reviewed["blind_candidate_hashes"],
            "blind_feedback_hash": reviewed["blind_feedback_hash"],
        }
        atomic_write_json(summary_path, summary)
        return summary
    packet = {
        "schema_version": 1,
        "iteration": 1,
        "discovery_technique": "verified_seed_variant",
        "semantic_ir_hash": canonical_hash(semantic),
        "seed_file": "verified-seeds.jsonl",
        "candidate_output": "informed-rescan-candidates.jsonl",
        "allowed_inputs": [
            "verified-seeds.jsonl",
            "semantic-ir.json",
            "finding schema",
            "security model",
            "exact target source in each seed neighborhood",
        ],
        "forbidden_inputs": [
            "first-pass report prose",
            "severity and recommendations",
            "benchmark answers",
            "rejected candidates and verdict rationales",
        ],
        "rules": [
            "Search sibling writers/readers, alternate callers, adjacent receipt states, and analogous methods.",
            "Do not emit an original excluded location or a pure rediscovery.",
            "Use origin_level L3 and discovery_technique verified_seed_variant.",
            "Every new candidate re-enters ordinary deduplication and both judge stages.",
            "Run once and stop.",
        ],
    }
    packet["packet_hash"] = canonical_hash(packet)
    atomic_write_json(run_dir / "informed-rescan-packet.json", packet)
    summary = {
        "schema_version": 1,
        "iteration": 1,
        "status": "prepared",
        "seed_count": len(seeds),
        "seed_ids": [row["seed_id"] for row in seeds],
        "packet_hash": packet["packet_hash"],
        "new_candidate_ids": [],
        "rediscovery_candidate_ids": [],
        "blind_candidate_hashes": reviewed["blind_candidate_hashes"],
        "blind_feedback_hash": reviewed["blind_feedback_hash"],
    }
    atomic_write_json(summary_path, summary)
    return summary


def complete(run_dir: Path) -> dict[str, object]:
    """Complete an explicit output artifact; mutating callers must hold run_lock."""
    require_mutable_run(run_dir)
    summary_path = run_dir / "informed-rescan-summary.json"
    summary = load_json(summary_path)
    if summary.get("status") == "complete":
        raise ValueError("informed rescan is already complete")
    if summary.get("status") == "skipped":
        reviewed_blind_population(run_dir)
        return summary
    if summary.get("status") != "prepared" or summary.get("iteration") != 1:
        raise ValueError("informed rescan must be prepared before completion")
    blind = reviewed_blind_population(run_dir)
    reviewed = load_json(run_dir / "feedback-summary.json")
    if (summary.get("blind_candidate_hashes") != reviewed["blind_candidate_hashes"]
            or summary.get("blind_feedback_hash") != reviewed["blind_feedback_hash"]):
        raise ValueError("informed rescan: frozen blind feedback differs")
    seeds = load_jsonl(run_dir / "verified-seeds.jsonl")
    expected_sources = {
        row["candidate_id"] for row in load_jsonl(run_dir / "finding-feedback.jsonl")
        if row.get("label") == "TP" and row.get("pass_origin") == "blind"
    }
    seed_candidates = {str(row["source_candidate_id"]) for row in seeds}
    if (seed_candidates != expected_sources or len(seed_candidates) != len(seeds)
            or summary.get("seed_count") != len(seeds)
            or summary.get("seed_ids") != [row.get("seed_id") for row in seeds]):
        raise ValueError("informed rescan: seeds differ from frozen blind TP feedback")
    for seed in seeds:
        unhashed = {key: value for key, value in seed.items() if key != "seed_hash"}
        source_id = str(seed["source_candidate_id"])
        if (seed.get("seed_hash") != canonical_hash(unhashed)
                or seed.get("source_candidate_hash") != canonical_hash(blind[source_id])):
            raise ValueError(f"informed seed {source_id}: content hash differs")
    excluded_by_seed = {
        str(row["source_candidate_id"]): {
            (str(location.get("path")), str(location.get("function")))
            for location in row.get("excluded_locations", [])
            if isinstance(location, dict)
        }
        for row in seeds
    }
    rows = load_jsonl(run_dir / "informed-rescan-candidates.jsonl")
    identifiers: set[str] = set()
    rediscoveries: list[str] = []
    for row in rows:
        candidate_id = row.get("candidate_id")
        if not isinstance(candidate_id, str) or not candidate_id:
            raise ValueError("informed candidate missing candidate_id")
        if candidate_id in identifiers:
            raise ValueError(f"duplicate informed candidate {candidate_id}")
        identifiers.add(candidate_id)
        techniques = values(row.get("discovery_technique"))
        if "verified_seed_variant" not in techniques or row.get("origin_level") != "L3":
            raise ValueError(f"informed candidate {candidate_id}: invalid attribution")
        source_id = row.get("seed_source_candidate_id")
        if source_id not in seed_candidates:
            raise ValueError(f"informed candidate {candidate_id}: missing or unknown seed source")
        variant_evidence = row.get("variant_evidence")
        if not isinstance(variant_evidence, list) or not variant_evidence or not all(
            isinstance(item, str) and item for item in variant_evidence
        ):
            raise ValueError(f"informed candidate {candidate_id}: variant_evidence is required")
        locations = row.get("locations")
        if not isinstance(locations, list) or not locations:
            raise ValueError(f"informed candidate {candidate_id}: locations are required")
        location_keys = {
            (str(location.get("path")), str(location.get("function")))
            for location in locations
            if isinstance(location, dict)
        }
        if (
            candidate_id in seed_candidates
            or row.get("pure_rediscovery") is True
            or not (location_keys - excluded_by_seed[str(source_id)])
        ):
            rediscoveries.append(candidate_id)
    if rediscoveries:
        raise ValueError(f"informed rescan emitted pure rediscoveries: {sorted(rediscoveries)}")
    summary["status"] = "complete"
    summary["new_candidate_ids"] = sorted(identifiers)
    summary["rediscovery_candidate_ids"] = []
    atomic_write_json(summary_path, summary)
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("run_dir", type=Path)
    parser.add_argument("--complete", action="store_true")
    args = parser.parse_args()
    run_dir = args.run_dir.resolve()
    if (run_dir / "run-manifest.json").exists():
        require_current_run(run_dir)
    run_dir.mkdir(parents=True, exist_ok=True)
    with run_lock(run_dir):
        result = complete(run_dir) if args.complete else prepare(run_dir)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
