#!/usr/bin/env python3
"""Validate raw-to-dedup accounting and one verdict per deduplicated candidate."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from functools import lru_cache
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from run_integrity import read_registry
from pattern_routing import validate_index


@lru_cache(maxsize=1)
def active_patterns() -> dict[str, dict[str, object]]:
    return validate_index()["cards"]


VERDICTS = {"valid", "valid_downgraded", "lead", "false_positive"}
PROOF_STATUSES = {
    "VERIFIED_EXECUTED",
    "VERIFIED_STRUCTURAL",
    "CODE_CONFIRMED",
    "PARTIAL",
    "CONTESTED",
    "REFUTED",
}
SEVERITIES = {"critical", "high", "medium", "low", "informational"}
IMPACTS = {"Severe", "Moderate", "Minor", "None"}
LIKELIHOODS = {"Likely", "Possible", "Rare"}
DISPOSITIONS = {"survives", "merged", "chain_absorbed", "quality", "deferred"}
ORIGIN_LEVELS = {"L1", "L2", "L3"}
DISCOVERY_TECHNIQUES = {
    "pattern_match",
    "intent_gap",
    "specialist_trace",
    "async_schedule",
    "invariant_counterexample",
    "differential_nep",
    "temporal_upgrade",
    "attack_chain",
    "corpus_echo",
    "counterexample_rescan",
    "verified_seed_variant",
}
TRIAGE_STATUSES = {"passed", "rejected", "blocked"}
VERIFICATION_STATUSES = {"verified", "downgraded", "lead", "refuted", "blocked", "contested"}
HUMAN_DISPOSITIONS = {
    "approved",
    "rejected",
    "standards_only",
    "advisory",
    "duplicate",
    "out_of_scope",
    "blocked",
}
CONFIDENCE_AXES = {
    "source_anchoring": (0, 2),
    "reachability": (0, 3),
    "material_harm": (0, 3),
    "execution": (0, 3),
    "counter_evidence": (0, 2),
}
NEP_REGISTRY_PATH = Path(__file__).resolve().parent.parent / "references" / "nep-registry.json"
OFFICIAL_DOCS_REGISTRY_PATH = (
    Path(__file__).resolve().parent.parent / "references" / "official-docs-registry.json"
)


def load_jsonl(path: Path) -> list[dict[str, object]]:
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


def unique(rows: list[dict[str, object]], field: str, label: str) -> dict[str, dict[str, object]]:
    indexed: dict[str, dict[str, object]] = {}
    for row in rows:
        value = row.get(field)
        if not isinstance(value, str) or not value:
            raise ValueError(f"{label}: missing {field}")
        if value in indexed:
            raise ValueError(f"{label}: duplicate {field} {value}")
        indexed[value] = row
    return indexed


def validate_candidate(
    candidate_id: str,
    row: dict[str, object],
    known_neps: set[str],
    known_guidance: dict[str, set[str]] | None = None,
) -> None:
    for field in (
        "role_id",
        "origin_level",
        "origin_role",
        "discovery_technique",
        "root_cause_fingerprint",
        "model_and_prompt_hash",
        "judge_stage",
        "verification_status",
        "human_disposition",
        "kind",
        "bug_class",
        "root_cause",
        "evidence",
        "locations",
    ):
        if not row.get(field):
            raise ValueError(f"candidate {candidate_id}: missing {field}")
    if row.get("schema_version") != 2:
        raise ValueError(f"candidate {candidate_id}: schema_version must be 2")
    origin_level = row["origin_level"]
    origin_levels = [origin_level] if isinstance(origin_level, str) else origin_level
    if not isinstance(origin_levels, list) or not origin_levels or not all(
        item in ORIGIN_LEVELS for item in origin_levels
    ):
        raise ValueError(f"candidate {candidate_id}: invalid origin_level")
    origin_role = row["origin_role"]
    if not isinstance(origin_role, str) and not (
        isinstance(origin_role, list)
        and origin_role
        and all(isinstance(item, str) and item for item in origin_role)
    ):
        raise ValueError(f"candidate {candidate_id}: invalid origin_role")
    technique = row["discovery_technique"]
    techniques = [technique] if isinstance(technique, str) else technique
    if not isinstance(techniques, list) or not techniques or not all(
        item in DISCOVERY_TECHNIQUES for item in techniques
    ):
        raise ValueError(f"candidate {candidate_id}: invalid discovery_technique")
    fingerprint = row["root_cause_fingerprint"]
    if not isinstance(fingerprint, str) or not fingerprint.startswith("sha256:"):
        raise ValueError(f"candidate {candidate_id}: invalid root_cause_fingerprint")
    digest = fingerprint.removeprefix("sha256:")
    if len(digest) != hashlib.sha256().digest_size * 2 or any(c not in "0123456789abcdef" for c in digest):
        raise ValueError(f"candidate {candidate_id}: root_cause_fingerprint must contain a lowercase SHA-256")
    prompt_hash = row["model_and_prompt_hash"]
    prompt_hashes = [prompt_hash] if isinstance(prompt_hash, str) else prompt_hash
    if not isinstance(prompt_hashes, list) or not prompt_hashes or not all(
        isinstance(item, str) and item.startswith("sha256:") for item in prompt_hashes
    ):
        raise ValueError(f"candidate {candidate_id}: invalid model_and_prompt_hash")
    if row["judge_stage"] != "unjudged" or row["verification_status"] != "unverified":
        raise ValueError(f"candidate {candidate_id}: discovery candidate must be unjudged/unverified")
    if row["human_disposition"] != "pending":
        raise ValueError(f"candidate {candidate_id}: discovery candidate human_disposition must be pending")
    invariant_ids = row.get("intent_invariant_ids")
    if not isinstance(invariant_ids, list) or not all(isinstance(item, str) and item for item in invariant_ids):
        raise ValueError(f"candidate {candidate_id}: intent_invariant_ids must be a string list")
    if row["kind"] not in {"finding", "lead"}:
        raise ValueError(f"candidate {candidate_id}: kind must be finding or lead")
    if not isinstance(row["locations"], list) or not row["locations"]:
        raise ValueError(f"candidate {candidate_id}: locations must be a non-empty list")
    for location in row["locations"]:
        if not isinstance(location, dict) or not location.get("path") or not location.get("function"):
            raise ValueError(f"candidate {candidate_id}: invalid location")
    if not isinstance(row["evidence"], list) or not row["evidence"]:
        raise ValueError(f"candidate {candidate_id}: evidence must be a non-empty list")
    if row["kind"] == "finding":
        for field in (
            "canonical_key",
            "broken_invariant",
            "receipt_trace",
            "terminal_harm",
            "defenses_checked",
            "fix_class",
        ):
            if not row.get(field):
                raise ValueError(f"finding {candidate_id}: missing {field}")
        if not invariant_ids:
            raise ValueError(f"finding {candidate_id}: requires intent_invariant_ids")
    if "L1" in origin_levels and not row.get("pattern_id"):
        raise ValueError(f"candidate {candidate_id}: L1 requires pattern_id")
    pattern_id = row.get("pattern_id")
    if pattern_id is not None:
        if not isinstance(pattern_id, str) or pattern_id not in active_patterns():
            raise ValueError(f"candidate {candidate_id}: pattern_id must be an active NA card")
        if row["kind"] == "finding" and active_patterns()[pattern_id]["kind"] == "quality_only":
            raise ValueError(f"candidate {candidate_id}: quality-only card cannot be a finding")
    corpus_ids = row.get("corpus_ids", [])
    if not isinstance(corpus_ids, list) or not all(isinstance(item, str) and item in active_patterns() for item in corpus_ids):
        raise ValueError(f"candidate {candidate_id}: corpus_ids must be active NA cards")
    if set(origin_levels) == {"L2"}:
        if row.get("pattern_id") or row.get("corpus_ids"):
            raise ValueError(f"candidate {candidate_id}: L2 must be corpus-blind")
        if not row.get("intent_evidence") or not row.get("implementation_behavior"):
            raise ValueError(f"candidate {candidate_id}: L2 requires intent evidence and implementation behavior")
    nep_ids = row.get("nep_ids", [])
    if not isinstance(nep_ids, list) or not all(isinstance(item, str) for item in nep_ids):
        raise ValueError(f"candidate {candidate_id}: nep_ids must be a string list")
    unknown_neps = sorted(set(nep_ids) - known_neps)
    if unknown_neps:
        raise ValueError(f"candidate {candidate_id}: unknown NEP ids {unknown_neps}")
    requirements = row.get("standard_requirements", [])
    if not isinstance(requirements, list) or not all(isinstance(item, dict) for item in requirements):
        raise ValueError(f"candidate {candidate_id}: standard_requirements must be an object list")
    requirement_neps: set[str] = set()
    for requirement in requirements:
        nep_id = requirement.get("nep_id")
        if (
            not isinstance(nep_id, str)
            or nep_id not in known_neps
            or not requirement.get("requirement")
            or not requirement.get("source_section")
        ):
            raise ValueError(f"candidate {candidate_id}: invalid standard requirement")
        requirement_neps.add(nep_id)
    if requirement_neps - set(nep_ids):
        raise ValueError(f"candidate {candidate_id}: standard requirement NEP missing from nep_ids")
    if nep_ids and not requirements:
        raise ValueError(f"candidate {candidate_id}: nep_ids require standard_requirements")
    guidance_ids = row.get("official_guidance_ids", [])
    if not isinstance(guidance_ids, list) or not all(isinstance(item, str) for item in guidance_ids):
        raise ValueError(f"candidate {candidate_id}: official_guidance_ids must be a string list")
    if known_guidance is not None:
        unknown_guidance = sorted(set(guidance_ids) - set(known_guidance))
        if unknown_guidance:
            raise ValueError(f"candidate {candidate_id}: unknown official guidance {unknown_guidance}")
    guidance_evidence = row.get("guidance_evidence", [])
    if not isinstance(guidance_evidence, list) or not all(isinstance(item, dict) for item in guidance_evidence):
        raise ValueError(f"candidate {candidate_id}: guidance_evidence must be an object list")
    evidence_cards: set[str] = set()
    for evidence in guidance_evidence:
        card_id = evidence.get("card_id")
        if (
            not isinstance(card_id, str)
            or card_id not in guidance_ids
            or not evidence.get("url_path")
            or not evidence.get("source_section")
        ):
            raise ValueError(f"candidate {candidate_id}: invalid guidance evidence")
        if known_guidance is not None and str(evidence["url_path"]) not in known_guidance[card_id]:
            raise ValueError(
                f"candidate {candidate_id}: guidance evidence URL is not routed to {card_id}"
            )
        evidence_cards.add(card_id)
    if set(guidance_ids) != evidence_cards:
        raise ValueError(f"candidate {candidate_id}: every guidance ID requires exact evidence")
    if set(origin_levels) == {"L2"} and (guidance_ids or guidance_evidence):
        raise ValueError(f"candidate {candidate_id}: L2 must be official-guidance blind")
    if "verified_seed_variant" in techniques and set(origin_levels) != {"L3"}:
        raise ValueError(f"candidate {candidate_id}: verified_seed_variant must originate at L3")


def location_key(value: object) -> tuple[str, str, int | None, int | None]:
    if not isinstance(value, dict):
        raise ValueError("location must be an object")
    path = value.get("path")
    function = value.get("function")
    start = value.get("start")
    end = value.get("end")
    if not isinstance(path, str) or not path or not isinstance(function, str) or not function:
        raise ValueError("location requires path and function")
    if start is not None and not isinstance(start, int):
        raise ValueError("location start must be an integer")
    if end is not None and not isinstance(end, int):
        raise ValueError("location end must be an integer")
    return path, function, start, end


def validate_confidence(candidate_id: str, value: object) -> None:
    if not isinstance(value, dict):
        raise ValueError(f"verdict {candidate_id}: confidence must be an object")
    total = 0
    for axis, (minimum, maximum) in CONFIDENCE_AXES.items():
        score = value.get(axis)
        if not isinstance(score, int) or not minimum <= score <= maximum:
            raise ValueError(f"verdict {candidate_id}: invalid confidence axis {axis}")
        total += score
    if value.get("total") != total:
        raise ValueError(f"verdict {candidate_id}: confidence total must equal {total}")


def ledger_index(rows: object, label: str) -> dict[str, dict[str, object]]:
    """Accept a JSONL path, rows, or an already indexed ledger."""
    if isinstance(rows, (str, Path)):
        rows = load_jsonl(Path(rows))
    if isinstance(rows, dict):
        indexed = unique(list(rows.values()), "candidate_id", label)
        if rows != indexed:
            raise ValueError(f"{label}: index keys differ from candidate IDs")
        return indexed
    if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
        raise ValueError(f"{label}: expected object rows")
    return unique(rows, "candidate_id", label)


def validate_dedup(
    raw: dict[str, dict[str, object]],
    dedup: dict[str, dict[str, object]],
    dispositions: dict[str, dict[str, object]],
) -> dict[str, object]:
    """Validate discovery rows and complete raw-to-dedup accounting."""
    raw = ledger_index(raw, "raw candidate")
    deduplicated = ledger_index(dedup, "deduplicated candidate")
    dispositions = ledger_index(dispositions, "disposition")

    known_neps = set(read_registry(NEP_REGISTRY_PATH)["neps"])
    docs_registry = read_registry(OFFICIAL_DOCS_REGISTRY_PATH)
    known_guidance = {card_id: set() for card_id in docs_registry["cards"]}
    for page in docs_registry["pages"]:
        for card_id in page["attacker_card_ids"]:
            known_guidance[card_id].add(page["url_path"])
    for source in (raw, deduplicated):
        for candidate_id, row in source.items():
            validate_candidate(candidate_id, row, known_neps, known_guidance)

    missing_dispositions = sorted(set(raw) - set(dispositions))
    unknown_dispositions = sorted(set(dispositions) - set(raw))
    if missing_dispositions or unknown_dispositions:
        raise ValueError(
            f"raw ledger mismatch: missing={missing_dispositions}; unknown={unknown_dispositions}"
        )

    targeted: set[str] = set()
    for candidate_id, row in dispositions.items():
        disposition = row.get("disposition")
        if disposition not in DISPOSITIONS:
            raise ValueError(f"disposition {candidate_id}: invalid disposition {disposition!r}")
        if not row.get("rationale"):
            raise ValueError(f"disposition {candidate_id}: missing rationale")
        target_id = row.get("target_id")
        if disposition in {"survives", "merged", "chain_absorbed"}:
            if not isinstance(target_id, str) or target_id not in deduplicated:
                raise ValueError(f"disposition {candidate_id}: invalid deduplicated target")
            targeted.add(target_id)
            raw_locations = {location_key(item) for item in raw[candidate_id]["locations"]}
            target_locations = {
                location_key(item) for item in deduplicated[target_id]["locations"]
            }
            dropped = sorted(raw_locations - target_locations)
            if dropped:
                raise ValueError(
                    f"disposition {candidate_id}: target {target_id} drops locations {dropped}"
                )
        elif target_id is not None:
            raise ValueError(f"disposition {candidate_id}: {disposition} must not have target_id")

    untargeted = sorted(set(deduplicated) - targeted)
    if untargeted:
        raise ValueError(f"deduplicated candidates without raw provenance: {untargeted}")

    return {
        "raw_candidates": len(raw),
        "deduplicated": len(deduplicated),
        "dispositions": len(dispositions),
        "complete": True,
    }


def validate_ledgers(
    raw: dict[str, dict[str, object]],
    dedup: dict[str, dict[str, object]],
    verdicts: dict[str, dict[str, object]],
    dispositions: dict[str, dict[str, object]],
    stage: str = "approved",
) -> dict[str, object]:
    """Validate all automated evidence; draft additionally permits pending review."""
    if stage not in {"draft", "approved"}:
        raise ValueError("ledger stage must be draft or approved")
    counts = validate_dedup(raw, dedup, dispositions)
    deduplicated = ledger_index(dedup, "deduplicated candidate")
    verdicts = ledger_index(verdicts, "verdict")

    missing_verdicts = sorted(set(deduplicated) - set(verdicts))
    unknown_verdicts = sorted(set(verdicts) - set(deduplicated))
    if missing_verdicts or unknown_verdicts:
        raise ValueError(
            f"verdict mismatch: missing={missing_verdicts}; unknown={unknown_verdicts}"
        )

    for candidate_id, row in verdicts.items():
        triage = row.get("triage")
        if not isinstance(triage, dict) or triage.get("status") not in TRIAGE_STATUSES:
            raise ValueError(f"verdict {candidate_id}: invalid or missing triage")
        triage_status = triage["status"]
        if not isinstance(triage.get("evidence"), list):
            raise ValueError(f"verdict {candidate_id}: triage evidence must be a list")
        if triage_status == "rejected" and not triage.get("blocking_fact"):
            raise ValueError(f"verdict {candidate_id}: rejected triage requires blocking_fact")
        if triage_status == "passed" and not triage.get("packet_hash"):
            raise ValueError(f"verdict {candidate_id}: passed triage requires packet_hash")
        expected_stage = "adversarial_verification" if triage_status == "passed" else "evidence_triage"
        if row.get("judge_stage") != expected_stage:
            raise ValueError(f"verdict {candidate_id}: judge_stage must be {expected_stage}")
        if row.get("verification_status") not in VERIFICATION_STATUSES:
            raise ValueError(f"verdict {candidate_id}: invalid verification_status")
        human_disposition = row.get("human_disposition")
        pending_review = stage == "draft" and human_disposition == "pending"
        if human_disposition not in HUMAN_DISPOSITIONS and not pending_review:
            raise ValueError(f"verdict {candidate_id}: final human_disposition required")
        verdict = row.get("verdict")
        if verdict not in VERDICTS:
            raise ValueError(f"verdict {candidate_id}: invalid verdict {verdict!r}")
        if triage_status == "rejected" and verdict != "false_positive":
            raise ValueError(f"verdict {candidate_id}: rejected triage must end false_positive")
        if triage_status == "blocked" and verdict != "lead":
            raise ValueError(f"verdict {candidate_id}: blocked triage must end lead")
        if row.get("proof_status") not in PROOF_STATUSES:
            raise ValueError(f"verdict {candidate_id}: invalid or missing proof_status")
        if verdict in {"valid", "valid_downgraded"}:
            severity = str(row.get("severity", "")).lower()
            if severity not in SEVERITIES:
                raise ValueError(f"verdict {candidate_id}: invalid or missing severity")
            if row.get("proof_status") == "REFUTED":
                raise ValueError(f"verdict {candidate_id}: valid verdict cannot be REFUTED")
            if human_disposition != "approved" and not pending_review:
                raise ValueError(f"verdict {candidate_id}: valid verdict requires human approval")
            expected_status = "verified" if verdict == "valid" else "downgraded"
            if row["verification_status"] != expected_status:
                raise ValueError(
                    f"verdict {candidate_id}: {verdict} requires verification_status {expected_status}"
                )
        if verdict == "false_positive":
            if row.get("proof_status") != "REFUTED" or not row.get("blocking_defense"):
                raise ValueError(
                    f"verdict {candidate_id}: false_positive requires REFUTED and blocking_defense"
                )
            if human_disposition != "rejected" and not pending_review:
                raise ValueError(f"verdict {candidate_id}: false_positive requires human rejection")
            if row["verification_status"] != "refuted":
                raise ValueError(f"verdict {candidate_id}: false_positive requires refuted status")
        if verdict == "lead" and row["verification_status"] not in {
            "lead",
            "blocked",
            "contested",
        }:
            raise ValueError(f"verdict {candidate_id}: lead has inconsistent verification_status")
        if row.get("impact") not in IMPACTS:
            raise ValueError(f"verdict {candidate_id}: invalid or missing impact")
        if row.get("likelihood") not in LIKELIHOODS:
            raise ValueError(f"verdict {candidate_id}: invalid or missing likelihood")
        if not isinstance(row.get("external_assumptions"), list):
            raise ValueError(f"verdict {candidate_id}: external_assumptions must be a list")
        if not row.get("rationale") or not row.get("evidence") or not row.get("poc_status"):
            raise ValueError(f"verdict {candidate_id}: missing rationale, evidence, or poc_status")
        validate_confidence(candidate_id, row.get("confidence"))

    return {**counts, "verdicts": len(verdicts)}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("raw_candidates", type=Path)
    parser.add_argument("deduplicated", type=Path)
    parser.add_argument("verdicts", type=Path)
    parser.add_argument("dispositions", type=Path)
    parser.add_argument("--stage", choices=("draft", "approved"), default="approved")
    args = parser.parse_args()
    print(json.dumps(validate_ledgers(
        args.raw_candidates, args.deduplicated, args.verdicts, args.dispositions,
        stage=args.stage,
    )))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
