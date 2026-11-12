#!/usr/bin/env python3
"""Validate exactly-one, status-aware audit coverage for every bundled NEP."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


DISPOSITIONS = {
    "conformant",
    "security_candidate",
    "conformance_deviation",
    "advisory",
    "superseded",
    "process_only",
    "not_applicable",
    "blocked",
}
APPLICABILITY = {"applicable", "not_applicable", "advisory", "superseded", "process_only", "blocked"}


def load_jsonl(path: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path}:{line_no}: invalid JSON: {exc}") from exc
        if not isinstance(row, dict):
            raise ValueError(f"{path}:{line_no}: expected object")
        rows.append(row)
    return rows


def string_list(row: dict[str, object], field: str, nep_id: str, *, nonempty: bool = False) -> list[str]:
    value = row.get(field)
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise ValueError(f"NEP-{nep_id}: {field} must be a string list")
    if nonempty and not value:
        raise ValueError(f"NEP-{nep_id}: {field} must not be empty")
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("coverage", type=Path)
    parser.add_argument(
        "--registry",
        type=Path,
        default=Path(__file__).resolve().parent.parent / "references" / "nep-registry.json",
    )
    args = parser.parse_args()
    registry = json.loads(args.registry.read_text(encoding="utf-8"))
    neps = registry["neps"]
    categories = registry["categories"]
    source_commit = registry["source"]["commit"]
    indexed: dict[str, dict[str, object]] = {}
    for row in load_jsonl(args.coverage):
        nep_id = row.get("nep_id")
        if not isinstance(nep_id, str) or nep_id not in neps:
            raise ValueError(f"coverage: unknown or missing nep_id {nep_id!r}")
        if nep_id in indexed:
            raise ValueError(f"coverage: duplicate NEP-{nep_id}")
        indexed[nep_id] = row
    missing = sorted(set(neps) - set(indexed))
    if missing:
        raise ValueError(f"coverage: missing NEPs {missing}")

    counts: dict[str, int] = {}
    for nep_id, row in indexed.items():
        spec = neps[nep_id]
        category = categories[spec["category"]]
        if row.get("role_id") != category["role_id"]:
            raise ValueError(f"NEP-{nep_id}: role_id does not own registry category")
        if row.get("source_commit") != source_commit:
            raise ValueError(f"NEP-{nep_id}: source_commit mismatch")
        if row.get("source_status") != spec["status"]:
            raise ValueError(f"NEP-{nep_id}: source_status mismatch")
        applicability = row.get("applicability")
        disposition = row.get("disposition")
        if applicability not in APPLICABILITY or disposition not in DISPOSITIONS:
            raise ValueError(f"NEP-{nep_id}: invalid applicability/disposition")
        if not isinstance(row.get("rationale"), str) or not row["rationale"]:
            raise ValueError(f"NEP-{nep_id}: missing rationale")
        string_list(row, "target_evidence", nep_id, nonempty=True)
        version_evidence = string_list(row, "version_evidence", nep_id)
        requirements = string_list(row, "requirements_checked", nep_id)
        candidates = string_list(row, "candidate_ids", nep_id)
        deviations = row.get("deviations")
        if not isinstance(deviations, list) or not all(isinstance(item, dict) for item in deviations):
            raise ValueError(f"NEP-{nep_id}: deviations must be an object list")
        for deviation in deviations:
            if deviation.get("classification") not in {"security", "conformance", "advisory"}:
                raise ValueError(f"NEP-{nep_id}: invalid deviation classification")
            for field in ("requirement", "location", "rationale"):
                if not isinstance(deviation.get(field), str) or not deviation[field]:
                    raise ValueError(f"NEP-{nep_id}: deviation missing {field}")

        status = spec["status"]
        if nep_id == "0001":
            if applicability != "process_only" or disposition != "process_only":
                raise ValueError("NEP-0001 must be process_only")
        elif nep_id == "0021":
            if applicability != "superseded" or disposition != "superseded":
                raise ValueError("NEP-0021 must be superseded")
        elif applicability == "not_applicable":
            if disposition != "not_applicable":
                raise ValueError(f"NEP-{nep_id}: not_applicable applicability/disposition mismatch")
        elif applicability == "blocked":
            if disposition != "blocked":
                raise ValueError(f"NEP-{nep_id}: blocked applicability/disposition mismatch")
        elif status in {"Draft", "New"}:
            if disposition == "conformance_deviation":
                raise ValueError(f"NEP-{nep_id}: Draft/New cannot create mandatory conformance deviation")
            if disposition not in {"advisory", "security_candidate"}:
                raise ValueError(f"NEP-{nep_id}: Draft/New must be advisory unless a real security candidate exists")
            if not requirements:
                raise ValueError(f"NEP-{nep_id}: advisory review requires checked hypotheses")
        else:
            if applicability != "applicable":
                raise ValueError(f"NEP-{nep_id}: normative review must be applicable, N/A, or blocked")
            if disposition not in {"conformant", "security_candidate", "conformance_deviation"}:
                raise ValueError(f"NEP-{nep_id}: invalid normative disposition")
            if not requirements:
                raise ValueError(f"NEP-{nep_id}: applicable review requires checked requirements")
            if spec["activation"] in {"runtime_feature", "node_feature"} and not version_evidence:
                raise ValueError(f"NEP-{nep_id}: applicable runtime/node review requires version_evidence")

        if disposition == "security_candidate" and not candidates:
            raise ValueError(f"NEP-{nep_id}: security_candidate requires candidate_ids")
        if disposition == "security_candidate" and not any(
            item.get("classification") == "security" for item in deviations
        ):
            raise ValueError(f"NEP-{nep_id}: security_candidate requires a security deviation")
        if disposition != "security_candidate" and nep_id != "0021" and candidates:
            raise ValueError(f"NEP-{nep_id}: only security_candidate may link candidate_ids")
        if nep_id == "0021" and candidates and not any(
            item.get("classification") == "security" for item in deviations
        ):
            raise ValueError("NEP-0021: linked legacy candidates require a security deviation")
        if disposition == "conformance_deviation" and not deviations:
            raise ValueError(f"NEP-{nep_id}: conformance_deviation requires deviations")
        if disposition == "conformance_deviation" and any(
            item.get("classification") != "conformance" for item in deviations
        ):
            raise ValueError(f"NEP-{nep_id}: conformance_deviation rows require conformance classifications")
        if disposition == "advisory" and any(
            item.get("classification") not in {"advisory", "security"} for item in deviations
        ):
            raise ValueError(f"NEP-{nep_id}: advisory rows cannot contain mandatory conformance deviations")
        if disposition in {"conformant", "not_applicable", "process_only"} and deviations:
            raise ValueError(f"NEP-{nep_id}: {disposition} rows cannot contain deviations")
        if disposition == "superseded" and nep_id != "0021" and deviations:
            raise ValueError(f"NEP-{nep_id}: unexpected superseded deviations")
        counts[disposition] = counts.get(disposition, 0) + 1

    print(json.dumps({"neps": len(indexed), "dispositions": counts, "complete": True}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
