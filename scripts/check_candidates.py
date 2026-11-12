#!/usr/bin/env python3
"""Validate one or more schema-v2 discovery candidate JSONL artifacts."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from check_ledger import (
    NEP_REGISTRY_PATH,
    OFFICIAL_DOCS_REGISTRY_PATH,
    load_jsonl,
    unique,
    validate_candidate,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("candidate_files", nargs="+", help="Candidate JSONL artifacts")
    args = parser.parse_args()

    known_neps = set(json.loads(NEP_REGISTRY_PATH.read_text(encoding="utf-8"))["neps"])
    docs_registry = json.loads(OFFICIAL_DOCS_REGISTRY_PATH.read_text(encoding="utf-8"))
    known_guidance = {card_id: set() for card_id in docs_registry["cards"]}
    for page in docs_registry["pages"]:
        for card_id in page["attacker_card_ids"]:
            known_guidance[card_id].add(page["url_path"])
    total = 0
    all_ids: set[str] = set()
    for filename in args.candidate_files:
        rows = unique(load_jsonl(Path(filename)), "candidate_id", filename)
        overlap = sorted(all_ids & set(rows))
        if overlap:
            raise ValueError(f"candidate IDs repeat across artifacts: {overlap}")
        for candidate_id, row in rows.items():
            validate_candidate(candidate_id, row, known_neps, known_guidance)
        all_ids.update(rows)
        total += len(rows)
    print(json.dumps({"files": len(args.candidate_files), "candidates": total, "complete": True}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
