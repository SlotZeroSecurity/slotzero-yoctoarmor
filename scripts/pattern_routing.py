"""Validate and route the local attack lenses without reading historical ledgers."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INDEX = ROOT / "references" / "attack-lenses-index.json"
ORDER = ("auth", "async", "account", "state", "econ", "resource", "integration", "crypto", "runtime", "offchain")
SIGNALS = {
    "async": ("promises", "callback_entrypoints", "yield_resume", "tokens"),
    "resource": ("storage", "gas", "queues"),
    "integration": ("tokens", "bridge", "intents", "oracle", "serialization"),
    "crypto": ("chain_signatures", "tee", "wallet_auth"),
    "runtime": ("runtime_consensus",),
    "offchain": ("offchain_rpc", "build_artifacts", "meta_transactions"),
}


def validate_index(path: Path = INDEX) -> dict[str, object]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema_version") != 1 or set(data.get("categories", {})) != set(ORDER):
        raise ValueError("attack-lens index has an invalid schema or category set")
    seen: set[str] = set()
    for category in ORDER:
        row = data["categories"][category]
        file = ROOT / row["file"]
        if not file.is_file() or file.parent != ROOT / "references" / "attack-lenses":
            raise ValueError(f"missing or misplaced lens file: {category}")
        headings = re.findall(r"^## (NA-[A-Z]+-\d{3}) —", file.read_text(encoding="utf-8"), re.M)
        if headings != row["ids"] or len(headings) != len(set(headings)):
            raise ValueError(f"lens headings differ from index: {category}")
        for card_id in headings:
            if card_id in seen or card_id not in data["cards"]:
                raise ValueError(f"duplicate or unindexed lens card: {card_id}")
            card = data["cards"][card_id]
            if card["category"] != category:
                raise ValueError(f"lens category mismatch: {card_id}")
            seen.add(card_id)
    if seen != set(data["cards"]):
        raise ValueError("attack-lens index does not close over all cards")
    if any(set(row.get("related_ids", [])) - seen for row in data["cards"].values()):
        raise ValueError("attack-lens index contains a dangling relation")
    return data


def select_categories(signal_counts: Mapping[str, int]) -> list[str]:
    selected = {"auth", "account", "state", "econ"}
    for category, signals in SIGNALS.items():
        if any(signal_counts.get(signal, 0) for signal in signals):
            selected.add(category)
    return [category for category in ORDER if category in selected]


def reference_paths(categories: list[str]) -> list[str]:
    index = validate_index()
    if set(categories) - set(ORDER):
        raise ValueError("unknown attack-lens category")
    return [index["categories"][category]["file"] for category in ORDER if category in categories]
