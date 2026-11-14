"""Validate and route the local attack lenses using only the pattern library."""

from __future__ import annotations

from reference_paths import reference_path, reference_relative

import json
import re
from collections.abc import Mapping
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INDEX = ROOT / reference_relative('attack_index')
ORDER = ("auth", "async", "account", "state", "econ", "resource", "integration", "crypto", "runtime", "offchain")
SIGNALS = {
    "async": ("promises", "callback_entrypoints", "yield_resume", "tokens"),
    "resource": ("storage", "gas", "queues"),
    "integration": ("tokens", "bridge", "intents", "oracle", "serialization"),
    "crypto": ("chain_signatures", "tee", "wallet_auth"),
    "runtime": ("runtime_consensus",),
    "offchain": ("offchain_rpc", "build_artifacts", "meta_transactions"),
}


def validate_index(path: Path = INDEX, *, package_root: Path | None = None) -> dict[str, object]:
    root = ROOT if package_root is None else package_root
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema_version") != 1 or set(data.get("categories", {})) != set(ORDER):
        raise ValueError("attack-lens index has an invalid schema or category set")
    seen: set[str] = set()
    for category in ORDER:
        row = data["categories"][category]
        file = root / row["file"]
        if not file.is_file() or file.resolve().parent != reference_path("lens_auth", root=root).resolve().parent:
            raise ValueError(f"missing or misplaced lens file: {category}")
        text = file.read_text(encoding="utf-8")
        raw_headings = re.findall(r"^## (.+)$", text, re.M)
        headings = re.findall(r"^## (NA-[A-Z]+-\d{3}) —", text, re.M)
        if len(raw_headings) != len(headings):
            raise ValueError(f"malformed pattern heading: {category}")
        if headings != row["ids"] or len(headings) != len(set(headings)):
            raise ValueError(f"lens headings differ from index: {category}")
        for card_id in headings:
            if card_id in seen or card_id not in data["cards"]:
                raise ValueError(f"duplicate or unindexed lens card: {card_id}")
            card = data["cards"][card_id]
            if card["category"] != category:
                raise ValueError(f"lens category mismatch: {card_id}")
            if not re.fullmatch(rf"NA-{category.upper()}-\d{{3}}", card_id):
                raise ValueError(f"invalid permanent pattern ID: {card_id}")
            block = text.split(f"## {card_id} — ", 1)[1].split("\n## ", 1)[0]
            fields = re.findall(r"^- \*\*([^*]+):\*\* (.*)$", block, re.M)
            required = {"Kind", "Root cause", "Activation", "Broken invariant", "Concrete sequence",
                        "Required evidence", "Exclusions", "Recovery", "Fix family"}
            values = dict(fields)
            if (len(fields) != len(values) or not required <= values.keys()
                    or any(not values[field].strip() for field in required)):
                raise ValueError(f"incomplete or duplicate card fields: {card_id}")
            # Activation in the index is a routing summary, not necessarily a verbatim field.
            if not isinstance(card.get("activation"), str) or not card["activation"].strip():
                raise ValueError(f"missing activation summary: {card_id}")
            if card.get("kind") not in {"security", "quality", "quality_only", "conditional", "applicability", "policy"}:
                raise ValueError(f"invalid pattern kind: {card_id}")
            related = card.get("related_ids")
            if (not isinstance(related, list) or any(not isinstance(cid, str) for cid in related)
                    or len(related) != len(set(related)) or card_id in related):
                raise ValueError(f"invalid related IDs: {card_id}")
            if card.get("title") != block.splitlines()[0] or card.get("kind") != values["Kind"]:
                raise ValueError(f"lens metadata differs from index: {card_id}")
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
