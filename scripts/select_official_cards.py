#!/usr/bin/env python3
"""Render only the official-doc attacker cards selected by surface schema v3."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


SKILL_ROOT = Path(__file__).resolve().parent.parent
GUIDE = SKILL_ROOT / "references" / "official-docs-attacker-guide.md"
REGISTRY = SKILL_ROOT / "references" / "official-docs-registry.json"
CARD_HEADING = re.compile(r"^###\s+(DOC-[A-Z0-9-]+)\s+—.*$", re.MULTILINE)


def extract_cards(text: str) -> dict[str, str]:
    matches = list(CARD_HEADING.finditer(text))
    cards: dict[str, str] = {}
    for index, match in enumerate(matches):
        next_card = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        next_section_match = re.search(r"^##\s+[^#].*$", text[match.end():], re.MULTILINE)
        next_section = (
            match.end() + next_section_match.start() if next_section_match else len(text)
        )
        end = min(next_card, next_section)
        cards[match.group(1)] = text[match.start():end].strip()
    return cards


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("surface", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    surface = json.loads(args.surface.read_text(encoding="utf-8"))
    if surface.get("schema_version") != 3:
        raise ValueError("selected official cards require surface schema_version 3")
    selected = surface.get("selected_attacker_cards")
    if not isinstance(selected, list) or not all(isinstance(item, str) for item in selected):
        raise ValueError("surface selected_attacker_cards must be a string list")
    registry = json.loads(REGISTRY.read_text(encoding="utf-8"))
    unknown = sorted(set(selected) - set(registry["cards"]))
    if unknown:
        raise ValueError(f"surface selects unknown official cards: {unknown}")
    cards = extract_cards(GUIDE.read_text(encoding="utf-8"))
    if set(cards) != set(registry["cards"]):
        raise ValueError("attacker-guide headings differ from registry cards")

    sections = [
        "# Selected Official NEAR Attacker Cards",
        "",
        "Generated deterministically from the pinned registry and surface evidence. Guidance is non-normative and forbidden to L2.",
        "",
    ]
    for card_id in selected:
        sections.extend((cards[card_id], ""))
    rendered = "\n".join(sections).rstrip() + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
