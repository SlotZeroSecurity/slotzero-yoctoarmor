#!/usr/bin/env python3
"""One offline entry point for corpus, standards, and qualification maintenance."""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
COMMANDS = {
    "corpus": {"index": "build_corpus_index.py", "pdf": "pdf_corpus_registry.py", "ledger": "check_ledger.py"},
    "standards": {"neps": "check_nep_registry.py", "docs": "check_official_docs.py", "coverage": "check_nep_coverage.py"},
    "qualification": {"benchmark": "score_benchmark.py", "maturity": "check_maturity.py", "guidance": "check_guidance_overhead.py", "harness": "check_harness_upgrade.py"},
}


def package_check() -> dict[str, object]:
    from pattern_routing import validate_index
    index = validate_index()
    history = json.loads((ROOT / "references/historical-id-map.json").read_text())
    for row in (*history["canonical"].values(), *history["portable"].values()):
        if not set(row["new_ids"]) <= set(index["cards"]):
            raise ValueError("historical translation points outside active lens index")
    contaminated = []
    for file in ROOT.rglob("*"):
        if file.is_file() and file.suffix in {".md", ".json", ".py", ".rs", ".yaml"}:
            if re.search(r"https?://", file.read_text(encoding="utf-8", errors="replace")):
                contaminated.append(file.relative_to(ROOT).as_posix())
    if contaminated:
        raise ValueError(f"external URL in package: {contaminated}")
    return {"ok": True, "categories": len(index["categories"]), "cards": len(index["cards"]),
            "historical_canonical": len(history["canonical"]), "historical_portable": len(history["portable"])}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("function", choices=(*COMMANDS, "check"))
    parser.add_argument("operation", nargs="?")
    args, rest = parser.parse_known_args()
    if args.function == "check":
        if args.operation or rest:
            parser.error("check takes no arguments")
        print(json.dumps(package_check(), sort_keys=True))
        return 0
    selected = COMMANDS[args.function]
    if args.operation not in selected:
        parser.error(f"{args.function} requires one of: {', '.join(selected)}")
    script = SCRIPTS / selected[args.operation]
    return subprocess.run([sys.executable, str(script), *rest], check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
