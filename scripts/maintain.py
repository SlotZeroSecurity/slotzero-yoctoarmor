#!/usr/bin/env python3
"""One offline entry point for patterns, evidence, standards, and qualification maintenance."""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

sys.dont_write_bytecode = True
from reference_paths import missing_resource_paths
from package_policy import external_url_paths

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
COMMANDS = {
    "evidence": {"ledger": "check_ledger.py"},
    "standards": {"neps": "check_nep_registry.py", "docs": "check_official_docs.py", "coverage": "check_nep_coverage.py"},
    "qualification": {"benchmark": "score_benchmark.py", "maturity": "check_maturity.py", "guidance": "check_guidance_overhead.py", "harness": "check_harness_upgrade.py"},
}


def package_check() -> dict[str, object]:
    missing = missing_resource_paths(ROOT)
    if missing:
        raise ValueError(f"missing package resources: {missing}")
    from pattern_routing import validate_index
    index = validate_index()
    from reference_links import reference_link_errors
    link_errors = reference_link_errors(ROOT)
    if link_errors:
        raise ValueError("; ".join(link_errors))
    contaminated = external_url_paths(ROOT)
    if contaminated:
        raise ValueError(f"external URL in package: {contaminated}")
    return {"ok": True, "categories": len(index["categories"]), "cards": len(index["cards"])}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("function", choices=(*COMMANDS, "check"))
    parser.add_argument("operation", nargs="?")
    parser.add_argument("arguments", nargs=argparse.REMAINDER, help="arguments forwarded to the selected helper")
    args = parser.parse_args()
    rest = args.arguments
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
