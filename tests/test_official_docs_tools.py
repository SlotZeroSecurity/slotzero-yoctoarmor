#!/usr/bin/env python3
"""Regression tests for official-doc registry, routing, and public safe twins."""

from __future__ import annotations

from support import reference_relative

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from support import run


SKILL = Path(__file__).resolve().parent.parent
REGISTRY = SKILL / reference_relative('docs_registry')
SCRIPTS = SKILL / "scripts"
FIXTURE = SKILL / "benchmarks" / "public" / "official-guidance-smoke"


class OfficialDocsToolsTest(unittest.TestCase):

    def test_registry_internal_validation_is_complete(self) -> None:
        sys.path.insert(0, str(SCRIPTS))
        try:
            spec = importlib.util.spec_from_file_location(
                "check_official_docs_test", SCRIPTS / "check_official_docs.py"
            )
            assert spec and spec.loader
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
        finally:
            sys.path.pop(0)
        registry = json.loads(REGISTRY.read_text(encoding="utf-8"))
        actual = [
            {
                key: row[key]
                for key in ("url_path", "title", "section", "source_path", "sha256")
            }
            for row in registry["pages"]
        ]
        result = module.validate_registry(registry, actual, registry["source"]["commit"])
        self.assertTrue(result["complete"], result)

    def test_public_fixture_routes_all_high_risk_guidance_families(self) -> None:
        result = run("python3", str(SCRIPTS / "map_surface.py"), str(FIXTURE), Path("vulnerable.rs"))
        surface = json.loads(result.stdout)
        expected = {
            "DOC-KEY-002",
            "DOC-ASYNC-003",
            "DOC-ASYNC-004",
            "DOC-YIELD-001",
            "DOC-STORAGE-001",
            "DOC-FT-001",
            "DOC-SERIAL-001",
            "DOC-UPGRADE-001",
            "DOC-INTENT-001",
            "DOC-BRIDGE-001",
            "DOC-MEV-002",
            "DOC-DUP-001",
            "DOC-ECON-001",
        }
        self.assertTrue(expected <= set(surface["selected_attacker_cards"]))
        self.assertIn("chain-signatures-yield", surface["selected_roles"])
        self.assertIn("bridge-relayer", surface["selected_roles"])
        self.assertIn("temporal-upgrade", surface["selected_roles"])
        for row in surface["official_guidance_review_queue"]:
            self.assertIn(row["owner_role"], surface["selected_roles"])
            self.assertTrue(row["invariant_families"])
            self.assertIn("mutation_families", row)

        with tempfile.TemporaryDirectory() as directory:
            surface_path = Path(directory) / "surface.json"
            surface_path.write_text(result.stdout, encoding="utf-8")
            selected = run(
                "python3", str(SCRIPTS / "select_official_cards.py"), str(surface_path)
            ).stdout
            self.assertEqual(selected.count("### DOC-"), len(surface["selected_attacker_cards"]))
            for card_id in surface["selected_attacker_cards"]:
                self.assertEqual(selected.count(f"### {card_id} —"), 1)

    def test_three_run_overhead_gate(self) -> None:
        def metrics(multiplier: float) -> dict[str, object]:
            return {
                "schema_version": 2,

                "audit_config_id": "official-guidance-smoke-v1",
                "runs": [
                    {
                        "run_id": f"run-{multiplier}-{index}",
                        "fixture_id": "contract-token-cross-chain-suite",
                        "runtime_seconds": value * multiplier,
                        "input_tokens": int(10_000 * multiplier),
                    }
                    for index, value in enumerate((10.0, 11.0, 12.0))
                ],
            }

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            baseline = root / "baseline.json"
            passing = root / "passing.json"
            failing = root / "failing.json"
            baseline.write_text(json.dumps(metrics(1.0)), encoding="utf-8")
            passing.write_text(json.dumps(metrics(1.1)), encoding="utf-8")
            failing.write_text(json.dumps(metrics(1.3)), encoding="utf-8")
            passed = run(
                "python3", str(SCRIPTS / "check_guidance_overhead.py"), str(baseline), str(passing)
            )
            self.assertTrue(json.loads(passed.stdout)["complete"])
            failed = subprocess.run(
                ["python3", str(SCRIPTS / "check_guidance_overhead.py"), str(baseline), str(failing)],
                check=False,
                text=True,
                capture_output=True,
            )
            self.assertNotEqual(failed.returncode, 0)
            self.assertFalse(json.loads(failed.stdout)["complete"])


if __name__ == "__main__":
    unittest.main()
