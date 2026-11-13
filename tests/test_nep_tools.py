#!/usr/bin/env python3
"""Dependency-free regression tests for NEP registry, routing, and coverage gates."""

from __future__ import annotations

import json
import re
import tempfile
import unittest
from pathlib import Path

from support import run, write_jsonl, coverage_rows


SKILL = Path(__file__).resolve().parent.parent
REGISTRY = SKILL / "references" / "nep-registry.json"
SCRIPTS = SKILL / "scripts"
FIXTURE = Path(__file__).resolve().parent / "fixtures" / "nep-surface"


class NepToolsTest(unittest.TestCase):
    def test_reference_routing_is_resolvable(self) -> None:
        registry = json.loads(REGISTRY.read_text(encoding="utf-8"))
        owned: list[str] = []
        for category in registry["categories"].values():
            checklist = SKILL / category["checklist"]
            self.assertTrue(checklist.is_file(), checklist)
            text = checklist.read_text(encoding="utf-8")
            for nep_id in category["ids"]:
                self.assertEqual(text.count(f"## NEP-{nep_id}"), 1)
                owned.append(nep_id)
        self.assertEqual(sorted(owned), sorted(registry["neps"]))

        for markdown in [SKILL / "SKILL.md", *(SKILL / "references").glob("*.md")]:
            text = markdown.read_text(encoding="utf-8")
            for link in re.findall(r"]\(([^)]+)\)", text):
                target = link.split("#", 1)[0]
                if not target or "://" in target:
                    continue
                self.assertTrue((markdown.parent / target).is_file(), f"{markdown}: {link}")

    def test_registry_is_complete(self) -> None:
        result = run("python3", str(SCRIPTS / "check_nep_registry.py"), str(REGISTRY))
        payload = json.loads(result.stdout)
        self.assertTrue(payload["complete"])
        self.assertEqual(payload["registry_documents"], len(json.loads(REGISTRY.read_text())["neps"]))

    def test_surface_schema_and_signals(self) -> None:
        result = run("python3", str(SCRIPTS / "map_surface.py"), str(FIXTURE))
        payload = json.loads(result.stdout)
        self.assertEqual(payload["schema_version"], 3)
        self.assertEqual(len(payload["nep_review_queue"]), len(json.loads(REGISTRY.read_text())["neps"]))
        self.assertEqual(len(payload["nep_roles"]), 7)
        self.assertEqual(payload["capability_roles"], ["protocol-modeler", "pattern-matcher", "intent-reasoner"])
        self.assertIn("invariant-synthesis", payload["selected_roles"])
        self.assertIn("mutation-analysis", payload["selected_roles"])
        self.assertIn("async-state-explorer", payload["selected_roles"])
        self.assertIn("nep-differential", payload["selected_roles"])
        self.assertTrue(payload["official_docs_source_commit"])
        self.assertTrue(payload["official_docs_registry_hash"])
        self.assertTrue(payload["selected_attacker_cards"])
        self.assertEqual(
            {row["card_id"] for row in payload["official_guidance_review_queue"]},
            set(payload["selected_attacker_cards"]),
        )
        for nep_id in ("0141", "0145", "0488", "0509", "0519", "0584", "0635", "0641", "0646"):
            self.assertGreater(payload["nep_signal_counts"].get(nep_id, 0), 0)


    def test_complete_status_aware_coverage_passes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "coverage.jsonl"
            write_jsonl(path, coverage_rows())
            result = run("python3", str(SCRIPTS / "check_nep_coverage.py"), str(path))
            payload = json.loads(result.stdout)
            self.assertTrue(payload["complete"])
            self.assertEqual(payload["neps"], len(json.loads(REGISTRY.read_text())["neps"]))

    def test_missing_nep_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "coverage.jsonl"
            write_jsonl(path, coverage_rows()[:-1])
            result = run(
                "python3", str(SCRIPTS / "check_nep_coverage.py"), str(path), check=False
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("missing NEPs", result.stderr)

    def test_draft_cannot_be_mandatory_deviation(self) -> None:
        rows = coverage_rows()
        draft = next(row for row in rows if row["nep_id"] == "0635")
        draft["applicability"] = "advisory"
        draft["disposition"] = "conformance_deviation"
        draft["deviations"] = [
            {"requirement": "draft ABI", "classification": "conformance", "location": "fixture", "rationale": "fixture"}
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "coverage.jsonl"
            write_jsonl(path, rows)
            result = run(
                "python3", str(SCRIPTS / "check_nep_coverage.py"), str(path), check=False
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Draft/New", result.stderr)


    def test_applicable_runtime_requires_version_evidence(self) -> None:
        rows = coverage_rows()
        gas = next(row for row in rows if row["nep_id"] == "0264")
        gas["applicability"] = "applicable"
        gas["disposition"] = "conformant"
        gas["requirements_checked"] = ["promise gas-weight semantics"]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "coverage.jsonl"
            write_jsonl(path, rows)
            result = run(
                "python3", str(SCRIPTS / "check_nep_coverage.py"), str(path), check=False
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("version_evidence", result.stderr)


if __name__ == "__main__":
    unittest.main()
