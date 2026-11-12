"""Presentation must follow validated verdicts and preserve finalized evidence."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import render_pashov_report as formatter


class PashovReportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.run = self.root / "run"
        self.run.mkdir()
        self.target = self.root / "target"
        source = self.target / "sample-contract/src/lib.rs"
        source.parent.mkdir(parents=True)
        source.write_text("fn vulnerable() {\n    allow_anyone();\n}\n")
        technical = self.run / "draft-report.md"
        technical.write_text("# Draft technical annex\n")
        fingerprint = "sha256:source"
        self.write_json("run-manifest.json", {
            "target": str(self.target), "target_revision": "abc123", "mode": "standard",
            "scope": ["sample-contract/src/lib.rs"], "discovery_passes_planned": 1,
            "input_fingerprint": fingerprint, "configuration_hash": "sha256:skill",
        })
        self.write_json("run-state.json", {
            "status": "draft_ready", "report": {
                "path": "draft-report.md", "stage": "draft", "input_fingerprint": fingerprint,
                "configuration_hash": "sha256:skill",
                "sha256": "sha256:" + hashlib.sha256(technical.read_bytes()).hexdigest(),
            },
        })
        self.write_jsonl("verdicts.jsonl", [
            {"candidate_id": "D-001", "verdict": "valid", "severity": "high", "confidence": {"total": 11}},
            {"candidate_id": "D-002", "verdict": "lead", "severity": "low", "confidence": {"total": 6}},
            {"candidate_id": "D-003", "verdict": "false_positive", "severity": "low", "confidence": {"total": 4}},
        ])
        self.write_jsonl("deduplicated.jsonl", [
            {"candidate_id": "D-001", "locations": [{"path": "sample-contract/src/lib.rs", "function": "vulnerable"}]},
            {"candidate_id": "D-002", "locations": [{"path": "sample-contract/src/lib.rs", "function": "vulnerable"}]},
            {"candidate_id": "D-003", "locations": [{"path": "sample-contract/src/lib.rs", "function": "vulnerable"}]},
        ])
        self.write_jsonl("dispositions.jsonl", [])
        self.rows = [
            {"candidate_id": "D-001", "title": "Anyone can act", "location": "Sample.vulnerable",
             "description": "Anyone can call this method and bypass the required role check.",
             "fix": {"source_path": "sample-contract/src/lib.rs", "old": ["allow_anyone();"], "new": ["require_role();"]}},
            {"candidate_id": "D-002", "title": "Potential repeated call", "location": "Sample.vulnerable",
             "description": "The repeated-call state remains unverified.", "code_smells": ["unbound callback"]},
        ]
        self.write_jsonl("pashov-content.jsonl", self.rows)

    def write_json(self, name, value):
        (self.run / name).write_text(json.dumps(value))

    def write_jsonl(self, name, values):
        (self.run / name).write_text("".join(json.dumps(value) + "\n" for value in values))

    def test_renders_all_supported_verdicts_and_excludes_refuted(self):
        with patch.object(formatter, "pass_sightings", return_value={"D-001": 1, "D-002": 0, "D-003": 0}):
            text = formatter.render(self.run, self.run / "pashov-content.jsonl", "sample")
        self.assertIn("# 🔐 Draft Security Review — sample", text)
        self.assertIn("[85] **1. Anyone can act**", text)
        self.assertIn("+ require_role();", text)
        self.assertIn("**Potential repeated call**", text)
        self.assertNotIn("D-003", text)
        self.assertIn("[Technical annex]", text)




    def test_tampered_final_report_fails_closed(self):
        (self.run / "draft-report.md").write_text("altered")
        with self.assertRaisesRegex(ValueError, "finalized hash"):
            formatter.render(self.run, self.run / "pashov-content.jsonl", "sample")

    def test_diff_requires_exact_frozen_source_line(self):
        self.rows[0]["fix"]["old"] = ["not_in_source();"]
        self.write_jsonl("pashov-content.jsonl", self.rows)
        with patch.object(formatter, "pass_sightings", return_value={}):
            with self.assertRaisesRegex(ValueError, "absent from frozen source"):
                formatter.render(self.run, self.run / "pashov-content.jsonl", "sample")


if __name__ == "__main__":
    unittest.main()
