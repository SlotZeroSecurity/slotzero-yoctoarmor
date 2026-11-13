"""Presentation must follow validated verdicts and preserve finalized evidence."""
import hashlib
import contextlib
import copy
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import render_slotzero_report as formatter


class SlotZeroReportTests(unittest.TestCase):
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
        technical = self.run / "technical-annex.md"
        technical.write_text("# 🔐 NEARShield v1 Security Review — sample\n")
        fingerprint = "sha256:source"
        self.write_json("run-manifest.json", {
            "target": str(self.target), "target_revision": "abc123",
            "scope": ["sample-contract/src/lib.rs"], "discovery_passes_planned": 1,
            "input_fingerprint": fingerprint, "configuration_hash": "sha256:skill",
        })
        self.write_json("run-state.json", {
            "status": "draft_ready", "report": {
                "path": "technical-annex.md", "stage": "draft", "input_fingerprint": fingerprint,
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
        self.write_jsonl("slotzero-content.jsonl", self.rows)

    def write_json(self, name, value):
        (self.run / name).write_text(json.dumps(value))

    def write_jsonl(self, name, values):
        (self.run / name).write_text("".join(json.dumps(value) + "\n" for value in values))

    def test_renders_all_supported_verdicts_and_excludes_refuted(self):
        with patch.object(formatter, "pass_sightings", return_value={"D-001": 1, "D-002": 0, "D-003": 0}):
            text = formatter.render(self.run, self.run / "slotzero-content.jsonl", "sample")
        self.assertIn("# 🔐 NEARShield v1 Security Review — sample", text)
        self.assertNotIn("**Review status**", text)
        self.assertNotIn("This draft was prepared", text)
        self.assertIn("[85] **1. Anyone can act**", text)
        self.assertIn("+ require_role();", text)
        self.assertIn("**Potential repeated call**", text)
        self.assertNotIn("D-003", text)
        self.assertIn("[Technical annex]", text)

    def test_approved_title_and_individual_review_edits(self):
        state = json.loads((self.run / "run-state.json").read_text())
        state.update(status="complete")
        state["report"]["stage"] = "approved"
        self.write_json("run-state.json", state)
        self.rows[0].update(review_status="CONFIRMED", reviewer="fixture reviewer",
                            reviewed_at="2026-11-13T00:00:00Z")
        self.write_jsonl("slotzero-content.jsonl", self.rows)
        with patch.object(formatter, "pass_sightings", return_value={}):
            text = formatter.render(self.run, self.run / "slotzero-content.jsonl", "sample")
        self.assertTrue(text.startswith("# 🔐 NEARShield v1 Security Review — sample\n"))
        self.assertEqual(text.count("Anyone can act — CONFIRMED"), 2)
        self.assertNotIn("**Review status**", text)
        self.rows[0].pop("review_status")
        self.rows[0].update(omit=True, omission_reason="Fixture presentation choice")
        self.write_jsonl("slotzero-content.jsonl", self.rows)
        with patch.object(formatter, "pass_sightings", return_value={}):
            text = formatter.render(self.run, self.run / "slotzero-content.jsonl", "sample")
        self.assertNotIn("Anyone can act", text)
        self.assertIn("1 audited finding omitted", text)
        self.assertIn("**Potential repeated call**", text)

    def test_small_and_large_console_output_has_no_removed_presentation(self):
        for count in (1, 21):
            with self.subTest(count=count):
                verdicts, candidates, rows = [], [], []
                for i in range(count):
                    cid = f"D-{i:03d}"
                    verdicts.append({"candidate_id": cid, "verdict": "valid", "severity": "high",
                                     "confidence": {"total": 11}})
                    candidates.append({"candidate_id": cid, "locations": [
                        {"path": "sample-contract/src/lib.rs", "function": "vulnerable"}]})
                    row = copy.deepcopy(self.rows[0])
                    row.update(candidate_id=cid, title=f"Example finding {i}")
                    rows.append(row)
                self.write_jsonl("verdicts.jsonl", verdicts)
                self.write_jsonl("deduplicated.jsonl", candidates)
                self.write_jsonl("slotzero-content.jsonl", rows)
                stdout = io.StringIO()
                with patch.object(sys, "argv", ["renderer", str(self.run), "--project", "sample"]), \
                        patch.object(formatter, "pass_sightings", return_value={}), contextlib.redirect_stdout(stdout):
                    formatter.main()
                report = (self.run / "slotzero-report.md").read_text()
                console = stdout.getvalue()
                self.assertEqual(report.count("**Description**"), count)
                for text in (report, console):
                    self.assertTrue(text.startswith("# 🔐 NEARShield v1 Security Review — sample\n"))
                    for removed in ("**Review status**", "This draft was prepared", "Format source:",
                                    "Slot Zero Security ·", "Independent review, a bug bounty"):
                        self.assertNotIn(removed, text)
                if count == 1:
                    self.assertEqual(console, report)
                else:
                    self.assertIn("top 3 of 21", console)
                    self.assertIn(f"Full report: {self.run.resolve() / 'slotzero-report.md'}", console)



    def test_tampered_final_report_fails_closed(self):
        (self.run / "technical-annex.md").write_text("altered")
        with self.assertRaisesRegex(ValueError, "finalized hash"):
            formatter.render(self.run, self.run / "slotzero-content.jsonl", "sample")

    def test_diff_requires_exact_frozen_source_line(self):
        self.rows[0]["fix"]["old"] = ["not_in_source();"]
        self.write_jsonl("slotzero-content.jsonl", self.rows)
        with patch.object(formatter, "pass_sightings", return_value={}):
            with self.assertRaisesRegex(ValueError, "absent from frozen source"):
                formatter.render(self.run, self.run / "slotzero-content.jsonl", "sample")


if __name__ == "__main__":
    unittest.main()
