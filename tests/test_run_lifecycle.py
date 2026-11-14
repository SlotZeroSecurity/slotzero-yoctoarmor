"""Synthetic, zero-finding lifecycle tests; no target audit or exploit execution."""
from __future__ import annotations

import hashlib
import json
import shutil
import unittest

from support import LifecycleFixture, SKILL


class RunLifecycleTests(LifecycleFixture):
    def test_draft_to_approved_and_retained_hash(self):
        self.complete_automated_fixture()
        result = json.loads(self.cli("resume", self.run_dir).stdout)
        self.assertEqual(result["current_phase"], "human-feedback")
        report = self.rendered_report()
        original = report.read_text()
        before = (self.run_dir / "run-state.json").read_bytes()
        for heading in ("# Draft Security Review — sample", "# 🔐 NEAR YoctoArmor v1 Security Review — "):
            with self.subTest(heading=heading):
                report.write_text(original.replace("# 🔐 NEAR YoctoArmor v1 Security Review — sample", heading))
                error = self.cli("finalize", self.run_dir, "--report", report, ok=False)
                self.assertIn("report heading must be", error.stderr)
                self.assertEqual(before, (self.run_dir / "run-state.json").read_bytes())
        report.write_text(original)
        self.assertIn("**Review stage:** Draft — pending human review.", original)
        report.write_text(original.replace("**Review stage:** Draft — pending human review.",
                                          "**Review stage:** Approved — human review recorded."))
        error = self.cli("finalize", self.run_dir, "--report", report, ok=False)
        self.assertIn("front section differs", error.stderr)
        self.assertEqual(before, (self.run_dir / "run-state.json").read_bytes())
        report.write_text(original)
        result = json.loads(self.cli("finalize", self.run_dir, "--report", report).stdout)
        self.assertEqual(result["status"], "draft_ready")
        self.assertEqual(result["report"]["sha256"], "sha256:" + hashlib.sha256(report.read_bytes()).hexdigest())
        before = (self.run_dir / "run-state.json").read_bytes()
        self.assertTrue(json.loads(self.cli("finalize", self.run_dir, "--stage", "draft", "--report", report).stdout)["unchanged"])
        self.assertEqual(before, (self.run_dir / "run-state.json").read_bytes())
        error = self.cli("finalize", self.run_dir, "--stage", "approved", "--report", report, ok=False)
        self.assertIn("requires completed human review/informed phases", error.stderr)
        self.assertEqual(before, (self.run_dir / "run-state.json").read_bytes())
        labels = self.root / "labels.jsonl"
        labels.write_text("")
        self.cli("feedback", self.run_dir, labels)
        self.assertEqual(json.loads(self.cli("informed-rescan", self.run_dir).stdout)["status"], "skipped")
        self.assertEqual(json.loads(self.cli("resume", self.run_dir).stdout)["current_phase"], "final")
        approved = self.rendered_report("approved")
        self.assertIn("**Review stage:** Approved — human review recorded.", approved.read_text())
        self.assertNotIn("**Review stage:** Approved", report.read_text())
        self.assertEqual(json.loads(self.cli("finalize", self.run_dir, "--stage", "approved", "--report", approved).stdout)["status"], "complete")
        self.assertTrue((self.run_dir / "raw-candidates.jsonl").is_file())
        completed = (self.run_dir / "run-state.json").read_bytes()
        for stage in ([], ["--stage", "draft"]):
            with self.subTest(stage=stage):
                result = self.cli("finalize", self.run_dir, *stage, "--report", report, ok=False)
                self.assertIn("cannot be downgraded", result.stderr)
                self.assertEqual(completed, (self.run_dir / "run-state.json").read_bytes())

    def test_three_pass_packets_and_report_counts(self):
        self.complete_automated_fixture(passes=3)
        packets = [json.loads(line) for line in (self.run_dir / "work-packets.jsonl").read_text().splitlines()]
        l2 = [packet for packet in packets if packet["role_id"] == "intent-reasoner"]
        self.assertEqual([packet["discovery_pass"] for packet in l2], [1, 2, 3])
        self.assertTrue(all("prior-pass candidates" in packet["forbidden_inputs"] for packet in l2))
        discovery = [packet for packet in packets if packet["phase"] == "blind-l3-active" and "discovery_pass" in packet]
        self.assertTrue(discovery)
        self.assertEqual({packet["discovery_pass"] for packet in discovery}, {1, 2, 3})
        result = json.loads(self.cli("resume", self.run_dir).stdout)
        self.assertEqual(result["current_phase"], "human-feedback")
        self.assertEqual(result["discovery_pass_progress"]["l2"], {"1": "complete", "2": "complete", "3": "complete"})
        report = self.rendered_report()
        self.assertIn("top 0 of 0", report.read_text())
        self.assertIn("3 planned discovery passes, 3 completed", report.read_text())
        self.assertEqual(json.loads(self.cli("finalize", self.run_dir, "--report", report).stdout)["status"], "draft_ready")


    def test_source_drift_preserves_state(self):
        self.initialize()
        state = (self.run_dir / "run-state.json").read_bytes()
        source = next(self.target.rglob("*.rs"))
        source.write_text(source.read_text() + "\n// changed\n")
        self.assertIn("source/context drift", self.cli("resume", self.run_dir, ok=False).stderr)
        self.assertEqual(state, (self.run_dir / "run-state.json").read_bytes())

    def test_relocated_skill_configuration_drift_and_readonly_doctor(self):
        self.skill = self.root / "relocated skill with spaces"
        shutil.copytree(SKILL, self.skill, ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.lock"))
        before = sorted(str(p.relative_to(self.skill)) for p in self.skill.rglob("*") if p.is_file())
        self.assertTrue(json.loads(self.cli("doctor").stdout)["ok"])
        self.assertEqual(before, sorted(str(p.relative_to(self.skill)) for p in self.skill.rglob("*") if p.is_file()))
        self.initialize()
        self.cli("status", self.run_dir)
        helper = self.skill / "scripts/source_inventory.py"
        helper.write_text(helper.read_text() + "\n# configuration drift fixture\n")
        self.assertIn("configuration drift", self.cli("resume", self.run_dir, ok=False).stderr)


if __name__ == "__main__":
    unittest.main()
