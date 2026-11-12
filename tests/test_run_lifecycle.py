"""Synthetic, zero-finding lifecycle tests; no target audit or exploit execution."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from test_capability_tools import make_run_artifacts, write_json, write_jsonl
from test_nep_tools import coverage_rows
from test_feedback_integrity import candidate, verdict

SKILL = Path(__file__).resolve().parents[1]
FIXTURE = SKILL / "tests/fixtures/nep-surface"


class RunLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.target = self.root / "target source"
        shutil.copytree(FIXTURE, self.target)
        self.run_dir = self.root / "review evidence"
        self.skill = SKILL

    def cli(self, *args, ok=True):
        result = subprocess.run(
            [sys.executable, str(self.skill / "scripts/near_audit.py"), *map(str, args)],
            cwd=self.root, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
            text=True, capture_output=True, timeout=45,
        )
        if ok:
            self.assertEqual(result.returncode, 0, result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0, result.stdout)
        return result

    def initialize(self, passes=1):
        self.cli("run", self.target, "--loop", str(passes), "--run-dir", self.run_dir)

    def complete_automated_fixture(self, passes=1):
        self.initialize(passes)
        # Reuse the original schema fixtures, retaining the new run's attestation.
        preserved = {name: (self.run_dir / name).read_bytes() for name in ("run-manifest.json", "surface.json")}
        make_run_artifacts(self.run_dir)
        for name, data in preserved.items():
            (self.run_dir / name).write_bytes(data)
        packets = [json.loads(line) for line in (self.run_dir / "work-packets.jsonl").read_text().splitlines()]
        for packet in packets:
            if packet["phase"] == "informed-rescan":
                continue
            for name in packet["candidate_outputs"]:
                write_jsonl(self.run_dir / name, [])
        for name in ("raw-candidates.jsonl", "deduplicated.jsonl", "dispositions.jsonl", "verdicts.jsonl", "triage.jsonl"):
            write_jsonl(self.run_dir / name, [])
        rows = coverage_rows()
        write_jsonl(self.run_dir / "nep-coverage.jsonl", rows)
        surface = json.loads((self.run_dir / "surface.json").read_text())
        for role in surface["nep_roles"]:
            write_jsonl(self.run_dir / f"nep/{role}.jsonl", [row for row in rows if row["role_id"] == role])
        guidance = [json.loads(line) for line in (self.run_dir / "official-guidance-coverage.jsonl").read_text().splitlines()]
        owners = {row["card_id"]: row["owner_role"] for row in surface["official_guidance_review_queue"]}
        for role in set(owners.values()):
            write_jsonl(self.run_dir / f"guidance/{role}.jsonl", [row for row in guidance if owners[row["card_id"]] == role])

    def rendered_report(self, stage="draft"):
        banner = (SKILL / "references/report-template.md").read_text().split("```text\n", 1)[1].split("\n```", 1)[0]
        sections = ("Audit metadata", "Executive summary", "Findings index", "Findings",
                    "Leads and contested items", "NEP standards conformance",
                    "Active-testing coverage", "Verification and coverage ledger")
        verdicts = [json.loads(line) for line in (self.run_dir / "verdicts.jsonl").read_text().splitlines() if line.strip()]
        detail = "\n".join("### " + row["candidate_id"] + "\n\nConfidence " + str(row["confidence"]["total"]) +
                           "/13\n\n#### Recommendation\n\nApply the synthetic fixture fix."
                           for row in verdicts if row["verdict"] in {"valid", "valid_downgraded"})
        body = self.run_dir / f"{stage}-body.md"
        body.write_text("```text\n" + banner + "\n```\n\n# " + stage.title() + " security review\n\nSynthetic inert fixture.\n\n" +
                        "\n\n".join("## " + section + "\n\nSynthetic inert fixture." + ("\n\n" + detail if section == "Findings" and detail else "") for section in sections) + "\n")
        output = self.run_dir / f"{stage}.md"
        rendered = self.cli("render-report", self.run_dir, "--body", body, "--output", output, "--stage", stage)
        self.assertEqual(rendered.stdout, output.read_text())
        return output

    def test_draft_to_approved_and_retained_hash(self):
        self.complete_automated_fixture()
        result = json.loads(self.cli("resume", self.run_dir).stdout)
        self.assertEqual(result["current_phase"], "human-feedback")
        report = self.rendered_report()
        result = json.loads(self.cli("finalize", self.run_dir, "--report", report).stdout)
        self.assertEqual(result["status"], "draft_ready")
        self.assertEqual(result["report"]["sha256"], "sha256:" + hashlib.sha256(report.read_bytes()).hexdigest())
        before = (self.run_dir / "run-state.json").read_bytes()
        self.assertTrue(json.loads(self.cli("finalize", self.run_dir, "--stage", "draft", "--report", report).stdout)["unchanged"])
        self.assertEqual(before, (self.run_dir / "run-state.json").read_bytes())
        self.cli("finalize", self.run_dir, "--stage", "approved", "--report", report, ok=False)
        self.assertEqual(before, (self.run_dir / "run-state.json").read_bytes())
        labels = self.root / "labels.jsonl"
        labels.write_text("")
        self.cli("feedback", self.run_dir, labels)
        self.assertEqual(json.loads(self.cli("informed-rescan", self.run_dir).stdout)["status"], "skipped")
        self.assertEqual(json.loads(self.cli("resume", self.run_dir).stdout)["current_phase"], "final")
        approved = self.rendered_report("approved")
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
