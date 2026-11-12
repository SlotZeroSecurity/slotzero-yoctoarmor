"""Threat-model input, evidence, and reporting regressions; no live audit."""
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from threat_model import BOUNDARIES, inspect_model, validate_verdict_assessments
from source_inventory import snapshot_inputs
from check_ledger import validate_ledgers
from test_feedback_integrity import candidate, verdict
import test_run_lifecycle as lifecycle
from test_run_lifecycle import write_jsonl

MODEL = """# Threat model
## Assets
- User deposits in the Vault.
## Trusted roles
- Owner is honest and may upgrade or pause.
- Price feeds are honest but may be stale.
## Attacker
- Any unprivileged account.
## Security properties
- Only owner may upgrade or pause.
- Withdrawals cannot exceed share value, including during honest admin actions.
"""
SOURCE = """pub fn upgrade(caller: &str, owner: &str) { assert_eq!(caller, owner); }
pub fn unauthorized_upgrade() { install_code(); }
pub fn stale_price() { use_price_without_age_check(); }
pub fn honest_admin_withdrawal() { overvalue_shares(); }
"""


def cite(path, text, line):
    return {"path": path, "start": line, "end": line, "quote": text.splitlines()[line - 1]}


def assessment(manifest, conclusion="in_scope", source_line=2, model_line=10):
    return {
        "model_sha256": manifest["threat_model"]["sha256"], "conclusion": conclusion,
        "model_citations": [] if conclusion in {"not_provided", "unresolved"} else [cite("THREAT_MODEL.md", MODEL, model_line)],
        "required_attacker_capabilities": ["Unprivileged exported-method access"],
        "trust_assumptions": ["Owner is honest within the declared authority"],
        "target_evidence": [cite("security.rs", SOURCE, source_line)],
        "rationale": "The cited path must be assessed against the explicit trust boundary.",
    }


def judged(manifest, conclusion="in_scope", *, at_verification=False, source_line=2, model_line=10):
    row = verdict()
    first = assessment(manifest, "in_scope" if at_verification else conclusion, source_line, model_line)
    row["triage"]["threat_model_assessment"] = first
    final = assessment(manifest, conclusion, source_line, model_line)
    if conclusion == "excluded":
        final["required_attacker_capabilities"] = ["Honest owner intentionally installs malicious code"]
        final["rationale"] = "Only deliberately malicious use of trusted owner authority enables this claimed harm."
        final["boundary_checks"] = {name: {
            "result": "ruled_out", "rationale": "Synthetic guarded authority path reviewed for " + name,
            "evidence": [cite("security.rs", SOURCE, 1)],
        } for name in BOUNDARIES}
        row.update(verdict="out_of_scope", verification_status="out_of_scope", proof_status="NOT_APPLICABLE",
                   poc_status="NOT_APPLICABLE", severity=None)
        if not at_verification:
            row["triage"].update(status="out_of_scope", blocking_fact="The supplied owner is explicitly trusted.",
                                 threat_model_assessment=final)
            row["judge_stage"] = "evidence_triage"
    elif conclusion == "unresolved":
        row.update(verdict="lead", verification_status="lead", proof_status="PARTIAL")
    if row["triage"]["status"] == "passed":
        row["threat_model_assessment"] = final
    return row


class ThreatModelTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.target = self.root / "target"
        shutil.copytree(ROOT / "tests/fixtures/nep-surface", self.target)
        (self.target / "THREAT_MODEL.md").write_text(MODEL)
        (self.target / "security.rs").write_text(SOURCE)
        self.run = self.root / "run"

    def cli(self, *args, ok=True):
        proc = subprocess.run([sys.executable, str(ROOT / "scripts/near_audit.py"), *map(str, args)],
                              capture_output=True, text=True, timeout=45,
                              env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
        if ok:
            self.assertEqual(proc.returncode, 0, proc.stderr)
            return json.loads(proc.stdout)
        self.assertNotEqual(proc.returncode, 0, proc.stdout)
        return proc.stderr

    def manifest(self, override=False):
        return {"target": str(self.target), "threat_model": inspect_model(self.target, override),
                "input_snapshot": snapshot_inputs(self.target, [])}

    def validate(self, row, manifest):
        raw = [candidate()]
        return validate_ledgers(raw, raw, [row], [{"candidate_id": "blind-1", "target_id": "blind-1",
            "disposition": "survives", "rationale": "Preserve raw accounting"}], stage="draft", manifest=manifest)

    def test_missing_empty_and_invalid_files_stop_before_run_creation(self):
        path = self.target / "THREAT_MODEL.md"
        for mode in ("missing", "empty", "invalid", "directory", "symlink", "unreadable"):
            with self.subTest(mode=mode):
                if path.is_dir() and not path.is_symlink(): path.rmdir()
                else: path.unlink(missing_ok=True)
                if mode == "empty": path.write_text(" \n")
                if mode == "invalid": path.write_bytes(b"\xff")
                if mode == "directory": path.mkdir()
                if mode == "symlink": path.symlink_to(self.target / "security.rs")
                if mode == "unreadable":
                    path.write_text(MODEL)
                    path.chmod(0)
                flags = [] if mode in {"missing", "empty"} else ["--allow-missing-threat-model"]
                error = self.cli("run", self.target, "--run-dir", self.run, *flags, ok=False)
                self.assertIn("THREAT_MODEL.md", error)
                self.assertFalse(self.run.exists())
                if mode in {"missing", "empty"}:
                    self.assertIn("false positives", error)
                    self.assertIn("restart", error)

    def test_override_is_explicit_and_never_discards_existing_model(self):
        for empty in (False, True):
            with self.subTest(empty=empty):
                path = self.target / "THREAT_MODEL.md"
                path.unlink(missing_ok=True)
                if empty: path.write_text(" \n")
                run = self.root / ("empty-run" if empty else "missing-run")
                self.cli("run", self.target, "--loop", "1", "--run-dir", run, "--allow-missing-threat-model")
                manifest = json.loads((run / "run-manifest.json").read_text())
                self.assertEqual(manifest["threat_model"]["status"], "overridden")
                packet = self.cli("packet", run, "l0-model:protocol-modeler")
                self.assertIn("No supplied threat model exists", packet["prompt"])
                (self.target / "THREAT_MODEL.md").write_text(MODEL)
                self.assertIn("drift", self.cli("resume", run, ok=False))
        self.cli("run", self.target, "--loop", "1", "--run-dir", self.run, "--allow-missing-threat-model")
        self.assertEqual(json.loads((self.run / "run-manifest.json").read_text())["threat_model"]["status"], "provided")

    def test_all_modes_pass_counts_and_workers_read_first(self):
        from worker_adapter import view as worker_view
        for mode, passes in (("standard", 1), ("explicit-files", 3), ("deep", 10)):
            run = self.root / mode
            flags = ["--files", "lib.rs"] if mode == "explicit-files" else []
            self.cli("run", self.target, "--mode", mode, "--loop", passes, "--run-dir", run, *flags)
            manifest = json.loads((run / "run-manifest.json").read_text())
            packets = [json.loads(line) for line in (run / "work-packets.jsonl").read_text().splitlines()]
            for packet in packets:
                self.assertEqual(packet["allowed_inputs"][0], str(self.target / "THREAT_MODEL.md"))
                view = worker_view(run, packet["packet_id"], ROOT / "references/agent-catalog.md")
                self.assertTrue(view["prompt"].startswith("FIRST,"))
                self.assertIn(manifest["threat_model"]["sha256"], view["prompt"])
                if packet["role_id"] in {"protocol-modeler", "intent-reasoner"}:
                    self.assertEqual(view["references"], ["references/neutral-schemas.md"])
                    self.assertEqual(view["owned_official_cards"], [])

    def test_modification_and_deletion_preserve_run_state(self):
        self.cli("run", self.target, "--loop", "1", "--run-dir", self.run)
        before = (self.run / "run-state.json").read_bytes()
        model = self.target / "THREAT_MODEL.md"
        for contents in (MODEL + "\nChanged trust.\n", None):
            if contents is None: model.unlink()
            else: model.write_text(contents)
            self.assertIn("drift", self.cli("status", self.run, ok=False))
            self.assertIn("drift", self.cli("packet", self.run, "l0-model:protocol-modeler", ok=False))
            self.assertEqual(before, (self.run / "run-state.json").read_bytes())

    def test_semantic_review_scenarios_remain_distinct(self):
        manifest = self.manifest()
        for stage in (False, True):
            excluded = judged(manifest, "excluded", at_verification=stage, source_line=1, model_line=5)
            self.assertTrue(self.validate(excluded, manifest)["complete"])
            self.assertEqual(excluded["human_disposition"], "pending")
        # These are explicit review outcomes, not an automated claim that prose can prove safety.
        for source_line, model_line in ((2, 10), (3, 6), (4, 11)):
            self.assertTrue(self.validate(judged(manifest, source_line=source_line, model_line=model_line), manifest)["complete"])
        uncertain = judged(manifest, "unresolved")
        self.validate(uncertain, manifest)
        uncertain.update(verdict="valid", verification_status="verified")
        with self.assertRaisesRegex(ValueError, "unresolved"):
            self.validate(uncertain, manifest)

    def test_exclusions_require_real_citations_and_all_boundary_checks(self):
        manifest = self.manifest()
        valid = judged(manifest, "excluded", source_line=1, model_line=5)
        changes = [
            lambda a: a.update(model_sha256="sha256:" + "0" * 64),
            lambda a: a["model_citations"][0].update(quote="Owner is malicious"),
            lambda a: a["target_evidence"][0].update(start=999),
            lambda a: a["target_evidence"][0].update(path="../outside.rs"),
            lambda a: a.update(trust_assumptions=[]),
            lambda a: a["boundary_checks"].pop("authorization_bypass"),
            lambda a: a["boundary_checks"]["privilege_escalation"].update(result="possible"),
            lambda a: a["boundary_checks"]["honest_operation_harm"].update(evidence=[]),
        ]
        for mutate in changes:
            row = copy.deepcopy(valid)
            mutate(row["triage"]["threat_model_assessment"])
            with self.assertRaises(ValueError): self.validate(row, manifest)
        row = copy.deepcopy(valid)
        row.update(verdict="valid", verification_status="verified", severity="low")
        with self.assertRaisesRegex(ValueError, "disagree"):
            self.validate(row, manifest)
        for place in ("triage", "verification"):
            row = judged(manifest)
            (row["triage"] if place == "triage" else row).pop("threat_model_assessment")
            with self.assertRaisesRegex(ValueError, "missing threat_model_assessment"):
                self.validate(row, manifest)

    def test_no_model_cannot_be_used_for_trusted_role_exclusions(self):
        (self.target / "THREAT_MODEL.md").unlink()
        manifest = self.manifest(override=True)
        self.validate(judged(manifest, "not_provided"), manifest)
        row = judged(manifest, "excluded", source_line=1, model_line=5)
        with self.assertRaisesRegex(ValueError, "availability"):
            self.validate(row, manifest)


class ThreatModelReportingTests(unittest.TestCase):
    def setUp(self):
        self.fixture = lifecycle.RunLifecycleTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.target, self.run = self.fixture.target, self.fixture.run_dir
        (self.target / "THREAT_MODEL.md").write_text(MODEL)
        (self.target / "security.rs").write_text(SOURCE)
        self.fixture.complete_automated_fixture()
        write_jsonl(self.run / "temporal-upgrade.jsonl", [{"schema_version": 1, "status": "complete",
                    "evidence": ["Synthetic temporal coverage for the upgrade-named fixture"], "candidate_ids": []}])
        surface = json.loads((self.run / "surface.json").read_text())
        template = json.loads((self.run / "official-guidance-coverage.jsonl").read_text().splitlines()[0])
        guidance = [dict(template, card_id=card) for card in surface["selected_attacker_cards"]]
        write_jsonl(self.run / "official-guidance-coverage.jsonl", guidance)
        owners = {item["card_id"]: item["owner_role"] for item in surface["official_guidance_review_queue"]}
        for owner in set(owners.values()):
            write_jsonl(self.run / "guidance" / (owner + ".jsonl"), [row for row in guidance if owners[row["card_id"]] == owner])
        self.manifest = json.loads((self.run / "run-manifest.json").read_text())
        raw = candidate()
        raw["locations"] = [{"path": "security.rs", "function": "upgrade"}]
        packets = [json.loads(line) for line in (self.run / "work-packets.jsonl").read_text().splitlines()]
        output = next(p["output_path"] for p in packets if p["phase"] == "blind-l3-active")
        write_jsonl(self.run / output, [raw])
        for name in ("raw-candidates.jsonl", "deduplicated.jsonl"):
            write_jsonl(self.run / name, [raw])
        write_jsonl(self.run / "dispositions.jsonl", [{"candidate_id": "blind-1", "target_id": "blind-1",
            "disposition": "survives", "rationale": "Preserve exclusion evidence"}])
        self.row = judged(self.manifest, "excluded", source_line=1, model_line=5)
        self.save_verdict()

    def save_verdict(self):
        write_jsonl(self.run / "verdicts.jsonl", [self.row])
        write_jsonl(self.run / "triage.jsonl", [{"candidate_id": "blind-1", "triage": self.row["triage"]}])

    def test_exclusion_survives_accounting_but_cannot_be_presented_as_finding(self):
        from render_pashov_report import render
        from report_assembly import assemble
        self.fixture.cli("resume", self.run)
        report = self.fixture.rendered_report()
        text = report.read_text()
        self.assertIn("no verified findings", text)
        self.assertIn("## Threat-model exclusions", text)
        self.assertIn("THREAT_MODEL.md:5-5", text)
        self.assertEqual(text.count("blind-1"), 1)
        with self.assertRaisesRegex(ValueError, "excluded candidate"):
            assemble(self.run, self.manifest, "# Draft\n## Findings\nblind-1\n")
        self.fixture.cli("finalize", self.run, "--report", report)
        content = self.run / "pashov-content.jsonl"
        content.write_text("")
        compact = render(self.run, content)
        self.assertNotIn("blind-1", compact)
        self.assertIn("Threat model", compact)
        write_jsonl(content, [{"candidate_id": "blind-1", "title": "Excluded", "location": "Vault.upgrade", "description": "Must not be shown"}])
        with self.assertRaisesRegex(ValueError, "not a finding or lead"):
            render(self.run, content)
        content.write_text("")
        self.row["triage"]["threat_model_assessment"]["model_sha256"] = "forged"
        self.save_verdict()
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            render(self.run, content)
        error = self.fixture.cli("finalize", self.run, "--report", report, ok=False)
        self.assertIn("digest mismatch", error.stderr)

    def test_missing_assessment_blocks_phase_before_reporting(self):
        self.row["triage"].pop("threat_model_assessment")
        self.save_verdict()
        result = self.fixture.cli("resume", self.run, ok=False)
        self.assertIn("threat_model_assessment", result.stderr)

    def test_override_limitation_reaches_both_reports(self):
        from render_pashov_report import render
        fixture = lifecycle.RunLifecycleTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        (fixture.target / "THREAT_MODEL.md").unlink()
        fixture.initialize = lambda passes=1: fixture.cli(
            "run", fixture.target, "--loop", passes, "--run-dir", fixture.run_dir, "--allow-missing-threat-model")
        fixture.complete_automated_fixture()
        fixture.cli("resume", fixture.run_dir)
        report = fixture.rendered_report()
        self.assertIn("explicitly overridden", report.read_text())
        self.assertIn("false-positive likelihood", report.read_text())
        fixture.cli("finalize", fixture.run_dir, "--report", report)
        content = fixture.run_dir / "pashov-content.jsonl"
        content.write_text("")
        self.assertIn("explicitly overridden", render(fixture.run_dir, content))


if __name__ == "__main__":
    unittest.main()
