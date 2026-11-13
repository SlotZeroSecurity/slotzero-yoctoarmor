"""Inert coverage-contract regressions; no audits, mutations, or AI execution."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import review_policy as policy
import near_audit
from check_run_artifacts import validate_rescan
from test_capability_tools import make_run_artifacts, write_json, write_jsonl
import test_run_lifecycle as lifecycle


class ReviewPolicyTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.run = Path(temp.name)
        make_run_artifacts(self.run)
        self.rows = [json.loads(line) for line in (self.run / "mutation-results.jsonl").read_text().splitlines()]

    def save(self):
        write_jsonl(self.run / "mutation-results.jsonl", self.rows)

    def applicable(self, result="survived"):
        row = self.rows[0]
        op = row["operators"][0]
        op["applicability"] = "applicable"
        op["locations"] = copy.deepcopy(op["target_evidence"])
        (self.run / "evidence.txt").write_text("Synthetic inert test evidence; not an audit.")
        op["outcomes"] = [{"location_index": 0, "result": result, "evidence": "Synthetic detector outcome",
                            "evidence_path": "evidence.txt", "candidate_ids": []}]
        row.update(applicability="applicable", mutations_total=1, killed=0, survived=0, blocked=0)
        row[result] = 1
        self.save()
        return op

    def test_complete_inventory_and_missing_operator_rejected(self):
        policy.validate_mutation_inventory(self.run)
        self.assertEqual(len(policy.operator_inventory()), 17)
        self.assertEqual(sum(map(len, policy.operator_inventory().values())), 52)
        self.rows[0]["operators"].pop()
        self.save()
        with self.assertRaisesRegex(ValueError, "every supported operator"):
            policy.validate_mutation_inventory(self.run)

    def test_applicable_sites_and_evidence_cannot_be_skipped(self):
        op = self.applicable()
        policy.validate_mutation_inventory(self.run)
        original = copy.deepcopy(self.rows)
        for change in ("location", "quote", "artifact", "count"):
            self.rows = copy.deepcopy(original)
            op = self.rows[0]["operators"][0]
            if change == "location": op["outcomes"] = []
            if change == "quote": op["locations"][0]["quote"] = "forged"
            if change == "artifact": op["outcomes"][0]["evidence_path"] = "../outside"
            if change == "count": self.rows[0]["survived"] = 10
            self.save()
            with self.subTest(change=change), self.assertRaises(ValueError):
                policy.validate_mutation_inventory(self.run)

    def test_killed_operator_needs_human_matching_evidence(self):
        op = self.applicable("killed")
        op["outcomes"][0]["candidate_ids"] = ["mutation-only-1"]
        self.rows[0]["candidate_ids"] = ["mutation-only-1"]
        self.save()
        with self.assertRaisesRegex(ValueError, "human adjudication"):
            policy.validate_mutation_inventory(self.run)
        op["outcomes"][0]["adjudication"] = {"reviewer": "synthetic fixture", "reviewed_at": "2026-11-13T00:00:00Z",
                                              "mechanism_match": True, "path_match": True}
        self.save()
        policy.validate_mutation_inventory(self.run)

    def rescan_fixture(self, severity="medium", merged=False):
        write_jsonl(self.run / "counterexample-rescan-candidates.jsonl", [{"candidate_id": "new"}])
        dispositions = [{"candidate_id": "new", "target_id": "D1", "disposition": "merged" if merged else "survives"}]
        if merged: dispositions.append({"candidate_id": "original", "target_id": "D1", "disposition": "survives"})
        write_jsonl(self.run / "dispositions.jsonl", dispositions)
        write_jsonl(self.run / "verdicts.jsonl", [{"candidate_id": "D1", "verdict": "valid", "severity": severity}])
        write_json(self.run / "rescan-summary.json", {"schema_version": 2, "iteration": 1, "status": "complete", "input_count": 0, "new_candidate_ids": ["new"]})
        write_jsonl(self.run / "work-packets.jsonl", [])

    def test_derived_rescan_limitations_and_duplicate_rediscovery(self):
        self.rescan_fixture()
        self.assertEqual(policy.rescan_result(self.run)["new_medium_plus"], ["D1"])
        self.assertIn("criterion was not met", policy.review_limitations(self.run))
        self.rescan_fixture(merged=True)
        self.assertTrue(policy.rescan_result(self.run)["criterion_met"])
        self.rescan_fixture(severity="low")
        self.assertTrue(policy.rescan_result(self.run)["criterion_met"])
        write_json(self.run / "rescan-summary.json", {"schema_version": 2, "iteration": 1, "status": "blocked", "input_count": 0, "new_candidate_ids": ["new"]})
        self.assertFalse(policy.rescan_result(self.run)["criterion_met"])
        self.assertIn("blocked", policy.review_limitations(self.run))

    def test_blocked_operators_without_sites_are_disclosed(self):
        self.rescan_fixture(severity="low")
        self.rows[0]["operators"][0].update(applicability="blocked", blocker="Missing dependency build")
        self.rows[0]["applicability"] = "blocked"
        self.save()
        policy.validate_mutation_inventory(self.run)
        self.assertIn("mutation checks were blocked", policy.review_limitations(self.run))

    def test_other_blocked_testing_is_disclosed(self):
        self.rescan_fixture(severity="low")
        for filename, field in (("invariant-ledger.jsonl", "execution_status"),
                                ("nep-differential.jsonl", "status"),
                                ("temporal-upgrade.jsonl", "status"),
                                ("official-guidance-coverage.jsonl", "test_status")):
            with self.subTest(filename=filename):
                write_jsonl(self.run / filename, [{field: "blocked"}])
                self.assertIn(f"Testing recorded in {filename} was blocked", policy.review_limitations(self.run))
                write_jsonl(self.run / filename, [])
        write_jsonl(self.run / "async-schedules.jsonl", [{"coverage": {"blocked": True, "blocker": "Synthetic build blocker"}}])
        self.assertIn("Asynchronous schedule testing was blocked", policy.review_limitations(self.run))

    def test_malformed_operator_and_outcome_rejected(self):
        original = copy.deepcopy(self.rows)
        self.rows[0]["operators"][0] = "not an object"
        self.save()
        with self.assertRaises(ValueError):
            policy.validate_mutation_inventory(self.run)
        self.rows = original
        op = self.applicable()
        op["outcomes"] = ["not an object"]
        self.save()
        with self.assertRaises(ValueError):
            policy.validate_mutation_inventory(self.run)


class ComprehensiveLifecycleTests(unittest.TestCase):
    def fixture(self, complete=True):
        fixture = lifecycle.RunLifecycleTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        if complete: fixture.complete_automated_fixture()
        return fixture

    def test_removed_flags_and_loop_selection(self):
        fixture = self.fixture(False)
        for flags in (("--mode", "standard"), ("--mode", "deep"), ("--deep",)):
            error = fixture.cli("run", fixture.target, "--loop", 1, "--run-dir", fixture.run_dir, *flags, ok=False)
            self.assertIn("unrecognized arguments", error.stderr)
            self.assertFalse(fixture.run_dir.exists())
        for count in (0, 11):
            fixture.cli("run", fixture.target, "--loop", count, "--run-dir", fixture.run_dir, ok=False)
            self.assertFalse(fixture.run_dir.exists())
        with patch("builtins.input", side_effect=AssertionError("must not prompt")):
            self.assertEqual(near_audit.choose_discovery_passes(3), 3)
        fixture.cli("run", fixture.target, "--loop", "--run-dir", fixture.run_dir)
        manifest = json.loads((fixture.run_dir / "run-manifest.json").read_text())
        self.assertEqual(manifest["discovery_passes_planned"], 3)
        self.assertEqual(manifest["schema_version"], 7)
        self.assertNotIn("mode", manifest)

    def test_old_runs_remain_readonly(self):
        fixture = self.fixture(False)
        fixture.run_dir.mkdir()
        write_json(fixture.run_dir / "run-manifest.json", {"schema_version": 6})
        write_json(fixture.run_dir / "run-state.json", {"status": "draft_ready", "current_phase": "human-feedback"})
        before = {p.name: p.read_bytes() for p in fixture.run_dir.iterdir()}
        self.assertTrue(json.loads(fixture.cli("status", fixture.run_dir).stdout)["legacy_read_only"])
        self.assertIn("legacy run is read-only", fixture.cli("resume", fixture.run_dir, ok=False).stderr)
        self.assertEqual(before, {p.name: p.read_bytes() for p in fixture.run_dir.iterdir()})

    def test_specialist_evidence_and_fresh_worker_packets(self):
        fixture = self.fixture()
        manifest = json.loads((fixture.run_dir / "run-manifest.json").read_text())
        policy.validate_specialists(fixture.run_dir, manifest)
        packets = [json.loads(line) for line in (fixture.run_dir / "work-packets.jsonl").read_text().splitlines()]
        for role in ("corpus-echo", "chain-constructor"):
            packet = next(p for p in packets if p["role_id"] == role)
            self.assertTrue(packet["fresh_context"])
            prompt = json.loads(fixture.cli("packet", fixture.run_dir, packet["packet_id"]).stdout)["prompt"]
            self.assertIn("fresh host context", prompt)
        path = fixture.run_dir / "discovery/oracle-freshness-applicability.json"
        row = json.loads(path.read_text())
        row["target_evidence"][0]["quote"] = "forged"
        write_json(path, row)
        with self.assertRaisesRegex(ValueError, "does not match"):
            policy.validate_specialists(fixture.run_dir, manifest)

    def test_missing_exclusion_revisit_is_rejected(self):
        fixture = self.fixture()
        write_jsonl(fixture.run_dir / "verdicts.jsonl", [{"candidate_id": "excluded", "verdict": "out_of_scope"}])
        write_jsonl(fixture.run_dir / "dispositions.jsonl", [{"candidate_id": "raw", "target_id": "excluded", "disposition": "survives"}])
        with self.assertRaisesRegex(ValueError, "must revisit"):
            validate_rescan(fixture.run_dir, True)

    def test_post_discovery_worker_cannot_reuse_discovery_identity(self):
        fixture = self.fixture()
        fixture.cli("worker", fixture.run_dir, "start", "l0-model:protocol-modeler", "--worker-id", "observed-discovery-worker")
        fixture.cli("worker", fixture.run_dir, "finish", "l0-model:protocol-modeler")
        # Leave the next independent review incomplete so resume stops at its phase.
        (fixture.run_dir / "corpus-echo-candidates.jsonl").unlink()
        result = json.loads(fixture.cli("resume", fixture.run_dir).stdout)
        self.assertEqual(result["current_phase"], "dedup-chains")
        rejected = fixture.cli("worker", fixture.run_dir, "start", "dedup-chains:corpus-echo",
                               "--worker-id", "observed-discovery-worker", ok=False)
        self.assertIn("new host worker identity", rejected.stderr)
        fixture.cli("worker", fixture.run_dir, "start", "dedup-chains:corpus-echo", "--worker-id", "observed-new-worker")

    def test_blocked_checks_reach_both_reports_without_scan_labels(self):
        from render_slotzero_report import render
        fixture = self.fixture()
        rows = [json.loads(line) for line in (fixture.run_dir / "mutation-results.jsonl").read_text().splitlines()]
        rows[0]["operators"][0].update(applicability="blocked", blocker="Synthetic missing toolchain")
        rows[0]["applicability"] = "blocked"
        write_jsonl(fixture.run_dir / "mutation-results.jsonl", rows)
        fixture.cli("resume", fixture.run_dir)
        report = fixture.rendered_report()
        fixture.cli("finalize", fixture.run_dir, "--report", report)
        content = fixture.run_dir / "slotzero-content.jsonl"
        content.write_text("")
        compact = render(fixture.run_dir, content)
        for text in (report.read_text(), compact):
            self.assertIn("mutation checks were blocked", text)
            self.assertNotIn("**Mode**", text)
            self.assertNotIn(" · mode ", text)
        altered = report.read_text().replace("Some mutation checks were blocked; full testing coverage was not established.", "All checks passed.")
        report.write_text(altered)
        with self.assertRaisesRegex(ValueError, "finalized hash"):
            render(fixture.run_dir, content)


if __name__ == "__main__":
    unittest.main()
