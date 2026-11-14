#!/usr/bin/env python3
"""Synthetic bookkeeping regressions; no target execution or variant search."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from support import candidate, verdict, write_compact_json as write_json, write_jsonl as write_rows
from unittest.mock import patch


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from check_ledger import validate_ledgers
from record_feedback import record_feedback, require_mutable_run, validate_feedback
from run_integrity import run_lock


def label(identifier: str = "blind-1", value: str = "TP", **extra) -> dict:
    return {
        "schema_version": 1, "candidate_id": identifier, "label": value,
        "reason_code": "synthetic_review", "reviewer": "test-reviewer",
        "reviewed_at": "2026-09-08T00:00:00Z", **extra,
    }


class LedgerStageTest(unittest.TestCase):
    def setUp(self) -> None:
        self.raw = [candidate()]
        self.dispositions = [{"candidate_id": "blind-1", "disposition": "survives",
                              "target_id": "blind-1", "rationale": "synthetic"}]

    def test_draft_accepts_pending_and_default_still_requires_approval(self) -> None:
        row = verdict()
        counts = validate_ledgers(self.raw, self.raw, [row], self.dispositions, stage="draft")
        self.assertEqual(counts["verdicts"], 1)
        with self.assertRaisesRegex(ValueError, "human_disposition"):
            validate_ledgers(self.raw, self.raw, [row], self.dispositions)
        row["human_disposition"] = "approved"
        self.assertTrue(validate_ledgers(self.raw, self.raw, [row], self.dispositions)["complete"])


class FeedbackIntegrityTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        write_rows(self.root / "deduplicated.jsonl", [candidate()])
        write_json(self.root / "semantic-ir.json", {"schema_version": 1, "symbols": []})
        self.labels = self.root / "labels.jsonl"

    def command(self, helper: str, *args: str, succeeds: bool = True) -> subprocess.CompletedProcess:
        result = subprocess.run([sys.executable, str(SCRIPTS / helper), str(self.root), *args], text=True, capture_output=True)
        if succeeds:
            self.assertEqual(result.returncode, 0, result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0, result.stdout)
        return result

    def record(self, rows: list[dict] | None = None, *, succeeds: bool = True) -> subprocess.CompletedProcess:
        write_rows(self.labels, [label()] if rows is None else rows)
        return self.command("record_feedback.py", str(self.labels), succeeds=succeeds)

    def test_review_hashes_normalized_content_and_rejects_drift(self) -> None:
        self.record()
        summary = validate_feedback(self.root, require_complete=True)
        self.assertEqual(set(summary["candidate_hashes"]), {"blind-1"})
        (self.root / "deduplicated.jsonl").write_text(json.dumps(candidate(), sort_keys=True) + "\n\n", encoding="utf-8")
        validate_feedback(self.root, require_complete=True)
        changed = candidate()
        changed["root_cause"] = "changed metadata"
        write_rows(self.root / "deduplicated.jsonl", [changed])
        with self.assertRaisesRegex(ValueError, "content drift"):
            validate_feedback(self.root)
        result = self.record(succeeds=False)
        self.assertIn("cannot reseed", result.stderr)

    def test_new_and_removed_candidates_invalidate_review(self) -> None:
        self.record()
        for rows, error in (([candidate(), candidate("blind-2")], "omitted"), ([], "unknown candidate")):
            with self.subTest(error=error):
                write_rows(self.root / "deduplicated.jsonl", rows)
                with self.assertRaisesRegex(ValueError, error):
                    validate_feedback(self.root, require_complete=True)


    def test_interrupted_feedback_commit_fails_closed(self) -> None:
        self.record()
        write_rows(self.labels, [label(value="FP")])
        with run_lock(self.root), patch("record_feedback.atomic_write_json", side_effect=OSError("synthetic interruption")):
            with self.assertRaisesRegex(OSError, "synthetic interruption"):
                record_feedback(self.root, self.labels)
        with self.assertRaisesRegex(ValueError, "differs from reviewed ledger"):
            validate_feedback(self.root, require_complete=True)


    def test_current_mutations_validate_state_and_input_bindings(self) -> None:
        write_json(self.root / "run-manifest.json", {"schema_version": 7, "run_id": "fixture"})
        write_json(self.root / "run-state.json", {"schema_version": 1, "run_id": "fixture"})
        with self.assertRaisesRegex(ValueError, "run-state v4"):
            require_mutable_run(self.root)
        write_json(self.root / "run-state.json", {"schema_version": 4, "run_id": "fixture"})
        with patch("record_feedback.validate_bindings", side_effect=ValueError("source/context drift")) as check:
            with self.assertRaisesRegex(ValueError, "source/context drift"):
                require_mutable_run(self.root)
            check.assert_called_once_with(self.root)


if __name__ == "__main__":
    unittest.main()
