"""Behavioral checks for the retained issue ledger and its source review."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
REF = ROOT / "references"
SPEC = importlib.util.spec_from_file_location("satoshi_near_audit", ROOT / "scripts/near_audit.py")
AUDIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDIT)


class SatoshiCorpusTests(unittest.TestCase):
    def test_source_review_retains_discussions_and_dispositions(self):
        ledger = json.loads((REF / "satoshi-issue-corpus.json").read_text())
        review = json.loads((REF / "source-review.json").read_text())
        self.assertEqual(53, len(ledger["sources"]))
        self.assertEqual(39, len(ledger["variants"]))
        self.assertEqual({r["source_id"] for r in ledger["sources"]}, set(review["issues"]))
        self.assertEqual(44, len({r["issue_number"] for r in ledger["sources"]}))
        for row in ledger["sources"]:
            self.assertEqual("reviewed_live", row["source_access"])
            self.assertTrue(row["review_note"] and row["disposition"])
            self.assertEqual(64, len(row["issue_body_sha256"]))
            self.assertEqual(64, len(row["discussion_sha256"]))
            self.assertNotIn("url", row)

    def test_variant_mappings_resolve_to_active_cards(self):
        ledger = json.loads((REF / "satoshi-issue-corpus.json").read_text())
        index = json.loads((REF / "attack-lenses-index.json").read_text())
        historical = json.loads((REF / "historical-id-map.json").read_text())
        for variant in ledger["variants"]:
            mapped = next(row for row in historical["portable"].values() if row["source_variant"] == variant["id"])
            self.assertLessEqual(set(mapped["new_ids"]), set(index["cards"]))
            self.assertLessEqual(set(variant["canonical_ids"]), set(index["cards"]))
            for field in ("invariant", "activation", "sequence", "evidence", "recovery", "exclusions", "fix"):
                self.assertTrue(variant[field].strip(), (variant["id"], field))

    def test_packets_keep_source_ledger_out_of_blind_phases(self):
        surface = {"selected_roles": ["async-promises"], "nep_roles": ["nep-token-assets"],
                   "selected_pattern_references": ["references/attack-lenses/async.md"]}
        with tempfile.TemporaryDirectory() as directory:
            packets = AUDIT.make_work_packets(Path(directory), surface)
        for packet in packets:
            if packet["role_id"] in {"protocol-modeler", "intent-reasoner"} or packet["phase"] in {"blind-l3-active", "nep-coverage"}:
                self.assertIn("attack lenses", packet["forbidden_inputs"])
                self.assertNotIn("references/attack-lenses/async.md", packet["allowed_inputs"])
        self.assertIn("references/attack-lenses/async.md", next(p for p in packets if p["role_id"] == "pattern-matcher")["allowed_inputs"])
        self.assertIn("references/attack-lenses/async.md", next(p for p in packets if p["role_id"] == "corpus-echo")["allowed_inputs"])
