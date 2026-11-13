"""Category-index closure, permanent IDs, and self-contained package rules."""

from support import reference_path
import json
import re
import subprocess
import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
REF = ROOT / "references"
sys.path.insert(0, str(ROOT / "scripts"))
from pattern_routing import ORDER, reference_paths, select_categories, validate_index
from package_policy import external_url_paths


class PatternPortabilityTests(unittest.TestCase):
    def test_index_closes_over_ten_category_files(self):
        index = validate_index()
        self.assertEqual(set(ORDER), set(index["categories"]))
        self.assertEqual(96, len(index["cards"]))
        self.assertIn("NA-AUTH-012", index["cards"])
        for category in ORDER:
            for card_id in index["categories"][category]["ids"]:
                self.assertRegex(card_id, rf"^NA-{category.upper()}-\d{{3}}$")

    def test_every_card_has_causal_and_recovery_fields(self):
        index = validate_index()
        for category in ORDER:
            text = (ROOT / index["categories"][category]["file"]).read_text()
            for card_id in index["categories"][category]["ids"]:
                block = text.split(f"## {card_id} —", 1)[1].split("\n## ", 1)[0]
                for field in ("Root cause", "Activation", "Broken invariant", "Concrete sequence", "Required evidence", "Exclusions", "Recovery", "Fix family"):
                    self.assertRegex(block, rf"- \*\*{field}:\*\* \S", (card_id, field))

    def test_historical_translation_is_many_to_many_and_never_active(self):
        history = json.loads((reference_path('historical_id_map', root=REF.parent)).read_text())
        index = validate_index()
        self.assertEqual(56, len(history["canonical"]))
        self.assertEqual(39, len(history["portable"]))
        for group in (history["canonical"], history["portable"]):
            for row in group.values():
                self.assertLessEqual(set(row["new_ids"]), set(index["cards"]))
        self.assertTrue(any(len(row["new_ids"]) > 1 for row in history["canonical"].values()))
        old_ids = set(history["canonical"])
        for path in ROOT.rglob("*"):
            if path.is_file() and path != reference_path('historical_id_map', root=REF.parent) and path.suffix in {".md", ".json", ".py", ".rs", ".yaml"}:
                content = path.read_text(errors="replace")
                self.assertFalse(any(re.search(rf"(?<![A-Z0-9-]){re.escape(old)}(?![A-Z0-9-])", content) for old in old_ids), path)

    def test_category_routing_limits_input_and_package_url_policy(self):
        selected = select_categories({"promises": 1, "storage": 1})
        self.assertIn("async", selected)
        self.assertIn("resource", selected)
        self.assertNotIn("crypto", selected)
        self.assertEqual(len(selected), len(reference_paths(selected)))
        self.assertEqual(external_url_paths(ROOT), [])

    def test_consolidated_maintenance_check(self):
        result = subprocess.run([sys.executable, str(ROOT / "scripts/maintain.py"), "check"],
                                text=True, capture_output=True, check=True)
        payload = json.loads(result.stdout)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["categories"], 10)
        self.assertEqual(payload["historical_canonical"], 56)
