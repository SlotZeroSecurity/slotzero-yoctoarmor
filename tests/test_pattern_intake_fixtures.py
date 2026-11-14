"""Consistency of semantic evaluation inputs; these are not classifier unit tests."""
from support import reference_path
from pathlib import Path
import json
import unittest
from pattern_routing import validate_index

ROOT = Path(__file__).resolve().parents[1]


class PatternIntakeFixtureTests(unittest.TestCase):
    def test_rubric_covers_inputs_and_uses_current_categories_and_ids(self):
        folder = ROOT / 'tests/fixtures/pattern-intake'
        inputs = json.loads((folder / 'inputs.json').read_text())['cases']
        rubric = json.loads((folder / 'expected.json').read_text())['cases']
        self.assertEqual({row['id'] for row in inputs}, {row['id'] for row in rubric})
        self.assertEqual(len(inputs), len({row['id'] for row in inputs}))
        self.assertEqual(len(rubric), len({row['id'] for row in rubric}))
        index = validate_index()
        for row in rubric:
            with self.subTest(case=row['id']):
                self.assertIn(row['category'], index['categories'])
                self.assertTrue(row['reason'])
                self.assertLessEqual(set(row['pattern_ids']), set(index['cards']))
                self.assertTrue(all(index['cards'][cid]['category'] == row['category'] for cid in row['pattern_ids']))
        self.assertEqual('quality_only', index['cards']['NA-OFFCHAIN-005']['kind'])
