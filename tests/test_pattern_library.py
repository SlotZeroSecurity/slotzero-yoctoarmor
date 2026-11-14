"""Pattern contract and extension regressions; no report-consumption state."""
from support import reference_path
from pathlib import Path
import copy
import json
import shutil
import tempfile
import unittest

from pattern_routing import ORDER, select_categories, validate_index
from near_audit import hash_files
from run_integrity import configuration_snapshot

ROOT = Path(__file__).resolve().parents[1]
BASELINE = json.loads((ROOT / 'tests/fixtures/pattern-baseline.json').read_text())


class PatternLibraryTests(unittest.TestCase):
    def test_original_ids_classifications_and_relative_order_survive(self):
        index = validate_index()
        self.assertEqual(set(ORDER), set(BASELINE['category_order']))
        self.assertLessEqual(set(BASELINE['cards']), set(index['cards']))
        for cid, expected in BASELINE['cards'].items():
            self.assertEqual(expected, {key: index['cards'][cid][key] for key in expected}, cid)
        for category, original in BASELINE['category_order'].items():
            self.assertEqual(original, [cid for cid in index['categories'][category]['ids']
                                        if cid in BASELINE['cards']])
        operators = json.loads(reference_path('mutation_operators').read_text())
        self.assertEqual(BASELINE['mutation_operators'], operators)
        self.assertEqual(52, sum(map(len, operators['families'].values())))

    def test_anonymous_mechanism_scenarios_resolve_to_current_patterns(self):
        index = validate_index()
        for group in ('mechanism-scenarios', 'portable-mechanisms'):
            data = json.loads((ROOT / 'tests/fixtures' / group / 'cases.json').read_text())
            ids = [case['id'] for case in data['cases']]
            self.assertEqual(len(ids), len(set(ids)))
            for case in data['cases']:
                with self.subTest(group=group, case=case['id']):
                    self.assertTrue(case['pattern_ids'])
                    self.assertLessEqual(set(case['pattern_ids']), set(index['cards']))
                    self.assertNotEqual(case['candidate'], case['safe_control'])
                    self.assertTrue(case['expected'])
                    self.assertNotIn('variant_ids', case)
                    self.assertNotIn('mechanism_keys', case)
        # This checks fixture consistency, not model reasoning or exploit execution.


class PatternExtensionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='pattern extension ')
        self.addCleanup(temporary.cleanup)
        self.package = Path(temporary.name)
        shutil.copytree(ROOT / 'references', self.package / 'references')
        self.index_path = reference_path('attack_index', root=self.package)
        self.index = json.loads(self.index_path.read_text())
        self.lens = reference_path('lens_auth', root=self.package)

    def validate(self):
        self.index_path.write_text(json.dumps(self.index))
        return validate_index(self.index_path, package_root=self.package)

    def test_valid_card_routes_without_controller_change(self):
        original_count = len(self.index['cards'])
        number = max(int(cid.rsplit('-', 1)[1]) for cid in self.index['categories']['auth']['ids']) + 1
        cid = f'NA-AUTH-{number:03}'
        title = 'Operation capability binds its intended resource'
        fields = {
            'Kind': 'security', 'Root cause': 'A delegated capability omits the resource identity.',
            'Activation': 'A caller can reuse an operation capability on another resource.',
            'Broken invariant': 'Authority is limited to its intended resource.',
            'Concrete sequence': 'Obtain a capability for A, then use it to mutate B.',
            'Required evidence': 'Show B changes without its owner granting authority.',
            'Exclusions': 'A lower layer binding the exact resource blocks the attempt.',
            'Recovery': 'Revoke the capability without changing the authority of other owners.',
            'Fix family': 'Bind and validate the resource in the authenticated capability.',
        }
        self.lens.write_text(self.lens.read_text() + '\n## ' + cid + ' — ' + title + '\n\n' +
                             ''.join(f'- **{key}:** {value}\n' for key, value in fields.items()))
        self.index['categories']['auth']['ids'].append(cid)
        self.index['cards'][cid] = dict(category='auth', kind='security', title=title,
                                       activation=fields['Activation'], related_ids=['NA-AUTH-007'])
        index = self.validate()
        routed = [card for cat in select_categories({}) for card in index['categories'][cat]['ids']]
        self.assertIn(cid, routed)
        self.assertEqual(original_count + 1, len(index['cards']))

    def test_variant_edit_keeps_identity_count_and_routing(self):
        before = copy.deepcopy(self.index)
        self.lens.write_text(self.lens.read_text().replace(
            '## NA-AUTH-002', '### Variants and safe controls\n\n'
            'A forwarding call preserves the original signer but changes the immediate caller.\n\n## NA-AUTH-002', 1))
        self.assertEqual(before, self.validate())
        self.assertEqual(select_categories({}), ['auth', 'account', 'state', 'econ'])

    def test_invalid_library_edits_fail(self):
        original_index, original_lens = copy.deepcopy(self.index), self.lens.read_text()
        for case in ('duplicate', 'incomplete', 'empty_field', 'duplicate_field', 'dangling',
                     'title', 'kind', 'unknown_kind', 'activation', 'category', 'malformed_id',
                     'wrong_id_prefix', 'unindexed', 'misplaced_file', 'duplicate_relation'):
            with self.subTest(case=case):
                self.index = copy.deepcopy(original_index)
                self.lens.write_text(original_lens)
                card = self.index['cards']['NA-AUTH-001']
                if case == 'duplicate':
                    self.lens.write_text(original_lens + '\n## NA-AUTH-001 — Duplicate\n')
                elif case == 'incomplete':
                    self.lens.write_text(original_lens.replace('- **Recovery:**', '- **Missing:**', 1))
                elif case == 'empty_field':
                    self.lens.write_text(original_lens.replace('- **Kind:** security', '- **Kind:** ', 1))
                elif case == 'duplicate_field':
                    self.lens.write_text(original_lens.replace('- **Kind:** security', '- **Kind:** security\n- **Kind:** security', 1))
                elif case == 'dangling': card['related_ids'] = ['NA-AUTH-999']
                elif case == 'duplicate_relation': card['related_ids'] = ['NA-AUTH-002', 'NA-AUTH-002']
                elif case == 'title': card['title'] = 'Different mechanism'
                elif case == 'kind': card['kind'] = 'quality'
                elif case == 'unknown_kind':
                    card['kind'] = 'confirmed'
                    self.lens.write_text(original_lens.replace('- **Kind:** security', '- **Kind:** confirmed', 1))
                elif case == 'activation': card['activation'] = ''
                elif case == 'category': card['category'] = 'async'
                elif case in ('malformed_id', 'wrong_id_prefix'):
                    cid = 'NA-AUTH-1' if case == 'malformed_id' else 'NA-ASYNC-999'
                    self.lens.write_text(original_lens.replace('NA-AUTH-001', cid))
                    self.index['categories']['auth']['ids'][0] = cid
                    self.index['cards'][cid] = self.index['cards'].pop('NA-AUTH-001')
                elif case == 'unindexed': self.index['cards'].pop('NA-AUTH-001')
                else: self.index['categories']['auth']['file'] = 'elsewhere.md'
                with self.assertRaises(ValueError): self.validate()

    def test_shorter_activation_summary_is_allowed(self):
        self.index['cards']['NA-AUTH-001']['activation'] = 'Authorization confuses signer and immediate caller.'
        self.validate()  # Semantic equivalence is reviewed; literal equality is not the contract.

    def test_pattern_hash_covers_index_card_and_binding(self):
        files = sorted((self.package / 'references').glob('*'))
        baseline = hash_files(files)
        for path in (self.index_path, self.lens, reference_path('target_binding', root=self.package)):
            with self.subTest(path=path.name):
                original = path.read_bytes()
                path.write_bytes(original + b'\n')
                self.assertNotEqual(baseline, hash_files(files))
                path.write_bytes(original)


class ConfigurationCoverageTests(unittest.TestCase):
    def test_snapshot_contains_every_shipped_configuration_resource(self):
        paths = {row['path'] for row in configuration_snapshot(ROOT)}
        for directory in ('references', 'runtime', 'docs'):
            expected = {p.relative_to(ROOT).as_posix() for p in (ROOT / directory).rglob('*')
                        if p.is_file() and p.suffix in {'.md', '.json'}}
            self.assertLessEqual(expected, paths)
        self.assertFalse(any(path.startswith('tests/') for path in paths))
