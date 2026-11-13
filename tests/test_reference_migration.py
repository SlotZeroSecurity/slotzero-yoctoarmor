"""Lossless reference relocation and safe extension against the frozen v1 baseline."""
from support import LifecycleFixture, reference_path
from pathlib import Path
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest

from reference_links import reference_link_errors
from reference_paths import REFERENCE_PATHS
from pattern_routing import validate_index, select_categories
from near_audit import make_work_packets
from check_nep_registry import validate_registry
from pdf_corpus_registry import load_manifest

ROOT = Path(__file__).resolve().parents[1]
BASELINE = json.loads((ROOT / 'tests/fixtures/reference-migration/baseline.json').read_text())
MOVES = BASELINE['moves']


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def restore_source_paths(value):
    """Undo only the specified path migration; source content must otherwise match."""
    if isinstance(value, dict):
        return {key: restore_source_paths(item) for key, item in value.items()}
    if isinstance(value, list):
        return [restore_source_paths(item) for item in value]
    if isinstance(value, str):
        reverse = {new: old for old, new in MOVES.items()}
        if value in reverse:
            return reverse[value]
        relative, separator, fragment = value.partition('#')
        source_path = 'references/sources/' + relative
        if separator and source_path in reverse:
            return reverse[source_path].removeprefix('references/') + '#' + fragment
        if value == 'review-cards.md':
            return 'official-docs-attacker-guide.md'
    return value


def routing_normalized(value, target):
    if isinstance(value, dict):
        return {key: routing_normalized(item, target) for key, item in value.items()
                if key not in {'packet_hash', 'official_docs_registry_hash'}}
    if isinstance(value, list):
        return [routing_normalized(item, target) for item in value]
    return '<TARGET>' if value == str(target) else value


class ReferenceMigrationTests(unittest.TestCase):
    def test_all_original_files_preserved_and_cataloged(self):
        self.assertEqual(48, len(MOVES))
        self.assertEqual(len(MOVES), len(set(MOVES.values())))
        catalog = reference_path('catalog').read_text()
        for old, new in MOVES.items():
            with self.subTest(path=new):
                self.assertTrue((ROOT / new).is_file())
                self.assertFalse((ROOT / new).is_symlink())
                if old != new:
                    self.assertFalse((ROOT / old).exists())
                self.assertIn('](' + new.removeprefix('references/') + ')', catalog)
        actual = {p.relative_to(ROOT).as_posix() for p in (ROOT / 'references').rglob('*') if p.is_file()}
        self.assertEqual(set(REFERENCE_PATHS.values()), actual)

    def test_original_card_bytes_and_source_records_are_preserved(self):
        for old, new in MOVES.items():
            if '/attack-lenses/' in old:
                self.assertEqual(BASELINE['original_sha256'][old], hashlib.sha256((ROOT / new).read_bytes()).hexdigest(), old)
            elif old.endswith('.json'):
                restored = restore_source_paths(json.loads((ROOT / new).read_text()))
                self.assertEqual(BASELINE['json_semantic_sha256'][old], digest(restored), old)
        operators = json.loads(reference_path('mutation_operators').read_text())['families']
        self.assertEqual(52, sum(map(len, operators.values())))
        self.assertEqual(96, len(validate_index()['cards']))
        load_manifest(reference_path('report_registry'))

    def test_fixture_routing_and_packet_ownership_match_v1(self):
        for fixture, expected in BASELINE['routing'].items():
            target = ROOT / 'tests/fixtures' / fixture
            surface = json.loads(subprocess.check_output(
                [sys.executable, '-B', str(ROOT / 'scripts/map_surface.py'), str(target)], text=True))
            with tempfile.TemporaryDirectory() as directory:
                packets = make_work_packets(Path(directory), surface, passes=2)
            self.assertEqual(expected['surface_sha256'], digest(routing_normalized(surface, target)), fixture)
            self.assertEqual(expected['packets_sha256'], digest(routing_normalized(packets, target)), fixture)

    def test_links_and_anchors_resolve_and_bad_anchor_fails(self):
        self.assertEqual([], reference_link_errors(ROOT))
        with tempfile.TemporaryDirectory() as temporary:
            package = Path(temporary)
            (package / 'references').mkdir()
            (package / 'SKILL.md').write_text('# Skill\n')
            (package / 'README.md').write_text('[missing](SKILL.md#absent)\n')
            self.assertTrue(any('broken anchor' in error for error in reference_link_errors(package)))

    def test_no_obsolete_operational_reference_paths(self):
        old_paths = [old for old, new in MOVES.items() if old != new]
        targets = [ROOT / 'SKILL.md', ROOT / 'README.md', *(ROOT / 'scripts').glob('*.py'),
                   *(ROOT / 'references').rglob('*.md'), *(ROOT / 'references').rglob('*.json')]
        for path in targets:
            text = path.read_text()
            for old in old_paths:
                self.assertNotIn(old, text, (path, old))

    def test_nested_registry_uses_explicit_package_root(self):
        with tempfile.TemporaryDirectory(prefix='reference package ') as temporary:
            package = Path(temporary)
            shutil.copytree(ROOT / 'references', package / 'references')
            registry = reference_path('nep_registry', root=package)
            self.assertEqual(51, len(validate_registry(registry, package_root=package)['neps']))
            reference_path('nep_token_assets', root=package).unlink()
            with self.assertRaisesRegex(ValueError, 'missing checklist'):
                validate_registry(registry, package_root=package)


class PatternExtensionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='pattern extension ')
        self.addCleanup(temporary.cleanup)
        self.package = Path(temporary.name)
        shutil.copytree(ROOT / 'references/patterns', self.package / 'references/patterns')
        self.index_path = reference_path('attack_index', root=self.package)
        self.index = json.loads(self.index_path.read_text())
        self.lens = reference_path('lens_auth', root=self.package)

    def validate(self):
        self.index_path.write_text(json.dumps(self.index))
        return validate_index(self.index_path, package_root=self.package)

    def test_add_valid_card_to_existing_category(self):
        original = self.lens.read_text().split('## NA-AUTH-001 — ', 1)[1].split('\n## ', 1)[0]
        card_id = 'NA-AUTH-013'
        self.lens.write_text(self.lens.read_text() + '\n## ' + card_id + ' — ' + original)
        self.index['categories']['auth']['ids'].append(card_id)
        self.index['cards'][card_id] = dict(self.index['cards']['NA-AUTH-001'])
        index = self.validate()
        categories = select_categories({})
        routed_ids = {cid for category in categories for cid in index['categories'][category]['ids']}
        self.assertIn(card_id, routed_ids)
        self.assertEqual(97, len(index['cards']))

    def test_reject_duplicate_incomplete_dangling_and_inconsistent_cards(self):
        original_index = json.loads(self.index_path.read_text())
        original_lens = self.lens.read_text()
        for case in ['duplicate', 'incomplete', 'dangling', 'title', 'kind', 'activation']:
            with self.subTest(case=case):
                self.index = json.loads(json.dumps(original_index))
                self.lens.write_text(original_lens)
                card = self.index['cards']['NA-AUTH-001']
                if case == 'duplicate':
                    self.lens.write_text(original_lens + '\n## NA-AUTH-001 — Duplicate\n')
                elif case == 'incomplete':
                    self.lens.write_text(original_lens.replace('- **Recovery:**', '- **Missing:**', 1))
                elif case == 'dangling':
                    card['related_ids'] = ['NA-AUTH-999']
                elif case == 'title':
                    card['title'] = 'Different mechanism'
                elif case == 'kind':
                    card['kind'] = 'quality'
                else:
                    card['activation'] = ''
                with self.assertRaises(ValueError):
                    self.validate()

from run_integrity import canonical_hash


class ReferenceRunBindingTests(LifecycleFixture):
    def test_relocated_source_change_blocks_resume_without_rewriting_run(self):
        self.skill = self.root / 'relocated package'
        shutil.copytree(ROOT, self.skill, ignore=shutil.ignore_patterns('.git', '__pycache__', '*.pyc', '*.lock'))
        self.initialize()
        manifest = self.run_dir / 'run-manifest.json'
        state = self.run_dir / 'run-state.json'
        before = (manifest.read_bytes(), state.read_bytes())
        ledger = reference_path('issue_findings', root=self.skill)
        ledger.write_text(ledger.read_text() + '\nChanged source context.\n')
        self.assertIn('configuration drift', self.cli('resume', self.run_dir, ok=False).stderr)
        self.assertEqual(before, (manifest.read_bytes(), state.read_bytes()))

    def test_old_reference_layout_is_not_silently_migrated(self):
        self.initialize()
        manifest_path = self.run_dir / 'run-manifest.json'
        manifest = json.loads(manifest_path.read_text())
        reverse = {new: old for old, new in MOVES.items()}
        for row in manifest['configuration_snapshot']:
            row['path'] = reverse.get(row['path'], row['path'])
        manifest['configuration_snapshot'].sort(key=lambda row: row['path'])
        manifest['configuration_hash'] = canonical_hash(manifest['configuration_snapshot'])
        manifest_path.write_text(json.dumps(manifest))
        state = self.run_dir / 'run-state.json'
        before = (manifest_path.read_bytes(), state.read_bytes())
        self.assertIn('configuration drift', self.cli('resume', self.run_dir, ok=False).stderr)
        self.assertEqual(before, (manifest_path.read_bytes(), state.read_bytes()))
