"""Frozen routing, actual worker views, and immutable saved-run bindings."""
from support import LifecycleFixture, reference_path, reference_relative
from pathlib import Path
import json
import shutil
import subprocess
import sys
import tempfile
import unittest

from near_audit import make_work_packets
from run_integrity import canonical_hash
from worker_adapter import view

ROOT = Path(__file__).resolve().parents[1]
BASELINE = json.loads((ROOT / 'tests/fixtures/pattern-baseline.json').read_text())
PACKET_KEYS = ('packet_id', 'phase', 'role_id', 'output_path', 'dependencies', 'retry_limit',
               'candidate_outputs', 'additional_outputs', 'isolation', 'fresh_context', 'discovery_pass')


def normalize(value, target):
    if isinstance(value, dict):
        return {k: normalize(v, target) for k, v in value.items()
                if k not in {'root', 'official_docs_registry_hash'}}
    if isinstance(value, list): return [normalize(v, target) for v in value]
    if isinstance(value, str): return value.replace(str(target), '<TARGET>')
    return value


class RoutingCompatibilityTests(unittest.TestCase):
    def test_existing_targets_keep_routing_roles_and_output_ownership(self):
        for fixture, expected in BASELINE['routing'].items():
            with self.subTest(fixture=fixture):
                target = ROOT / 'tests/fixtures' / fixture
                surface = json.loads(subprocess.check_output(
                    [sys.executable, '-B', str(ROOT / 'scripts/map_surface.py'), str(target)], text=True))
                self.assertEqual(expected['surface'], normalize(surface, target))
                self.assertEqual(expected['selected_pattern_references'],
                                 [Path(p).name for p in surface['selected_pattern_references']])
                with tempfile.TemporaryDirectory() as directory:
                    packets = make_work_packets(Path(directory), surface, passes=2)
                self.assertEqual(expected['packets'],
                                 [{k: p[k] for k in PACKET_KEYS if k in p} for p in packets])


class WorkerIsolationTests(LifecycleFixture):
    def test_actual_worker_views_keep_patterns_selected_and_neutral_roles_blind(self):
        self.initialize(passes=2)
        surface = json.loads((self.run_dir / 'surface.json').read_text())
        selected = set(surface['selected_pattern_references'])
        packets = [json.loads(line) for line in (self.run_dir / 'work-packets.jsonl').read_text().splitlines()]
        for packet in packets:
            role = packet['role_id']
            if role not in {'protocol-modeler', 'intent-reasoner', 'pattern-matcher', 'corpus-echo'} and packet['phase'] not in {'blind-l3-active', 'nep-coverage'}:
                continue
            with self.subTest(packet=packet['packet_id']):
                actual = view(self.run_dir, packet['packet_id'], reference_path('agent_catalog'))
                refs = set(actual['references'])
                self.assertFalse(any(p.startswith(('tests/', 'benchmarks/', 'docs/')) for p in refs))
                self.assertFalse(any('fixtures/' in p for p in packet['allowed_inputs']))
                if role in {'protocol-modeler', 'intent-reasoner'}:
                    self.assertEqual({reference_relative('neutral_schemas')}, refs)
                    self.assertEqual('neutral-surface.json', actual['surface'])
                    self.assertEqual([], actual['owned_official_cards'])
                if role in {'pattern-matcher', 'corpus-echo'}:
                    pattern_refs = {p for p in refs if p.startswith('references/')}
                    self.assertEqual(selected | {reference_relative('attack_index'), reference_relative('target_binding')}, pattern_refs)
                    self.assertTrue(selected <= set(packet['allowed_inputs']))
                    self.assertTrue(actual['prompt'])
                else:
                    self.assertFalse(any(p.startswith('references/') for p in refs))
                    self.assertIn('attack lenses', packet['forbidden_inputs'])
                    self.assertNotIn('- **Root cause:**', actual['prompt'])
                for ref in refs: self.assertTrue((ROOT / ref).is_file(), ref)
                if packet['phase'] == 'nep-coverage':
                    checklists = [p for p in refs if p.startswith('runtime/standards/neps/') and p.endswith('.md')]
                    self.assertEqual([f'runtime/standards/neps/{role}.md'], checklists)


class PatternRunBindingTests(LifecycleFixture):
    def test_changed_resources_block_resume_without_rewriting_saved_run(self):
        self.skill = self.root / 'relocated package with spaces'
        shutil.copytree(ROOT, self.skill, ignore=shutil.ignore_patterns('.git', '__pycache__', '*.pyc', '*.lock'))
        self.initialize()
        manifest, state = self.run_dir / 'run-manifest.json', self.run_dir / 'run-state.json'
        before = manifest.read_bytes(), state.read_bytes()
        for name in ('attack_index', 'lens_auth', 'target_binding', 'agent_catalog', 'neutral_schemas',
                     'nep_registry', 'technical_annex_template', 'adding_patterns'):
            with self.subTest(resource=name):
                resource = reference_path(name, root=self.skill)
                original = resource.read_bytes()
                try:
                    resource.write_bytes(original + b'\n')
                    self.assertIn('configuration drift', self.cli('resume', self.run_dir, ok=False).stderr)
                    self.assertEqual(before, (manifest.read_bytes(), state.read_bytes()))
                finally: resource.write_bytes(original)
        self.cli('status', self.run_dir)

    def test_old_layout_binding_is_not_silently_migrated(self):
        self.initialize()
        manifest_path = self.run_dir / 'run-manifest.json'
        manifest = json.loads(manifest_path.read_text())
        for row in manifest['configuration_snapshot']:
            if row['path'] == reference_relative('lens_auth'):
                row['path'] = 'references/patterns/attack-lenses/auth.md'
        manifest['configuration_snapshot'].sort(key=lambda row: row['path'])
        manifest['configuration_hash'] = canonical_hash(manifest['configuration_snapshot'])
        manifest_path.write_text(json.dumps(manifest))
        state = self.run_dir / 'run-state.json'
        before = manifest_path.read_bytes(), state.read_bytes()
        self.assertIn('configuration drift', self.cli('resume', self.run_dir, ok=False).stderr)
        self.assertEqual(before, (manifest_path.read_bytes(), state.read_bytes()))
