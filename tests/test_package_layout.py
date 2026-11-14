"""The distributed package needs patterns and runtime resources, not history."""
from support import reference_path
from pathlib import Path
import json
import shutil
import subprocess
import sys
import tempfile
import unittest

from reference_links import reference_link_errors
from reference_paths import REFERENCE_PATHS, missing_resource_paths
from check_nep_registry import validate_registry

ROOT = Path(__file__).resolve().parents[1]


class PackageLayoutTests(unittest.TestCase):
    def test_pattern_directory_and_fixed_resource_catalog_are_complete(self):
        expected = {'index.json', 'target-binding.md', *(c + '.md' for c in
                    ('auth', 'async', 'account', 'state', 'econ', 'resource', 'integration', 'crypto', 'runtime', 'offchain'))}
        self.assertEqual(expected, {p.name for p in (ROOT / 'references').iterdir()})
        self.assertEqual([], missing_resource_paths(ROOT))
        self.assertEqual([], reference_link_errors(ROOT))
        actual = {p.relative_to(ROOT).as_posix() for directory in ('references', 'runtime', 'docs')
                  for p in (ROOT / directory).rglob('*') if p.is_file()}
        self.assertEqual(set(REFERENCE_PATHS.values()), actual)
        self.assertFalse(any((ROOT / p).is_symlink() for p in actual))

    def test_runtime_and_contributor_links_validate_anchors(self):
        with tempfile.TemporaryDirectory() as td:
            package = Path(td)
            for directory in ('references', 'runtime', 'docs'):
                (package / directory).mkdir()
            (package / 'SKILL.md').write_text('# Skill\n')
            (package / 'README.md').write_text('# Package\n')
            for directory in ('runtime', 'docs'):
                p = package / directory / 'guide.md'
                p.write_text('[broken](../SKILL.md#absent)\n')
                self.assertTrue(any('broken anchor' in error for error in reference_link_errors(package)))
                p.write_text('[valid](../SKILL.md#skill)\n')
                self.assertEqual([], reference_link_errors(package))

    def test_nested_standards_registry_resolves_disposable_package(self):
        with tempfile.TemporaryDirectory(prefix='reference package ') as td:
            package = Path(td)
            shutil.copytree(ROOT / 'runtime', package / 'runtime')
            registry = reference_path('nep_registry', root=package)
            expected = json.loads(registry.read_text())
            self.assertEqual(len(expected['neps']), len(validate_registry(registry, package_root=package)['neps']))
            reference_path('nep_token_assets', root=package).unlink()
            with self.assertRaisesRegex(ValueError, 'missing checklist'):
                validate_registry(registry, package_root=package)

    def test_operational_files_have_no_removed_paths_or_helpers(self):
        fragments = ('references/sources/', 'references/patterns/', 'references/workflow/',
                     'references/maintenance/', 'pdf_corpus_registry', 'build_corpus_index',
                     'historical-id-map.json')
        paths = [ROOT / 'SKILL.md', ROOT / 'README.md', *(ROOT / 'scripts').glob('*.py'),
                 *(p for d in ('runtime', 'references', 'docs') for p in (ROOT / d).rglob('*') if p.is_file())]
        for path in paths:
            for fragment in fragments: self.assertNotIn(fragment, path.read_text(), (path, fragment))

    def test_registry_cli_validates_the_supplied_package_not_its_own(self):
        with tempfile.TemporaryDirectory(prefix='external package ') as td:
            package = Path(td)
            shutil.copytree(ROOT / 'runtime', package / 'runtime')
            registry = reference_path('nep_registry', root=package)
            command = [sys.executable, '-B', str(ROOT / 'scripts/maintain.py'),
                       'standards', 'neps', str(registry)]
            valid = subprocess.run(command, cwd=package, capture_output=True, text=True)
            self.assertEqual(0, valid.returncode, valid.stderr)
            reference_path('nep_token_assets', root=package).unlink()
            invalid = subprocess.run(command, cwd=package, capture_output=True, text=True)
            self.assertNotEqual(0, invalid.returncode)
            self.assertIn('missing checklist', invalid.stderr)

    def test_standalone_registry_requires_an_explicit_package_root(self):
        with tempfile.TemporaryDirectory() as td:
            registry = Path(td) / 'review-registry.json'
            shutil.copyfile(reference_path('nep_registry'), registry)
            command = [sys.executable, '-B', str(ROOT / 'scripts/check_nep_registry.py'), str(registry)]
            ambiguous = subprocess.run(command, capture_output=True, text=True)
            self.assertNotEqual(0, ambiguous.returncode)
            self.assertIn('--package-root', ambiguous.stderr)
            explicit = subprocess.run(command + ['--package-root', str(ROOT)],
                                      capture_output=True, text=True)
            self.assertEqual(0, explicit.returncode, explicit.stderr)

    def test_maintenance_keeps_evidence_cli_and_removes_ingestion_cli(self):
        script = ROOT / 'scripts/maintain.py'
        result = subprocess.run([sys.executable, '-B', str(script), 'evidence', 'ledger', '--help'],
                                capture_output=True, text=True)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn('raw_candidates', result.stdout)
        removed = subprocess.run([sys.executable, '-B', str(script), 'corpus', 'pdf'],
                                 capture_output=True, text=True)
        self.assertNotEqual(0, removed.returncode)
