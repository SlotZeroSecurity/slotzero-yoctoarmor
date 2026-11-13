"""Health-check URL boundaries and read-only behavior in disposable packages."""

from support import reference_relative
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class PackagePolicyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.skill = Path(temporary.name) / "skill with spaces"
        shutil.copytree(ROOT, self.skill, ignore=shutil.ignore_patterns(
            ".git", "__pycache__", "*.pyc", "*.lock"))

    def snapshot(self):
        return {
            path.relative_to(self.skill).as_posix(): (
                hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None
            )
            for path in self.skill.rglob("*")
        }

    def check_commands(self, prohibited=None):
        # Exercise ordinary CLI invocation without relying on the caller to disable caches.
        environment = {key: value for key, value in os.environ.items()
                       if key not in {"PYTHONDONTWRITEBYTECODE", "PYTHONPYCACHEPREFIX"}}
        for script, command in (("near_audit.py", "doctor"), ("maintain.py", "check")):
            with self.subTest(script=script):
                before = self.snapshot()
                result = subprocess.run(
                    [sys.executable, str(self.skill / "scripts" / script), command],
                    cwd=self.skill.parent, env=environment, text=True,
                    capture_output=True, timeout=45,
                )
                self.assertEqual(before, self.snapshot(), "health check changed package contents")
                if prohibited is None:
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertTrue(json.loads(result.stdout)["ok"])
                else:
                    self.assertNotEqual(result.returncode, 0)
                    if command == "doctor":
                        payload = json.loads(result.stdout)
                        self.assertFalse(payload["ok"])
                        self.assertIn(f"external URL in {prohibited}", payload["errors"])
                    else:
                        self.assertIn("external URL in package:", result.stderr)
                        self.assertIn(prohibited, result.stderr)

    def test_top_level_readme_links_pass_without_writes(self):
        readme = self.skill / "README.md"
        original = readme.read_text(encoding="utf-8")
        for scheme in ("http", "https"):
            with self.subTest(scheme=scheme):
                readme.write_text(original + "\n[Documentation](" + scheme +
                                  "://example.invalid/docs)\n", encoding="utf-8")
                self.check_commands()

    def test_urls_outside_top_level_readme_fail_without_writes(self):
        for relative in ("SKILL.md", reference_relative('maintenance'), "scripts/package_policy.py",
                         "tests/url-fixture.py", "references/url-fixture.json",
                         "agents/url-fixture.yaml", "tests/url-fixture.rs",
                         reference_relative('catalog')):
            path = self.skill / relative
            original = path.read_bytes() if path.exists() else None
            try:
                for scheme in ("http", "https"):
                    with self.subTest(path=relative, scheme=scheme):
                        path.write_bytes((original or b"") + b"\n# " + scheme.encode() +
                                         b"://example.invalid/docs\n")
                        self.check_commands(prohibited=relative)
            finally:
                if original is None:
                    path.unlink()
                else:
                    path.write_bytes(original)
