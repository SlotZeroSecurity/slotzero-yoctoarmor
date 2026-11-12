import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SKILL_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = SKILL_ROOT / "scripts" / "pdf_corpus_registry.py"
SPEC = importlib.util.spec_from_file_location("pdf_corpus_registry", SCRIPT)
registry = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(registry)


class PdfCorpusRegistryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.manifest = self.root / "pdf-corpus-manifest.json"
        self.ledger = self.root / "ledger.md"
        self.ledger.write_text(
            "# Ledger\n\n| Ledger ID | Report |\n|---|---|\n| TEST-01 | Test report |\n",
            encoding="utf-8",
        )
        self.manifest.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "hash_algorithm": "sha256",
                    "reports": [],
                    "legacy_unhashed_sources": [],
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

    def tearDown(self):
        self.temporary.cleanup()

    def run_cli(self, *arguments, expected=0, env=None):
        completed = subprocess.run(
            [sys.executable, str(SCRIPT), *arguments, "--manifest", str(self.manifest)],
            check=False,
            capture_output=True,
            text=True,
            env=env,
        )
        self.assertEqual(expected, completed.returncode, completed.stderr or completed.stdout)
        self.assertNotIn("Traceback", completed.stderr)
        return [json.loads(line) for line in completed.stdout.splitlines() if line]

    def make_pdf(self, name="report.pdf", payload=b"one"):
        path = self.root / name
        path.write_bytes(b"%PDF-1.4\n" + payload + b"\n%%EOF\n")
        return path

    def finalize(self, sha256):
        return self.run_cli(
            "finalize",
            sha256,
            "--disposition",
            "ingested",
            "--title",
            "Test report",
            "--auditor",
            "Test auditor",
            "--report-date",
            "2026-09-07",
            "--ecosystem-scope",
            "near-native",
            "--corpus-ref",
            "ledger.md#TEST-01",
        )

    def test_register_resume_finalize_and_terminal_skip_are_idempotent(self):
        source = self.make_pdf()
        expected_hash = hashlib.sha256(source.read_bytes()).hexdigest()

        registered = self.run_cli("register", str(source))[0]
        self.assertEqual("registered", registered["action"])
        self.assertEqual(expected_hash, registered["sha256"])

        renamed = self.root / "renamed.pdf"
        renamed.write_bytes(source.read_bytes())
        before_resume = self.manifest.read_bytes()
        resumed = self.run_cli("register", str(renamed))[0]
        self.assertEqual("resume", resumed["action"])
        self.assertEqual(before_resume, self.manifest.read_bytes())

        finalized = self.finalize(expected_hash)[0]
        self.assertEqual("registered", finalized["action"])
        before_skip = self.manifest.read_bytes()
        skipped = self.run_cli("register", str(renamed))[0]
        self.assertEqual("skip", skipped["action"])
        self.assertEqual(before_skip, self.manifest.read_bytes())

        finalize_again = self.finalize(expected_hash)[0]
        self.assertEqual("skip", finalize_again["action"])
        self.assertEqual(before_skip, self.manifest.read_bytes())



    def test_invalid_pdf_rejects_batch_without_manifest_mutation(self):
        self.make_pdf("valid.pdf")
        invalid = self.root / "invalid.pdf"
        invalid.write_bytes(b"not a pdf")
        before = self.manifest.read_bytes()
        result = self.run_cli("register", str(self.root), expected=2)[0]
        self.assertEqual("invalid", result["action"])
        self.assertEqual(before, self.manifest.read_bytes())

    def test_corrupt_manifest_fails_closed(self):
        source = self.make_pdf()
        self.manifest.write_text('{"schema_version": 1,', encoding="utf-8")
        before = self.manifest.read_bytes()
        result = self.run_cli("register", str(source), expected=3)[0]
        self.assertEqual("invalid", result["action"])
        self.assertEqual(before, self.manifest.read_bytes())



    def sample_manifest(self):
        data = registry.empty_manifest()
        data["reports"] = [{
            "sha256": "a" * 64, "filename": "synthetic.pdf", "byte_size": 32,
            "registered_at": "2026-09-08T00:00:00Z", "title": "Synthetic report",
            "auditor": "Synthetic auditor", "report_date": "2024-02-29",
            "ecosystem_scope": "near-native", "disposition": "ingested",
            "corpus_refs": ["ledger.md#TEST-01"], "notes": "", "legacy_backfill": False,
        }]
        return data

    def snapshot(self):
        return {
            str(path.relative_to(self.root)): (
                path.stat().st_ino, path.stat().st_mode, path.stat().st_mtime_ns,
                path.read_bytes() if path.is_file() else None,
            ) for path in [self.root, *self.root.rglob("*")]
        }













    def test_atomic_manifest_write_failure_preserves_original(self):
        before = self.manifest.read_bytes()
        for operation in ("fsync", "replace"):
            with self.subTest(operation=operation), mock.patch.object(
                registry.os, operation, side_effect=OSError("synthetic interruption")
            ):
                with self.assertRaises(OSError):
                    registry.atomic_write_manifest(self.manifest, self.sample_manifest())
            self.assertEqual(before, self.manifest.read_bytes())
            self.assertFalse(list(self.root.glob(f".{self.manifest.name}.*")))


if __name__ == "__main__":
    unittest.main()
