import copy
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "build_corpus_index.py"
SPEC = importlib.util.spec_from_file_location("build_corpus_index", SCRIPT)
indexer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(indexer)


class CorpusIndexToolsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.corpus = self.root / "corpus"
        self.corpus.mkdir()
        self.output = self.root / "index.json"
        self.output.write_bytes(b"existing index sentinel\n")

    def tearDown(self):
        self.temporary.cleanup()

    def report(self, content="# GUV-1 Synthetic finding - Low\n", name="Synthetic.md"):
        path = self.corpus / name
        path.write_text(content, encoding="utf-8")
        return path

    def run_cli(self, corpus=None, *, expected=0, output=True):
        arguments = [sys.executable, str(SCRIPT), str(corpus or self.corpus)]
        if output:
            arguments.extend(["--output", str(self.output)])
        result = subprocess.run(arguments, capture_output=True, text=True, check=False)
        self.assertEqual(expected, result.returncode, result.stdout or result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        if expected:
            self.assertEqual("invalid", json.loads(result.stdout)["action"])
        return result

    def snapshot(self):
        return {str(path.relative_to(self.root)): (path.stat().st_ino, path.stat().st_mtime_ns,
                path.read_bytes() if path.is_file() else None)
                for path in [self.root, *self.root.rglob("*")]}

    def test_generated_index_retains_schema_and_accounting(self):
        self.report()
        self.report("# Findings\n## High Risk\n### Second synthetic finding\n", "Native.md")
        self.report("# Synthetic review with no findings\n", "Zero.md")
        self.report("# Ignored README\n", "README.md")
        self.run_cli()
        data = json.loads(self.output.read_text(encoding="utf-8"))
        indexer.validate_index(data)
        self.assertEqual({"schema_version", "classification_version", "report_count", "finding_count",
                          "canonical_group_count", "report_counts", "canonical_groups", "findings"}, set(data))
        self.assertEqual(1, data["schema_version"])
        self.assertEqual(1, data["classification_version"])
        self.assertEqual(3, data["report_count"])
        self.assertEqual(2, data["finding_count"])
        self.assertEqual({"Native.md": 1, "Synthetic.md": 1, "Zero.md": 0}, data["report_counts"])
        self.assertEqual(["Native:L3", "Synthetic:GUV-1"], [item["source_id"] for item in data["findings"]])
        self.assertEqual(1, data["canonical_group_count"])
        self.assertEqual(2, data["canonical_groups"][0]["instance_count"])
        self.assertEqual(data, json.loads(self.run_cli(output=False).stdout))


    def test_malformed_or_unextractable_reports_do_not_write(self):
        path = self.report()
        for content in (b"", b" \n\t", b"\xff", b"# No extractable findings\n",
                        b"# Findings\n## High\n### **Severity:** High\n"):
            with self.subTest(content=content):
                path.write_bytes(content)
                before = self.snapshot()
                self.run_cli(expected=2)
                self.assertEqual(before, self.snapshot())



    def test_interrupted_writes_preserve_existing_index_and_cleanup(self):
        self.report()
        rendered = json.dumps(indexer.build_index(self.corpus))
        before = self.output.read_bytes()
        for operation in ("fsync", "replace"):
            with self.subTest(operation=operation), mock.patch.object(
                indexer.os, operation, side_effect=OSError("synthetic write interruption")
            ):
                with self.assertRaises(OSError):
                    indexer.write_index(self.output, rendered)
                self.assertEqual(before, self.output.read_bytes())
                self.assertEqual([], list(self.root.glob(".index.json.*")))


    def test_atomic_replace_observes_complete_valid_staged_payload(self):
        self.report()
        rendered = json.dumps(indexer.build_index(self.corpus))
        self.output.chmod(0o640)
        before = self.output.read_bytes()
        replace = indexer.os.replace

        def observe(source, destination):
            self.assertEqual(self.output.parent, source.parent)
            self.assertEqual(self.output, destination)
            self.assertEqual(before, destination.read_bytes())
            indexer.validate_index(json.loads(source.read_text(encoding="utf-8")))
            replace(source, destination)

        with mock.patch.object(indexer.os, "replace", side_effect=observe):
            indexer.write_index(self.output, rendered)
        self.assertEqual(json.loads(rendered), json.loads(self.output.read_text(encoding="utf-8")))
        self.assertEqual(0o640, self.output.stat().st_mode & 0o777)
        self.assertEqual([], list(self.root.glob(".index.json.*")))

    def test_write_failure_is_machine_readable_at_cli_boundary(self):
        self.report()
        self.output = self.root / "missing" / "index.json"
        before = self.snapshot()
        self.run_cli(expected=2)
        self.assertEqual(before, self.snapshot())


if __name__ == "__main__":
    unittest.main()
