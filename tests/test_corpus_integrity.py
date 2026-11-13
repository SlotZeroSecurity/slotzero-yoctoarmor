"""Historical finding accounting stays linked to the active taxonomy."""

from support import reference_path
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SKILL_ROOT = Path(__file__).resolve().parents[1]
REFERENCES = SKILL_ROOT / "references"


class CorpusIntegrityTests(unittest.TestCase):
    def test_original_and_legacy_reports_resolve_to_new_cards(self):
        index = json.loads((reference_path('attack_index', root=REFERENCES.parent)).read_text())["cards"]
        corpus = json.loads((reference_path('original_findings_index', root=REFERENCES.parent)).read_text())
        legacy = json.loads((reference_path('legacy_design_review', root=REFERENCES.parent)).read_text())
        self.assertEqual(222, len(corpus["findings"]))
        self.assertEqual(21, len(legacy["reports"]))
        self.assertEqual(185, sum(row["indexed_finding_count"] for row in legacy["reports"]))
        for finding in corpus["findings"]:
            self.assertTrue(finding["canonical_ids"])
            self.assertLessEqual(set(finding["canonical_ids"]), set(index))
        for report in legacy["reports"]:
            self.assertEqual(64, len(report["pdf_sha256"]))
            self.assertLessEqual(set(report["mapped_new_ids"]), set(index))

    def test_pdf_manifest_retains_unique_terminal_sources(self):
        manifest_path = reference_path('report_registry', root=REFERENCES.parent)
        manifest = json.loads(manifest_path.read_text())
        digests = [row["sha256"] for row in manifest["reports"]]
        self.assertEqual(len(digests), len(set(digests)))
        self.assertFalse({row["disposition"] for row in manifest["reports"]} & {"pending_review", "extraction_failed"})
        spec = importlib.util.spec_from_file_location("pdf_corpus_registry", SKILL_ROOT / "scripts/pdf_corpus_registry.py")
        registry = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(registry)
        registry.validate_manifest(manifest, manifest_path)

    def test_corpus_hash_changes_with_a_source_ledger(self):
        spec = importlib.util.spec_from_file_location("near_audit", SKILL_ROOT / "scripts/near_audit.py")
        audit = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(audit)
        self.assertIn(reference_path('report_registry', root=REFERENCES.parent), audit.CORPUS_FILES)
        with tempfile.TemporaryDirectory() as directory:
            copies = []
            for source in audit.CORPUS_FILES:
                destination = Path(directory) / source.name
                destination.write_bytes(source.read_bytes())
                copies.append(destination)
            before = audit.hash_files(copies)
            target = Path(directory) / "report-registry.json"
            target.write_bytes(target.read_bytes() + b"\n")
            self.assertNotEqual(before, audit.hash_files(copies))
