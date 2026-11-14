"""Compatibility boundaries for consolidated runtime and fixture helpers."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import build_semantic_ir
import check_maturity
import check_run_artifacts
import near_audit
import prepare_informed_rescan
import record_feedback
import run_integrity
import score_benchmark
from support import write_compact_json, write_json, write_jsonl


class SharedHelperTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name) / "artifact.json"
        self.hashers = (
            run_integrity.canonical_hash, near_audit.canonical_hash,
            check_run_artifacts.canonical_hash, prepare_informed_rescan.canonical_hash,
            score_benchmark.canonical_hash,
        )
        self.loaders = (
            run_integrity.load_json_object, near_audit.read_json,
            record_feedback.load_json, prepare_informed_rescan.load_json,
        )

    def test_hash_bytes_and_key_order_are_preserved(self):
        expected = "sha256:" + hashlib.sha256(b'{"a":1,"b":[true,null]}').hexdigest()
        for hasher in self.hashers:
            for value in ({"a": 1, "b": [True, None]}, {"b": [True, None], "a": 1}):
                with self.subTest(hasher=hasher, value=value):
                    self.assertEqual(hasher(value), expected)

    def test_unicode_and_digest_prefix_variants_remain_distinct(self):
        value = {"name": "caf\u00e9"}
        escaped_digest = hashlib.sha256(b'{"name":"caf\\u00e9"}').hexdigest()
        unicode_digest = hashlib.sha256('{"name":"caf\u00e9"}'.encode("utf-8")).hexdigest()
        for hasher in self.hashers:
            self.assertEqual(hasher(value), "sha256:" + escaped_digest)
        self.assertEqual(record_feedback.canonical_hash(value), "sha256:" + escaped_digest)
        self.assertEqual(build_semantic_ir.canonical_hash(value), "sha256:" + unicode_digest)
        self.assertEqual(check_maturity.canonical_hash(value), escaped_digest)

    def test_nonfinite_hash_policy_is_unchanged(self):
        for value, encoded in ((float("nan"), b'{"value":NaN}'),
                               (float("inf"), b'{"value":Infinity}'),
                               (float("-inf"), b'{"value":-Infinity}')):
            with self.subTest(encoded=encoded):
                digest = hashlib.sha256(encoded).hexdigest()
                for hasher in (*self.hashers, build_semantic_ir.canonical_hash):
                    self.assertEqual(hasher({"value": value}), "sha256:" + digest)
                self.assertEqual(check_maturity.canonical_hash({"value": value}), digest)
                with self.assertRaises(ValueError):
                    record_feedback.canonical_hash({"value": value})

    def test_object_loading_preserves_standard_duplicate_key_behavior(self):
        self.path.write_text('{"name":"caf\u00e9","nested":{"key":1,"key":2}}', encoding="utf-8")
        for loader in self.loaders:
            with self.subTest(loader=loader):
                self.assertEqual(loader(self.path), {"name": "caf\u00e9", "nested": {"key": 2}})
        for reader in (run_integrity.read_json, run_integrity.read_jsonl):
            with self.assertRaisesRegex(ValueError, "duplicate JSON key: key"):
                reader(self.path)

    def test_object_loading_preserves_nonobject_and_decode_errors(self):
        for text in ("[]", "null", "1", '"text"'):
            self.path.write_text(text, encoding="utf-8")
            for loader in self.loaders:
                with self.subTest(text=text, loader=loader):
                    with self.assertRaises(ValueError) as caught:
                        loader(self.path)
                    self.assertEqual(str(caught.exception), f"{self.path}: expected object")
        self.path.write_text('{"broken":', encoding="utf-8")
        for loader in self.loaders:
            with self.assertRaises(json.JSONDecodeError) as caught:
                loader(self.path)
            self.assertEqual(caught.exception.doc, '{"broken":')
            self.assertEqual(caught.exception.pos, 10)

    def test_missing_object_file_still_raises_file_not_found(self):
        for loader in self.loaders:
            with self.subTest(loader=loader):
                with self.assertRaises(FileNotFoundError) as caught:
                    loader(self.path)
                self.assertEqual(caught.exception.filename, str(self.path))

    def test_string_normalization_preserves_mixed_list_behavior(self):
        for value, expected in (("role", ["role"]), (["role", None, 1, ""], ["role", ""]),
                                (None, []), ({"role": True}, []), (("role",), [])):
            with self.subTest(value=value):
                self.assertEqual(record_feedback.string_values(value), expected)
                self.assertEqual(prepare_informed_rescan.values(value), expected)

    def test_fixture_serialization_variants_are_preserved(self):
        write_json(self.path, {"value": 1})
        self.assertEqual(self.path.read_bytes(), b'{\n  "value": 1\n}\n')
        write_compact_json(self.path, {"value": 1})
        self.assertEqual(self.path.read_bytes(), b'{"value": 1}')
        write_jsonl(self.path, [{"value": 1}, {"value": 2}])
        self.assertEqual(self.path.read_bytes(), b'{"value": 1}\n{"value": 2}\n')
