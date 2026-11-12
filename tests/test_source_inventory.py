"""Synthetic filesystem-only regression tests for shared input discovery."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS))
import build_semantic_ir as semantic
import map_surface
import source_inventory as inventory


class SourceInventoryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.root = self.base / "target-project"
        self.root.mkdir()

    def put(self, name: str, data: str | bytes = "fixture\n") -> Path:
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data.encode() if isinstance(data, str) else data)
        return path

    def paths(self, paths: list[Path]) -> list[str]:
        return [path.relative_to(self.root).as_posix() for path in paths]

    def snapshot(self, explicit: list[Path] | None = None) -> dict[str, str]:
        rows = inventory.snapshot_inputs(self.root, explicit or [])
        self.assertEqual([row["path"] for row in rows], sorted(row["path"] for row in rows))
        self.assertTrue(all(set(row) == {"path", "sha256"} for row in rows))
        return {row["path"]: row["sha256"] for row in rows}

    def test_shared_discovery_prunes_before_entering_and_sorts(self) -> None:
        self.put("z.rs")
        self.put("src/b.ts")
        self.put("src/a.rs")
        for directory in inventory.SKIP_DIRS | {"TESTS", "examples", "fixtures"}:
            self.put(f"{directory}/deep/ignored.rs")
        visited = []
        real_scandir = os.scandir

        def tracked_scandir(path):
            visited.append(Path(path))
            return real_scandir(path)

        with mock.patch.object(inventory.os, "scandir", side_effect=tracked_scandir):
            found = inventory.discover(self.root, [])
        self.assertEqual(self.paths(found), ["src/a.rs", "src/b.ts", "z.rs"])
        self.assertEqual(set(visited), {self.root, self.root / "src"})
        self.assertIs(map_surface.discover, inventory.discover)
        self.assertIs(semantic.discover, inventory.discover)
        self.assertIs(semantic.discover_artifacts, inventory.discover_artifacts)



    def test_no_file_or_directory_symlinks_even_for_in_target_destinations(self) -> None:
        original = self.put("src/lib.rs")
        self.put("src/README.md")
        self.put("src/Cargo.toml", '[package]\nname = "fixture"\nversion = "0.1.0"\n')
        self.put("build/contract.abi.json", '{}')
        outside = self.base / "external"
        outside.mkdir()
        (outside / "external.rs").write_text("external", encoding="utf-8")
        (self.root / "alias.rs").symlink_to(original)
        (self.root / "alias-dir").symlink_to(original.parent, target_is_directory=True)
        (self.root / "escape").symlink_to(outside, target_is_directory=True)
        (self.root / "dangling.rs").symlink_to(self.base / "missing.rs")
        (self.root / "Cargo.toml").symlink_to(self.root / "src/Cargo.toml")
        (self.root / "linked.abi.json").symlink_to(self.root / "build/contract.abi.json")
        (self.root / "linked.md").symlink_to(self.root / "src/README.md")
        self.assertEqual(inventory.discover(self.root, []), [original])
        for name in ["alias.rs", "alias-dir/lib.rs", "escape/external.rs", "dangling.rs",
                     "alias-dir/../src/lib.rs"]:
            with self.subTest(name=name), self.assertRaises(ValueError):
                inventory.discover(self.root, [Path(name)])
        self.assertEqual(set(self.snapshot()), {"src/lib.rs", "src/README.md", "src/Cargo.toml", "build/contract.abi.json"})
        with mock.patch.object(semantic.subprocess, "run") as run:
            manifests, _ = semantic.cargo_manifests(self.root)
        self.assertEqual([row["path"] for row in manifests], ["src/Cargo.toml"])
        run.assert_not_called()
        for root in [self.root / "alias-dir", self.root / "alias-dir/child"]:
            with self.subTest(root=root), self.assertRaises(ValueError):
                inventory.discover(root, [])





    def test_snapshot_content_drift_additions_deletions_and_ignored_changes(self) -> None:
        source = self.put("src/lib.rs", "first")
        self.put("README.md", "intent")
        initial = self.snapshot()
        before = source.stat()
        source.write_text("other", encoding="utf-8")  # Same length and timestamp; content matters.
        os.utime(source, ns=(before.st_atime_ns, before.st_mtime_ns))
        changed = self.snapshot()
        self.assertNotEqual(initial["src/lib.rs"], changed["src/lib.rs"])
        self.assertEqual(initial["README.md"], changed["README.md"])
        for name in ["src/new.ts", "docs/new.md", "nested/package.json", "nested/yarn.lock", "target/new.wasm"]:
            with self.subTest(name=name):
                previous = self.snapshot()
                added = self.put(name, b"\x00asm\x01\x00\x00\x00" if name.endswith(".wasm") else "new")
                current = self.snapshot()
                self.assertEqual(set(current) - set(previous), {name})
                added.unlink()
                self.assertEqual(self.snapshot(), previous)
        self.put("vendor/ignored.rs")
        self.put(".env.json", "hidden")
        self.assertEqual(self.snapshot(), changed)





    def test_cargo_is_frozen_offline_bounded_and_reports_timeout(self) -> None:
        self.put("Cargo.toml", '[package]\nname="fixture"\nversion="0.1.0"\n')
        blocked = subprocess.CompletedProcess([], 1, "", "lock file needs updating")
        with mock.patch.object(semantic.shutil, "which", return_value="cargo"), \
                mock.patch.object(semantic.subprocess, "run", return_value=blocked) as run:
            _, metadata = semantic.cargo_manifests(self.root)
        self.assertEqual(metadata["status"], "blocked")
        command = run.call_args.args[0]
        self.assertTrue({"--frozen", "--offline", "--no-deps"}.issubset(command))
        self.assertEqual(run.call_args.kwargs["cwd"], self.root)
        self.assertGreater(run.call_args.kwargs["timeout"], 0)
        self.assertLessEqual(run.call_args.kwargs["timeout"], 20)
        with mock.patch.object(semantic.shutil, "which", return_value="cargo"), \
                mock.patch.object(semantic.subprocess, "run", side_effect=subprocess.TimeoutExpired(command, 20)) as run:
            _, metadata = semantic.cargo_manifests(self.root)
        self.assertEqual(metadata["status"], "blocked")
        self.assertEqual(run.call_count, 1)






if __name__ == "__main__":
    unittest.main()
