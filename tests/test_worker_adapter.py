"""Inert worker-contract and journal regressions; no target audit is performed."""

from __future__ import annotations

from support import reference_relative

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from near_audit import run_checked


SKILL = Path(__file__).resolve().parents[1]
FIXTURE = SKILL / "tests/fixtures/nep-surface"


class WorkerAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.target = self.root / "target"
        self.run_dir = self.root / "run"
        shutil.copytree(FIXTURE, self.target)
        self.cli("run", self.target, "--loop", "1", "--run-dir", self.run_dir)
        self.packet = "l0-model:protocol-modeler"

    def cli(self, *args: object, ok: bool = True) -> dict:
        result = subprocess.run([sys.executable, str(SKILL / "scripts/near_audit.py"), *map(str, args)],
                                text=True, capture_output=True, timeout=30,
                                env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
        if ok:
            self.assertEqual(result.returncode, 0, result.stderr)
            return json.loads(result.stdout)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        return json.loads(result.stderr.splitlines()[-1])



    def test_neutral_worker_packet_excludes_attacker_guidance(self) -> None:
        packets = [json.loads(line) for line in (self.run_dir / "work-packets.jsonl").read_text().splitlines()]
        for role in ("protocol-modeler", "intent-reasoner"):
            packet_id = next(row["packet_id"] for row in packets if row["role_id"] == role)
            view = self.cli("packet", self.run_dir, packet_id)
            self.assertEqual(view["surface"], "neutral-surface.json")
            self.assertEqual(view["references"], [reference_relative('neutral_schemas')])
            self.assertEqual(view["owned_official_cards"], [])
            self.assertNotIn(reference_relative('docs_cards'), view["prompt"])

    def test_missing_and_oversized_outputs_remain_visible(self) -> None:
        self.cli("worker", self.run_dir, "start", self.packet, "--worker-id", "host-worker-1")
        missing = self.cli("worker", self.run_dir, "finish", self.packet)
        self.assertEqual(missing["worker"]["status"], "failed")
        self.assertEqual(missing["worker"]["diagnostics"][0]["code"], "missing_output")
        self.cli("worker", self.run_dir, "start", self.packet, "--worker-id", "host-worker-2")
        artifact = self.run_dir / "intent-model.json"
        with artifact.open("wb") as stream:
            stream.truncate(16 * 1024 * 1024 + 1)
        oversized = self.cli("worker", self.run_dir, "finish", self.packet)
        self.assertEqual(oversized["worker"]["diagnostics"][0]["code"], "oversized_output")
        self.assertEqual(artifact.stat().st_size, 16 * 1024 * 1024 + 1)
        self.assertIn("oversized", self.cli("status", self.run_dir)["missing_artifacts"][0])
        self.assertIn("retry limit", self.cli("worker", self.run_dir, "start", self.packet,
                                               "--worker-id", "host-worker-3", ok=False)["error"])


    def test_controller_helper_output_is_bounded(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "8 MiB"):
            run_checked([sys.executable, "-c", "import sys; sys.stdout.write('x' * (9 * 1024 * 1024))"])


if __name__ == "__main__":
    unittest.main()
