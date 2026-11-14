"""Shared inert fixtures and CLI helpers; path imports do not execute an audit."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


SKILL = Path(__file__).resolve().parent.parent
SCRIPTS = SKILL / "scripts"
sys.path.insert(0, str(SCRIPTS))
from reference_paths import reference_path, reference_relative
FIXTURE = Path(__file__).resolve().parent / "fixtures" / "nep-surface"
NEP_PIN = json.loads((SKILL / reference_relative('nep_registry')).read_text(encoding="utf-8"))[
    "source"
]["commit"]
OFFICIAL_REGISTRY = SKILL / reference_relative('docs_registry')
OFFICIAL_PIN = json.loads(OFFICIAL_REGISTRY.read_text(encoding="utf-8"))["source"]["commit"]
REGISTRY = SKILL / reference_relative('nep_registry')


def run(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, check=check, text=True, capture_output=True)


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


def make_run_artifacts(root: Path) -> None:
    surface_result = run("python3", str(SCRIPTS / "map_surface.py"), str(FIXTURE))
    (root / "surface.json").write_text(surface_result.stdout, encoding="utf-8")
    surface = json.loads(surface_result.stdout)
    write_json(
        root / "run-manifest.json",
        {
            "schema_version": 2,
            "target": str(FIXTURE),
            "target_revision": "fixture",
            "dirty_tree": False,
            "scope": ["lib.rs"],
            "exclusions": [],

            "toolchain": {"rust": "fixture"},
            "sdk_versions": {"near-sdk": "fixture"},
            "nep_source_commit": NEP_PIN,
            "official_docs_source_commit": OFFICIAL_PIN,
            "official_docs_registry_hash": hashlib.sha256(OFFICIAL_REGISTRY.read_bytes()).hexdigest(),
            "corpus_hash": "sha256:" + "a" * 64,
            "models": {"orchestrator": "fixture"},
            "prompt_hashes": {"L0": "sha256:" + "b" * 64},
            "tool_versions": {"python": "3"},
            "worker_capacity": 8,
            "started_at": "2026-08-27T00:00:00Z",
        },
    )
    write_json(
        root / "intent-model.json",
        {
            "schema_version": 1,
            "actors": [],
            "assets": [],
            "entrypoints": [],
            "receipt_state_machines": [],
            "standards": [],
            "trust_boundaries": [],
            "invariants": [{"invariant_id": "INV-SETTLE-ONCE-1", "statement": "settle once"}],
            "unresolved_intent": [],
            "upgrade_dependencies": [],
            "account_key_capabilities": [],
            "yield_resume_flows": [],
            "global_contract_dependencies": [],
            "cross_chain_routes": [],
            "version_claims": [],
        },
    )
    write_jsonl(
        root / "level-coverage.jsonl",
        [
            {
                "schema_version": 1,
                "level": level,
                "status": "complete",
                "roles": [role],
                "inputs": ["fixture"],
                "artifacts": ["fixture"],
                "model_and_prompt_hashes": ["sha256:" + "c" * 64],
                "started_at": "2026-08-27T00:00:00Z",
                "completed_at": "2026-08-27T00:01:00Z",
                "cost": {"tokens": 1},
                "blockers": [],
            }
            for level, role in (
                ("L0", "protocol-modeler"),
                ("L1", "pattern-matcher"),
                ("L2", "intent-reasoner"),
                ("L3", "specialists"),
            )
        ],
    )
    write_jsonl(
        root / "invariant-ledger.jsonl",
        [
            {
                "schema_version": 1,
                "invariant_id": "INV-SETTLE-ONCE-1",
                "statement": "settle once",
                "scope": ["fixture"],
                "assets": ["token"],
                "writers": ["withdraw"],
                "readers": ["resolve"],
                "receipt_boundaries": ["R1", "R2"],
                "test_class": "structural",
                "execution_status": "structural",
                "candidate_ids": [],
            }
        ],
    )
    inventory = json.loads((SKILL / reference_relative('mutation_operators')).read_text())["families"]
    citation = {"path": "lib.rs", "start": 1, "end": 1, "quote": (FIXTURE / "lib.rs").read_text().splitlines()[0]}
    write_jsonl(root / "mutation-results.jsonl", [
        {"schema_version": 2, "operator_family": family, "applicability": "not_applicable",
         "mutations_total": 0, "killed": 0, "survived": 0, "blocked": 0, "candidate_ids": [],
         "rationale": "Inert validation fixture; no mutations executed.", "operators": [
             {"operator_id": op["operator_id"], "applicability": "not_applicable",
              "rationale": "Synthetic coverage disposition, not a target audit.",
              "target_evidence": [citation], "locations": [], "outcomes": []} for op in operators]}
        for family, operators in inventory.items()])
    write_jsonl(
        root / "async-schedules.jsonl",
        [
            {
                "schema_version": 1,
                "operation_id": "withdraw-1",
                "state_machine_id": "withdraw",
                "initiating_export": "withdraw",
                "receipts": ["R1", "R2"],
                "reserved_state": ["balance"],
                "terminal_states": ["succeeded", "compensated"],
                "coverage": {"success": True, "failure": True, "pending_interleaving": True},
                "candidate_ids": [],
            }
        ],
    )
    write_jsonl(
        root / "nep-differential.jsonl",
        [
            {
                "schema_version": 1,
                "status": "complete",
                "evidence": ["fixture oracle"],
                "candidate_ids": [],
            }
        ],
    )
    write_jsonl(
        root / "official-guidance-coverage.jsonl",
        [
            {
                "schema_version": 1,
                "card_id": card_id,
                "applicability": "applicable",
                "version_evidence": ["fixture version"],
                "target_evidence": ["fixture signal"],
                "checks_performed": ["safe structural check"],
                "test_status": "structural",
                "candidate_ids": [],
                "advisory_observations": [],
                "disposition": "conformant",
                "rationale": "Fixture supplies a complete safe disposition.",
            }
            for card_id in surface["selected_attacker_cards"]
        ],
    )
    (root / "unresolved-assumptions.jsonl").write_text("", encoding="utf-8")
    write_json(
        root / "rescan-summary.json",
        {
            "schema_version": 2,
            "iteration": 1,
            "status": "complete",
            "input_count": 0,
            "new_candidate_ids": [],
        },
    )


def write_compact_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")


def candidate(identifier: str = "blind-1", *, informed: bool = False) -> dict:
    return {
        "schema_version": 2,
        "candidate_id": identifier,
        "role_id": "metadata-fixture",
        "origin_role": "metadata-fixture",
        "origin_level": "L3",
        "discovery_technique": "verified_seed_variant" if informed else "specialist_trace",
        "root_cause_fingerprint": "sha256:" + "a" * 64,
        "model_and_prompt_hash": "sha256:" + "b" * 64,
        "judge_stage": "unjudged",
        "verification_status": "unverified",
        "human_disposition": "pending",
        "kind": "lead",
        "bug_class": "synthetic-metadata",
        "root_cause": "Synthetic metadata condition",
        "intent_invariant_ids": [],
        "evidence": ["synthetic evidence"],
        "locations": [{"path": "fixture.txt", "function": identifier}],
        **({"seed_source_candidate_id": "blind-1", "variant_evidence": ["synthetic distinct metadata"]} if informed else {}),
    }


def verdict() -> dict:
    return {
        "candidate_id": "blind-1", "triage": {"status": "passed", "packet_hash": "fixture", "evidence": []},
        "judge_stage": "adversarial_verification", "verification_status": "verified",
        "human_disposition": "pending", "verdict": "valid", "proof_status": "CODE_CONFIRMED",
        "severity": "low", "impact": "Minor", "likelihood": "Rare", "external_assumptions": [],
        "rationale": "synthetic", "evidence": ["synthetic"], "poc_status": "not_required",
        "confidence": {"source_anchoring": 1, "reachability": 1, "material_harm": 1,
                       "execution": 0, "counter_evidence": 1, "total": 4},
    }


def coverage_rows() -> list[dict[str, object]]:
    registry = json.loads(REGISTRY.read_text(encoding="utf-8"))
    rows: list[dict[str, object]] = []
    for nep_id, spec in registry["neps"].items():
        role_id = registry["categories"][spec["category"]]["role_id"]
        if nep_id == "0001":
            applicability, disposition = "process_only", "process_only"
        elif nep_id == "0021":
            applicability, disposition = "superseded", "superseded"
        elif spec["status"] in {"Draft", "New"}:
            applicability, disposition = "advisory", "advisory"
        else:
            applicability, disposition = "not_applicable", "not_applicable"
        rows.append(
            {
                "nep_id": nep_id,
                "role_id": role_id,
                "source_commit": registry["source"]["commit"],
                "source_status": spec["status"],
                "applicability": applicability,
                "version_evidence": [],
                "target_evidence": ["Fixture scope has no matching implemented or claimed surface."],
                "requirements_checked": ["status-aware advisory hypothesis"]
                if disposition == "advisory"
                else [],
                "deviations": [],
                "candidate_ids": [],
                "disposition": disposition,
                "rationale": "Status and target applicability were reviewed explicitly.",
            }
        )
    return rows


class LifecycleFixture(unittest.TestCase):
    """Reusable setup and assertions, intentionally containing no test methods."""
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.target = self.root / "target source"
        shutil.copytree(FIXTURE, self.target)
        self.run_dir = self.root / "review evidence"
        self.skill = SKILL

    def cli(self, *args, ok=True):
        result = subprocess.run(
            [sys.executable, str(self.skill / "scripts/near_audit.py"), *map(str, args)],
            cwd=self.root, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
            text=True, capture_output=True, timeout=45,
        )
        if ok:
            self.assertEqual(result.returncode, 0, result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0, result.stdout)
        return result

    def initialize(self, passes=1):
        self.cli("run", self.target, "--loop", str(passes), "--run-dir", self.run_dir)

    def complete_automated_fixture(self, passes=1):
        self.initialize(passes)
        # Reuse the original schema fixtures, retaining the new run's attestation.
        preserved = {name: (self.run_dir / name).read_bytes() for name in ("run-manifest.json", "surface.json")}
        make_run_artifacts(self.run_dir)
        for name, data in preserved.items():
            (self.run_dir / name).write_bytes(data)
        packets = [json.loads(line) for line in (self.run_dir / "work-packets.jsonl").read_text().splitlines()]
        for packet in packets:
            if packet["phase"] == "informed-rescan":
                continue
            for name in packet["candidate_outputs"]:
                write_jsonl(self.run_dir / name, [])
        for name in ("raw-candidates.jsonl", "deduplicated.jsonl", "dispositions.jsonl", "verdicts.jsonl", "triage.jsonl"):
            write_jsonl(self.run_dir / name, [])
        citation = {"path": "lib.rs", "start": 1, "end": 1, "quote": (self.target / "lib.rs").read_text().splitlines()[0]}
        for packet in packets:
            for name in packet.get("additional_outputs", []):
                if name.endswith("-applicability.json"):
                    write_json(self.run_dir / name, {
                        "schema_version": 1, "role_id": packet["role_id"],
                        "discovery_pass": packet.get("discovery_pass", 1), "applicability": "not_applicable",
                        "rationale": "Inert fixture disposition, not a semantic audit.", "target_evidence": [citation]})
        rows = coverage_rows()
        write_jsonl(self.run_dir / "nep-coverage.jsonl", rows)
        surface = json.loads((self.run_dir / "surface.json").read_text())
        for role in surface["nep_roles"]:
            write_jsonl(self.run_dir / f"nep/{role}.jsonl", [row for row in rows if row["role_id"] == role])
        guidance = [json.loads(line) for line in (self.run_dir / "official-guidance-coverage.jsonl").read_text().splitlines()]
        owners = {row["card_id"]: row["owner_role"] for row in surface["official_guidance_review_queue"]}
        for role in set(owners.values()):
            write_jsonl(self.run_dir / f"guidance/{role}.jsonl", [row for row in guidance if owners[row["card_id"]] == role])

    def rendered_report(self, stage="draft"):
        banner = (SKILL / reference_relative('technical_annex_template')).read_text().split("```text\n", 1)[1].split("\n```", 1)[0]
        sections = ("Architecture and trust assumptions", "Findings index", "Findings",
                    "Unverified leads", "Standards and hardening notes",
                    "Testing and limitations", "Remediation priorities")
        verdicts = [json.loads(line) for line in (self.run_dir / "verdicts.jsonl").read_text().splitlines() if line.strip()]
        detail = "\n".join("### " + row["candidate_id"] + "\n\nConfidence " + str(row["confidence"]["total"]) +
                           "/13\n\n#### Recommendation\n\nApply the synthetic fixture fix."
                           for row in verdicts if row["verdict"] in {"valid", "valid_downgraded"})
        body = self.run_dir / f"{stage}-body.md"
        body.write_text("```text\n" + banner + "\n```\n\n# 🔐 NEAR YoctoArmor v1 Security Review — sample\n\nSynthetic inert fixture.\n\n" +
                        "\n\n".join("## " + section + "\n\nSynthetic inert fixture." + ("\n\n" + detail if section == "Findings" and detail else "") for section in sections) + "\n")
        output = self.run_dir / f"{stage}.md"
        rendered = self.cli("render-report", self.run_dir, "--body", body, "--output", output, "--stage", stage)
        self.assertEqual(rendered.stdout, output.read_text())
        return output
