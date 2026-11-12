#!/usr/bin/env python3
"""Local, resumable phase controller for the NEAR multi-agent auditor.

This controller prepares and validates work; the Codex orchestrator remains
responsible for dispatching isolated agents described by the generated packets.
It never sends source or findings to a hosted service.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
import os
import shutil
import subprocess
import sys
import tempfile
import re
import selectors
import signal
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from run_integrity import (
    RUN_SCHEMA, STATE_SCHEMA, artifact_path, atomic_write_json, atomic_write_jsonl,
    configuration_snapshot, file_hash, read_jsonl, reconcile_candidates,
    require_current_run, run_lock, validate_bindings, validate_state,
)
from run_journal import append as append_run_event, load as load_run_state
from worker_adapter import MAX_ARTIFACT_BYTES, inspect_outputs, packet_for, view as worker_view


SKILL = Path(__file__).resolve().parent.parent
SCRIPTS = SKILL / "scripts"
REFERENCES = SKILL / "references"
RUNTIME_BANNER = """███████╗██╗      ██████╗ ████████╗    ███████╗███████╗██████╗  ██████╗
██╔════╝██║     ██╔═══██╗╚══██╔══╝    ╚══███╔╝██╔════╝██╔══██╗██╔═══██╗
███████╗██║     ██║   ██║   ██║          ███╔╝ █████╗  ██████╔╝██║   ██║
╚════██║██║     ██║   ██║   ██║         ███╔╝  ██╔══╝  ██╔══██╗██║   ██║
███████║███████╗╚██████╔╝   ██║        ███████╗███████╗██║  ██║╚██████╔╝
╚══════╝╚══════╝ ╚═════╝    ╚═╝        ╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝

███████╗███████╗ ██████╗██╗   ██╗██████╗ ██╗████████╗██╗   ██╗
██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██║╚══██╔══╝╚██╗ ██╔╝
███████╗█████╗  ██║     ██║   ██║██████╔╝██║   ██║    ╚████╔╝
╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██║   ██║     ╚██╔╝
███████║███████╗╚██████╗╚██████╔╝██║  ██║██║   ██║      ██║
╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝   ╚═╝      ╚═╝

               NEAR MULTI-AGENT SECURITY SCANNER
"""
PHASES = (
    "l0-model",
    "isolated-l1-l2",
    "blind-l3-active",
    "nep-coverage",
    "dedup-chains",
    "two-stage-judge",
    "counterexample-rescan",
    "human-feedback",
    "informed-rescan",
    "final",
)
CORPUS_FILES = (
    REFERENCES / "attack-lenses-index.json",
    *sorted((REFERENCES / "attack-lenses").glob("*.md")),
    REFERENCES / "historical-id-map.json",
    REFERENCES / "corpus-index.json",
    REFERENCES / "pdf-corpus-2022-2023.md",
    REFERENCES / "pdf-corpus-2024-2026.md",
    REFERENCES / "pdf-corpus-manifest.json",
    REFERENCES / "satoshi-issue-corpus.md",
    REFERENCES / "satoshi-issue-corpus.json",
    REFERENCES / "source-review.json",
    REFERENCES / "legacy-design-review.json",
    REFERENCES / "pattern-portability.md",
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def canonical_hash(value: object) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return sha256_bytes(raw)


def read_json(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected object")
    return value


def run_checked(command: list[str], *, cwd: Path | None = None) -> str:
    # Spool locally so a helper cannot fill controller memory before a limit is checked.
    limit = 8 * 1024 * 1024
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        process = subprocess.Popen(command, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   start_new_session=True,
                                   env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
        try:
            deadline = time.monotonic() + 120
            sizes = {"stdout": 0, "stderr": 0}
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ, (stdout, "stdout"))
                selector.register(process.stderr, selectors.EVENT_READ, (stderr, "stderr"))
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError("helper timed out")
                    for key, _ in selector.select(remaining):
                        destination, name = key.data
                        chunk = os.read(key.fileobj.fileno(), 65536)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            key.fileobj.close()
                            continue
                        sizes[name] += len(chunk)
                        if sizes[name] > limit:
                            raise ValueError("helper output exceeded the 8 MiB controller limit")
                        destination.write(chunk)
            process.wait(timeout=max(0.01, deadline - time.monotonic()))
        except (TimeoutError, subprocess.TimeoutExpired, ValueError) as exc:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            raise RuntimeError(f"helper terminated: {exc}") from exc
        finally:
            for stream in (process.stdout, process.stderr):
                if stream is not None and not stream.closed:
                    stream.close()
        stdout.seek(0)
        stderr.seek(0)
        output = stdout.read().decode("utf-8", errors="replace")
        error = stderr.read().decode("utf-8", errors="replace")
    if process.returncode != 0:
        raise RuntimeError(f"command failed ({' '.join(command)}): {error.strip()[:2000]}")
    return output


def git_state(target: Path) -> tuple[str, bool]:
    git = shutil.which("git")
    if not git:
        return "not-a-git-repository", False
    probe = subprocess.run(
        [git, "-C", str(target), "rev-parse", "--show-toplevel"],
        text=True,
        capture_output=True,
        check=False,
    )
    if probe.returncode != 0:
        return "not-a-git-repository", False
    head = subprocess.run([git, "-C", str(target), "rev-parse", "--verify", "HEAD"],
                          text=True, capture_output=True, check=False, timeout=5)
    revision = head.stdout.strip() if head.returncode == 0 else "unborn-HEAD"
    dirty = bool(run_checked([git, "-C", str(target), "status", "--porcelain"]).strip())
    return revision, dirty


def hash_files(paths: list[Path]) -> str:
    rows = []
    for path in sorted(paths):
        if path.is_file():
            rows.append({"path": path.name, "sha256": sha256_bytes(path.read_bytes())})
    return canonical_hash(rows)


def tool_versions() -> dict[str, object]:
    result: dict[str, object] = {"python": sys.version.split()[0]}
    for name, command in (("git", ["git", "--version"]), ("cargo", ["cargo", "--version"])):
        executable = shutil.which(command[0])
        if not executable:
            result[name] = "not_available"
            continue
        try:
            probe = subprocess.run([executable, *command[1:]], text=True, capture_output=True, check=False, timeout=5)
            result[name] = probe.stdout.strip() if probe.returncode == 0 else "blocked"
        except subprocess.TimeoutExpired:
            result[name] = "blocked: version probe timed out"
    return result


def prompt_hashes() -> dict[str, str]:
    paths = [SKILL / "SKILL.md", *sorted(REFERENCES.rglob("*.md"))]
    return {path.relative_to(SKILL).as_posix(): sha256_bytes(path.read_bytes()) for path in paths}


def write_json(path: Path, value: object) -> None:
    atomic_write_json(path, value)


ACTIVE_ROLES = {"invariant-synthesis", "mutation-analysis", "async-state-explorer", "nep-differential", "temporal-upgrade"}


def make_work_packets(run_dir: Path, surface: dict[str, object], passes: int = 1) -> list[dict[str, object]]:
    packets: list[dict[str, object]] = []
    routed_lenses = list(surface.get("selected_pattern_references", []))

    def append(
        phase: str,
        role: str,
        allowed: list[str],
        forbidden: list[str],
        output: str,
        dependencies: list[str],
        candidate_outputs: list[str] | None = None,
        additional_outputs: list[str] | None = None,
        discovery_pass: int | None = None,
    ) -> None:
        packet: dict[str, object] = {
            "schema_version": 1,
            "packet_id": f"{phase}:{role}" + (f":pass-{discovery_pass:02d}" if discovery_pass is not None else ""),
            "phase": phase,
            "role_id": role,
            "allowed_inputs": allowed,
            "forbidden_inputs": forbidden,
            "output_path": output,
            "dependencies": dependencies,
            "retry_limit": 1,
            "candidate_outputs": candidate_outputs or [],
            "additional_outputs": additional_outputs or [],
            "isolation": "instruction_only_unless_runtime_enforced",
        }
        if discovery_pass is not None:
            packet["discovery_pass"] = discovery_pass
        packet["packet_hash"] = canonical_hash(packet)
        packets.append(packet)

    append(
        "l0-model",
        "protocol-modeler",
        ["neutral-surface.json", "semantic-ir.json", "target source", "manifests", "tests", "target docs", "neutral schemas"],
        ["security model", "attack lenses", "official cards and registry", "historical findings", "satoshi-issue-corpus.md", "satoshi-issue-corpus.json", "pattern-portability.md", "training answers", "benchmark answers"],
        "intent-model.json",
        [],
    )
    append(
        "isolated-l1-l2",
        "pattern-matcher",
        ["target source", "surface.json", "semantic-ir.json", "intent-model.json", "attack-lenses-index.json", *routed_lenses, "target-binding protocol", "optional selected historical examples after target binding"],
        ["l2/candidates.jsonl", "peer candidates", "training answers", "benchmark answers"],
        "l1/candidates.jsonl",
        ["l0-model:protocol-modeler"],
        candidate_outputs=["l1/candidates.jsonl"],
    )
    l2_ids = []
    for number in range(1, passes + 1):
        output = "l2/candidates.jsonl" if passes == 1 else f"l2/pass-{number:02d}/candidates.jsonl"
        append(
            "isolated-l1-l2", "intent-reasoner",
            ["target source", "target docs/tests", "manifests", "semantic-ir.json", "intent-model.json", "neutral schemas"],
            ["security model", "corpus", "attack lenses", "satoshi-issue-corpus.md", "satoshi-issue-corpus.json", "pattern-portability.md", "training answers", "official attacker cards and registry", "l1/candidates.jsonl", "peer candidates", "prior-pass candidates", "benchmark answers"],
            output, ["l0-model:protocol-modeler"], candidate_outputs=[output],
            discovery_pass=number if passes > 1 else None,
        )
        l2_ids.append(f"isolated-l1-l2:intent-reasoner" + (f":pass-{number:02d}" if passes > 1 else ""))
    for role in surface.get("selected_roles", []):
      for number in range(1, passes + 1 if role not in ACTIVE_ROLES else 2):
        output = f"discovery/{role}.jsonl" if passes == 1 or role in ACTIVE_ROLES else f"discovery/pass-{number:02d}/{role}.jsonl"
        append(
            "blind-l3-active",
            str(role),
            ["assigned target cluster", "surface.json", "semantic-ir role packet", "intent-model.json", "role rules"],
            ["peer candidates", "prior-pass candidates", "deduplicated findings", "historical corpus", "attack lenses", "satoshi-issue-corpus.md", "satoshi-issue-corpus.json", "pattern-portability.md", "training answers", "benchmark answers"],
            output,
            ["isolated-l1-l2:pattern-matcher", *l2_ids],
            candidate_outputs=[output],
            additional_outputs=({
                "invariant-synthesis": ["invariant-ledger.jsonl"],
                "mutation-analysis": ["mutation-results.jsonl"],
                "async-state-explorer": ["async-schedules.jsonl"],
                "nep-differential": ["nep-differential.jsonl"],
                "temporal-upgrade": ["temporal-upgrade.jsonl"],
            }.get(str(role), []) + ([f"guidance/{role}.jsonl"] if number == 1 and any(
                item.get("owner_role") == role for item in surface.get("official_guidance_review_queue", [])
            ) else [])),
            discovery_pass=number if passes > 1 and role not in ACTIVE_ROLES else None,
        )
    for role in surface.get("nep_roles", []):
        append(
            "nep-coverage",
            str(role),
            ["surface.json", "semantic-ir.json", "NEP registry", "owned checklist", "target evidence"],
            ["other NEP checklists", "peer candidates", "historical corpus", "attack lenses", "satoshi-issue-corpus.md", "satoshi-issue-corpus.json", "pattern-portability.md", "training answers", "benchmark answers"],
            f"nep/{role}.jsonl",
            ["blind-l3-active"],
            candidate_outputs=[f"nep/{role}-candidates.jsonl"],
            additional_outputs=[f"nep/{role}-candidates.jsonl"],
        )
    # Account for the already-required post-blind corpus review; no model dispatch.
    append(
        "dedup-chains", "corpus-echo",
        ["frozen blind artifacts", "attack-lenses-index.json", *routed_lenses, "target-binding protocol", "optional selected historical examples after target binding", "target evidence"],
        ["training answers", "benchmark answers"], "corpus-echo-candidates.jsonl", ["nep-coverage"],
        candidate_outputs=["corpus-echo-candidates.jsonl"],
    )
    append(
        "dedup-chains",
        "chain-constructor",
        ["all frozen blind candidate artifacts", "intent-model.json", "semantic-ir.json", "finding schema"],
        ["benchmark answers", "verdicts.jsonl", "final report"],
        "deduplicated.jsonl",
        ["nep-coverage"],
        candidate_outputs=["chain-candidates.jsonl"],
        additional_outputs=["chain-candidates.jsonl"],
    )
    append(
        "two-stage-judge",
        "evidence-triage",
        ["one deduplicated candidate", "cited target context", "security model", "verification rules"],
        ["peer verdicts", "benchmark answers", "final report"],
        "triage.jsonl",
        ["dedup-chains:chain-constructor"],
    )
    append(
        "two-stage-judge",
        "adversarial-verifier",
        ["one triage survivor", "cited target context", "security model", "verification rules"],
        ["peer verdicts", "corpus history", "benchmark answers", "final report"],
        "verdicts.jsonl",
        ["two-stage-judge:evidence-triage"],
    )
    append(
        "counterexample-rescan",
        "counterexample-rescan",
        ["unresolved-assumptions.jsonl", "target source", "finding schema", "security model"],
        ["rejected conclusions", "verdict rationales", "peer findings", "benchmark answers"],
        "counterexample-rescan-candidates.jsonl",
        ["two-stage-judge:adversarial-verifier"],
        candidate_outputs=["counterexample-rescan-candidates.jsonl"],
    )
    append(
        "informed-rescan",
        "verified-seed-variant",
        ["verified-seeds.jsonl", "semantic-ir.json", "seed-neighborhood target source", "finding schema", "security model"],
        ["report prose", "severity", "recommendations", "rejected candidates", "benchmark answers"],
        "informed-rescan-candidates.jsonl",
        ["counterexample-rescan:counterexample-rescan"],
        candidate_outputs=["informed-rescan-candidates.jsonl"],
    )
    work_path = run_dir / "work-packets.jsonl"
    atomic_write_jsonl(work_path, packets)
    return packets


def default_feedback_files(run_dir: Path) -> None:
    atomic_write_jsonl(run_dir / "finding-feedback.jsonl", [])
    write_json(
        run_dir / "feedback-summary.json",
        {
            "schema_version": 1,
            "feedback_policy": "metrics_only",
            "automatic_learning": False,
            "status": "not_run",
            "total_rows": 0,
            "label_counts": {},
            "precision": None,
            "by_role": {},
            "by_pattern": {},
            "by_pass": {},
            "reason_codes": {},
            "corpus_changed": False,
            "prompts_changed": False,
            "routing_changed": False,
            "mutations_changed": False,
        },
    )
    write_json(
        run_dir / "informed-rescan-summary.json",
        {
            "schema_version": 1,
            "iteration": 1,
            "status": "not_run",
            "seed_count": 0,
            "new_candidate_ids": [],
            "rediscovery_candidate_ids": [],
        },
    )


def initialize(args: argparse.Namespace) -> dict[str, object]:
    from source_inventory import snapshot_inputs, validate_root
    from map_surface import discover

    passes = choose_discovery_passes(args.loop)
    target = validate_root(args.target)
    if not target.is_dir():
        raise ValueError(f"target is not a directory: {target}")
    if args.mode == "explicit-files" and not args.files:
        raise ValueError("explicit-files mode requires at least one --files entry")
    discover(target, args.files)  # Validate every explicit input before creating output.
    if isinstance(args.worker_capacity, bool) or args.worker_capacity < 1:
        raise ValueError("worker capacity is the positive number of spawned workers, excluding the primary")
    if args.runtime_capacity is not None and (args.runtime_capacity < 1 or args.worker_capacity > args.runtime_capacity):
        raise ValueError("requested workers exceed the observed spawned-worker runtime capacity")
    if args.run_dir and args.run_dir.resolve().is_relative_to(target):
        raise ValueError("run directory must be outside audited source")
    inputs_before = snapshot_inputs(target, args.files)
    configuration = configuration_snapshot(SKILL)
    run_dir = args.run_dir.resolve() if args.run_dir else Path(
        tempfile.mkdtemp(prefix=f"near-audit-{target.name}-")
    )
    if run_dir.exists() and any(run_dir.iterdir()):
        raise ValueError(f"run directory is not empty: {run_dir}")
    run_dir.mkdir(parents=True, exist_ok=True)
    for directory in ("l1", "l2", "discovery", "nep", "packets", "guidance"):
        (run_dir / directory).mkdir()

    explicit = [str(item) for item in args.files]
    run_checked(
        [sys.executable, str(SCRIPTS / "map_surface.py"), str(target), *explicit, "--output", str(run_dir / "surface.json")]
    )
    run_checked(
        [
            sys.executable,
            str(SCRIPTS / "build_semantic_ir.py"),
            str(target),
            *explicit,
            "--output",
            str(run_dir / "semantic-ir.json"),
        ]
    )
    run_checked(
        [
            sys.executable,
            str(SCRIPTS / "select_official_cards.py"),
            str(run_dir / "surface.json"),
            "--output",
            str(run_dir / "selected-official-cards.md"),
        ]
    )
    surface = read_json(run_dir / "surface.json")
    semantic = read_json(run_dir / "semantic-ir.json")
    neutral_surface = {"schema_version": 1, "root": str(target), "files": [
        {name: row[name] for name in ("path", "language", "lines")}
        for row in surface["files"]
    ]}
    write_json(run_dir / "neutral-surface.json", neutral_surface)
    if snapshot_inputs(target, args.files) != inputs_before:
        raise ValueError("source/context changed during initialization; use a new run directory")
    if configuration_snapshot(SKILL) != configuration:
        raise ValueError("skill configuration changed during initialization; use a new run directory")
    revision, dirty = git_state(target)
    nep = read_json(REFERENCES / "nep-registry.json")
    docs = read_json(REFERENCES / "official-docs-registry.json")
    packets = make_work_packets(run_dir, surface, passes)
    if passes > 1:
        for number in range(1, passes + 1):
            (run_dir / "l2" / f"pass-{number:02d}").mkdir()
            (run_dir / "discovery" / f"pass-{number:02d}").mkdir()
    default_feedback_files(run_dir)
    versions = tool_versions()
    run_id = str(uuid.uuid4())
    manifest = {
        "schema_version": RUN_SCHEMA,
        "run_id": run_id,
        "target": str(target),
        "target_revision": revision,
        "dirty_tree": dirty,
        "scope": [row["path"] for row in surface.get("files", [])],
        "exclusions": ["target", "node_modules", "dist", "build", "vendor", "unrelated crates"],
        "mode": args.mode,
        "discovery_passes_planned": passes,
        "toolchain": versions,
        "sdk_versions": {"near-sdk": {"version": None, "status": "unknown", "evidence": "resolve from the frozen lockfile"}},
        "nep_source_commit": nep["source"]["commit"],
        "official_docs_source_commit": docs["source"]["commit"],
        "official_docs_registry_hash": hashlib.sha256(
            (REFERENCES / "official-docs-registry.json").read_bytes()
        ).hexdigest(),
        "corpus_hash": hash_files(list(CORPUS_FILES)),
        "models": {"orchestrator": args.orchestrator_model, "workers": args.worker_model},
        "prompt_hashes": prompt_hashes(),
        "tool_versions": versions,
        "worker_capacity": args.worker_capacity,
        "started_at": utc_now(),
        "run_directory_id": run_dir.name,
        "trust_assumptions": [],
        "semantic_ir_hash": canonical_hash(semantic),
        "semantic_extractor_hash": semantic["extractor_hash"],
        "content_fingerprint": semantic["content_fingerprint"],
        "driver_hash": sha256_bytes(Path(__file__).read_bytes()),
        "work_packets_hash": canonical_hash(packets),
        "feedback_policy": "metrics_only",
        "second_pass_mode": "targeted_verified_seed",
        "runtime_capacity": args.runtime_capacity,
        "runtime_capabilities": {"worker_isolation": "unknown", "worker_termination": "unknown",
                                 "usage_export": "unknown", "stream_output_limit": "unknown"},
        "capacity_semantics": "spawned_workers_excluding_primary",
        "explicit_files": [str(Path(item).resolve().relative_to(target)) if Path(item).is_absolute() else str(item) for item in args.files],
        "input_snapshot": inputs_before,
        "input_fingerprint": canonical_hash(inputs_before),
        "configuration_snapshot": configuration,
        "configuration_hash": canonical_hash(configuration),
        "surface_hash": canonical_hash(surface),
        "neutral_surface_hash": canonical_hash(neutral_surface),
    }
    write_json(run_dir / "run-manifest.json", manifest)
    state = {
        "schema_version": STATE_SCHEMA,
        "run_id": run_id,
        "manifest_hash": canonical_hash(manifest),
        "target": str(target),
        "run_dir": str(run_dir),
        "phase_order": list(PHASES),
        "current_phase": PHASES[0],
        "status": "active",
        "phase_status": {phase: "pending" for phase in PHASES},
        "discovery_pass_status": {name: {str(i): "pending" for i in range(1, passes + 1)} for name in ("l2", "l3")},
        "retry_counts": {},
        "history": [{"event": "initialized", "phase": PHASES[0], "at": utc_now()}],
    }
    state["phase_status"][PHASES[0]] = "ready"
    state["workers"] = {}
    append_run_event(run_dir, "initialized", state)
    return {
        "run_dir": str(run_dir),
        "run_id": run_id,
        "current_phase": PHASES[0],
        "work_packets": len(packets),
        "discovery_passes_planned": passes,
        "semantic_coverage": semantic["coverage"],
    }


def choose_discovery_passes(value: int | None) -> int:
    if value is None:
        if not sys.stdin.isatty():
            raise ValueError("discovery pass count unspecified; ask before audit work or pass --loop 1..10")
        answer = input("Discovery passes? [1 / 3 recommended / 5 / custom 1-10]: ").strip()
        value = 3 if not answer else int(answer)
    if type(value) is not int or not 1 <= value <= 10:
        raise ValueError("--loop requires an integer from 1 to 10")
    return value


def phase_requirements(run_dir: Path, phase: str) -> list[str]:
    surface = read_json(run_dir / "surface.json")
    mapping: dict[str, list[str]] = {
        "l0-model": ["intent-model.json"],
        "isolated-l1-l2": ["l1/candidates.jsonl"],
        "blind-l3-active": [
            "invariant-ledger.jsonl",
            "mutation-results.jsonl",
        ],
        "nep-coverage": ["nep-coverage.jsonl"],
        "dedup-chains": ["raw-candidates.jsonl", "deduplicated.jsonl", "dispositions.jsonl"],
        "two-stage-judge": ["verdicts.jsonl"],
        "counterexample-rescan": ["unresolved-assumptions.jsonl", "rescan-summary.json"],
        "human-feedback": ["finding-feedback.jsonl", "feedback-summary.json"],
        "informed-rescan": ["informed-rescan-summary.json"],
        "final": [],
    }
    required = set(mapping[phase])
    for packet in read_jsonl(run_dir / "work-packets.jsonl"):
        if packet["phase"] == phase and phase not in {"informed-rescan"}:
            required.add(packet["output_path"])
            required.update(packet.get("candidate_outputs", []))
            required.update(packet.get("additional_outputs", []))
    if phase == "blind-l3-active":
        required.add("official-guidance-coverage.jsonl")
    return sorted(required)


def validate_ready_phase(run_dir: Path, phase: str, manifest: dict | None = None) -> None:
    from check_run_artifacts import validate_phase
    validate_phase(run_dir, phase, manifest=manifest)


def observed_discovery_passes(run_dir: Path, manifest: dict) -> dict[str, dict[str, str]]:
    from check_run_artifacts import validate_candidate_artifacts, validate_discovery_pass_candidates
    packets = read_jsonl(run_dir / "work-packets.jsonl")
    result: dict[str, dict[str, str]] = {"l2": {}, "l3": {}}
    for number in range(1, manifest["discovery_passes_planned"] + 1):
        for key, phase, role in (("l2", "isolated-l1-l2", "intent-reasoner"), ("l3", "blind-l3-active", None)):
            selected = [packet for packet in packets if packet["phase"] == phase and
                        (role is None or packet["role_id"] == role) and
                        (packet.get("discovery_pass", 1) == number) and
                        (key != "l3" or packet["role_id"] not in ACTIVE_ROLES)]
            paths = [artifact_path(run_dir, packet["output_path"]) for packet in selected]
            status = "pending"
            if paths and all(path.is_file() for path in paths):
                try:
                    validate_candidate_artifacts(paths)
                    validate_discovery_pass_candidates(run_dir, paths, manifest)
                except (OSError, ValueError, TypeError, KeyError):
                    status = "invalid"
                else:
                    status = "complete"
            result[key][str(number)] = status
    return result


def inspect_state(run_dir: Path, *, advance: bool) -> dict[str, object]:
    if advance:
        require_current_run(run_dir)  # Refuse archived runs without creating a lock.
        with run_lock(run_dir):
            return _inspect_state(run_dir, advance=True)
    return _inspect_state(run_dir, advance=False)


def _inspect_state(run_dir: Path, *, advance: bool) -> dict[str, object]:
    manifest = read_json(run_dir / "run-manifest.json")
    if manifest.get("schema_version") != RUN_SCHEMA:
        state = read_json(run_dir / "run-state.json")
        return {"run_dir": str(run_dir), "status": state.get("status"), "current_phase": state.get("current_phase"),
                "legacy_read_only": True, "ready": False, "message": "start a new run to use the current skill"}
    state = load_run_state(run_dir, repair_snapshot=advance)
    validate_bindings(run_dir, SKILL)
    validate_state(run_dir, manifest, PHASES)
    from check_run_artifacts import validate_semantic_ir, validate_controller_artifacts
    validate_semantic_ir(run_dir, manifest)
    validate_controller_artifacts(run_dir, manifest)
    current = str(state["current_phase"])
    while current != "final":
        observed = observed_discovery_passes(run_dir, manifest)
        if advance:
            for key in ("l2", "l3"):
                for number, status in observed[key].items():
                    if status == "complete" and state["discovery_pass_status"][key][number] != "complete":
                        state["discovery_pass_status"][key][number] = "complete"
                        append_run_event(run_dir, "discovery_pass_completed", state,
                                         detail={"level": key, "pass": number})
        missing = []
        for name in phase_requirements(run_dir, current):
            path = artifact_path(run_dir, name)
            if not path.is_file():
                missing.append(name)
            elif path.stat().st_size > MAX_ARTIFACT_BYTES:
                missing.append(f"{name}:oversized ({path.stat().st_size} bytes; retained at {path})")
        if current in {"isolated-l1-l2", "blind-l3-active"}:
            key = "l2" if current == "isolated-l1-l2" else "l3"
            missing.extend(f"discovery-pass-{key}-{number}:invalid" for number, status in observed[key].items() if status == "invalid")
        missing.extend(f"worker:{packet_id}:{record['status']}" for packet_id, record in state.get("workers", {}).items()
                       if packet_for(run_dir, packet_id)["phase"] == current
                       and record["status"] != "submitted")
        if not missing and current == "human-feedback":
            feedback_summary = read_json(run_dir / "feedback-summary.json")
            if feedback_summary.get("status") not in {"complete", "skipped"}:
                missing.append("feedback-summary.json:complete-or-skipped")
        if not missing and current == "informed-rescan":
            informed_summary = read_json(run_dir / "informed-rescan-summary.json")
            if informed_summary.get("status") not in {"complete", "skipped", "blocked"}:
                missing.append("informed-rescan-summary.json:complete-skipped-or-blocked")
        if not missing:
            validate_ready_phase(run_dir, current, manifest)
        if missing or not advance:
            return {
                "run_dir": str(run_dir),
                "status": state["status"],
                "current_phase": current,
                "missing_artifacts": missing,
                "discovery_pass_progress": observed,
                "ready": not missing,
                "workers": state.get("workers", {}),
            }
        state["phase_status"][current] = "complete"
        if current in {"isolated-l1-l2", "blind-l3-active"}:
            key = "l2" if current == "isolated-l1-l2" else "l3"
            state["discovery_pass_status"][key] = {str(i): "complete" for i in range(1, manifest["discovery_passes_planned"] + 1)}
        index = PHASES.index(current)
        current = PHASES[index + 1]
        state["current_phase"] = current
        state["phase_status"][current] = "ready"
        state["status"] = "active"
        state["history"].append({"event": "gate_passed", "phase": PHASES[index], "at": utc_now()})
        append_run_event(run_dir, "gate_passed", state, detail={"phase": PHASES[index]})
    return {
        "run_dir": str(run_dir),
        "status": state["status"],
        "current_phase": current,
        "missing_artifacts": [],
        "discovery_pass_progress": observed_discovery_passes(run_dir, manifest),
        "ready": True,
        "workers": state.get("workers", {}),
    }


def feedback(args: argparse.Namespace) -> dict[str, object]:
    output = run_checked(
        [sys.executable, str(SCRIPTS / "record_feedback.py"), str(args.run_dir.resolve()), str(args.labels.resolve())]
    )
    return json.loads(output)


def informed(args: argparse.Namespace) -> dict[str, object]:
    command = [sys.executable, str(SCRIPTS / "prepare_informed_rescan.py"), str(args.run_dir.resolve())]
    if args.complete:
        command.append("--complete")
    return json.loads(run_checked(command))


def packet_view(args: argparse.Namespace) -> dict[str, object]:
    run_dir = args.run_dir.resolve()
    validate_bindings(run_dir, SKILL)
    return worker_view(run_dir, args.packet_id, REFERENCES / "agent-catalog.md")


def worker_action(args: argparse.Namespace) -> dict[str, object]:
    """Record host-observed worker facts; never imply a sandbox or kill occurred."""
    run_dir = args.run_dir.resolve()
    require_current_run(run_dir)
    with run_lock(run_dir):
        manifest = validate_bindings(run_dir, SKILL)
        state = load_run_state(run_dir, repair_snapshot=True)
        validate_state(run_dir, manifest, PHASES)
        packet = packet_for(run_dir, args.packet_id)
        current = state["workers"].get(args.packet_id)
        action = args.action
        if action == "start":
            if packet["phase"] != state["current_phase"]:
                raise ValueError("worker packet is not in the current phase")
            if not args.worker_id:
                raise ValueError("start requires an observed --worker-id")
            if args.isolation == "host_enforced" and not args.isolation_evidence:
                raise ValueError("host-enforced isolation requires --isolation-evidence")
            if current and current["status"] not in {"failed", "cancelled"}:
                raise ValueError("worker is already active or submitted")
            active = sum(item["status"] in {"running", "cancel_requested"}
                         for item in state["workers"].values())
            limit = min(manifest["worker_capacity"], manifest.get("runtime_capacity") or 1)
            if active >= limit:
                raise ValueError("recorded worker capacity is full")
            attempt = (current["attempt"] + 1) if current else 1
            if attempt > packet["retry_limit"] + 1:
                raise ValueError("worker retry limit exhausted")
            record = {"status": "running", "worker_id": args.worker_id, "attempt": attempt,
                      "isolation": args.isolation, "isolation_evidence": args.isolation_evidence,
                      "started_at": utc_now(), "updated_at": utc_now(), "outputs": [], "diagnostics": [],
                      "usage": {"wall_clock_seconds": None, "input_tokens": None, "output_tokens": None}}
        else:
            if not current or current["status"] not in {"running", "cancel_requested"}:
                raise ValueError("worker must be running or awaiting cancellation")
            if args.worker_id and args.worker_id != current["worker_id"]:
                raise ValueError("worker identity differs from the recorded host worker")
            record = dict(current)
            record["updated_at"] = utc_now()
            if action == "finish":
                outputs, diagnostics = inspect_outputs(run_dir, packet)
                record["outputs"] = outputs
                record["diagnostics"] = diagnostics
                record["status"] = "failed" if diagnostics else "submitted"
                record["validation_level"] = "syntax_checked; phase gate validates full schema"
            elif action == "fail":
                if not args.reason:
                    raise ValueError("fail requires --reason")
                record["status"] = "failed"
                record["diagnostics"] = [{"code": "host_failure", "reason": args.reason[:500]}]
            elif action == "cancel":
                record["status"] = "cancelled" if args.termination_evidence else "cancel_requested"
                record["termination_evidence"] = args.termination_evidence
            for key, value in (("wall_clock_seconds", args.wall_seconds),
                               ("input_tokens", args.input_tokens), ("output_tokens", args.output_tokens)):
                if value is not None:
                    if value < 0 or (key == "wall_clock_seconds" and not math.isfinite(value)):
                        raise ValueError("observed usage must be finite and nonnegative")
                    record["usage"][key] = value
        state["workers"][args.packet_id] = record
        append_run_event(run_dir, f"worker_{action}", state,
                         detail={"packet_id": args.packet_id, "worker_id": record["worker_id"],
                                 "status": record["status"]})
        return {"packet_id": args.packet_id, "worker": record}


def finalize(args: argparse.Namespace) -> dict[str, object]:
    run_dir = args.run_dir.resolve()
    require_current_run(run_dir)
    with run_lock(run_dir):
        from check_run_artifacts import validate_run
        manifest = validate_bindings(run_dir, SKILL)
        state = validate_state(run_dir, manifest, PHASES)
        if any(state["phase_status"][phase] != "complete" for phase in PHASES[:7]):
            raise ValueError("finalization requires all automated predecessor phases to be complete")
        if args.stage == "approved" and state["current_phase"] != "final":
            raise ValueError("approved finalization requires completed human review/informed phases; resume the run first")
        if args.stage == "draft" and state["status"] == "complete":
            raise ValueError("an approved run cannot be downgraded to draft")
        supplied = args.report if args.report.is_absolute() else run_dir / args.report
        if not supplied.resolve().is_relative_to(run_dir):
            raise ValueError("report must be a retained Markdown artifact inside the run directory")
        report = artifact_path(run_dir, supplied.relative_to(run_dir).as_posix())
        if report.suffix.lower() != ".md" or not report.is_file():
            raise ValueError("--report must identify an existing Markdown report")
        text = report.read_text(encoding="utf-8")
        heading = next((line for line in text.splitlines() if line.startswith("# ")), "")
        if args.stage not in heading.lower():
            raise ValueError(f"report heading must explicitly identify stage {args.stage}")
        result = validate_run(run_dir, final=True, stage=args.stage)
        from report_assembly import validate_assembled
        validate_assembled(run_dir, manifest, text)
        record = {"path": report.relative_to(run_dir).as_posix(), "sha256": file_hash(report), "stage": args.stage,
                  "input_fingerprint": manifest["input_fingerprint"], "configuration_hash": manifest["configuration_hash"]}
        if state.get("report") == record and state["status"] == ("draft_ready" if args.stage == "draft" else "complete"):
            return {"run_dir": str(run_dir), "status": state["status"], "complete": args.stage == "approved", "unchanged": True, "report": record}
        if args.stage == "draft":
            summary = read_json(run_dir / "informed-rescan-summary.json")
            if summary.get("status") == "not_run":
                summary.update(status="deferred", reason="awaiting completed human feedback")
                write_json(run_dir / "informed-rescan-summary.json", summary)
            state["status"] = "draft_ready"
        else:
            state["status"] = "complete"
            state["phase_status"]["final"] = "complete"
        state["report"] = record
        state["history"].append({"event": "report_validated", "stage": args.stage, "at": utc_now()})
        append_run_event(run_dir, "report_validated", state, detail={"stage": args.stage})
        return {"run_dir": str(run_dir), "status": state["status"], "complete": args.stage == "approved", "checks": result, "report": record}


def render_report(args: argparse.Namespace) -> dict[str, object]:
    """Assemble one retained Markdown report and return those exact console bytes."""
    run_dir = args.run_dir.resolve()
    require_current_run(run_dir)
    with run_lock(run_dir):
        from check_run_artifacts import validate_run
        from report_assembly import assemble, validate_assembled
        manifest = validate_bindings(run_dir, SKILL)
        state = validate_state(run_dir, manifest, PHASES)
        if any(state["phase_status"][phase] != "complete" for phase in PHASES[:7]):
            raise ValueError("rendering requires all automated predecessor phases")
        validate_run(run_dir, final=True, stage=args.stage)
        body = artifact_path(run_dir, args.body.relative_to(run_dir).as_posix() if args.body.is_absolute() else args.body.as_posix())
        output = artifact_path(run_dir, args.output.relative_to(run_dir).as_posix() if args.output.is_absolute() else args.output.as_posix())
        if body.suffix != ".md" or output.suffix != ".md" or not body.is_file() or body == output:
            raise ValueError("body and output must be distinct run-directory Markdown files")
        text = assemble(run_dir, manifest, body.read_text(encoding="utf-8"))
        validate_assembled(run_dir, manifest, text)
        from run_integrity import atomic_write
        atomic_write(output, text.encode("utf-8"))
        return {"report_markdown": text, "report_path": str(output)}


def doctor(args: argparse.Namespace) -> dict[str, object]:
    """Inspect the installed package without starting a run or creating caches."""
    from pdf_corpus_registry import load_manifest
    from check_nep_registry import validate_registry
    from pattern_routing import validate_index
    errors = []
    if sys.version_info < (3, 10):
        errors.append("Python 3.10 or newer is required")
    if sys.platform not in {"darwin", "linux"}:
        errors.append("supported platforms are macOS and Linux")
    required = ("audit-workflow.md", "neutral-schemas.md", "capability-model.md", "agent-catalog.md", "report-template.md")
    for name in required:
        if not (REFERENCES / name).is_file():
            errors.append(f"missing reference: {name}")
    for path in [SKILL / "SKILL.md", *sorted(REFERENCES.rglob("*.md"))]:
        for destination in re.findall(r"\]\(([^)]+)\)", path.read_text(encoding="utf-8")):
            if "://" in destination or destination.startswith("#"):
                continue
            relative = destination.split("#", 1)[0]
            if relative and not (path.parent / relative).is_file():
                errors.append(f"broken link in {path.relative_to(SKILL)}: {relative}")
    for path in SKILL.rglob("*"):
        if path.is_file() and path.suffix in {".md", ".json", ".py", ".yaml", ".rs"}:
            if re.search(r"https?://", path.read_text(encoding="utf-8", errors="replace")):
                errors.append(f"external URL in {path.relative_to(SKILL)}")
    counts = {}
    for label, check in (
        ("attack_lenses", validate_index),
        ("pdf_registry", lambda: load_manifest(REFERENCES / "pdf-corpus-manifest.json")),
        ("nep_registry", lambda: validate_registry(REFERENCES / "nep-registry.json")),
    ):
        try:
            payload = check()
            counts[label] = len(payload.get("reports", payload.get("neps", payload.get("cards", []))))
        except (ValueError, OSError, KeyError, TypeError) as exc:
            errors.append(f"{label}: {exc}")
    try:
        from check_official_docs import validate_registry as validate_docs
        docs = read_json(REFERENCES / "official-docs-registry.json")
        # Internal consistency only; upstream freshness requires an explicit checkout.
        result = validate_docs(docs, docs["pages"], docs["source"]["commit"])
        errors.extend(f"official_docs_registry: {error}" for error in result["errors"])
        counts["official_docs_registry"] = result["registry_pages"]
    except (ValueError, OSError, KeyError, TypeError) as exc:
        errors.append(f"official_docs_registry: {exc}")
    return {"command": "doctor", "ok": not errors, "errors": errors, "python": sys.version.split()[0],
            "platform": sys.platform, "run_schema": RUN_SCHEMA, "state_schema": STATE_SCHEMA,
            "optional": {"git": bool(shutil.which("git")), "cargo": bool(shutil.which("cargo")),
                         "skill_validator_pyyaml": importlib.util.find_spec("yaml") is not None},
            "subagent_runtime": "unknown; inspect the active Codex tool surface", "registries": counts,
            "upstream_freshness": "not checked; supply source checkouts explicitly for maintenance"}


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    commands = root.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run")
    run.add_argument("target", type=Path)
    run.add_argument("--mode", choices=("standard", "explicit-files", "deep"), default="standard")
    run.add_argument("--files", nargs="+", type=Path, default=[])
    run.add_argument("--loop", nargs="?", const=3, type=int, default=None,
                     help="Repeat blind L2/L3 discovery 1-10 times; bare flag selects 3")
    run.add_argument("--run-dir", type=Path)
    run.add_argument("--worker-capacity", type=int, default=8)
    run.add_argument("--runtime-capacity", type=int, help="Observed spawned-worker slots; omit when unknown")
    run.add_argument("--orchestrator-model", default=None)
    run.add_argument("--worker-model", default=None)
    run.set_defaults(handler=initialize)
    for name in ("status", "resume", "finalize"):
        command = commands.add_parser(name)
        command.add_argument("run_dir", type=Path)
        if name == "status":
            command.set_defaults(handler=lambda args: inspect_state(args.run_dir.resolve(), advance=False))
        elif name == "resume":
            command.set_defaults(handler=lambda args: inspect_state(args.run_dir.resolve(), advance=True))
        else:
            command.add_argument("--stage", choices=("draft", "approved"), default="draft")
            command.add_argument("--report", type=Path, required=True)
            command.set_defaults(handler=finalize)
    commands.add_parser("doctor").set_defaults(handler=doctor)
    packet_parser = commands.add_parser("packet")
    packet_parser.add_argument("run_dir", type=Path)
    packet_parser.add_argument("packet_id")
    packet_parser.set_defaults(handler=packet_view)
    worker_parser = commands.add_parser("worker")
    worker_parser.add_argument("run_dir", type=Path)
    worker_parser.add_argument("action", choices=("start", "finish", "fail", "cancel"))
    worker_parser.add_argument("packet_id")
    worker_parser.add_argument("--worker-id")
    worker_parser.add_argument("--isolation", choices=("prompt_only", "host_enforced"), default="prompt_only")
    worker_parser.add_argument("--isolation-evidence")
    worker_parser.add_argument("--termination-evidence")
    worker_parser.add_argument("--reason")
    worker_parser.add_argument("--wall-seconds", type=float)
    worker_parser.add_argument("--input-tokens", type=int)
    worker_parser.add_argument("--output-tokens", type=int)
    worker_parser.set_defaults(handler=worker_action)
    feedback_parser = commands.add_parser("feedback")
    feedback_parser.add_argument("run_dir", type=Path)
    feedback_parser.add_argument("labels", type=Path)
    feedback_parser.set_defaults(handler=feedback)
    informed_parser = commands.add_parser("informed-rescan")
    informed_parser.add_argument("run_dir", type=Path)
    informed_parser.add_argument("--complete", action="store_true")
    informed_parser.set_defaults(handler=informed)
    report_parser = commands.add_parser("render-report")
    report_parser.add_argument("run_dir", type=Path)
    report_parser.add_argument("--body", type=Path, required=True)
    report_parser.add_argument("--output", type=Path, required=True)
    report_parser.add_argument("--stage", choices=("draft", "approved"), default="draft")
    report_parser.set_defaults(handler=render_report)
    return root


def main() -> int:
    args = parser().parse_args()
    if args.command == "run":
        print(RUNTIME_BANNER, file=sys.stderr)
    try:
        result = args.handler(args)
    except (ValueError, OSError, RuntimeError, subprocess.TimeoutExpired, KeyError, TypeError) as exc:
        print(json.dumps({"action": "invalid", "error": str(exc)}), file=sys.stderr)
        return 2
    if args.command == "render-report":
        sys.stdout.write(result["report_markdown"])
    else:
        print(json.dumps(result, indent=2, sort_keys=True))
    return 1 if result.get("ok") is False else 0


if __name__ == "__main__":
    raise SystemExit(main())
