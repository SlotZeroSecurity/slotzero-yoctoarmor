"""Read-only evidence binding and atomic storage for local review runs."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import tempfile
from contextlib import contextmanager
from functools import lru_cache
from pathlib import Path

RUN_SCHEMA = 6
STATE_SCHEMA = 4


def canonical_hash(value: object) -> str:
    return "sha256:" + hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _unique_keys(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def read_json(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_keys)
    if not isinstance(value, dict):
        raise ValueError(f"{path.name}: expected JSON object")
    return value


@lru_cache(maxsize=16)
def _cached_registry(path: Path, modified_ns: int, size: int) -> dict:
    return read_json(path)


def read_registry(path: Path) -> dict:
    """Command-local read cache; changed files miss it. Treat returned data as immutable."""
    status = path.stat()
    return _cached_registry(path, status.st_mtime_ns, status.st_size)


def read_jsonl(path: Path) -> list[dict]:
    rows = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        value = json.loads(line, object_pairs_hook=_unique_keys)
        if not isinstance(value, dict):
            raise ValueError(f"{path.name}:{number}: expected JSON object")
        rows.append(value)
    return rows


def atomic_write(path: Path, payload: bytes) -> None:
    """Replace a complete artifact on the same filesystem; never truncate it."""
    if path.is_symlink():
        raise ValueError(f"refusing to replace symlink artifact: {path}")
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def atomic_write_json(path: Path, value: object) -> None:
    atomic_write(path, (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8"))


def atomic_write_jsonl(path: Path, rows: list[dict]) -> None:
    atomic_write(path, "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows).encode("utf-8"))


@contextmanager
def run_lock(run_dir: Path):
    """A persistent adjacent inode coordinates writers, independently of TMPDIR."""
    lock = run_dir / ".run.lock"
    if lock.is_symlink():
        raise ValueError("run lock must not be a symlink")
    with lock.open("a+b") as stream:
        fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


def configuration_snapshot(skill: Path) -> list[dict]:
    """Bind shipped instructions, data and all helper imports; exclude test/cache data."""
    files = [skill / "SKILL.md", skill / "agents" / "openai.yaml"]
    for folder, suffixes in (("scripts", {".py"}), ("references", {".md", ".json"})):
        for directory, children, names in os.walk(skill / folder, followlinks=False):
            children[:] = sorted(name for name in children if name != "__pycache__" and not (Path(directory) / name).is_symlink())
            files.extend(Path(directory) / name for name in names if Path(name).suffix in suffixes)
    result = []
    for path in sorted(files):
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"missing or nonportable configuration file: {path}")
        result.append({"path": path.relative_to(skill).as_posix(), "sha256": file_hash(path)})
    return result


def require_current_run(run_dir: Path) -> dict:
    manifest = read_json(run_dir / "run-manifest.json")
    if manifest.get("schema_version") != RUN_SCHEMA:
        raise ValueError("legacy run is read-only; start a new run with this skill version")
    return manifest


def validate_bindings(run_dir: Path, skill: Path | None = None) -> dict:
    """Do not confuse self-consistent saved hashes with unchanged current inputs."""
    from source_inventory import snapshot_inputs

    manifest = require_current_run(run_dir)
    skill = skill or Path(__file__).resolve().parents[1]
    target = Path(manifest["target"])
    configuration = configuration_snapshot(skill)
    if (manifest.get("configuration_snapshot") != configuration or
            manifest.get("configuration_hash") != canonical_hash(configuration)):
        raise ValueError("configuration drift: skill scripts, instructions or registries changed; start a new run")
    current = snapshot_inputs(target, [Path(item) for item in manifest.get("explicit_files", [])])
    if manifest.get("input_snapshot") != current or manifest.get("input_fingerprint") != canonical_hash(current):
        raise ValueError("source/context drift: input files changed, appeared or disappeared; start a new run")
    from threat_model import validate_model_binding
    validate_model_binding(manifest)
    if manifest.get("surface_hash") != canonical_hash(read_json(run_dir / "surface.json")):
        raise ValueError("surface manifest differs from its frozen hash")
    if manifest.get("neutral_surface_hash") != canonical_hash(read_json(run_dir / "neutral-surface.json")):
        raise ValueError("neutral surface differs from its frozen hash")
    return manifest


def artifact_path(run_dir: Path, relative: str) -> Path:
    item = Path(relative)
    if item.is_absolute() or ".." in item.parts or not relative:
        raise ValueError(f"artifact must have a contained relative path: {relative}")
    path = run_dir / item
    if any((run_dir / Path(*item.parts[:index])).is_symlink() for index in range(1, len(item.parts) + 1)):
        raise ValueError(f"symlink artifact is not accepted: {relative}")
    return path


def producer_paths(run_dir: Path, *, include_rescans: bool = True) -> list[Path]:
    packets = read_jsonl(run_dir / "work-packets.jsonl")
    names = set()
    for packet in packets:
        if not include_rescans and packet["phase"] in {"counterexample-rescan", "informed-rescan"}:
            continue
        for relative in packet.get("candidate_outputs", []):
            if packet["phase"] == "informed-rescan":
                summary = read_json(run_dir / "informed-rescan-summary.json")
                if summary.get("status") in {"not_run", "deferred", "skipped"}:
                    continue
            names.add(relative)
    return [artifact_path(run_dir, name) for name in sorted(names)]


def reconcile_candidates(run_dir: Path, *, include_rescans: bool = True) -> dict:
    produced = {}
    manifest = read_json(run_dir / "run-manifest.json")
    passes = manifest.get("discovery_passes_planned", 1)
    for path in producer_paths(run_dir, include_rescans=include_rescans):
        for row in read_jsonl(path):
            candidate = row.get("candidate_id")
            if not isinstance(candidate, str) or not candidate or candidate in produced:
                raise ValueError(f"{path.name}: missing or duplicate producer candidate ID {candidate!r}")
            if passes > 1 and ("l2/pass-" in path.as_posix() or "discovery/pass-" in path.as_posix()):
                number = int(path.parent.name.removeprefix("pass-"))
                if row.get("discovery_pass") != number or not candidate.startswith(f"P{number:02d}-"):
                    raise ValueError(f"{path}: candidate must carry its pass number and P{number:02d}- ID prefix")
            produced[candidate] = row
    raw = {}
    for row in read_jsonl(run_dir / "raw-candidates.jsonl"):
        candidate = row.get("candidate_id")
        if not isinstance(candidate, str) or not candidate or candidate in raw:
            raise ValueError("raw ledger: missing or duplicate candidate ID")
        raw[candidate] = row
    # At the initial dedup gate only frozen discovery producers are expected.
    if set(raw) != set(produced):
        raise ValueError(f"producer/raw mismatch: missing={sorted(set(produced) - set(raw))}; unknown={sorted(set(raw) - set(produced))}")
    for candidate, row in produced.items():
        if row != raw[candidate]:
            raise ValueError(f"raw ledger altered producer evidence: {candidate}")
    return {"producers": len(producer_paths(run_dir, include_rescans=include_rescans)), "candidates": len(raw)}


def validate_state(run_dir: Path, manifest: dict, phases: tuple[str, ...]) -> dict:
    from run_journal import load
    state = load(run_dir)
    if state.get("schema_version") != STATE_SCHEMA or state.get("run_id") != manifest.get("run_id"):
        raise ValueError("run-state: invalid schema or run ID")
    if state.get("manifest_hash") != canonical_hash(manifest):
        raise ValueError("run-state: frozen manifest content changed")
    if state.get("phase_order") != list(phases) or state.get("current_phase") not in phases:
        raise ValueError("run-state: invalid phase order/current phase")
    if state.get("target") != manifest.get("target") or Path(state.get("run_dir", "")).resolve() != run_dir.resolve():
        raise ValueError("run-state: target/run directory differs from manifest")
    statuses = state.get("phase_status", {})
    if set(statuses) != set(phases) or any(value not in {"pending", "ready", "complete", "deferred"} for value in statuses.values()):
        raise ValueError("run-state: invalid phase statuses")
    current = phases.index(state["current_phase"])
    if any(statuses[phase] != "complete" for phase in phases[:current]):
        raise ValueError("run-state: a predecessor phase is incomplete")
    if any(statuses[phase] != "pending" for phase in phases[current + 1:]):
        raise ValueError("run-state: a future phase is already completed")
    if state.get("status") not in {"active", "draft_ready", "complete"}:
        raise ValueError("run-state: invalid run status")
    expected = {str(i): "pending" for i in range(1, manifest["discovery_passes_planned"] + 1)}
    progress = state.get("discovery_pass_status")
    if not isinstance(progress, dict) or set(progress) != {"l2", "l3"}:
        raise ValueError("run-state: missing discovery pass status")
    for name, gate in (("l2", "isolated-l1-l2"), ("l3", "blind-l3-active")):
        if not isinstance(progress[name], dict) or set(progress[name]) != set(expected):
            raise ValueError(f"run-state: invalid {name} pass inventory")
        if any(value not in {"pending", "complete"} for value in progress[name].values()):
            raise ValueError(f"run-state: invalid {name} pass status")
        if statuses[gate] == "complete" and any(value != "complete" for value in progress[name].values()):
            raise ValueError(f"run-state: {gate} complete without all discovery passes")
    if state["status"] == "complete" and (state["current_phase"] != "final" or statuses["final"] != "complete"):
        raise ValueError("run-state: completion requires every predecessor and final phase")
    workers = state.get("workers")
    if not isinstance(workers, dict):
        raise ValueError("run-state: workers must be an object")
    packets = {row["packet_id"] for row in read_jsonl(run_dir / "work-packets.jsonl")}
    for packet_id, record in workers.items():
        if packet_id not in packets or not isinstance(record, dict):
            raise ValueError("run-state: unknown worker packet")
        if record.get("status") not in {"running", "submitted", "failed", "cancel_requested", "cancelled"}:
            raise ValueError("run-state: invalid worker status")
        if not isinstance(record.get("worker_id"), str) or not record["worker_id"]:
            raise ValueError("run-state: missing observed worker identity")
    return state
