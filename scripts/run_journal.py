"""Append-only, hash-linked run journal; run-state.json is a replaceable projection."""

from __future__ import annotations

import os
from pathlib import Path

from run_integrity import atomic_write_json, canonical_hash, read_json


def events_dir(run_dir: Path) -> Path:
    path = run_dir / "run-events"
    if path.is_symlink():
        raise ValueError("run-events must not be a symlink")
    return path


def replay(run_dir: Path) -> tuple[dict, int, str]:
    folder = events_dir(run_dir)
    if not folder.is_dir():
        raise ValueError("run event journal is missing")
    entries = sorted(folder.iterdir())
    if not entries:
        raise ValueError("run event journal is empty")
    previous = "genesis"
    state = {}
    for number, path in enumerate(entries, 1):
        if path.is_symlink() or not path.is_file() or path.name != f"{number:06d}.json":
            raise ValueError("run event journal has a missing or unexpected entry")
        event = read_json(path)
        claimed = event.pop("event_hash", None)
        if event.get("sequence") != number or event.get("previous_hash") != previous:
            raise ValueError("run event journal sequence or hash chain differs")
        if claimed != canonical_hash(event):
            raise ValueError("run event journal content hash differs")
        if not isinstance(event.get("state"), dict):
            raise ValueError("run event journal state must be an object")
        state = event["state"]
        previous = claimed
    return state, len(entries), previous


def append(run_dir: Path, kind: str, state: dict, *, detail: dict | None = None) -> None:
    """Caller holds the run lock except while initializing a fresh run."""
    folder = events_dir(run_dir)
    folder.mkdir(exist_ok=True)
    entries = list(folder.iterdir())
    if entries:
        _, sequence, previous = replay(run_dir)
    else:
        sequence, previous = 0, "genesis"
        if kind != "initialized":
            raise ValueError("first run event must initialize the run")
    event = {"schema_version": 1, "sequence": sequence + 1, "previous_hash": previous,
             "kind": kind, "detail": detail or {}, "state": state}
    event["event_hash"] = canonical_hash(event)
    atomic_write_json(folder / f"{sequence + 1:06d}.json", event)
    directory_fd = os.open(folder, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    atomic_write_json(run_dir / "run-state.json", state)


def load(run_dir: Path, *, repair_snapshot: bool = False) -> dict:
    state, _, _ = replay(run_dir)
    if repair_snapshot:
        path = run_dir / "run-state.json"
        if not path.is_file() or read_json(path) != state:
            atomic_write_json(path, state)
    return state
