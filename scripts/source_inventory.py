"""Shared deterministic, read-only target input discovery.

Snapshots cover selected sources and in-target context/artifacts, including new
and deleted files. They do not cover external workspace members, toolchain state,
environment variables, or ignored/generated inputs. Source files are always
hashed regardless of secret-looking names; only paths and digests are emitted.
Secret exclusion for non-source context is based on conservative path names,
not content inspection. A snapshot is not atomic; callers should keep the
target quiescent (including directory/symlink changes) while collecting it.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
import sys
from pathlib import Path
from typing import Iterator


SKIP_DIRS = {
    ".git", ".near-audit", "node_modules", "target", "vendor", "dist",
    "build", "coverage",
}
ARTIFACT_SKIP_DIRS = {".git", "node_modules", "vendor"}
SOURCE_SUFFIXES = {".rs", ".ts", ".tsx", ".js", ".jsx", ".sol"}
TEST_DIRS = {"test", "tests", "example", "examples", "fixture", "fixtures"}
CONTEXT_SKIP_DIRS = SKIP_DIRS | {
    "generated", ".cache", "__pycache__", ".next", ".nuxt", ".output",
}
CONTEXT_SUFFIXES = {".md", ".mdx", ".txt", ".json", ".toml", ".yaml", ".yml"}
LOCKFILES = {
    "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
    "bun.lock", "bun.lockb", "deno.lock",
}
SECRET_DIRS = {".ssh", ".aws", ".gnupg", ".near-credentials", "secrets", "credentials"}
SECRET_NAME = re.compile(
    r"(?:^|[._-])(?:secrets?|credentials?|private[._-]?keys?|keystore)(?:[._-]|$)",
    re.I,
)


def is_test_or_example(path: Path) -> bool:
    return any(part.lower() in TEST_DIRS for part in path.parts)


def is_secret(path: Path) -> bool:
    return any(
        part.lower() in SECRET_DIRS
        or part.lower().startswith((".env", "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"))
        or bool(SECRET_NAME.search(part))
        for part in path.parts
    ) or path.suffix.lower() in {".pem", ".key", ".p12", ".pfx", ".jks"}


def _canonical_host_alias(path: Path) -> Path:
    """Normalize only verified macOS /var and /tmp aliases, leaving entries intact."""
    path = path.absolute()
    if sys.platform == "darwin" and len(path.parts) > 1:
        alias = Path(path.anchor) / path.parts[1]
        destination = {Path("/var"): Path("/private/var"), Path("/tmp"): Path("/private/tmp")}.get(alias)
        if destination is not None and alias.is_symlink() and alias.resolve(strict=True) == destination:
            return destination.joinpath(*path.parts[2:])
    return path


def validate_root(root: Path) -> Path:
    # Normalize host aliases before checking every remaining component; resolving
    # the whole input first would hide target/link/child directory symlinks.
    root = _canonical_host_alias(root)
    current = Path(root.anchor)
    for part in root.parts[1:]:
        current = current / part
        if current.is_symlink():
            raise ValueError(f"target root uses a symlink: {current}")
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError(f"root is not a directory: {root}")
    return root


def _walk_error(error: OSError) -> None:
    raise error


def iter_files(
    root: Path, *, excluded_dirs: set[str] = SKIP_DIRS,
    exclude_tests: bool = False, exclude_secrets: bool = False,
) -> Iterator[Path]:
    """Walk regular files without entering excluded or symlink directories."""
    root = validate_root(root)
    for directory, dirs, files in os.walk(root, topdown=True, followlinks=False, onerror=_walk_error):
        parent = Path(directory)
        dirs[:] = sorted(
            name for name in dirs
            if name not in excluded_dirs
            and not (exclude_tests and name.lower() in TEST_DIRS)
            and not (exclude_secrets and is_secret(Path(name)))
            and not (parent / name).is_symlink()
        )
        for name in sorted(files):
            path = parent / name
            if exclude_secrets and is_secret(path.relative_to(root)):
                continue
            if stat.S_ISREG(path.lstat().st_mode):
                yield path


def discover(root: Path, explicit: list[Path]) -> list[Path]:
    """Select source files; explicit inputs override only test/example filtering.

    Invalid explicit inputs raise ValueError (or OSError for unreadable paths),
    even when other inputs are valid. No partial selection is returned.
    """
    root = validate_root(root)
    if explicit:
        selected: set[Path] = set()
        for item in explicit:
            path = _canonical_host_alias(item) if item.is_absolute() else root / item
            try:
                relative = path.relative_to(root)
            except ValueError as exc:
                raise ValueError(f"explicit input is outside target: {item}") from exc
            # Reject traversal before normalization so link/../file cannot hide a link.
            if ".." in relative.parts:
                raise ValueError(f"explicit input contains parent traversal: {item}")
            if any(part in SKIP_DIRS for part in relative.parts[:-1]):
                raise ValueError(f"explicit input is excluded: {item}")
            current = root
            for part in relative.parts:
                current = current / part
                if current.is_symlink():
                    raise ValueError(f"explicit input uses a symlink: {item}")
            if not path.exists():
                raise ValueError(f"explicit input is missing: {item}")
            if not stat.S_ISREG(path.lstat().st_mode) or path.suffix.lower() not in SOURCE_SUFFIXES:
                raise ValueError(f"explicit input is not a supported source file: {item}")
            selected.add(path)
        return sorted(selected, key=lambda path: path.relative_to(root).as_posix())
    return sorted(
        (path for path in iter_files(root, exclude_tests=True) if path.suffix.lower() in SOURCE_SUFFIXES),
        key=lambda path: path.relative_to(root).as_posix(),
    )


def artifact_kind(path: Path) -> str | None:
    """Use the existing ABI/Wasm filename and size limits; no parsing needed."""
    suffix = path.suffix.lower()
    if suffix == ".json" and "abi" in path.name.lower() and path.stat().st_size <= 5_000_000:
        return "abi"
    if suffix == ".wasm" and path.stat().st_size <= 50_000_000:
        return "wasm"
    return None


def discover_artifacts(root: Path) -> list[Path]:
    # Existing build/target/dist directories are deliberately available here.
    return sorted(
        (path for path in iter_files(root, excluded_dirs=ARTIFACT_SKIP_DIRS, exclude_secrets=True)
         if artifact_kind(path)),
        key=lambda path: path.as_posix(),
    )


def snapshot_inputs(root: Path, explicit: list[Path]) -> list[dict]:
    """Return sorted {'path': relative POSIX, 'sha256': 'sha256:'+digest} records.

    All sources selected by ``discover`` are hashed, regardless of their names.
    Context also hashes source files across non-generated target directories,
    including tests/examples/support, without expanding primary source scope.
    Non-source context includes docs and nested workspace manifests, with secret
    path exclusions applied only to these non-source files.
    ABI/Wasm candidates use ``discover_artifacts`` rules even if parsing would
    fail, so repairing a malformed artifact changes the snapshot. Each included
    file is read once. No subprocesses, git, network, or filesystem writes occur.
    See module documentation for context and consistency limitations.
    """
    root = validate_root(root)
    paths = set(discover(root, explicit))
    for path in iter_files(root, excluded_dirs=CONTEXT_SKIP_DIRS):
        if path.suffix.lower() in SOURCE_SUFFIXES:
            paths.add(path)
            continue
        if is_secret(path.relative_to(root)):
            continue
        if path.suffix.lower() == ".json" and "abi" in path.name.lower():
            # ABI candidates, including oversized files, use only artifact rules.
            continue
        if (path.suffix.lower() in CONTEXT_SUFFIXES or path.name.startswith(("Cargo", "rust-toolchain"))
                or path.name in LOCKFILES or path.relative_to(root).as_posix() == ".cargo/config"):
            paths.add(path)
    paths.update(discover_artifacts(root))
    records = []
    for path in sorted(paths, key=lambda path: path.relative_to(root).as_posix()):
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        records.append({"path": path.relative_to(root).as_posix(), "sha256": "sha256:" + digest.hexdigest()})
    return records
