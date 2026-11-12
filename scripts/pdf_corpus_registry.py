#!/usr/bin/env python3
"""Register and deduplicate NEAR ecosystem audit PDFs by raw-file SHA-256."""

from __future__ import annotations

import argparse
import datetime as dt
import fcntl
import hashlib
import json
import os
import re
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterable


SKILL_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = SKILL_ROOT / "references" / "pdf-corpus-manifest.json"
HASH_RE = re.compile(r"^[0-9a-f]{64}$")
DATE_RE = re.compile(r"^\d{4}-(?:\d{2})(?:-\d{2})?$")
TIMESTAMP_RE = re.compile(
    r"\d{4}-\d{2}-\d{2}T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d+)?Z", re.ASCII
)
DISPOSITIONS = {
    "pending_review",
    "extraction_failed",
    "ingested",
    "already_represented",
    "excluded",
}
TERMINAL_DISPOSITIONS = {"ingested", "already_represented", "excluded"}


class RegistryError(ValueError):
    """Raised when input or registry state is invalid."""


class RegistryParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise RegistryError(message)


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def empty_manifest() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "hash_algorithm": "sha256",
        "reports": [],
        "legacy_unhashed_sources": [],
    }


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RegistryError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def reject_nonfinite(value: str) -> None:
    raise RegistryError(f"invalid JSON constant: {value}")


def load_manifest(path: Path, *, allow_missing: bool = False) -> dict[str, Any]:
    if not path.exists():
        if allow_missing:
            return empty_manifest()
        raise RegistryError(f"manifest not found: {path}")
    try:
        manifest = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_nonfinite,
        )
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise RegistryError(f"cannot read manifest {path}: {exc}") from exc
    validate_manifest(manifest, path)
    return manifest


def _valid_timestamp(value: Any) -> bool:
    if not isinstance(value, str) or not TIMESTAMP_RE.fullmatch(value):
        return False
    try:
        dt.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return False
    return True


def _valid_date(value: str) -> bool:
    if not DATE_RE.fullmatch(value):
        return False
    try:
        dt.date.fromisoformat(value + "-01" if len(value) == 7 else value)
    except ValueError:
        return False
    return True


def markdown_reference_ids(content: str) -> set[str]:
    """Read report inventory IDs and explicit source-ledger identities.

    Supported prefixes are complete IDs in a Prefix/Report table, or a
    `### PREFIX — Report` heading with matching ID-table entries beneath it.
    Numbered source entries such as ``1. `ORS-01` ...`` resolve exactly.
    Prose, partial IDs, arbitrary headings, and fenced examples do not resolve.
    """
    identifiers: set[str] = set()
    lines = content.splitlines()
    heading_prefix = None
    table_kind = None
    table_width = 0
    fence = None

    def cells(line: str) -> list[str]:
        return [cell.strip().strip("`") for cell in line.strip().strip("|").split("|")]

    for index, raw in enumerate(lines):
        line = raw.strip()
        marker = re.match(r"^(`{3,}|~{3,})", line)
        if marker:
            token = marker.group(1)
            if fence is None:
                fence = token
            elif token[0] == fence[0] and len(token) >= len(fence):
                fence = None
            table_kind = None
            continue
        if fence is not None:
            continue
        if line.startswith("#"):
            heading = re.fullmatch(r"#{1,6}\s+([A-Z][A-Z0-9-]*)\s+—\s+\S.*", line)
            heading_prefix = heading.group(1) if heading else None
        if not line.startswith("|"):
            table_kind = None
            entry = re.match(r"^\d+\.\s+`([A-Z][A-Z0-9-]*)`\s+\S", line)
            if entry:
                identifiers.add(entry.group(1))
            continue
        row = cells(line)
        if index + 1 < len(lines) and lines[index + 1].strip().startswith("|"):
            separator = cells(lines[index + 1])
            if len(separator) == len(row) and all(re.fullmatch(r":?-{3,}:?", cell) for cell in separator):
                table_width = len(row)
                table_kind = (
                    "report" if row[0] in {"Prefix", "Ledger ID", "ID", "Report ID"} and "Report" in row[1:]
                    else "finding" if row[0] == "ID" and "Issue" in row[1:]
                    else None
                )
                continue
        if (table_kind and len(row) == table_width and len(row) > 1 and row[1].strip()
                and re.fullmatch(r"[A-Z][A-Z0-9-]*", row[0])):
            identifiers.add(row[0])
            if table_kind == "finding" and heading_prefix and row[0].startswith(heading_prefix + "-"):
                identifiers.add(heading_prefix)
    return identifiers


def reference_ids(reference_path: Path) -> set[str]:
    try:
        content = reference_path.read_text(encoding="utf-8")
        if reference_path.suffix.lower() == ".md":
            return markdown_reference_ids(content)
        if reference_path.suffix.lower() != ".json":
            raise RegistryError("corpus references must point to Markdown or JSON")
        data = json.loads(content, object_pairs_hook=reject_duplicate_keys, parse_constant=reject_nonfinite)
        if not isinstance(data, dict):
            raise RegistryError("JSON corpus reference must be an object")
        counts = data.get("report_counts")
        findings = data.get("findings")
        if not isinstance(counts, dict) or not counts or not all(
            isinstance(name, str) and name.strip() and type(count) is int and count >= 0
            for name, count in counts.items()
        ):
            raise RegistryError("JSON corpus reference requires valid report_counts")
        if not isinstance(findings, list) or not all(
            isinstance(item, dict) and isinstance(item.get("report"), str)
            and item["report"] in counts for item in findings
        ):
            raise RegistryError("JSON corpus reference requires valid finding report identities")
        return set(counts)
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise RegistryError(f"cannot read corpus reference {reference_path}: {exc}") from exc


def validate_reference(corpus_ref: str, base: Path, cache: dict[Path, set[str]]) -> None:
    relative, separator, fragment = corpus_ref.partition("#")
    if (
        not separator or not relative.strip() or not fragment.strip()
        or corpus_ref != corpus_ref.strip() or "#" in fragment
        or "\\" in relative or "\x00" in corpus_ref
        or Path(relative).is_absolute() or ".." in Path(relative).parts
    ):
        raise RegistryError("corpus reference must use contained relative-path#ledger-id")
    try:
        reference_path = (base / relative).resolve()
    except (OSError, RuntimeError, ValueError) as exc:
        raise RegistryError(f"invalid corpus reference path: {corpus_ref}") from exc
    if not reference_path.is_relative_to(base):
        raise RegistryError(f"corpus reference escapes manifest directory: {corpus_ref}")
    if reference_path not in cache:
        cache[reference_path] = reference_ids(reference_path)
    if fragment not in cache[reference_path]:
        raise RegistryError(f"corpus reference identity is not present: {corpus_ref}")


def validate_manifest(manifest: Any, path: Path = DEFAULT_MANIFEST) -> None:
    if not isinstance(manifest, dict):
        raise RegistryError("manifest root must be an object")
    if type(manifest.get("schema_version")) is not int or manifest["schema_version"] != 1:
        raise RegistryError("schema_version must be 1")
    if manifest.get("hash_algorithm") != "sha256":
        raise RegistryError("hash_algorithm must be sha256")
    reports = manifest.get("reports")
    legacy = manifest.get("legacy_unhashed_sources")
    if not isinstance(reports, list) or not isinstance(legacy, list):
        raise RegistryError("reports and legacy_unhashed_sources must be arrays")

    hashes: list[str] = []
    base = path.resolve().parent
    reference_cache: dict[Path, set[str]] = {}
    for index, report in enumerate(reports):
        label = f"reports[{index}]"
        if not isinstance(report, dict):
            raise RegistryError(f"{label} must be an object")
        required = {
            "sha256",
            "filename",
            "byte_size",
            "registered_at",
            "title",
            "auditor",
            "report_date",
            "ecosystem_scope",
            "disposition",
            "corpus_refs",
            "notes",
            "legacy_backfill",
        }
        missing = required - report.keys()
        if missing:
            raise RegistryError(f"{label} missing fields: {sorted(missing)}")
        sha256 = report["sha256"]
        if not isinstance(sha256, str) or not HASH_RE.fullmatch(sha256):
            raise RegistryError(f"{label}.sha256 must be 64 lowercase hex characters")
        hashes.append(sha256)
        if report["filename"] is not None and not isinstance(report["filename"], str):
            raise RegistryError(f"{label}.filename must be a string or null")
        if isinstance(report["filename"], str) and (not report["filename"].strip() or report["filename"] != report["filename"].strip()):
            raise RegistryError(f"{label}.filename must be non-empty and trimmed")
        size = report["byte_size"]
        if size is not None and (not isinstance(size, int) or isinstance(size, bool) or size < 0):
            raise RegistryError(f"{label}.byte_size must be a non-negative integer or null")
        if not isinstance(report["legacy_backfill"], bool):
            raise RegistryError(f"{label}.legacy_backfill must be a boolean")
        if not report["legacy_backfill"] and (report["filename"] is None or size is None):
            raise RegistryError(f"{label} new registrations require filename and byte_size")
        if not _valid_timestamp(report["registered_at"]):
            raise RegistryError(f"{label}.registered_at must be an ISO-8601 UTC timestamp")
        disposition = report["disposition"]
        if not isinstance(disposition, str) or disposition not in DISPOSITIONS:
            raise RegistryError(f"{label}.disposition is invalid: {disposition}")
        if not isinstance(report["corpus_refs"], list) or not all(
            isinstance(item, str) and item.strip() for item in report["corpus_refs"]
        ):
            raise RegistryError(f"{label}.corpus_refs must be an array of non-empty strings")
        if not isinstance(report["notes"], str):
            raise RegistryError(f"{label}.notes must be a string")
        for field in ("title", "auditor", "report_date", "ecosystem_scope"):
            if report[field] is not None and not isinstance(report[field], str):
                raise RegistryError(f"{label}.{field} must be a string or null")
            if isinstance(report[field], str) and (not report[field].strip() or report[field] != report[field].strip()):
                raise RegistryError(f"{label}.{field} must be non-empty and trimmed")
        if report["report_date"] is not None and not _valid_date(report["report_date"]):
            raise RegistryError(f"{label}.report_date must be YYYY-MM or YYYY-MM-DD")
        if disposition in {"ingested", "already_represented"}:
            required_metadata = ["title", "auditor", "ecosystem_scope"]
            if not report["legacy_backfill"]:
                required_metadata.append("report_date")
            for field in required_metadata:
                if not report[field]:
                    raise RegistryError(f"{label}.{field} is required when finalized")
            if not report["corpus_refs"]:
                raise RegistryError(f"{label}.corpus_refs is required when finalized")
        for corpus_ref in report["corpus_refs"]:
            validate_reference(corpus_ref, base, reference_cache)
        if disposition == "excluded" and not report["notes"].strip():
            raise RegistryError(f"{label}.notes is required when excluded")

    if hashes != sorted(hashes):
        raise RegistryError("reports must be sorted lexicographically by sha256")
    if len(hashes) != len(set(hashes)):
        raise RegistryError("report sha256 values must be unique")

    for index, source in enumerate(legacy):
        label = f"legacy_unhashed_sources[{index}]"
        if not isinstance(source, dict):
            raise RegistryError(f"{label} must be an object")
        if not isinstance(source.get("title"), str) or not source["title"].strip():
            raise RegistryError(f"{label}.title is required")
        if source["title"] != source["title"].strip():
            raise RegistryError(f"{label}.title must be trimmed")
        if not isinstance(source.get("corpus_ref"), str) or not source["corpus_ref"].strip():
            raise RegistryError(f"{label}.corpus_ref is required")
        if not isinstance(source.get("notes"), str) or not source["notes"].strip():
            raise RegistryError(f"{label}.notes is required")
        validate_reference(source["corpus_ref"], base, reference_cache)

    legacy_refs = [source["corpus_ref"] for source in legacy]
    if legacy_refs != sorted(legacy_refs):
        raise RegistryError("legacy_unhashed_sources must be sorted by corpus_ref")
    if len(legacy_refs) != len(set(legacy_refs)):
        raise RegistryError("legacy_unhashed_sources must have unique corpus_ref values")


def serialize_manifest(manifest: dict[str, Any], path: Path = DEFAULT_MANIFEST) -> bytes:
    manifest["reports"].sort(key=lambda item: item["sha256"])
    validate_manifest(manifest, path)
    return (json.dumps(manifest, indent=2, ensure_ascii=True) + "\n").encode("utf-8")


def atomic_write_manifest(path: Path, manifest: dict[str, Any]) -> None:
    payload = serialize_manifest(manifest, path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


@contextmanager
def manifest_lock(path: Path) -> Iterable[None]:
    # Keep this inode adjacent and persistent across manifest replacements.
    # Removing it after unlocking would let waiters lock a detached inode.
    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_name(f".{path.name}.lock")
    if lock_path.is_symlink():
        raise RegistryError("manifest lock must not be a symlink")
    with lock_path.open("a+", encoding="utf-8") as stream:
        fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


def collect_pdfs(inputs: list[str]) -> list[Path]:
    found: dict[str, Path] = {}
    for raw in inputs:
        candidate = Path(raw)
        if candidate.is_symlink():
            raise RegistryError(f"symlinks are not accepted: {candidate}")
        if candidate.is_file():
            if candidate.suffix.lower() != ".pdf":
                raise RegistryError(f"not a PDF path: {candidate}")
            found[str(candidate.resolve())] = candidate
            continue
        if candidate.is_dir():
            for root, directories, files in os.walk(candidate, followlinks=False):
                directories[:] = sorted(
                    name
                    for name in directories
                    if not (Path(root) / name).is_symlink()
                )
                for name in sorted(files):
                    path = Path(root) / name
                    if path.suffix.lower() == ".pdf" and not path.is_symlink():
                        found[str(path.resolve())] = path
            continue
        raise RegistryError(f"input does not exist: {candidate}")
    if not found:
        raise RegistryError("no PDF files found")
    return [found[key] for key in sorted(found)]


def hash_pdf(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    try:
        with path.open("rb") as stream:
            first = stream.read(1024 * 1024)
            if b"%PDF-" not in first[:1024]:
                raise RegistryError(f"invalid PDF signature: {path}")
            digest.update(first)
            size += len(first)
            while True:
                chunk = stream.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
                size += len(chunk)
    except OSError as exc:
        raise RegistryError(f"cannot read {path}: {exc}") from exc
    return digest.hexdigest(), size


def probe_inputs(inputs: list[str]) -> list[dict[str, Any]]:
    probes = []
    for path in collect_pdfs(inputs):
        sha256, size = hash_pdf(path)
        probes.append({"path": str(path), "sha256": sha256, "byte_size": size})
    return probes


def classify(probe: dict[str, Any], by_hash: dict[str, dict[str, Any]]) -> str:
    existing = by_hash.get(probe["sha256"])
    if existing is None:
        return "registered"
    if existing["disposition"] in TERMINAL_DISPOSITIONS:
        return "skip"
    return "resume"


def emit(result: dict[str, Any]) -> None:
    print(json.dumps(result, sort_keys=True, ensure_ascii=True))


def command_scan(args: argparse.Namespace) -> int:
    manifest = load_manifest(args.manifest, allow_missing=True)
    by_hash = {item["sha256"]: item for item in manifest["reports"]}
    for probe in probe_inputs(args.inputs):
        action = classify(probe, by_hash)
        result = {**probe, "action": action, "dry_run": True}
        if probe["sha256"] in by_hash:
            result["disposition"] = by_hash[probe["sha256"]]["disposition"]
        emit(result)
    return 0


def command_register(args: argparse.Namespace) -> int:
    probes = probe_inputs(args.inputs)
    manifest = load_manifest(args.manifest, allow_missing=True)
    by_hash = {item["sha256"]: item for item in manifest["reports"]}
    if all(classify(probe, by_hash) in {"skip", "resume"} for probe in probes):
        for probe in probes:
            emit({**probe, "action": classify(probe, by_hash), "dry_run": False,
                  "disposition": by_hash[probe["sha256"]]["disposition"]})
        return 0
    # A writer must reload after acquiring the lock; the preflight is a snapshot.
    with manifest_lock(args.manifest):
        manifest = load_manifest(args.manifest, allow_missing=True)
        by_hash = {item["sha256"]: item for item in manifest["reports"]}
        results = []
        changed = False
        for probe in probes:
            action = classify(probe, by_hash)
            result = {**probe, "action": action, "dry_run": False}
            existing = by_hash.get(probe["sha256"])
            if existing is not None:
                result["disposition"] = existing["disposition"]
            else:
                record = {
                    "sha256": probe["sha256"],
                    "filename": Path(probe["path"]).name,
                    "byte_size": probe["byte_size"],
                    "registered_at": utc_now(),
                    "title": None,
                    "auditor": None,
                    "report_date": None,
                    "ecosystem_scope": None,
                    "disposition": "pending_review",
                    "corpus_refs": [],
                    "notes": "",
                    "legacy_backfill": False,
                }
                manifest["reports"].append(record)
                by_hash[record["sha256"]] = record
                result["disposition"] = "pending_review"
                changed = True
            results.append(result)
        if changed:
            atomic_write_manifest(args.manifest, manifest)
        for result in results:
            emit(result)
    return 0


def command_finalize(args: argparse.Namespace) -> int:
    if not HASH_RE.fullmatch(args.sha256):
        raise RegistryError("sha256 must be 64 lowercase hex characters")
    manifest = load_manifest(args.manifest)
    report = next((item for item in manifest["reports"] if item["sha256"] == args.sha256), None)
    if report is None:
        raise RegistryError(f"hash is not registered: {args.sha256}")
    if report["disposition"] in TERMINAL_DISPOSITIONS:
        emit({"action": "skip", "sha256": args.sha256, "disposition": report["disposition"]})
        return 0
    with manifest_lock(args.manifest):
        manifest = load_manifest(args.manifest)
        report = next(
            (item for item in manifest["reports"] if item["sha256"] == args.sha256),
            None,
        )
        if report is None:
            raise RegistryError(f"hash is not registered: {args.sha256}")
        if report["disposition"] in TERMINAL_DISPOSITIONS:
            emit(
                {
                    "action": "skip",
                    "sha256": args.sha256,
                    "disposition": report["disposition"],
                }
            )
            return 0
        updated = dict(report)
        updated.update(
            {
                "title": args.title if args.title is not None else report["title"],
                "auditor": args.auditor if args.auditor is not None else report["auditor"],
                "report_date": (
                    args.report_date if args.report_date is not None else report["report_date"]
                ),
                "ecosystem_scope": (
                    args.ecosystem_scope
                    if args.ecosystem_scope is not None
                    else report["ecosystem_scope"]
                ),
                "disposition": args.disposition,
                "corpus_refs": args.corpus_ref or report["corpus_refs"],
                "notes": args.notes if args.notes is not None else report["notes"],
            }
        )
        report.clear()
        report.update(updated)
        atomic_write_manifest(args.manifest, manifest)
        emit(
            {
                "action": "registered",
                "sha256": args.sha256,
                "disposition": args.disposition,
            }
        )
    return 0


def command_validate(args: argparse.Namespace) -> int:
    manifest = load_manifest(args.manifest)
    emit(
        {
            "action": "skip",
            "valid": True,
            "reports": len(manifest["reports"]),
            "legacy_unhashed_sources": len(manifest["legacy_unhashed_sources"]),
        }
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = RegistryParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    for name, function in (("scan", command_scan), ("register", command_register)):
        subparser = subparsers.add_parser(name)
        subparser.add_argument("inputs", nargs="+")
        subparser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
        subparser.set_defaults(function=function)

    finalize = subparsers.add_parser("finalize")
    finalize.add_argument("sha256")
    finalize.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    finalize.add_argument("--disposition", choices=sorted(DISPOSITIONS - {"pending_review"}), required=True)
    finalize.add_argument("--title")
    finalize.add_argument("--auditor")
    finalize.add_argument("--report-date")
    finalize.add_argument("--ecosystem-scope")
    finalize.add_argument("--corpus-ref", action="append", default=[])
    finalize.add_argument("--notes")
    finalize.set_defaults(function=command_finalize)

    validate = subparsers.add_parser("validate")
    validate.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    validate.set_defaults(function=command_validate)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
        args.manifest = args.manifest.resolve()
        return args.function(args)
    except RegistryError as exc:
        emit({"action": "invalid", "error": str(exc)})
        return 3 if "manifest" in str(exc).lower() else 2
    except (OSError, UnicodeError, ValueError, RecursionError, RuntimeError) as exc:
        emit({"action": "invalid", "error": str(exc)})
        return 2


if __name__ == "__main__":
    sys.exit(main())
