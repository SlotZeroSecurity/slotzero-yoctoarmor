#!/usr/bin/env python3
"""Validate the bundled NEP registry and optionally compare a local near/NEPs checkout."""

from __future__ import annotations

from reference_paths import reference_relative

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
KNOWN_STATUSES = {"Final", "Approved", "Draft", "New"}


def fail(message: str) -> None:
    raise ValueError(message)


def parse_frontmatter(path: Path) -> dict[str, str]:
    text = path.read_text(encoding="utf-8", errors="replace")
    match = re.match(r"---\n(.*?)\n---", text, re.DOTALL)
    if not match:
        fail(f"{path}: missing YAML-style frontmatter")
    result: dict[str, str] = {}
    for line in match.group(1).splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        result[key.strip()] = value.strip().strip("\"'")
    return result


def parse_ids(value: str | None) -> list[str]:
    if not value:
        return []
    result: list[str] = []
    for item in value.split(","):
        match = re.search(r"\d+", item)
        if match:
            result.append(f"{int(match.group()):04d}")
    return result


def validate_registry(path: Path, *, package_root: Path | None = None) -> dict[str, object]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema_version") != 1:
        fail("registry: unsupported schema_version")
    source = data.get("source")
    categories = data.get("categories")
    neps = data.get("neps")
    if not isinstance(source, dict) or not isinstance(categories, dict) or not isinstance(neps, dict):
        fail("registry: source, categories, and neps must be objects")
    commit = source.get("commit")
    if not isinstance(commit, str) or not COMMIT_RE.fullmatch(commit):
        fail("registry: source commit must be a full 40-character hash")
    expected_count = source.get("document_count")
    if expected_count != len(neps):
        fail(f"registry: document_count={expected_count} but neps={len(neps)}")

    owned: list[str] = []
    skill_root = Path(__file__).resolve().parents[1] if package_root is None else package_root
    for category_id, category in categories.items():
        if not isinstance(category, dict):
            fail(f"category {category_id}: expected object")
        role_id = category.get("role_id")
        checklist = category.get("checklist")
        ids = category.get("ids")
        if not isinstance(role_id, str) or not role_id:
            fail(f"category {category_id}: missing role_id")
        if not isinstance(checklist, str) or not checklist:
            fail(f"category {category_id}: missing checklist")
        if not (skill_root / checklist).is_file():
            fail(f"category {category_id}: missing checklist file {checklist}")
        if not isinstance(ids, list) or not all(isinstance(item, str) for item in ids):
            fail(f"category {category_id}: ids must be strings")
        owned.extend(ids)
    duplicates = sorted({item for item in owned if owned.count(item) > 1})
    if duplicates:
        fail(f"registry: duplicate category ownership {duplicates}")
    if set(owned) != set(neps):
        fail(
            f"registry: category coverage mismatch missing={sorted(set(neps) - set(owned))} "
            f"unknown={sorted(set(owned) - set(neps))}"
        )

    for nep_id, row in neps.items():
        if not re.fullmatch(r"\d{4}", nep_id):
            fail(f"registry: invalid NEP id {nep_id!r}")
        if not isinstance(row, dict):
            fail(f"NEP-{nep_id}: expected object")
        for field in ("title", "status", "type", "category", "activation", "version_gate"):
            if not isinstance(row.get(field), str) or not row[field]:
                fail(f"NEP-{nep_id}: missing {field}")
        if row["status"] not in KNOWN_STATUSES:
            fail(f"NEP-{nep_id}: unknown status {row['status']!r}")
        category_id = row["category"]
        if category_id not in categories or nep_id not in categories[category_id]["ids"]:
            fail(f"NEP-{nep_id}: category ownership mismatch")
        for field in ("requires", "supersedes", "superseded_by", "signals"):
            if not isinstance(row.get(field), list) or not all(
                isinstance(item, str) for item in row[field]
            ):
                fail(f"NEP-{nep_id}: {field} must be a string list")
        missing_dependencies = sorted(set(row["requires"]) - set(neps))
        if missing_dependencies:
            fail(f"NEP-{nep_id}: missing required NEPs {missing_dependencies}")
        missing_replacements = sorted(set(row["superseded_by"]) - set(neps))
        if missing_replacements:
            fail(f"NEP-{nep_id}: missing replacement NEPs {missing_replacements}")
        digest = row.get("source_sha256")
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            fail(f"NEP-{nep_id}: invalid source_sha256")
    return data


def compare_checkout(data: dict[str, object], root: Path) -> dict[str, object]:
    neps_root = root / "neps"
    if not neps_root.is_dir():
        fail(f"source root lacks neps/: {root}")
    files = sorted(neps_root.glob("nep-*.md"))
    actual: dict[str, dict[str, object]] = {}
    for path in files:
        meta = parse_frontmatter(path)
        raw_id = meta.get("NEP") or path.stem.split("-", 1)[1]
        nep_id = f"{int(raw_id):04d}"
        actual[nep_id] = {
            "title": meta.get("Title"),
            "status": meta.get("Status"),
            "type": meta.get("Type"),
            "requires": parse_ids(meta.get("Requires")),
            "supersedes": parse_ids(meta.get("Replaces")),
            "superseded_by": parse_ids(meta.get("SupersededBy")),
            "source_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }
    expected = data["neps"]
    changes: list[dict[str, object]] = []
    for nep_id in sorted(set(actual) | set(expected)):
        if nep_id not in expected:
            changes.append({"nep_id": nep_id, "change": "added_in_source"})
            continue
        if nep_id not in actual:
            changes.append({"nep_id": nep_id, "change": "missing_from_source"})
            continue
        for field in (
            "title",
            "status",
            "type",
            "requires",
            "supersedes",
            "superseded_by",
            "source_sha256",
        ):
            if actual[nep_id][field] != expected[nep_id][field]:
                changes.append(
                    {
                        "nep_id": nep_id,
                        "change": field,
                        "expected": expected[nep_id][field],
                        "actual": actual[nep_id][field],
                    }
                )
    try:
        commit = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            check=True,
            text=True,
            capture_output=True,
        ).stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        commit = None
    expected_commit = data["source"]["commit"]
    if commit != expected_commit:
        changes.insert(
            0,
            {
                "change": "commit",
                "expected": expected_commit,
                "actual": commit,
            },
        )
    return {"source_documents": len(actual), "source_commit": commit, "changes": changes}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "registry",
        nargs="?",
        type=Path,
        default=Path(__file__).resolve().parent.parent / reference_relative('nep_registry'),
    )
    parser.add_argument(
        "--source-root",
        type=Path,
        help="Optional local checkout of near/NEPs to compare without network access.",
    )
    args = parser.parse_args()
    data = validate_registry(args.registry.resolve())
    result: dict[str, object] = {
        "registry_documents": len(data["neps"]),
        "source_commit": data["source"]["commit"],
        "refresh_status": "current",
        "complete": True,
    }
    if args.source_root:
        comparison = compare_checkout(data, args.source_root.resolve())
        result["checkout"] = comparison
        if comparison["changes"]:
            result["complete"] = False
            result["refresh_status"] = "needs_semantic_review"
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return 1
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
