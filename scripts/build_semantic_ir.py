#!/usr/bin/env python3
"""Build a deterministic, evidence-linked semantic IR for a NEAR audit target.

The portable extractor intentionally uses only the Python standard library.  It
does not claim compiler completeness: uncertain macro, dynamic, and dependency
edges are retained in ``unresolved_edges`` and routed back to human/agent review.
When Cargo metadata, an ABI, or a built Wasm already exists, those artifacts are
consumed read-only as additional evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Iterator

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11
    tomllib = None  # type: ignore[assignment]

from source_inventory import SOURCE_SUFFIXES, discover, discover_artifacts, iter_files, validate_root


SCHEMA_VERSION = 1
CALL_EXCLUSIONS = {
    "as",
    "assert",
    "assert_eq",
    "assert_ne",
    "break",
    "catch",
    "else",
    "for",
    "format",
    "if",
    "into",
    "loop",
    "match",
    "move",
    "panic",
    "print",
    "println",
    "require",
    "return",
    "sizeof",
    "Some",
    "Ok",
    "Err",
    "vec",
    "while",
}
WRITE_METHODS = {
    "append",
    "clear",
    "extend",
    "flush",
    "get_mut",
    "insert",
    "pop",
    "pop_back",
    "pop_front",
    "push",
    "push_back",
    "remove",
    "replace",
    "set",
    "swap_remove",
    "take",
}
AUTH_PATTERNS = {
    "predecessor": re.compile(r"(?:env::)?predecessor_account_id\s*\("),
    "signer": re.compile(r"(?:env::)?signer_account_id\s*\("),
    "current_account": re.compile(r"(?:env::)?current_account_id\s*\("),
    "private_macro": re.compile(r"#\[\s*private\s*\]"),
    "one_yocto": re.compile(r"assert_one_yocto|one[_ -]?yocto", re.I),
    "attached_deposit": re.compile(r"attached_deposit\s*\("),
    "state_exists": re.compile(r"state_exists\s*\("),
    "role_guard": re.compile(r"(?:assert|require)!?\s*\([^\n]*(?:owner|admin|role|operator)", re.I),
}
SERIAL_PATTERNS = {
    "borsh": re.compile(r"Borsh(?:Serialize|Deserialize)|try_from_slice|borsh::", re.I),
    "json": re.compile(r"serde_json|JSON\.parse|json!\s*\(|serializer\s*\(\s*json", re.I),
    "base64": re.compile(r"Base64VecU8|base64", re.I),
    "raw_bytes": re.compile(r"read_register|input\s*\(|value_return|Vec\s*<\s*u8", re.I),
}
VALUE_PATTERNS = {
    "native_transfer": re.compile(r"\.transfer\s*\(|TransferAction|Promise::new", re.I),
    "attached_deposit": re.compile(r"attached_deposit\s*\(", re.I),
    "fungible_token": re.compile(r"\bft_(?:transfer|transfer_call|on_transfer|resolve_transfer)\b", re.I),
    "non_fungible_token": re.compile(r"\bnft_(?:transfer|transfer_call|on_transfer|resolve_transfer)\b", re.I),
    "mint_burn": re.compile(r"\b(?:mint|burn)(?:_internal)?\s*\(", re.I),
    "storage_payment": re.compile(r"storage_(?:deposit|withdraw|unregister)|storage_usage|storage_byte_cost", re.I),
}


def sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def canonical_hash(value: object) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return sha256_bytes(raw)


def line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def mask_comments_and_strings(text: str) -> str:
    """Replace comments/string contents with spaces while preserving offsets."""

    chars = list(text)
    index = 0
    state = "code"
    block_depth = 0
    raw_hashes = 0
    while index < len(chars):
        current = chars[index]
        nxt = chars[index + 1] if index + 1 < len(chars) else ""
        if state == "code":
            if current == "/" and nxt == "/":
                chars[index] = chars[index + 1] = " "
                index += 2
                state = "line_comment"
                continue
            if current == "/" and nxt == "*":
                chars[index] = chars[index + 1] = " "
                block_depth = 1
                index += 2
                state = "block_comment"
                continue
            if current == "\"":
                chars[index] = " "
                index += 1
                state = "string"
                continue
            if current == "'" and index + 2 < len(chars):
                # Lifetime tokens are not character literals.
                end = text.find("'", index + 1, min(len(text), index + 8))
                if end != -1:
                    for cursor in range(index, end + 1):
                        if chars[cursor] != "\n":
                            chars[cursor] = " "
                    index = end + 1
                    continue
            if current == "r":
                match = re.match(r'r(#{0,16})"', text[index:])
                if match:
                    raw_hashes = len(match.group(1))
                    for cursor in range(index, index + len(match.group(0))):
                        chars[cursor] = " "
                    index += len(match.group(0))
                    state = "raw_string"
                    continue
        elif state == "line_comment":
            if current == "\n":
                state = "code"
            else:
                chars[index] = " "
        elif state == "block_comment":
            if current == "/" and nxt == "*":
                chars[index] = chars[index + 1] = " "
                block_depth += 1
                index += 2
                continue
            if current == "*" and nxt == "/":
                chars[index] = chars[index + 1] = " "
                block_depth -= 1
                index += 2
                if block_depth == 0:
                    state = "code"
                continue
            if current != "\n":
                chars[index] = " "
        elif state == "string":
            if current == "\\" and nxt:
                chars[index] = chars[index + 1] = " "
                index += 2
                continue
            if current == "\"":
                chars[index] = " "
                state = "code"
            elif current != "\n":
                chars[index] = " "
        elif state == "raw_string":
            terminator = '"' + "#" * raw_hashes
            if text.startswith(terminator, index):
                for cursor in range(index, index + len(terminator)):
                    chars[cursor] = " "
                index += len(terminator)
                state = "code"
                continue
            if current != "\n":
                chars[index] = " "
        index += 1
    return "".join(chars)


def matching_delimiter(text: str, start: int, opening: str, closing: str) -> int | None:
    depth = 0
    for index in range(start, len(text)):
        if text[index] == opening:
            depth += 1
        elif text[index] == closing:
            depth -= 1
            if depth == 0:
                return index
    return None


def attributes_before(masked: str, start: int) -> list[str]:
    prefix = masked[max(0, start - 2000) : start]
    lines = prefix.splitlines()
    selected: list[str] = []
    for value in reversed(lines):
        stripped = value.strip()
        if not stripped:
            if selected:
                break
            continue
        if stripped.startswith("#[") or (selected and stripped.startswith(("cfg", "feature", "="))):
            selected.append(stripped)
            continue
        break
    return list(reversed(selected))


def iter_containers(masked: str) -> Iterator[dict[str, object]]:
    pattern = re.compile(r"\b(?P<kind>impl|trait|mod)\s+(?P<head>[^\{;\n]+)\{")
    for match in pattern.finditer(masked):
        brace = masked.find("{", match.start(), match.end())
        end = matching_delimiter(masked, brace, "{", "}")
        if end is None:
            continue
        yield {
            "kind": match.group("kind"),
            "head": " ".join(match.group("head").split()),
            "start": match.start(),
            "end": end,
            "attributes": attributes_before(masked, match.start()),
        }


def containing_container(containers: list[dict[str, object]], offset: int) -> dict[str, object] | None:
    matches = [item for item in containers if int(item["start"]) < offset < int(item["end"])]
    return min(matches, key=lambda item: int(item["end"]) - int(item["start"])) if matches else None


def iter_functions(masked: str) -> Iterator[tuple[re.Match[str], int | None, int | None]]:
    pattern = re.compile(
        r"(?P<visibility>\bpub(?:\s*\([^\)]*\))?\s+)?"
        r"(?P<async>\basync\s+)?(?:unsafe\s+)?(?:extern\s+\"[^\"]+\"\s+)?"
        r"\bfn\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*"
    )
    for match in pattern.finditer(masked):
        paren = masked.find("(", match.end())
        if paren < 0:
            continue
        params_end = matching_delimiter(masked, paren, "(", ")")
        if params_end is None:
            continue
        cursor = params_end + 1
        angle_depth = 0
        while cursor < len(masked):
            char = masked[cursor]
            if char == "<":
                angle_depth += 1
            elif char == ">" and angle_depth:
                angle_depth -= 1
            elif char == ";" and angle_depth == 0:
                yield match, None, None
                break
            elif char == "{" and angle_depth == 0:
                body_end = matching_delimiter(masked, cursor, "{", "}")
                yield match, cursor, body_end
                break
            cursor += 1


def rust_file_ir(root: Path, path: Path) -> dict[str, object]:
    data = path.read_bytes()
    text = data.decode("utf-8", errors="replace").replace("\r\n", "\n").replace("\r", "\n")
    masked = mask_comments_and_strings(text)
    containers = list(iter_containers(masked))
    relative = path.relative_to(root).as_posix()
    symbols: list[dict[str, object]] = []
    state_accesses: list[dict[str, object]] = []
    calls: list[dict[str, object]] = []
    receipt_edges: list[dict[str, object]] = []
    authority_edges: list[dict[str, object]] = []
    value_flows: list[dict[str, object]] = []
    serialization_boundaries: list[dict[str, object]] = []

    for match, body_start, body_end in iter_functions(masked):
        name = match.group("name")
        container = containing_container(containers, match.start())
        container_name = str(container["head"]) if container else None
        attrs = attributes_before(masked, match.start())
        container_attrs = list(container.get("attributes", [])) if container else []
        all_attrs = attrs + container_attrs
        is_private = any(re.search(r"\bprivate\b", value) for value in attrs)
        near_annotated = any(re.search(r"near(?:_bindgen)?\b", value) for value in all_attrs)
        public = bool(match.group("visibility"))
        export = public and near_annotated and not is_private
        start_line = line_number(text, match.start())
        end_offset = body_end if body_end is not None else match.end()
        end_line = line_number(text, end_offset)
        symbol_id = f"{relative}::{container_name + '::' if container_name else ''}{name}"
        symbol = {
            "symbol_id": symbol_id,
            "name": name,
            "kind": "method" if container and container["kind"] == "impl" else "function",
            "path": relative,
            "container": container_name,
            "visibility": "public" if public else "private",
            "attributes": attrs,
            "async": bool(match.group("async")),
            "export": export,
            "export_evidence": "source-annotation" if near_annotated else "none",
            "start": start_line,
            "end": end_line,
            "body_present": body_start is not None and body_end is not None,
        }
        symbols.append(symbol)
        if body_start is None or body_end is None:
            continue
        body_masked = masked[body_start + 1 : body_end]
        body_text = text[body_start + 1 : body_end]
        body_base = body_start + 1

        for access in re.finditer(r"\bself\s*\.\s*(?P<field>[A-Za-z_][A-Za-z0-9_]*)", body_masked):
            tail = body_masked[access.end() : access.end() + 80]
            write = bool(
                re.match(r"\s*(?:[+\-*/]?=|\.\s*(?:" + "|".join(sorted(WRITE_METHODS)) + r")\s*\()", tail)
            )
            state_accesses.append(
                {
                    "symbol_id": symbol_id,
                    "field": access.group("field"),
                    "access": "write" if write else "read",
                    "path": relative,
                    "line": line_number(text, body_base + access.start()),
                    "evidence": text[body_base + access.start() : body_base + access.end()],
                }
            )

        for call in re.finditer(
            r"(?:(?P<receiver>self|Self|[A-Za-z_][A-Za-z0-9_]*)\s*\.\s*)?"
            r"(?P<callee>[A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)*)\s*\(",
            body_masked,
        ):
            callee = call.group("callee")
            if callee in CALL_EXCLUSIONS:
                continue
            calls.append(
                {
                    "caller": symbol_id,
                    "callee": callee,
                    "receiver": call.group("receiver"),
                    "path": relative,
                    "line": line_number(text, body_base + call.start()),
                    "resolution": "pending",
                }
            )

        promise_markers = list(
            re.finditer(
                r"Promise::new\s*\(|\.\s*(?:then|and)\s*\(|\bext(?:_[A-Za-z0-9_]+)?\s*::\s*ext\s*\(|"
                r"promise_(?:create|batch|yield|return)|PromiseOrValue",
                body_masked,
            )
        )
        for marker in promise_markers:
            nearby = body_text[max(0, marker.start() - 120) : marker.end() + 220]
            callback = None
            callback_match = re.search(r"\.\s*(on_[A-Za-z0-9_]+|after_[A-Za-z0-9_]+|resolve_[A-Za-z0-9_]+)\s*\(", nearby)
            if callback_match:
                callback = callback_match.group(1)
            receipt_edges.append(
                {
                    "from_symbol": symbol_id,
                    "kind": "yield" if "yield" in marker.group(0) else "promise",
                    "callback": callback,
                    "path": relative,
                    "line": line_number(text, body_base + marker.start()),
                    "evidence": " ".join(nearby.split())[:400],
                }
            )

        for authority, pattern in AUTH_PATTERNS.items():
            for found in pattern.finditer(body_text):
                authority_edges.append(
                    {
                        "symbol_id": symbol_id,
                        "authority": authority,
                        "path": relative,
                        "line": line_number(text, body_base + found.start()),
                        "evidence": " ".join(body_text[found.start() : found.start() + 180].split()),
                    }
                )
        if is_private:
            authority_edges.append(
                {
                    "symbol_id": symbol_id,
                    "authority": "private_macro",
                    "path": relative,
                    "line": start_line,
                    "evidence": "#[private]",
                }
            )

        for flow_kind, pattern in VALUE_PATTERNS.items():
            for found in pattern.finditer(body_text):
                value_flows.append(
                    {
                        "symbol_id": symbol_id,
                        "flow_kind": flow_kind,
                        "path": relative,
                        "line": line_number(text, body_base + found.start()),
                        "evidence": " ".join(body_text[found.start() : found.start() + 180].split()),
                    }
                )
        for serial_kind, pattern in SERIAL_PATTERNS.items():
            for found in pattern.finditer(body_text):
                serialization_boundaries.append(
                    {
                        "symbol_id": symbol_id,
                        "serialization": serial_kind,
                        "path": relative,
                        "line": line_number(text, body_base + found.start()),
                        "evidence": " ".join(body_text[found.start() : found.start() + 180].split()),
                    }
                )

    return {
        "path": relative,
        "language": "rust",
        "sha256": sha256_bytes(data),
        "lines": text.count("\n") + (0 if text.endswith("\n") else 1),
        "symbols": symbols,
        "state_accesses": state_accesses,
        "call_edges": calls,
        "receipt_edges": receipt_edges,
        "authority_edges": authority_edges,
        "value_flows": value_flows,
        "serialization_boundaries": serialization_boundaries,
    }


def generic_file_ir(root: Path, path: Path) -> dict[str, object]:
    data = path.read_bytes()
    text = data.decode("utf-8", errors="replace").replace("\r\n", "\n").replace("\r", "\n")
    relative = path.relative_to(root).as_posix()
    symbols = []
    for match in re.finditer(
        r"(?:export\s+)?(?:async\s+)?(?:function\s+|(?:const|let|var)\s+)"
        r"(?P<name>[A-Za-z_$][A-Za-z0-9_$]*)",
        text,
    ):
        symbols.append(
            {
                "symbol_id": f"{relative}::{match.group('name')}",
                "name": match.group("name"),
                "kind": "function",
                "path": relative,
                "container": None,
                "visibility": "public" if "export" in match.group(0) else "unknown",
                "attributes": [],
                "async": "async" in match.group(0),
                "export": "export" in match.group(0),
                "export_evidence": "source-keyword" if "export" in match.group(0) else "none",
                "start": line_number(text, match.start()),
                "end": line_number(text, match.end()),
                "body_present": True,
            }
        )
    return {
        "path": relative,
        "language": path.suffix.lower().lstrip("."),
        "sha256": sha256_bytes(data),
        "lines": text.count("\n") + (0 if text.endswith("\n") else 1),
        "symbols": symbols,
        "state_accesses": [],
        "call_edges": [],
        "receipt_edges": [],
        "authority_edges": [],
        "value_flows": [],
        "serialization_boundaries": [],
    }


def cargo_manifests(root: Path) -> tuple[list[dict[str, object]], dict[str, object]]:
    root = validate_root(root)
    manifests: list[dict[str, object]] = []
    for path in sorted(path for path in iter_files(root) if path.name == "Cargo.toml"):
        relative = path.relative_to(root)
        data = path.read_bytes()
        row: dict[str, object] = {
            "path": relative.as_posix(),
            "sha256": sha256_bytes(data),
        }
        if tomllib is not None:
            try:
                parsed = tomllib.loads(data.decode("utf-8"))
                package = parsed.get("package", {})
                row["package"] = package.get("name")
                row["version"] = package.get("version")
                row["edition"] = package.get("edition")
                row["features"] = sorted(parsed.get("features", {}))
                row["dependencies"] = sorted(parsed.get("dependencies", {}))
                row["release_profile"] = parsed.get("profile", {}).get("release", {})
            except (OSError, ValueError) as exc:
                row["parse_error"] = str(exc)
        manifests.append(row)

    metadata: dict[str, object] = {"status": "not_available", "packages": []}
    cargo = shutil.which("cargo")
    # Do not let Cargo search an ancestor workspace when no root manifest exists,
    # or follow a symlink for its local lock/config inputs.
    cargo_links = any((root / name).is_symlink() for name in (
        "Cargo.lock", ".cargo", ".cargo/config", ".cargo/config.toml",
    ))
    if cargo_links:
        metadata = {"status": "blocked", "reason": "symlink Cargo lock/config input", "packages": []}
    elif any(row["path"] == "Cargo.toml" for row in manifests) and cargo:
        try:
            result = subprocess.run(
                [cargo, "metadata", "--frozen", "--offline", "--no-deps", "--format-version", "1"],
                cwd=root,
                text=True,
                capture_output=True,
                timeout=20,
                check=False,
            )
            if result.returncode == 0:
                parsed = json.loads(result.stdout)
                metadata = {
                    "status": "complete",
                    "workspace_root": parsed.get("workspace_root"),
                    "target_directory": parsed.get("target_directory"),
                    "packages": [
                        {
                            "name": package.get("name"),
                            "version": package.get("version"),
                            "manifest_path": package.get("manifest_path"),
                            "targets": package.get("targets", []),
                            "features": sorted(package.get("features", {})),
                        }
                        for package in parsed.get("packages", [])
                    ],
                }
            else:
                metadata = {"status": "blocked", "reason": result.stderr.strip()[:1000], "packages": []}
        except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
            metadata = {"status": "blocked", "reason": str(exc), "packages": []}
    return manifests, metadata


def read_varuint(data: bytes, offset: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while offset < len(data):
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, offset
        shift += 7
        if shift > 35:
            break
    raise ValueError("invalid Wasm varuint")


def wasm_exports(path: Path, data: bytes | None = None) -> list[dict[str, object]]:
    if data is None:
        data = path.read_bytes()
    if not data.startswith(b"\x00asm"):
        raise ValueError("not a Wasm module")
    offset = 8
    exports: list[dict[str, object]] = []
    while offset < len(data):
        section_id = data[offset]
        offset += 1
        size, offset = read_varuint(data, offset)
        end = offset + size
        if section_id == 7:
            count, cursor = read_varuint(data, offset)
            for _ in range(count):
                length, cursor = read_varuint(data, cursor)
                name = data[cursor : cursor + length].decode("utf-8", errors="replace")
                cursor += length
                kind = data[cursor]
                cursor += 1
                index, cursor = read_varuint(data, cursor)
                exports.append({"name": name, "kind": kind, "index": index})
            return exports
        offset = end
    return exports


def artifact_evidence(root: Path) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    root = validate_root(root)
    abis: list[dict[str, object]] = []
    wasms: list[dict[str, object]] = []
    for path in discover_artifacts(root):
        relative = path.relative_to(root)
        if path.suffix.lower() == ".json":
            try:
                data = path.read_bytes()
                payload = json.loads(data.decode("utf-8"))
                abis.append(
                    {
                        "path": relative.as_posix(),
                        "sha256": sha256_bytes(data),
                        "functions": payload.get("body", {}).get("functions", [])
                        if isinstance(payload, dict)
                        else [],
                    }
                )
            except (OSError, ValueError):
                continue
        if path.suffix.lower() == ".wasm":
            try:
                data = path.read_bytes()
                wasms.append(
                    {
                        "path": relative.as_posix(),
                        "sha256": sha256_bytes(data),
                        "exports": wasm_exports(path, data),
                    }
                )
            except (OSError, ValueError):
                continue
    return abis, wasms


def resolve_calls(files: list[dict[str, object]]) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    symbols = [symbol for file in files for symbol in file["symbols"]]
    by_name: dict[str, list[str]] = {}
    for symbol in symbols:
        by_name.setdefault(str(symbol["name"]), []).append(str(symbol["symbol_id"]))
    edges: list[dict[str, object]] = []
    unresolved: list[dict[str, object]] = []
    for file in files:
        for edge in file["call_edges"]:
            callee = str(edge["callee"]).split("::")[-1]
            matches = sorted(by_name.get(callee, []))
            value = dict(edge)
            if len(matches) == 1:
                value["resolution"] = "resolved"
                value["to_symbol"] = matches[0]
            elif len(matches) > 1:
                value["resolution"] = "ambiguous"
                value["candidate_symbols"] = matches
                unresolved.append(
                    {
                        "kind": "ambiguous_call",
                        "from_symbol": value["caller"],
                        "name": edge["callee"],
                        "candidate_symbols": matches,
                        "path": edge["path"],
                        "line": edge["line"],
                    }
                )
            else:
                value["resolution"] = "external_or_builtin"
            edges.append(value)
    return edges, unresolved


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("files", nargs="*", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        root = validate_root(args.root)
        source_files = discover(root, args.files)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    if not source_files:
        parser.error("no in-scope source files found")

    file_rows: list[dict[str, object]] = []
    for path in source_files:
        if path.suffix.lower() == ".rs":
            file_rows.append(rust_file_ir(root, path))
        elif path.suffix.lower() in SOURCE_SUFFIXES:
            file_rows.append(generic_file_ir(root, path))

    manifests, metadata = cargo_manifests(root)
    abis, wasms = artifact_evidence(root)
    calls, unresolved = resolve_calls(file_rows)
    for file in file_rows:
        file.pop("call_edges", None)

    all_symbols = sorted(
        [symbol for file in file_rows for symbol in file["symbols"]],
        key=lambda item: str(item["symbol_id"]),
    )
    exports = [item for item in all_symbols if item["export"]]
    abi_exports = sorted(
        {
            function.get("name")
            for abi in abis
            for function in abi.get("functions", [])
            if isinstance(function, dict) and function.get("name")
        }
    )
    wasm_export_names = sorted(
        {str(item["name"]) for wasm in wasms for item in wasm.get("exports", [])}
    )
    source_export_names = sorted({str(item["name"]) for item in exports})
    for name in sorted(set(abi_exports + wasm_export_names) - set(source_export_names)):
        unresolved.append(
            {
                "kind": "artifact_export_without_source_export",
                "name": name,
                "evidence": "abi_or_wasm",
            }
        )
    for name in sorted(set(source_export_names) - set(abi_exports + wasm_export_names)):
        if abis or wasms:
            unresolved.append(
                {
                    "kind": "source_export_without_artifact_export",
                    "name": name,
                    "evidence": "source_annotation",
                }
            )

    content_items = [
        {"path": file["path"], "sha256": file["sha256"]} for file in file_rows
    ] + [{"path": item["path"], "sha256": item["sha256"]} for item in manifests]
    lock = root / "Cargo.lock"
    if not lock.is_symlink() and lock.is_file():
        content_items.append({"path": "Cargo.lock", "sha256": sha256_bytes(lock.read_bytes())})
    extractor_hash = sha256_bytes(Path(__file__).read_bytes())

    payload = {
        "schema_version": SCHEMA_VERSION,
        "extractor": "near-semantic-ir-portable",
        "extractor_hash": extractor_hash,
        "target_root": str(root),
        "content_fingerprint": canonical_hash(sorted(content_items, key=lambda item: item["path"])),
        "files": file_rows,
        "manifests": manifests,
        "cargo_metadata": metadata,
        "symbols": all_symbols,
        "exports": exports,
        "call_edges": sorted(calls, key=lambda item: (str(item["caller"]), int(item["line"]))),
        "state_accesses": sorted(
            [item for file in file_rows for item in file["state_accesses"]],
            key=lambda item: (str(item["symbol_id"]), int(item["line"])),
        ),
        "receipt_edges": sorted(
            [item for file in file_rows for item in file["receipt_edges"]],
            key=lambda item: (str(item["from_symbol"]), int(item["line"])),
        ),
        "authority_edges": sorted(
            [item for file in file_rows for item in file["authority_edges"]],
            key=lambda item: (str(item["symbol_id"]), int(item["line"])),
        ),
        "value_flows": sorted(
            [item for file in file_rows for item in file["value_flows"]],
            key=lambda item: (str(item["symbol_id"]), int(item["line"])),
        ),
        "serialization_boundaries": sorted(
            [item for file in file_rows for item in file["serialization_boundaries"]],
            key=lambda item: (str(item["symbol_id"]), int(item["line"])),
        ),
        "abi_artifacts": abis,
        "wasm_artifacts": wasms,
        "unresolved_edges": sorted(unresolved, key=lambda item: json.dumps(item, sort_keys=True)),
        "coverage": {
            "source_files": len(file_rows),
            "symbols": len(all_symbols),
            "source_exports": len(exports),
            "resolved_calls": sum(item["resolution"] == "resolved" for item in calls),
            "ambiguous_calls": sum(item["resolution"] == "ambiguous" for item in calls),
            "receipt_edges": sum(len(file["receipt_edges"]) for file in file_rows),
            "unresolved_edges": len(unresolved),
            "cargo_metadata": metadata["status"],
            "abi_artifacts": len(abis),
            "wasm_artifacts": len(wasms),
        },
    }
    rendered = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
