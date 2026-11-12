#!/usr/bin/env python3
"""Extract finding titles and provenance from the NEAR Markdown report corpus.

This intentionally performs syntactic extraction only. Semantic classification and
deduplication live in the curated canonical taxonomy bundled with the skill.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import tempfile
from pathlib import Path


SEVERITIES = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "informational": "Informational",
    "informaitonal": "Informational",
    "quality assurance": "Informational",
}

GUV_RE = re.compile(
    r"^GUV-(\d+)\s+(.+?)(?:\s*-\s*(Critical|High|Medium|Low|Informational|Informaitonal))?\s*$",
    re.I,
)
SEVERITY_HEADING_RE = re.compile(
    r"^(Critical|High|Medium|Low|Informational)(?:\s+Risk)?\s*$", re.I
)
INLINE_SEVERITY_RE = re.compile(
    r"(?:\*\*)?Severity:(?:\*\*)?\s*(Critical|High|Medium|Low|Informational|Quality Assurance)",
    re.I,
)

CANONICAL_TITLES = {
    "NA-ASYNC-001": "Late reservation enables split-receipt double spend",
    "NA-ASYNC-002": "Missing or incomplete failure compensation",
    "NA-ASYNC-003": "Callback authority or identity mismatch",
    "NA-ASYNC-004": "Promise graph or return semantics are misinterpreted",
    "NA-ASYNC-005": "Pending state can be permanently poisoned",
    "NA-AUTH-001": "Signer/predecessor confused-deputy boundary",
    "NA-AUTH-002": "Exposed privileged or internal endpoint",
    "NA-AUTH-003": "One-yocto or function-call-key boundary is unsafe",
    "NA-AUTH-004": "Stale access key bypasses new governance",
    "NA-RESOURCE-001": "Attacker-induced storage is unpaid or underpriced",
    "NA-RESOURCE-002": "Persistent prefix collision or orphaned nested state",
    "NA-STATE-001": "Coupled indexes or lifecycle state diverge",
    "NA-STATE-002": "Read or validation path unexpectedly creates state",
    "NA-RESOURCE-005": "Unbounded work, logs, or serialization blocks operations",
    "NA-INTEGRATION-001": "Receiver hook trusts the wrong token or sender context",
    "NA-ASYNC-009": "Resolver refund or ownership semantics break conservation",
    "NA-ACCOUNT-002": "Liability, reserve, fee, or supply accounting diverges",
    "NA-ECON-002": "Rounding, precision, overflow, or unit error changes value",
    "NA-AUTH-006": "Effective upgrade authority bypasses governance",
    "NA-STATE-003": "Migration corrupts or strands persistent state",
    "NA-AUTH-007": "Signed intent replay, recomposition, or weak domain binding",
    "NA-AUTH-008": "Passkey or solver verification accepts attacker context",
    "NA-INTEGRATION-003": "Bridge finality, proof, or timeout race releases value twice",
    "NA-OFFCHAIN-001": "Indexer trusts failed, foreign, or malformed chain data",
    "NA-OFFCHAIN-002": "Relayer retry, persistence, or nonce ordering loses funds",
    "NA-STATE-004": "Protocol state-machine transition or validation is incomplete",
    "NA-INTEGRATION-005": "Stale, manipulable, or unavailable input corrupts decisions",
    "NA-OFFCHAIN-004": "Dependency, build, ABI, or release configuration changes security",
    "NA-OFFCHAIN-003": "Off-chain input or authorization reaches a dangerous sink",
    "NA-OFFCHAIN-005": "Missing or incomplete security tests",
    "NA-OFFCHAIN-006": "Missing or inconsistent security observability",
    "NA-OFFCHAIN-007": "Documentation or specification is incomplete",
    "NA-OFFCHAIN-008": "Non-material code quality or efficiency issue",
}

# Exact semantic overrides from the manual corpus review where the short report
# title does not expose the full receipt/state mechanism described in the body.
EXTRA_CLASSIFICATIONS = {
    "Potlock-NEAR-Rust-Smart-Contract-Security-Assessment:GUV-2": {
        "NA-STATE-001",
        "NA-RESOURCE-002",
    },
    "Potlock-NEAR-Rust-Smart-Contract-Security-Assessment:GUV-3": {
        "NA-AUTH-001",
        "NA-ASYNC-002",
    },
    "Ample-Protocol-NEAR-Rust-Smart-Contract-Security-Assessment:GUV-8": {
        "NA-STATE-001",
        "NA-ASYNC-009",
    },
    "DeFiShards-NEAR-Rust-Smart-Contract-Security-Assessment-Final-Report:GUV-5": {
        "NA-ACCOUNT-002",
        "NA-ASYNC-004",
    },
    "Jump-Defi-NEAR-Rust-Smart-Contract-Security-Assessment:GUV-1": {
        "NA-ACCOUNT-002",
        "NA-ASYNC-004",
    },
    "Jump-Defi-NEAR-Rust-Smart-Contract-Security-Assessment:GUV-12": {
        "NA-RESOURCE-005",
        "NA-RESOURCE-001",
    },
    "Sailor-Lend-NEAR-Smart-Contract-Security-Review-Final:GUV-5": {
        "NA-ACCOUNT-002",
    },
    "Sailor-Lend-NEAR-Smart-Contract-Security-Review-Final:GUV-11": {
        "NA-ASYNC-004",
        "NA-ASYNC-009",
    },
}


def classify(record: dict[str, object]) -> list[str]:
    """Map a reviewed historical title into the curated semantic catalog.

    These rules encode the completed 22-report taxonomy. Broad fallback groups
    preserve otherwise unmatched instances, but any future corpus addition still
    requires human review before its canonical mapping is accepted.
    """

    title = str(record["title"]).lower().replace("\\_", "_")
    report = str(record["report"]).lower()
    severity = str(record.get("source_severity") or "")
    ids: set[str] = set()

    def has(*terms: str) -> bool:
        return any(term in title for term in terms)

    if "aurorafastbridge" in report:
        if has("reorg", "proof verification", "double-unlock", "withdraw multiple", "unexpected token unlock"):
            ids.add("NA-INTEGRATION-003")
        if has("withdraw multiple", "double-unlock"):
            ids.add("NA-ASYNC-001")
        if has("message may get lost", "redis", "timeout", "wrong parameter", "limitations and risks"):
            ids.add("NA-OFFCHAIN-002")
        if has("valid_till", "lock_time", "same token_eth", "checktoken"):
            ids.add("NA-STATE-004")

    if "nearplugins" in report:
        if has("full access key", "access key"):
            ids.add("NA-AUTH-004")
        if has("timelock", "staging code", "upgradable"):
            ids.add("NA-AUTH-006")
        if "migration" in title:
            ids.add("NA-STATE-003")
        if has("pausable", "paused_key", "revoke_super_admin"):
            ids.add("NA-AUTH-002")

    if "passkeys" in report:
        ids.add("NA-AUTH-008")
    elif "near-intents-security" in report:
        if has("repeating failed intents", "nonce"):
            ids.add("NA-AUTH-007")
        elif has("public key", "access control"):
            ids.add("NA-AUTH-002")

    if "sailor-lend-web" in report:
        ids.add("NA-OFFCHAIN-004" if "react2shell" in title else "NA-OFFCHAIN-003")
    if "jump-defi-backend" in report:
        if has("sql injection", "blacklisted"):
            ids.add("NA-OFFCHAIN-003")
        elif "missing tests" in title:
            ids.add("NA-OFFCHAIN-005")
        else:
            ids.add("NA-OFFCHAIN-001")
    if "trove-labs" in report:
        if has("documentation", "modularity", "redundant"):
            ids.add("NA-OFFCHAIN-007" if "documentation" in title else "NA-OFFCHAIN-008")
        else:
            ids.add("NA-OFFCHAIN-002")

    if has("signer account", "phishing"):
        ids.add("NA-AUTH-001")
    if has("access control", "anyone can", "unasserted", "unrestricted unlend", "protocol config lacks", "privileged functions", "notification modification"):
        ids.add("NA-AUTH-002")
    if has("2fa", "one yocto", "assert_one_yocto", "1 yocto"):
        ids.add("NA-AUTH-003")
    if has("race condition", "double claim", "overlapping deferred", "ticket reuse"):
        ids.add("NA-ASYNC-001")
    if has("not returned on error", "not reverted after failed", "missing callback on withdraw", "lack of promise callback"):
        ids.add("NA-ASYNC-002")
    if has("nft transfer resolver", "custom check instead of #[private]"):
        ids.add("NA-ASYNC-003")
    if has("invalid callback", "callback does not see errors", "promise handling", "promise success"):
        ids.add("NA-ASYNC-004")
    if has("lifecycle panic", "irrecoverable", "supply withdrawal mechanism dos"):
        ids.add("NA-ASYNC-005")

    if has("storage key collision", "storage key collisions"):
        ids.add("NA-RESOURCE-002")
    if "storage" in title and has("bloat", "staking", "undercharge", "hardcoded", "refund", "deposit", "unregister"):
        ids.add("NA-RESOURCE-001")
    if has("inconsistent state", "state corruption", "retains all stamps", "does not remove", "not properly tracked"):
        ids.add("NA-STATE-001")
    if has("getter", "redundant state access"):
        ids.add("NA-STATE-002")
    if has("denial of service", " dos", "gas limit", "log limit", "batch", "prepaid gas", "missing limits", "too many", "exceesive number"):
        ids.add("NA-RESOURCE-005")

    if has("ft_transfer", "nft contract", "token lock", "royalt", "manual nft transfer", "nft burn"):
        ids.add("NA-ASYNC-009")
    if has("invalid withdraw token", "token id collision", "token ids disrupt", "same token_eth"):
        ids.add("NA-INTEGRATION-001")
    if has("accounting", "overrepayment", "unlend", "leveraged lending", "fees and interest", "liquidation", "auction", "market data", "payout"):
        ids.add("NA-ACCOUNT-002")
    if has("overflow", "underflow", "precision", "rounding", "division before", "floating point", "calculation", "apy", "margin ratio", "fee calculation", "burn rate"):
        ids.add("NA-ECON-002")

    if has("upgrade", "deploy_code", "staging code"):
        ids.add("NA-AUTH-006")
    if "migration" in title:
        ids.add("NA-STATE-003")
    if has("intent", "signature", "nonce entropy", "ticket reuse") and "passkey" not in title:
        ids.add("NA-AUTH-007")
    if has("passkey", "solver", "callback url", "malleability"):
        ids.add("NA-AUTH-008")
    if has("oracle", "asset price"):
        ids.add("NA-INTEGRATION-005")

    if has("indexer", "aggregator crash", "message format", "invalid utf", "artificial data", "parsing of liquidity"):
        ids.add("NA-OFFCHAIN-001")
    if has("relayer", "airdrop", "retry", "finished folder", "completed transactions", "error file"):
        ids.add("NA-OFFCHAIN-002")
    if has("sql injection", "hardcoded password"):
        ids.add("NA-OFFCHAIN-003")
    if has("out-of-date", "react2shell", "contract accounts", "wrong parameter", "json incompatible", "native collections", "macro attributes", "mismatched variable"):
        ids.add("NA-OFFCHAIN-004")

    if has("missing tests"):
        ids.add("NA-OFFCHAIN-005")
    if has("event emission", "logging inconsistencies", "lack of feedback"):
        ids.add("NA-OFFCHAIN-006")
    if has("documentation", "missing comments"):
        ids.add("NA-OFFCHAIN-007")
    if has("suboptimal assertion", "assert instead of require", "panic function", "unnecessary", "redundant", "code duplication", "contract size", "storage can be optimized", "open to-do", "not resolved todo", "dead or useless"):
        ids.add("NA-OFFCHAIN-008")

    if not ids:
        if severity == "Informational":
            ids.add("NA-OFFCHAIN-008")
        else:
            ids.add("NA-STATE-004")
    ids.update(EXTRA_CLASSIFICATIONS.get(str(record["source_id"]), set()))
    return sorted(ids)


def clean_heading(line: str) -> tuple[int, str] | None:
    match = re.match(r"^(#{1,6})\s+(.*)$", line.strip())
    if not match:
        return None
    level = len(match.group(1))
    text = re.sub(r"</?u>", "", match.group(2), flags=re.I)
    text = text.replace("**", "").strip()
    return level, text


def extract_file(path: Path) -> list[dict[str, object]]:
    lines = path.read_text(encoding="utf-8").splitlines()
    if not any(line.strip() for line in lines):
        raise ValueError(f"empty report: {path}")
    records: list[dict[str, object]] = []
    in_native_findings = False
    native_severity: str | None = None
    seen: set[tuple[int, str]] = set()

    for line_no, raw in enumerate(lines, start=1):
        stripped = raw.strip()
        heading = clean_heading(raw)

        if heading:
            level, title = heading
            if level == 1:
                in_native_findings = title.lower() == "findings"
                native_severity = None

            if in_native_findings and level == 2:
                severity_match = SEVERITY_HEADING_RE.match(title)
                native_severity = (
                    SEVERITIES[severity_match.group(1).lower()] if severity_match else None
                )

            if in_native_findings and level == 3 and native_severity:
                inline = INLINE_SEVERITY_RE.search(title)
                severity = SEVERITIES[inline.group(1).lower()] if inline else native_severity
                clean_title = INLINE_SEVERITY_RE.sub("", title).strip(" -")
                key = (line_no, clean_title)
                if key not in seen:
                    records.append(
                        {
                            "source_id": f"{path.stem}:L{line_no}",
                            "report": path.name,
                            "line": line_no,
                            "original_id": None,
                            "title": clean_title,
                            "source_severity": severity,
                        }
                    )
                    seen.add(key)

        candidate = stripped.lstrip("#").strip().replace("**", "")
        guv_match = GUV_RE.match(candidate)
        if not guv_match:
            continue

        finding_number, title, severity = guv_match.groups()
        key = (line_no, title)
        if key in seen:
            continue
        records.append(
            {
                "source_id": f"{path.stem}:GUV-{finding_number}",
                "report": path.name,
                "line": line_no,
                "original_id": f"GUV-{finding_number}",
                "title": title.strip(),
                "source_severity": SEVERITIES[severity.lower()] if severity else None,
            }
        )
        seen.add(key)

    return records


def build_index(corpus: Path) -> dict[str, object]:
    if not corpus.is_dir():
        raise ValueError(f"corpus must be an existing directory: {corpus}")
    records: list[dict[str, object]] = []
    report_counts: dict[str, int] = {}
    source_ids_seen: set[str] = set()
    for path in sorted(corpus.glob("*.md")):
        if path.name.lower() == "readme.md":
            continue
        extracted = extract_file(path)
        for record in extracted:
            source_id = record["source_id"]
            if source_id in source_ids_seen:
                raise ValueError(f"duplicate source_id: {source_id}")
            source_ids_seen.add(source_id)
        records.extend(extracted)
        report_counts[path.name] = len(extracted)

    if not report_counts or not records:
        raise ValueError("corpus must contain Markdown reports with extractable findings")
    for record in records:
        record["canonical_ids"] = classify(record)

    canonical_groups = []
    for canonical_id, title in sorted(CANONICAL_TITLES.items()):
        source_ids = [
            str(record["source_id"])
            for record in records
            if canonical_id in record["canonical_ids"]
        ]
        if source_ids:
            canonical_groups.append(
                {
                    "canonical_id": canonical_id,
                    "title": title,
                    "instance_count": len(source_ids),
                    "source_ids": source_ids,
                }
            )

    return {
        "schema_version": 1,
        "classification_version": 1,
        "report_count": len(report_counts),
        "finding_count": len(records),
        "canonical_group_count": len(canonical_groups),
        "report_counts": report_counts,
        "canonical_groups": canonical_groups,
        "findings": records,
    }


def validate_index(payload: object) -> None:
    """Check schema and both directions of report/group accounting before publish."""
    def require(condition: bool, message: str) -> None:
        if not condition:
            raise ValueError(f"invalid corpus index: {message}")

    def nonempty(value: object) -> bool:
        return isinstance(value, str) and bool(value.strip())

    require(isinstance(payload, dict), "root must be an object")
    for field in ("schema_version", "classification_version"):
        require(type(payload.get(field)) is int and payload[field] == 1, field)
    counts = payload.get("report_counts")
    records = payload.get("findings")
    groups = payload.get("canonical_groups")
    require(isinstance(counts, dict) and bool(counts), "report_counts must be nonempty")
    require(isinstance(records, list) and bool(records), "findings must be nonempty")
    require(isinstance(groups, list) and bool(groups), "canonical_groups must be nonempty")
    for field, expected in (("report_count", len(counts)), ("finding_count", len(records)),
                            ("canonical_group_count", len(groups))):
        require(type(payload.get(field)) is int and payload[field] == expected, field)
    require(all(nonempty(name) and type(count) is int and count >= 0
                for name, count in counts.items()), "invalid report counts")
    actual_counts = dict.fromkeys(counts, 0)
    expected_groups: dict[str, list[str]] = {}
    source_ids = set()
    for record in records:
        require(isinstance(record, dict), "finding must be an object")
        source_id = record.get("source_id")
        report = record.get("report")
        require(nonempty(source_id) and source_id not in source_ids, "invalid or duplicate source_id")
        source_ids.add(source_id)
        require(nonempty(report) and report in counts, "unknown report identity")
        require(type(record.get("line")) is int and record["line"] > 0, "invalid line")
        require(nonempty(record.get("title")), "empty finding title")
        original_id = record.get("original_id")
        require("original_id" in record and (original_id is None or nonempty(original_id)), "original_id")
        suffix = original_id if original_id is not None else f"L{record['line']}"
        require(source_id == f"{Path(report).stem}:{suffix}", "source identity mismatch")
        severity = record.get("source_severity")
        require("source_severity" in record and (severity is None or
                isinstance(severity, str) and severity in SEVERITIES.values()), "source_severity")
        canonical_ids = record.get("canonical_ids")
        require(isinstance(canonical_ids, list) and bool(canonical_ids) and all(
            isinstance(item, str) and item in CANONICAL_TITLES for item in canonical_ids
        ), "unknown canonical IDs")
        require(len(canonical_ids) == len(set(canonical_ids)), "duplicate canonical IDs")
        actual_counts[report] += 1
        for canonical_id in canonical_ids:
            expected_groups.setdefault(canonical_id, []).append(source_id)
    require(actual_counts == counts, "report accounting mismatch")
    seen_groups = set()
    for group in groups:
        require(isinstance(group, dict), "group must be an object")
        canonical_id = group.get("canonical_id")
        require(isinstance(canonical_id, str) and canonical_id in expected_groups
                and canonical_id not in seen_groups, "unknown or duplicate canonical group")
        seen_groups.add(canonical_id)
        require(group.get("title") == CANONICAL_TITLES[canonical_id], "canonical title")
        expected = expected_groups[canonical_id]
        require(group.get("source_ids") == expected, "group membership mismatch")
        require(type(group.get("instance_count")) is int and group["instance_count"] == len(expected),
                "group accounting mismatch")
    require(seen_groups == set(expected_groups), "missing canonical groups")


def parse_index(rendered: str) -> object:
    def unique_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise ValueError(f"invalid JSON constant: {value}")

    return json.loads(rendered, object_pairs_hook=unique_keys, parse_constant=reject_constant)


def write_index(output: Path, rendered: str) -> None:
    # Validate the serialized form before creating any file, then stage beside
    # the destination so replace remains atomic on a single filesystem.
    validate_index(parse_index(rendered))
    mode = stat.S_IMODE(output.stat().st_mode) if output.exists() else 0o644
    fd, name = tempfile.mkstemp(prefix=f".{output.name}.", dir=output.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(rendered)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, output)
    finally:
        temporary.unlink(missing_ok=True)


class IndexParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise ValueError(message)


def main(argv: list[str] | None = None) -> int:
    parser = IndexParser()
    parser.add_argument("corpus", type=Path, help="Directory containing report Markdown files")
    parser.add_argument("--output", type=Path, help="Write JSON here; stdout if omitted")
    try:
        args = parser.parse_args(argv)
        payload = build_index(args.corpus)
        rendered = json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
        if args.output:
            write_index(args.output, rendered)
        else:
            validate_index(parse_index(rendered))
            print(rendered, end="")
        return 0
    except (OSError, UnicodeError, ValueError, RecursionError) as exc:
        print(json.dumps({"action": "invalid", "error": str(exc)}, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
