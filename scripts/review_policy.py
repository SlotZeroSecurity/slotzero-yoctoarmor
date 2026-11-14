"""Mandatory specialist and mutation coverage for every new review."""
from __future__ import annotations

from reference_paths import reference_relative

from collections import Counter
from pathlib import Path
import re
from run_integrity import artifact_path, read_json, read_jsonl

SPECIALIST_ROLES = (
    "upgrade-keys", "intents-auth", "bridge-relayer", "chain-signatures-yield",
    "runtime-consensus", "oracle-freshness",
)
REGISTRY = Path(__file__).resolve().parents[1] / reference_relative('mutation_operators')


def operator_inventory() -> dict[str, list[dict]]:
    value = read_json(REGISTRY)
    if value.get("schema_version") != 1 or not isinstance(value.get("families"), dict):
        raise ValueError("invalid mutation operator registry")
    seen = set()
    for family, operators in value["families"].items():
        if not operators:
            raise ValueError(f"empty mutation family: {family}")
        for operator in operators:
            oid = operator.get("operator_id")
            if not isinstance(oid, str) or not oid or oid in seen or not operator.get("description"):
                raise ValueError("invalid or duplicate mutation operator")
            seen.add(oid)
    return value["families"]


def nonempty(value, label):
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label}: nonempty text required")


def citations(value, manifest, label):
    if not isinstance(value, list) or not value:
        raise ValueError(f"{label}: target evidence required")
    root = Path(manifest["target"]).resolve()
    frozen = {row["path"] for row in manifest.get("input_snapshot", [])}
    for cite in value:
        if not isinstance(cite, dict):
            raise ValueError(f"{label}: invalid citation")
        relative = cite.get("path")
        nonempty(relative, label)
        path = artifact_path(root, relative)
        if not path.is_file() or (frozen and relative not in frozen):
            raise ValueError(f"{label}: citation outside frozen target")
        start, end = cite.get("start"), cite.get("end")
        lines = path.read_text(encoding="utf-8").splitlines()
        if type(start) is not int or type(end) is not int or not 1 <= start <= end <= len(lines):
            raise ValueError(f"{label}: invalid citation range")
        if cite.get("quote") != "\n".join(lines[start - 1:end]):
            raise ValueError(f"{label}: citation does not match target")


def validate_specialists(run_dir, manifest):
    packets = read_jsonl(run_dir / "work-packets.jsonl")
    expected = {(role, number) for role in SPECIALIST_ROLES
                for number in range(1, manifest["discovery_passes_planned"] + 1)}
    actual = []
    for packet in packets:
        if packet["phase"] != "blind-l3-active" or packet["role_id"] not in SPECIALIST_ROLES:
            continue
        key = (packet["role_id"], packet.get("discovery_pass", 1))
        actual.append(key)
        name = str(Path(packet["output_path"]).with_suffix("")) + "-applicability.json"
        if name not in packet["additional_outputs"]:
            raise ValueError("specialist packet lacks applicability output")
        row = read_json(artifact_path(run_dir, name))
        if row.get("schema_version") != 1 or (row.get("role_id"), row.get("discovery_pass")) != key:
            raise ValueError("specialist applicability identity mismatch")
        if row.get("applicability") not in {"applicable", "not_applicable", "uncertain", "blocked"}:
            raise ValueError("invalid specialist applicability")
        nonempty(row.get("rationale"), "specialist rationale")
        citations(row.get("target_evidence"), manifest, "specialist")
        if row["applicability"] in {"uncertain", "blocked"}:
            nonempty(row.get("limitation"), "specialist limitation")
        if row["applicability"] == "not_applicable" and read_jsonl(artifact_path(run_dir, packet["output_path"])):
            raise ValueError("not-applicable specialist cannot emit candidates")
    if len(actual) != len(expected) or set(actual) != expected:
        raise ValueError("every specialist requires applicability review in every discovery pass")


def validate_mutation_inventory(run_dir):
    manifest = read_json(run_dir / "run-manifest.json")
    inventory = operator_inventory()
    rows = read_jsonl(run_dir / "mutation-results.jsonl")
    seen = set()
    for row in rows:
        family = row.get("operator_family")
        if row.get("schema_version") != 2 or "mode" in row:
            raise ValueError("mutation results require schema 2 without a scan selector")
        if family not in inventory or family in seen:
            raise ValueError("invalid or duplicate mutation family")
        seen.add(family)
        nonempty(row.get("rationale"), "mutation family rationale")
        operators = row.get("operators")
        if not isinstance(operators, list) or any(not isinstance(op, dict) for op in operators):
            raise ValueError("mutation operator inventory missing")
        ids = [op.get("operator_id") for op in operators]
        expected = {op["operator_id"] for op in inventory[family]}
        if len(ids) != len(expected) or set(ids) != expected:
            raise ValueError(f"{family}: every supported operator requires a disposition")
        counts = Counter()
        linked = set()
        states = set()
        for op in operators:
            status = op.get("applicability")
            if status not in {"applicable", "not_applicable", "blocked"}:
                raise ValueError("invalid mutation applicability")
            states.add(status)
            nonempty(op.get("rationale"), "operator rationale")
            citations(op.get("target_evidence"), manifest, "mutation operator")
            locations, outcomes = op.get("locations"), op.get("outcomes")
            if not isinstance(locations, list) or not isinstance(outcomes, list):
                raise ValueError("operator requires locations and outcomes")
            if status == "not_applicable":
                if locations or outcomes:
                    raise ValueError("not-applicable operator cannot have mutation outcomes")
                continue
            if status == "blocked":
                nonempty(op.get("blocker"), "operator blocker")
            if not locations:
                if status != "blocked" or outcomes:
                    raise ValueError("applicable operator requires target locations")
                continue
            citations(locations, manifest, "mutation location")
            keys = [(c["path"], c["start"], c["end"]) for c in locations]
            if len(set(keys)) != len(keys):
                raise ValueError("duplicate mutation location")
            covered = set()
            for outcome in outcomes:
                if not isinstance(outcome, dict):
                    raise ValueError("mutation outcome must be an object")
                index = outcome.get("location_index")
                if type(index) is not int or not 0 <= index < len(locations):
                    raise ValueError("mutation outcome lacks a planned location")
                covered.add(index)
                disposition = outcome.get("result")
                if disposition not in {"killed", "survived", "blocked"} or (status == "blocked" and disposition != "blocked"):
                    raise ValueError("invalid mutation outcome")
                nonempty(outcome.get("evidence"), "mutation outcome evidence")
                evidence_file = outcome.get("evidence_path")
                nonempty(evidence_file, "mutation evidence path")
                evidence_path = artifact_path(run_dir, evidence_file)
                if not evidence_path.is_file() or not evidence_path.stat().st_size:
                    raise ValueError("mutation outcome evidence artifact missing")
                candidate_ids = outcome.get("candidate_ids")
                if not isinstance(candidate_ids, list) or any(not isinstance(cid, str) or not cid for cid in candidate_ids):
                    raise ValueError("mutation candidate IDs invalid")
                if disposition == "killed" and not candidate_ids:
                    raise ValueError("killed mutation requires adjudicated candidate evidence")
                if disposition == "killed":
                    review = outcome.get("adjudication")
                    if not isinstance(review, dict) or review.get("mechanism_match") is not True or review.get("path_match") is not True:
                        raise ValueError("killed mutation requires matching human adjudication")
                    nonempty(review.get("reviewer"), "mutation reviewer")
                    if not isinstance(review.get("reviewed_at"), str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", review["reviewed_at"]):
                        raise ValueError("mutation adjudication requires UTC review time")
                linked.update(candidate_ids)
                counts[disposition] += 1
            if covered != set(range(len(locations))):
                raise ValueError("mutation location lacks an outcome")
        expected_status = "applicable" if "applicable" in states else ("blocked" if "blocked" in states else "not_applicable")
        if row.get("applicability") != expected_status:
            raise ValueError("mutation family applicability differs from operators")
        for key in ("killed", "survived", "blocked", "mutations_total"):
            expected_count = sum(counts.values()) if key == "mutations_total" else counts[key]
            if type(row.get(key)) is not int or row[key] != expected_count:
                raise ValueError("mutation totals differ from operator outcomes")
        if not isinstance(row.get("candidate_ids"), list) or set(row["candidate_ids"]) != linked:
            raise ValueError("mutation family candidate IDs differ from operators")
    if seen != set(inventory):
        raise ValueError("mutation-results: every operator family requires one disposition row")


def rescan_result(run_dir):
    """Derive the stopping condition; never trust a claimed zero-new-findings count."""
    summary = read_json(run_dir / "rescan-summary.json")
    candidates = read_jsonl(run_dir / "counterexample-rescan-candidates.jsonl")
    verdicts = {r["candidate_id"]: r for r in read_jsonl(run_dir / "verdicts.jsonl")}
    dispositions = {r["candidate_id"]: r for r in read_jsonl(run_dir / "dispositions.jsonl")}
    ids = {r["candidate_id"] for r in candidates}
    if len(ids) != len(candidates) or set(summary["new_candidate_ids"]) != ids:
        raise ValueError("rescan summary differs from producer output")
    informed_path = run_dir / "informed-rescan-candidates.jsonl"
    informed_ids = {r["candidate_id"] for r in read_jsonl(informed_path)} if informed_path.exists() else set()
    earlier_targets = {r.get("target_id") for cid, r in dispositions.items() if cid not in ids | informed_ids}
    high, unresolved = set(), False
    for cid in ids:
        if cid not in dispositions:
            raise ValueError("rescan candidate lacks disposition")
        row = dispositions[cid]
        target = row.get("target_id")
        verdict = verdicts.get(target)
        if target and verdict is None:
            raise ValueError("rescan survivor lacks verification")
        # A new trace merged into an existing finding is not a new finding.
        if row.get("disposition") == "merged" and target in earlier_targets:
            continue
        if verdict and verdict["verdict"] in {"valid", "valid_downgraded"} and verdict["severity"].lower() in {"critical", "high", "medium"}:
            high.add(target)
        if row.get("disposition") == "deferred":
            unresolved = True
        if verdict and (verdict["verdict"] == "lead" or verdict.get("verification_status") in {"blocked", "contested"}):
            unresolved = True
    blocked = summary["status"] == "blocked" or unresolved or any(
        r.get("status") == "blocked" for r in read_jsonl(run_dir / "unresolved-assumptions.jsonl"))
    return {"new_medium_plus": sorted(high), "blocked": blocked,
            "criterion_met": not high and not blocked}


def review_limitations(run_dir):
    result = rescan_result(run_dir)
    reasons = []
    if result["new_medium_plus"]:
        reasons.append(f"The final rescan found {len(result['new_medium_plus'])} new Medium-or-higher finding(s); the zero-new-finding stopping criterion was not met.")
    if result["blocked"]:
        reasons.append("Final rescan validation was blocked or unresolved; the stopping criterion was not established.")
    rows = read_jsonl(run_dir / "mutation-results.jsonl")
    if any(op["applicability"] == "blocked" or any(o["result"] == "blocked" for o in op["outcomes"])
           for row in rows for op in row["operators"]):
        reasons.append("Some mutation checks were blocked; full testing coverage was not established.")
    for filename, field in (("invariant-ledger.jsonl", "execution_status"),
                            ("nep-differential.jsonl", "status"),
                            ("temporal-upgrade.jsonl", "status"),
                            ("official-guidance-coverage.jsonl", "test_status")):
        path = run_dir / filename
        if path.exists() and any(row.get(field) == "blocked" for row in read_jsonl(path)):
            reasons.append(f"Testing recorded in {filename} was blocked; the stopping criterion was not established.")
    async_path = run_dir / "async-schedules.jsonl"
    if async_path.exists() and any(row.get("coverage", {}).get("blocked") for row in read_jsonl(async_path)):
        reasons.append("Asynchronous schedule testing was blocked; the stopping criterion was not established.")
    for packet in read_jsonl(run_dir / "work-packets.jsonl"):
        if packet["role_id"] in SPECIALIST_ROLES and packet["phase"] == "blind-l3-active":
            row = read_json(artifact_path(run_dir, str(Path(packet["output_path"]).with_suffix("")) + "-applicability.json"))
            if row["applicability"] in {"uncertain", "blocked"}:
                reasons.append("Some specialist reviews remain uncertain or blocked; see Testing and limitations.")
                break
    return " ".join(reasons)
