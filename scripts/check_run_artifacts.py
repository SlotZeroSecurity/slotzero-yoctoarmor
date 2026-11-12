#!/usr/bin/env python3
"""Validate L0-L3 audit artifacts and active-testing coverage."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from run_integrity import (
    artifact_path, read_jsonl as strict_jsonl, reconcile_candidates,
    validate_bindings, validate_state,
    read_registry,
)


LEVELS = {"L0", "L1", "L2", "L3"}
LEVEL_STATUSES = {"complete", "partial", "blocked", "not_run"}
MUTATION_FAMILIES = {
    "identity-substitution",
    "access-macro-removal",
    "late-reservation",
    "promise-result-semantics",
    "callback-gas",
    "refund-cap",
    "storage-accounting",
    "terminal-promise",
    "arithmetic-rounding",
    "migration-layout",
    "key-capability",
    "yield-resume-binding",
    "refund-principal",
    "transfer-call-polarity",
    "route-finality",
    "serializer-mismatch",
    "deployed-code-identity",
}
NEP_PIN_PATH = Path(__file__).resolve().parent.parent / "references" / "nep-registry.json"
OFFICIAL_DOCS_PIN_PATH = (
    Path(__file__).resolve().parent.parent / "references" / "official-docs-registry.json"
)


def load_json(path: Path) -> dict[str, object]:
    if path in {NEP_PIN_PATH, OFFICIAL_DOCS_PIN_PATH}:
        return read_registry(path)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError(f"missing required artifact: {path.name}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path}: invalid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected object")
    return value


def load_jsonl(path: Path, *, required: bool = True) -> list[dict[str, object]]:
    if not path.exists():
        if required:
            raise ValueError(f"missing required artifact: {path.name}")
        return []
    rows: list[dict[str, object]] = []
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path}:{line_no}: invalid JSON: {exc}") from exc
        if not isinstance(value, dict):
            raise ValueError(f"{path}:{line_no}: expected object")
        rows.append(value)
    return rows


def require_fields(row: dict[str, object], fields: tuple[str, ...], label: str) -> None:
    missing = [field for field in fields if row.get(field) is None or row.get(field) == ""]
    if missing:
        raise ValueError(f"{label}: missing fields {missing}")


def canonical_hash(value: object) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def validate_manifest(run_dir: Path) -> dict[str, object]:
    row = load_json(run_dir / "run-manifest.json")
    require_fields(
        row,
        (
            "schema_version",
            "target",
            "target_revision",
            "dirty_tree",
            "scope",
            "exclusions",
            "mode",
            "toolchain",
            "sdk_versions",
            "nep_source_commit",
            "corpus_hash",
            "models",
            "prompt_hashes",
            "tool_versions",
            "worker_capacity",
            "started_at",
        ),
        "run-manifest",
    )
    if row["schema_version"] not in {1, 2, 3, 4, 5, 6}:
        raise ValueError("run-manifest: unsupported schema version")
    if row["mode"] not in {"standard", "explicit-files", "deep"}:
        raise ValueError("run-manifest: invalid mode")
    if not isinstance(row["worker_capacity"], int) or row["worker_capacity"] < 1:
        raise ValueError("run-manifest: worker_capacity must be a positive integer")
    expected_pin = json.loads(NEP_PIN_PATH.read_text(encoding="utf-8"))["source"]["commit"]
    if row["nep_source_commit"] != expected_pin:
        raise ValueError("run-manifest: NEP source pin differs from bundled registry")
    if int(row["schema_version"]) >= 2:
        require_fields(
            row,
            ("official_docs_source_commit", "official_docs_registry_hash"),
            "run-manifest",
        )
        docs = json.loads(OFFICIAL_DOCS_PIN_PATH.read_text(encoding="utf-8"))
        expected_hash = hashlib.sha256(OFFICIAL_DOCS_PIN_PATH.read_bytes()).hexdigest()
        if row["official_docs_source_commit"] != docs["source"]["commit"]:
            raise ValueError("run-manifest: official-docs source pin differs from bundled registry")
        if row["official_docs_registry_hash"] != expected_hash:
            raise ValueError("run-manifest: official-docs registry hash differs from bundled registry")
    if row["schema_version"] >= 3:
        require_fields(
            row,
            (
                "run_id",
                "semantic_ir_hash",
                "semantic_extractor_hash",
                "content_fingerprint",
                "driver_hash",
                "work_packets_hash",
                "feedback_policy",
                "second_pass_mode",
            ),
            "run-manifest v3",
        )
        if row["feedback_policy"] != "metrics_only":
            raise ValueError("run-manifest v3: feedback_policy must be metrics_only")
        if row["second_pass_mode"] != "targeted_verified_seed":
            raise ValueError("run-manifest v3: invalid second_pass_mode")
    if row["schema_version"] >= 5:
        validate_bindings(run_dir)
    if row["schema_version"] >= 5 and (type(row.get("discovery_passes_planned")) is not int or
                                       not 1 <= row["discovery_passes_planned"] <= 10):
        raise ValueError("run-manifest: invalid discovery pass count")
    if row["schema_version"] == 6:
        capabilities = row.get("runtime_capabilities")
        if not isinstance(capabilities, dict) or set(capabilities) != {
            "worker_isolation", "worker_termination", "usage_export", "stream_output_limit"
        } or any(value != "unknown" for value in capabilities.values()):
            raise ValueError("run-manifest: initial runtime capabilities must be unknown")
    return row


def validate_semantic_ir(run_dir: Path, manifest: dict[str, object]) -> None:
    semantic = load_json(run_dir / "semantic-ir.json")
    if semantic.get("schema_version") != 1:
        raise ValueError("semantic-ir: schema_version must be 1")
    for field in (
        "files",
        "symbols",
        "exports",
        "state_accesses",
        "call_edges",
        "receipt_edges",
        "authority_edges",
        "value_flows",
        "serialization_boundaries",
        "unresolved_edges",
    ):
        if not isinstance(semantic.get(field), list):
            raise ValueError(f"semantic-ir: {field} must be a list")
    require_fields(
        semantic,
        ("extractor_hash", "content_fingerprint", "coverage"),
        "semantic-ir",
    )
    if manifest["semantic_ir_hash"] != canonical_hash(semantic):
        raise ValueError("semantic-ir: content differs from run-manifest hash")
    if manifest["semantic_extractor_hash"] != semantic["extractor_hash"]:
        raise ValueError("semantic-ir: extractor hash differs from run-manifest")
    if manifest["content_fingerprint"] != semantic["content_fingerprint"]:
        raise ValueError("semantic-ir: content fingerprint differs from run-manifest")


def validate_controller_artifacts(run_dir: Path, manifest: dict[str, object]) -> None:
    packets = load_jsonl(run_dir / "work-packets.jsonl")
    if not packets:
        raise ValueError("work-packets: at least one packet is required")
    packet_ids: set[str] = set()
    for packet in packets:
        require_fields(
            packet,
            (
                "schema_version", "packet_id", "phase", "role_id", "allowed_inputs",
                "forbidden_inputs", "output_path", "dependencies", "retry_limit", "packet_hash",
            ),
            "work packet",
        )
        packet_id = str(packet["packet_id"])
        if packet_id in packet_ids:
            raise ValueError(f"work-packets: duplicate packet_id {packet_id}")
        packet_ids.add(packet_id)
        if packet["schema_version"] != 1 or packet["retry_limit"] != 1:
            raise ValueError(f"work-packets: invalid schema or retry limit for {packet_id}")
        unhashed = dict(packet)
        claimed = unhashed.pop("packet_hash")
        if claimed != canonical_hash(unhashed):
            raise ValueError(f"work-packets: invalid packet hash for {packet_id}")
    if manifest["work_packets_hash"] != canonical_hash(packets):
        raise ValueError("work-packets: aggregate hash differs from run-manifest")
    if manifest["schema_version"] == 6:
        from run_journal import load as load_run_state
        state = load_run_state(run_dir)
    else:
        state = load_json(run_dir / "run-state.json")
    require_fields(
        state,
        ("schema_version", "run_id", "target", "run_dir", "phase_order", "current_phase", "status", "phase_status", "retry_counts", "history"),
        "run-state",
    )
    expected_schema = 4 if manifest["schema_version"] == 6 else (3 if manifest["schema_version"] == 5 else (2 if manifest["schema_version"] == 4 else 1))
    if state["schema_version"] != expected_schema or state["run_id"] != manifest["run_id"]:
        raise ValueError("run-state: schema or run ID differs from manifest")
    if manifest["schema_version"] >= 5:
        from near_audit import ACTIVE_ROLES
        passes = manifest["discovery_passes_planned"]
        surface = load_json(run_dir / "surface.json")
        expected = {(number, role) for number in range(1, passes + 1) for role in surface["selected_roles"] if role not in ACTIVE_ROLES}
        actual = {(packet.get("discovery_pass"), packet["role_id"]) for packet in packets if packet["phase"] == "blind-l3-active" and packet["role_id"] not in ACTIVE_ROLES}
        if passes == 1:
            expected = {(None, role) for _, role in expected}
        if actual != expected:
            raise ValueError("work-packets: incomplete or duplicate L3 discovery pass inventory")
        l2 = {packet.get("discovery_pass") for packet in packets if packet["role_id"] == "intent-reasoner"}
        if l2 != (set(range(1, passes + 1)) if passes > 1 else {None}):
            raise ValueError("work-packets: incomplete L2 discovery pass inventory")
        output_paths = [packet["output_path"] for packet in packets]
        if len(output_paths) != len(set(output_paths)):
            raise ValueError("work-packets: duplicate primary output path")
        for packet in packets:
            if packet["role_id"] == "intent-reasoner" or (packet["phase"] == "blind-l3-active" and packet["role_id"] not in ACTIVE_ROLES):
                number = packet.get("discovery_pass", 1)
                expected_path = ("l2/candidates.jsonl" if packet["role_id"] == "intent-reasoner" else f"discovery/{packet['role_id']}.jsonl") if passes == 1 else (
                    f"l2/pass-{number:02d}/candidates.jsonl" if packet["role_id"] == "intent-reasoner" else f"discovery/pass-{number:02d}/{packet['role_id']}.jsonl")
                if packet["output_path"] != expected_path or "prior-pass candidates" not in packet["forbidden_inputs"]:
                    raise ValueError("work-packets: repeated blind role path or isolation policy differs")
        active_expected = {role for role in surface["selected_roles"] if role in ACTIVE_ROLES}
        active_actual = [packet["role_id"] for packet in packets if packet["phase"] == "blind-l3-active" and packet["role_id"] in ACTIVE_ROLES]
        if len(active_actual) != len(active_expected) or set(active_actual) != active_expected:
            raise ValueError("work-packets: active roles must run exactly once")
        l1 = [packet for packet in packets if packet["phase"] == "isolated-l1-l2" and packet["role_id"] == "pattern-matcher"]
        if len(l1) != 1:
            raise ValueError("work-packets: L1 pattern review must run exactly once")
        nep = [packet["role_id"] for packet in packets if packet["phase"] == "nep-coverage"]
        if len(nep) != len(surface["nep_roles"]) or set(nep) != set(surface["nep_roles"]):
            raise ValueError("work-packets: NEP roles must run exactly once")
    if manifest["schema_version"] >= 5:
        from near_audit import PHASES
        validate_state(run_dir, manifest, PHASES)


def validate_feedback_and_informed_rescan(run_dir: Path, final: bool, stage: str = "approved") -> None:
    controlled = load_json(run_dir / "run-manifest.json").get("schema_version") in {4, 5, 6}
    if controlled:
        from record_feedback import validate_feedback
        validate_feedback(run_dir, require_complete=final and stage == "approved")
    feedback = load_json(run_dir / "feedback-summary.json")
    require_fields(
        feedback,
        ("schema_version", "status", "feedback_policy", "automatic_learning", "total_rows", "label_counts", "corpus_changed", "prompts_changed", "routing_changed", "mutations_changed"),
        "feedback-summary",
    )
    if feedback["feedback_policy"] != "metrics_only" or feedback["automatic_learning"] is not False:
        raise ValueError("feedback-summary: autonomous learning is forbidden")
    if feedback["status"] not in {"not_run", "pending", "complete", "skipped"}:
        raise ValueError("feedback-summary: invalid status")
    if final and stage == "approved" and feedback["status"] not in {"complete", "skipped"}:
        raise ValueError("feedback-summary: final audit requires completed or skipped human feedback")
    if any(feedback[name] is not False for name in ("corpus_changed", "prompts_changed", "routing_changed", "mutations_changed")):
        raise ValueError("feedback-summary: feedback may not mutate scanner configuration")
    rows = load_jsonl(run_dir / "finding-feedback.jsonl")
    if feedback["total_rows"] != len(rows):
        raise ValueError("feedback-summary: total_rows differs from feedback ledger")
    feedback_ids: set[str] = set()
    tp_blind_ids: set[str] = set()
    observed_labels: dict[str, int] = {}
    for row in rows:
        require_fields(
            row,
            ("schema_version", "candidate_id", "label", "reason_code", "reviewer", "reviewed_at", "pass_origin"),
            "finding-feedback row",
        )
        candidate_id = str(row["candidate_id"])
        if candidate_id in feedback_ids:
            raise ValueError(f"finding-feedback: duplicate candidate {candidate_id}")
        feedback_ids.add(candidate_id)
        if row["schema_version"] != 1 or row["label"] not in {"TP", "FP", "DUPLICATE", "UNRESOLVED"}:
            raise ValueError(f"finding-feedback {candidate_id}: invalid schema or label")
        if row["pass_origin"] not in {"blind", "informed"}:
            raise ValueError(f"finding-feedback {candidate_id}: invalid pass_origin")
        label = str(row["label"])
        observed_labels[label] = observed_labels.get(label, 0) + 1
        if row["label"] == "TP" and row["pass_origin"] == "blind":
            tp_blind_ids.add(candidate_id)
    if feedback["label_counts"] != dict(sorted(observed_labels.items())):
        raise ValueError("feedback-summary: label_counts differ from feedback ledger")
    if final:
        summary = load_json(run_dir / "informed-rescan-summary.json")
        require_fields(
            summary,
            ("schema_version", "iteration", "status", "seed_count", "new_candidate_ids"),
            "informed-rescan-summary",
        )
        if summary["status"] in {"not_run", "deferred"} and stage == "draft":
            if feedback["status"] in {"complete", "skipped"}:
                raise ValueError("completed human feedback requires an accounted informed pass")
            if summary["seed_count"] or summary["new_candidate_ids"] or (run_dir / "verified-seeds.jsonl").exists() or (run_dir / "informed-rescan-candidates.jsonl").exists():
                raise ValueError("deferred informed pass cannot contain seeds or candidate artifacts")
            return
        if summary["iteration"] != 1 or summary["status"] not in {"complete", "skipped", "blocked"}:
            raise ValueError("informed-rescan-summary: exactly one complete, skipped, or blocked pass is required")
        if summary["status"] == "skipped" and summary["seed_count"] != 0:
            raise ValueError("informed-rescan-summary: skipped pass cannot contain seeds")
        seeds = load_jsonl(run_dir / "verified-seeds.jsonl", required=False)
        if summary["seed_count"] != len(seeds):
            raise ValueError("informed-rescan-summary: seed_count differs from verified seeds")
        if controlled:
            from record_feedback import reviewed_blind_population
            blind = reviewed_blind_population(run_dir)
            if (summary.get("blind_candidate_hashes") != feedback.get("blind_candidate_hashes") or
                    summary.get("blind_feedback_hash") != feedback.get("blind_feedback_hash")):
                raise ValueError("informed rescan: frozen blind feedback differs")
            if {seed.get("source_candidate_id") for seed in seeds} != tp_blind_ids:
                raise ValueError("informed rescan: seeds must equal the reviewed blind TP population")
            for seed in seeds:
                source_id = seed.get("source_candidate_id")
                if source_id not in blind or seed.get("source_candidate_hash") != canonical_hash(blind[source_id]):
                    raise ValueError("informed rescan: source candidate content hash differs")
        source_ids: set[str] = set()
        excluded: dict[str, set[tuple[str, str]]] = {}
        for seed in seeds:
            require_fields(
                seed,
                ("schema_version", "seed_id", "source_candidate_id", "seed_hash", "excluded_locations", "search_neighborhood", "forbidden_fields_removed"),
                "verified seed",
            )
            source_id = str(seed["source_candidate_id"])
            if source_id in source_ids or source_id not in tp_blind_ids:
                raise ValueError(f"verified seed {source_id}: duplicate or not a manually labelled blind TP")
            source_ids.add(source_id)
            unhashed_seed = dict(seed)
            claimed_seed_hash = unhashed_seed.pop("seed_hash")
            if seed["schema_version"] != 1 or claimed_seed_hash != canonical_hash(unhashed_seed):
                raise ValueError(f"verified seed {source_id}: invalid schema or seed hash")
            forbidden = set(seed)
            if {"severity", "recommendation", "fix", "report_title"} & forbidden:
                raise ValueError(f"verified seed {source_id}: report fields were not stripped")
            locations = seed["excluded_locations"]
            if not isinstance(locations, list):
                raise ValueError(f"verified seed {source_id}: excluded_locations must be a list")
            excluded[source_id] = {
                (str(item.get("path")), str(item.get("function")))
                for item in locations
                if isinstance(item, dict)
            }
        informed = load_jsonl(run_dir / "informed-rescan-candidates.jsonl", required=controlled and summary["status"] == "complete")
        informed_ids: set[str] = set()
        for row in informed:
            candidate_id = row.get("candidate_id")
            if not isinstance(candidate_id, str) or not candidate_id or candidate_id in informed_ids:
                raise ValueError("informed-rescan-candidates: missing or duplicate candidate ID")
            informed_ids.add(candidate_id)
            techniques = row.get("discovery_technique")
            techniques = [techniques] if isinstance(techniques, str) else techniques
            source_id = row.get("seed_source_candidate_id")
            evidence = row.get("variant_evidence")
            locations = row.get("locations")
            if (
                not isinstance(techniques, list)
                or "verified_seed_variant" not in techniques
                or row.get("origin_level") != "L3"
                or source_id not in source_ids
                or not isinstance(evidence, list)
                or not evidence
                or not isinstance(locations, list)
                or not locations
            ):
                raise ValueError(f"informed candidate {candidate_id}: invalid seed attribution or variant evidence")
            location_keys = {
                (str(item.get("path")), str(item.get("function")))
                for item in locations
                if isinstance(item, dict)
            }
            if not (location_keys - excluded[str(source_id)]):
                raise ValueError(f"informed candidate {candidate_id}: pure seed-location rediscovery")
        if summary["status"] == "complete" and set(summary["new_candidate_ids"]) != informed_ids:
            raise ValueError("informed-rescan-summary: new candidate IDs differ from candidate artifact")


def validate_intent_model(run_dir: Path, manifest_schema: int) -> None:
    row = load_json(run_dir / "intent-model.json")
    if row.get("schema_version") != 1:
        raise ValueError("intent-model: schema_version must be 1")
    required_arrays = (
        "actors",
        "assets",
        "entrypoints",
        "receipt_state_machines",
        "standards",
        "trust_boundaries",
        "invariants",
        "unresolved_intent",
        "upgrade_dependencies",
    )
    for field in required_arrays:
        if not isinstance(row.get(field), list):
            raise ValueError(f"intent-model: {field} must be a list")
    if manifest_schema >= 2:
        for field in (
            "account_key_capabilities",
            "yield_resume_flows",
            "global_contract_dependencies",
            "cross_chain_routes",
            "version_claims",
        ):
            if not isinstance(row.get(field), list):
                raise ValueError(f"intent-model: {field} must be a list for run-manifest v2")
    forbidden = {"candidate_id", "severity", "findings"} & set(row)
    if forbidden:
        raise ValueError(f"intent-model: L0 cannot contain finding fields {sorted(forbidden)}")
    invariant_ids: set[str] = set()
    for item in row["invariants"]:
        if not isinstance(item, dict) or not item.get("invariant_id") or not item.get("statement"):
            raise ValueError("intent-model: every invariant requires invariant_id and statement")
        invariant_id = str(item["invariant_id"])
        if invariant_id in invariant_ids:
            raise ValueError(f"intent-model: duplicate invariant_id {invariant_id}")
        invariant_ids.add(invariant_id)


def validate_levels(run_dir: Path, final: bool) -> None:
    rows = load_jsonl(run_dir / "level-coverage.jsonl")
    indexed: dict[str, dict[str, object]] = {}
    for row in rows:
        level = row.get("level")
        if level not in LEVELS or level in indexed:
            raise ValueError(f"level-coverage: invalid or duplicate level {level!r}")
        required_keys = {
            "schema_version",
            "level",
            "status",
            "roles",
            "inputs",
            "artifacts",
            "model_and_prompt_hashes",
            "started_at",
            "completed_at",
            "cost",
            "blockers",
        }
        missing_keys = sorted(required_keys - set(row))
        if missing_keys:
            raise ValueError(f"level-coverage {level}: missing fields {missing_keys}")
        if row["schema_version"] != 1 or row["status"] not in LEVEL_STATUSES:
            raise ValueError(f"level-coverage {level}: invalid schema or status")
        if row["status"] == "complete" and (not row["started_at"] or not row["completed_at"]):
            raise ValueError(f"level-coverage {level}: complete row needs start and completion times")
        indexed[str(level)] = row
    if set(indexed) != LEVELS:
        raise ValueError(f"level-coverage: expected {sorted(LEVELS)}, got {sorted(indexed)}")
    if final and any(row["status"] != "complete" for row in indexed.values()):
        raise ValueError("level-coverage: final audit requires complete L0-L3 rows")


def validate_invariants(run_dir: Path) -> None:
    rows = load_jsonl(run_dir / "invariant-ledger.jsonl")
    if not rows:
        raise ValueError("invariant-ledger: at least one invariant is required")
    seen: set[str] = set()
    for row in rows:
        require_fields(
            row,
            (
                "schema_version",
                "invariant_id",
                "statement",
                "scope",
                "assets",
                "writers",
                "readers",
                "receipt_boundaries",
                "test_class",
                "execution_status",
                "candidate_ids",
            ),
            "invariant-ledger row",
        )
        invariant_id = str(row["invariant_id"])
        if invariant_id in seen:
            raise ValueError(f"invariant-ledger: duplicate invariant_id {invariant_id}")
        seen.add(invariant_id)
        if row["execution_status"] not in {"executed", "structural", "blocked", "not_applicable"}:
            raise ValueError(f"invariant {invariant_id}: invalid execution_status")


def validate_mutations(run_dir: Path, mode: str) -> None:
    rows = load_jsonl(run_dir / "mutation-results.jsonl")
    indexed: dict[str, dict[str, object]] = {}
    for row in rows:
        family = row.get("operator_family")
        if family not in MUTATION_FAMILIES or family in indexed:
            raise ValueError(f"mutation-results: invalid or duplicate family {family!r}")
        require_fields(
            row,
            (
                "schema_version",
                "operator_family",
                "applicability",
                "mode",
                "mutations_total",
                "killed",
                "survived",
                "blocked",
                "candidate_ids",
                "rationale",
            ),
            f"mutation family {family}",
        )
        if row["mode"] != mode:
            raise ValueError(f"mutation family {family}: mode differs from run manifest")
        if row["applicability"] not in {"applicable", "not_applicable", "blocked"}:
            raise ValueError(f"mutation family {family}: invalid applicability")
        values = [row[name] for name in ("mutations_total", "killed", "survived", "blocked")]
        if not all(isinstance(value, int) and value >= 0 for value in values):
            raise ValueError(f"mutation family {family}: counts must be non-negative integers")
        if row["killed"] + row["survived"] + row["blocked"] != row["mutations_total"]:
            raise ValueError(f"mutation family {family}: outcome counts do not sum to total")
        if row["applicability"] == "applicable" and row["mutations_total"] < 1:
            raise ValueError(f"mutation family {family}: applicable family was not sampled")
        indexed[str(family)] = row
    if set(indexed) != MUTATION_FAMILIES:
        raise ValueError("mutation-results: every operator family requires one disposition row")


def validate_async(run_dir: Path, required: bool) -> None:
    rows = load_jsonl(run_dir / "async-schedules.jsonl", required=required)
    if required and not rows:
        raise ValueError("async-schedules: selected async role requires operation rows")
    for row in rows:
        require_fields(
            row,
            (
                "schema_version",
                "operation_id",
                "state_machine_id",
                "initiating_export",
                "receipts",
                "reserved_state",
                "terminal_states",
                "coverage",
                "candidate_ids",
            ),
            "async-schedules row",
        )
        coverage = row["coverage"]
        if not isinstance(coverage, dict):
            raise ValueError(f"async operation {row['operation_id']}: coverage must be an object")
        if coverage.get("blocked"):
            if not coverage.get("blocker"):
                raise ValueError(f"async operation {row['operation_id']}: blocked coverage needs blocker")
        elif not all(coverage.get(name) is True for name in ("success", "failure", "pending_interleaving")):
            raise ValueError(f"async operation {row['operation_id']}: incomplete required coverage")


def validate_optional_active(run_dir: Path, filename: str, required: bool, kind: str) -> None:
    rows = load_jsonl(run_dir / filename, required=required)
    if required and not rows:
        raise ValueError(f"{filename}: selected {kind} role requires at least one row")
    for row in rows:
        require_fields(row, ("schema_version", "status", "evidence", "candidate_ids"), filename)
        if row["status"] not in {"complete", "blocked", "not_applicable"}:
            raise ValueError(f"{filename}: invalid status")


def validate_rescan(run_dir: Path, final: bool) -> None:
    assumptions = load_jsonl(run_dir / "unresolved-assumptions.jsonl", required=final)
    for row in assumptions:
        require_fields(
            row,
            (
                "schema_version",
                "assumption_id",
                "candidate_id",
                "category",
                "question",
                "target_context",
                "evidence_needed",
                "rescan_iteration",
                "status",
            ),
            "unresolved assumption",
        )
        if row["rescan_iteration"] != 1:
            raise ValueError("unresolved assumption: only rescan iteration 1 is allowed")
    if final:
        summary = load_json(run_dir / "rescan-summary.json")
        require_fields(
            summary,
            ("schema_version", "iteration", "status", "input_count", "new_candidate_ids"),
            "rescan-summary",
        )
        if summary["iteration"] != 1 or summary["status"] not in {"complete", "blocked"}:
            raise ValueError("rescan-summary: exactly one complete or blocked iteration is required")
        if summary["input_count"] != len(assumptions):
            raise ValueError("rescan-summary: input_count differs from unresolved assumptions")


def validate_official_guidance(run_dir: Path, surface: dict[str, object]) -> None:
    rows = load_jsonl(run_dir / "official-guidance-coverage.jsonl")
    selected = set(surface.get("selected_attacker_cards", []))
    indexed: dict[str, dict[str, object]] = {}
    allowed = {
        "conformant",
        "security_candidate",
        "advisory",
        "quality_observation",
        "not_applicable",
        "blocked",
    }
    for row in rows:
        require_fields(
            row,
            (
                "schema_version",
                "card_id",
                "applicability",
                "version_evidence",
                "target_evidence",
                "checks_performed",
                "test_status",
                "candidate_ids",
                "advisory_observations",
                "disposition",
                "rationale",
            ),
            "official-guidance row",
        )
        card_id = str(row["card_id"])
        if row["schema_version"] != 1 or card_id in indexed:
            raise ValueError(f"official-guidance: invalid schema or duplicate card {card_id}")
        if row["disposition"] not in allowed:
            raise ValueError(f"official-guidance {card_id}: invalid disposition")
        if row["applicability"] not in {"applicable", "not_applicable", "blocked"}:
            raise ValueError(f"official-guidance {card_id}: invalid applicability")
        if row["test_status"] not in {"executed", "structural", "not_applicable", "blocked"}:
            raise ValueError(f"official-guidance {card_id}: invalid test_status")
        if not all(isinstance(row[field], list) for field in (
            "version_evidence",
            "target_evidence",
            "checks_performed",
            "candidate_ids",
            "advisory_observations",
        )):
            raise ValueError(f"official-guidance {card_id}: evidence fields must be lists")
        if row["disposition"] == "security_candidate" and not row["candidate_ids"]:
            raise ValueError(f"official-guidance {card_id}: security candidate lacks candidate IDs")
        if row["applicability"] == "applicable" and not row["version_evidence"]:
            raise ValueError(f"official-guidance {card_id}: applicable card lacks version evidence")
        if row["applicability"] == "not_applicable" and row["disposition"] != "not_applicable":
            raise ValueError(f"official-guidance {card_id}: N/A applicability/disposition mismatch")
        if row["applicability"] == "blocked" and row["disposition"] != "blocked":
            raise ValueError(f"official-guidance {card_id}: blocked applicability/disposition mismatch")
        if row["applicability"] == "not_applicable" and row["test_status"] != "not_applicable":
            raise ValueError(f"official-guidance {card_id}: N/A card needs N/A test status")
        if row["applicability"] == "blocked" and row["test_status"] != "blocked":
            raise ValueError(f"official-guidance {card_id}: blocked card needs blocked test status")
        if row["applicability"] == "applicable" and row["disposition"] in {"not_applicable", "blocked"}:
            raise ValueError(f"official-guidance {card_id}: applicable card has terminal N/A/blocked disposition")
        indexed[card_id] = row
    if set(indexed) != selected:
        raise ValueError(
            "official-guidance: coverage rows must equal surface selected_attacker_cards"
        )


def validate_candidate_artifacts(paths: list[Path]) -> None:
    from check_ledger import unique, validate_candidate
    neps = set(load_json(NEP_PIN_PATH)["neps"])
    docs = load_json(OFFICIAL_DOCS_PIN_PATH)
    guidance = {card: set() for card in docs["cards"]}
    for page in docs["pages"]:
        for card in page["attacker_card_ids"]:
            guidance[card].add(page["url_path"])
    for path in paths:
        for candidate, row in unique(strict_jsonl(path), "candidate_id", path.name).items():
            validate_candidate(candidate, row, neps, guidance)


def ledger_inputs(run_dir: Path) -> dict:
    from check_ledger import unique
    return {key: unique(strict_jsonl(run_dir / filename), "candidate_id", key) for key, filename in (
        ("raw", "raw-candidates.jsonl"), ("dedup", "deduplicated.jsonl"),
        ("verdicts", "verdicts.jsonl"), ("dispositions", "dispositions.jsonl"),
    )}


def validate_fragment_union(run_dir: Path, fragments: list[str], combined: str) -> None:
    rows = [row for fragment in fragments for row in strict_jsonl(artifact_path(run_dir, fragment))]
    expected = sorted(canonical_hash(row) for row in rows)
    actual = sorted(canonical_hash(row) for row in strict_jsonl(run_dir / combined))
    if actual != expected:
        raise ValueError(f"{combined}: aggregate differs from owned producer fragments")


def validate_discovery_pass_candidates(run_dir: Path, paths: list[Path], manifest: dict) -> None:
    """Bind every repeated discovery row to its packet pass without altering evidence."""
    if manifest["schema_version"] < 5 or manifest["discovery_passes_planned"] == 1:
        return
    for path in paths:
        if not path.parent.name.startswith("pass-"):
            continue  # Active roles run once outside the repeated blind discovery set.
        number = int(path.parent.name.removeprefix("pass-"))
        for row in strict_jsonl(path):
            if row.get("discovery_pass") != number or not str(row.get("candidate_id", "")).startswith(f"P{number:02d}-"):
                raise ValueError(f"{path}: candidate has wrong discovery pass provenance")


def validate_phase(run_dir: Path, phase: str, *, manifest: dict | None = None) -> None:
    """Shared gates for phase advancement and independent final revalidation."""
    from check_ledger import unique, validate_dedup, validate_ledgers
    from near_audit import run_checked, SCRIPTS, phase_requirements

    manifest = manifest or validate_manifest(run_dir)
    if manifest["schema_version"] >= 4:
        for relative in phase_requirements(run_dir, phase):
            if not artifact_path(run_dir, relative).is_file():
                raise ValueError(f"missing required artifact: {relative}")
    surface = load_json(run_dir / "surface.json")
    selected = surface["selected_roles"]
    if phase == "l0-model":
        validate_intent_model(run_dir, int(manifest["schema_version"]))
    elif phase == "isolated-l1-l2":
        paths = [run_dir / "l1/candidates.jsonl"]
        paths += [artifact_path(run_dir, item["output_path"]) for item in load_jsonl(run_dir / "work-packets.jsonl") if item["role_id"] == "intent-reasoner"]
        validate_candidate_artifacts(paths)
        validate_discovery_pass_candidates(run_dir, paths[1:], manifest)
    elif phase == "blind-l3-active":
        paths = [artifact_path(run_dir, item["output_path"]) for item in load_jsonl(run_dir / "work-packets.jsonl") if item["phase"] == "blind-l3-active"]
        validate_candidate_artifacts(paths)
        validate_discovery_pass_candidates(run_dir, paths, manifest)
        validate_invariants(run_dir)
        validate_mutations(run_dir, str(manifest["mode"]))
        validate_async(run_dir, "async-state-explorer" in selected)
        validate_optional_active(run_dir, "nep-differential.jsonl", "nep-differential" in selected, "NEP differential")
        validate_optional_active(run_dir, "temporal-upgrade.jsonl", "temporal-upgrade" in selected, "temporal upgrade")
        validate_official_guidance(run_dir, surface)
        owners = sorted({item["owner_role"] for item in surface.get("official_guidance_review_queue", [])})
        validate_fragment_union(run_dir, [f"guidance/{role}.jsonl" for role in owners], "official-guidance-coverage.jsonl")
    elif phase == "nep-coverage":
        roles = surface["nep_roles"]
        validate_fragment_union(run_dir, [f"nep/{role}.jsonl" for role in roles], "nep-coverage.jsonl")
        validate_candidate_artifacts([run_dir / f"nep/{role}-candidates.jsonl" for role in roles])
        run_checked([sys.executable, str(SCRIPTS / "check_nep_coverage.py"), str(run_dir / "nep-coverage.jsonl")])
    elif phase == "dedup-chains":
        validate_candidate_artifacts([run_dir / "corpus-echo-candidates.jsonl", run_dir / "raw-candidates.jsonl", run_dir / "deduplicated.jsonl"])
        # Once rescans have run, the raw ledger intentionally includes those outputs.
        if manifest["schema_version"] == 6:
            from run_journal import load as load_run_state
            state = load_run_state(run_dir)
        else:
            state = load_json(run_dir / "run-state.json")
        include_rescans = state["phase_status"].get("counterexample-rescan") == "complete"
        reconcile_candidates(run_dir, include_rescans=include_rescans)
        values = [unique(strict_jsonl(run_dir / name), "candidate_id", name) for name in (
            "raw-candidates.jsonl", "deduplicated.jsonl", "dispositions.jsonl")]
        validate_dedup(*values)
    elif phase == "two-stage-judge":
        values = ledger_inputs(run_dir)
        validate_ledgers(**values, stage="draft")
        triage = unique(strict_jsonl(run_dir / "triage.jsonl"), "candidate_id", "triage")
        if set(triage) != set(values["dedup"]):
            raise ValueError("triage artifact must account for every deduplicated candidate")
        for candidate, row in triage.items():
            payload = row.get("triage", {key: value for key, value in row.items() if key != "candidate_id"})
            if payload != values["verdicts"][candidate].get("triage"):
                raise ValueError(f"triage verdict differs from producer artifact: {candidate}")
    elif phase == "counterexample-rescan":
        validate_rescan(run_dir, True)
        output = run_dir / "counterexample-rescan-candidates.jsonl"
        validate_candidate_artifacts([output])
        summary = load_json(run_dir / "rescan-summary.json")
        ids = [row["candidate_id"] for row in strict_jsonl(output)]
        if set(ids) != set(summary["new_candidate_ids"]):
            raise ValueError("rescan summary differs from its producer output")
        reconcile_candidates(run_dir)
        validate_ledgers(**ledger_inputs(run_dir), stage="draft")
    elif phase == "human-feedback":
        from record_feedback import validate_feedback
        validate_feedback(run_dir, require_complete=True)
    elif phase == "informed-rescan":
        validate_feedback_and_informed_rescan(run_dir, True, "approved")
        reconcile_candidates(run_dir)
        validate_ledgers(**ledger_inputs(run_dir), stage="draft")
    else:
        raise ValueError(f"unknown validation phase: {phase}")


def validate_run(run_dir: Path, *, final: bool = False, stage: str = "approved") -> dict:
    manifest = validate_manifest(run_dir)
    surface = load_json(run_dir / "surface.json")
    if surface.get("schema_version") not in {2, 3}:
        raise ValueError("surface.json: schema_version must be 2 or 3")
    if int(manifest["schema_version"]) >= 2 and surface.get("schema_version") != 3:
        raise ValueError("run-manifest v2+ requires surface.json schema_version 3")
    if surface.get("schema_version") == 3:
        docs = load_json(OFFICIAL_DOCS_PIN_PATH)
        expected_hash = hashlib.sha256(OFFICIAL_DOCS_PIN_PATH.read_bytes()).hexdigest()
        if surface.get("official_docs_source_commit") != docs["source"]["commit"]:
            raise ValueError("surface.json: official-docs source pin differs")
        if surface.get("official_docs_registry_hash") != expected_hash:
            raise ValueError("surface.json: official-docs registry hash differs")
    selected = set(surface.get("selected_roles", []))
    if manifest["schema_version"] >= 3:
        validate_semantic_ir(run_dir, manifest)
        validate_controller_artifacts(run_dir, manifest)
        validate_feedback_and_informed_rescan(run_dir, final, stage)
    validate_intent_model(run_dir, int(manifest["schema_version"]))
    validate_levels(run_dir, final)
    validate_invariants(run_dir)
    validate_mutations(run_dir, str(manifest["mode"]))
    validate_async(run_dir, "async-state-explorer" in selected)
    validate_optional_active(run_dir, "nep-differential.jsonl", "nep-differential" in selected, "NEP differential")
    validate_optional_active(run_dir, "temporal-upgrade.jsonl", "temporal-upgrade" in selected, "temporal upgrade")
    validate_rescan(run_dir, final)
    if surface.get("schema_version") == 3:
        validate_official_guidance(run_dir, surface)
    if manifest["schema_version"] >= 4 and final:
        from near_audit import PHASES
        from check_ledger import validate_ledgers
        for phase in PHASES[:7]:
            validate_phase(run_dir, phase, manifest=manifest)
        reconcile_candidates(run_dir)
        validate_ledgers(**ledger_inputs(run_dir), stage=stage)
        raw_ids = set(ledger_inputs(run_dir)["raw"])
        for filename in ("invariant-ledger.jsonl", "async-schedules.jsonl", "nep-differential.jsonl", "temporal-upgrade.jsonl", "official-guidance-coverage.jsonl", "nep-coverage.jsonl"):
            for row in load_jsonl(run_dir / filename, required=False):
                if set(row.get("candidate_ids", [])) - raw_ids:
                    raise ValueError(f"{filename}: references candidates absent from the raw ledger")
                if stage == "approved" and row.get("disposition") == "conformance_deviation":
                    if row.get("human_disposition") not in {"approved", "standards_only"} or not row.get("reviewer") or not row.get("reviewed_at"):
                        raise ValueError("conformance deviation requires recorded human approval")
    return {"run_dir": str(run_dir), "levels": sorted(LEVELS), "selected_roles": len(selected), "final": final, "stage": stage, "complete": True}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("run_dir", type=Path)
    parser.add_argument("--final", action="store_true", help="Apply final human/report gates")
    parser.add_argument("--stage", choices=("draft", "approved"), default="approved")
    args = parser.parse_args()
    run_dir = args.run_dir.resolve()
    if not run_dir.is_dir():
        parser.error(f"run directory does not exist: {run_dir}")

    print(json.dumps(validate_run(run_dir, final=args.final, stage=args.stage)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
