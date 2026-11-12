"""Deterministic front section from a validated NEAR run's finding ledgers."""
from __future__ import annotations

from pathlib import Path

from run_integrity import artifact_path, read_json, read_jsonl

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}


def _sentence(value: object) -> str:
    text = " ".join(str(value or "unknown").split()).rstrip(". ")
    return text[:1].lower() + text[1:] if text else "unknown"


def discovery_origins(run_dir: Path, manifest: dict) -> dict[str, int]:
    from near_audit import ACTIVE_ROLES
    origins = {}
    for packet in read_jsonl(run_dir / "work-packets.jsonl"):
        if packet["phase"] not in {"isolated-l1-l2", "blind-l3-active"}:
            continue
        if packet["role_id"] != "intent-reasoner" and (
                packet["phase"] != "blind-l3-active" or packet["role_id"] in ACTIVE_ROLES):
            continue
        number = packet.get("discovery_pass", 1)
        for relative in packet.get("candidate_outputs", []):
            for row in read_jsonl(artifact_path(run_dir, relative)):
                cid = row["candidate_id"]
                if cid in origins:
                    raise ValueError(f"duplicate pass producer: {cid}")
                origins[cid] = number
    return origins


def canonical_front(run_dir: Path, manifest: dict) -> str:
    state = read_json(run_dir / "run-state.json")
    planned = manifest["discovery_passes_planned"]
    progress = state["discovery_pass_status"]
    l2 = sum(value == "complete" for value in progress["l2"].values())
    l3 = sum(value == "complete" for value in progress["l3"].values())
    if l2 != planned or l3 != planned:
        raise ValueError("report requires all L2 and L3 discovery passes")
    dedup = {row["candidate_id"]: row for row in read_jsonl(run_dir / "deduplicated.jsonl")}
    verdicts = {row["candidate_id"]: row for row in read_jsonl(run_dir / "verdicts.jsonl")}
    origins = discovery_origins(run_dir, manifest)
    by_target: dict[str, set[int]] = {candidate: set() for candidate in dedup}
    for row in read_jsonl(run_dir / "dispositions.jsonl"):
        source = row["candidate_id"]
        target = row.get("target_id")
        if target in by_target and source in origins:
            by_target[target].add(origins[source])
    findings = [(candidate, verdicts[candidate], dedup[candidate]) for candidate in dedup
                if verdicts[candidate]["verdict"] in {"valid", "valid_downgraded"}]
    findings.sort(key=lambda item: (SEVERITY_ORDER[item[1]["severity"].lower()],
                                    -item[1]["confidence"]["total"], item[0]))
    scope = ", ".join(manifest["scope"][:4])
    if len(manifest["scope"]) > 4:
        scope += f", +{len(manifest['scope']) - 4} more"
    lines = ["## Scope at a glance", "",
             f"`{manifest['target']}` · revision `{manifest['target_revision']}` · {scope or 'no source files'} · mode `{manifest['mode']}` · {planned} planned discovery passes, {min(l2, l3)} completed", "",
             f"## Top findings — top {min(3, len(findings))} of {len(findings)}", ""]
    if findings:
        lines.extend(["| ID | Severity | Finding in one sentence | Seen in discovery passes |",
                      "|---|---|---|---|"])
        for candidate, verdict, row in findings[:3]:
            actor = _sentence(row.get("attacker", "an attacker"))
            cause = _sentence(row.get("root_cause"))
            harm = _sentence(row.get("terminal_harm"))
            sentence = f"{actor} can exploit this path because {cause}, harming users through {harm}."
            sentence = sentence.replace("|", "\\|").replace("\n", " ")
            lines.append(f"| `{candidate}` | {verdict['severity'].title()} | {sentence} | {len(by_target[candidate])}/{planned} |")
    else:
        lines.append("Top 0 of 0 — no verified findings.")
    return "\n".join(lines) + "\n\n"


def assemble(run_dir: Path, manifest: dict, body: str) -> str:
    if "## Scope at a glance" in body or "## Top findings —" in body:
        raise ValueError("body already contains an assembled front section")
    lines = body.splitlines(keepends=True)
    index = next((i for i, line in enumerate(lines) if line.startswith("# ")), None)
    if index is None:
        raise ValueError("report body has no title heading")
    return "".join(lines[:index + 1]) + "\n" + canonical_front(run_dir, manifest) + "".join(lines[index + 1:])


def validate_assembled(run_dir: Path, manifest: dict, report: str) -> None:
    if not report.startswith("```text\n███████╗"):
        raise ValueError("Slot Zero NEAR banner missing from report start")
    front = canonical_front(run_dir, manifest)
    if report.count(front) != 1:
        raise ValueError("report front section differs from validated records")
    for section in ("## Audit metadata", "## Executive summary", "## Findings index", "## Findings",
                    "## Leads and contested items", "## NEP standards conformance",
                    "## Active-testing coverage", "## Verification and coverage ledger"):
        if section not in report:
            raise ValueError(f"report lacks required full section: {section}")
    details = report.split("\n## Findings\n", 1)
    if len(details) != 2:
        raise ValueError("full findings section missing")
    findings = [row for row in read_jsonl(run_dir / "verdicts.jsonl") if row["verdict"] in {"valid", "valid_downgraded"}]
    for row in findings:
        if row["candidate_id"] not in details[1] or f"{row['confidence']['total']}/13" not in details[1]:
            raise ValueError(f"verified finding or its confidence absent from detailed report: {row['candidate_id']}")
    if details[1].count("#### Recommendation") < len(findings):
        raise ValueError("every verified finding requires a complete fix")
