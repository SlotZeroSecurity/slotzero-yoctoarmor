"""Deterministic front section from a validated NEAR run's finding ledgers."""
from __future__ import annotations

from pathlib import Path
import re
from html import escape

from run_integrity import artifact_path, read_json, read_jsonl

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
ANNEX_SUBTITLE = "NEARShield v1  - SLOT ZERO SECURITY"
BODY_SECTIONS = (
    "Architecture and trust assumptions", "Findings index", "Findings",
    "Unverified leads", "Standards and hardening notes", "Testing and limitations",
    "Remediation priorities",
)


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


def canonical_front(run_dir: Path, manifest: dict, stage: str = "draft") -> str:
    if stage not in {"draft", "approved"}:
        raise ValueError("report stage must be draft or approved")
    state = read_json(run_dir / "run-state.json")
    planned = manifest["discovery_passes_planned"]
    progress = state["discovery_pass_status"]
    l2 = sum(value == "complete" for value in progress["l2"].values())
    l3 = sum(value == "complete" for value in progress["l3"].values())
    if l2 != planned or l3 != planned:
        raise ValueError("report requires all L2 and L3 discovery passes")
    dedup = {row["candidate_id"]: row for row in read_jsonl(run_dir / "deduplicated.jsonl")}
    verdicts = {row["candidate_id"]: row for row in read_jsonl(run_dir / "verdicts.jsonl")}
    if manifest.get("schema_version", 0) >= 6:
        from threat_model import validate_verdict_assessments
        validate_verdict_assessments(list(verdicts.values()), manifest)
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
             f"`{manifest['target']}` · revision `{manifest['target_revision']}` · {scope or 'no source files'} · {planned} planned discovery passes, {min(l2, l3)} completed", "",
             "**Review stage:** " + ("Draft — pending human review." if stage == "draft" else "Approved — human review recorded."), ""]
    if manifest.get("schema_version", 0) >= 6:
        from threat_model import report_context
        lines += [report_context(manifest), ""]
    if manifest.get("schema_version", 0) >= 7:
        from review_policy import review_limitations
        limitations = review_limitations(run_dir)
        if limitations:
            lines += ["**Review limitations:** " + limitations, ""]
    lines += [f"## Top findings — top {min(3, len(findings))} of {len(findings)}", ""]
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


def exclusions(run_dir: Path) -> str:
    """Retain exclusions as accounting, never findings or recommendations."""
    rows = [row for row in read_jsonl(run_dir / "verdicts.jsonl") if row["verdict"] == "out_of_scope"]
    if not rows:
        return ""
    def cell(value: str) -> str:
        return escape(" ".join(value.split())).replace("|", "&#124;")
    lines = ["## Threat-model exclusions", "", "Excluded from findings and leads; retained only for audit accounting.", "",
             "| Candidate | Model evidence | Exclusion reason |", "| --- | --- | --- |"]
    for row in sorted(rows, key=lambda item: item["candidate_id"]):
        assessment = row.get("threat_model_assessment", row["triage"]["threat_model_assessment"])
        citations = "; ".join(f"{c['path']}:{c['start']}-{c['end']}: {c['quote']}" for c in assessment["model_citations"])
        lines.append(f"| {cell(row['candidate_id'])} | {cell(citations)} | {cell(assessment['rationale'])} |")
    return "\n".join(lines) + "\n"


def reject_excluded_presentation(run_dir: Path, text: str) -> None:
    for row in read_jsonl(run_dir / "verdicts.jsonl"):
        if row["verdict"] == "out_of_scope" and re.search(r"(?<![\w-])" + re.escape(row["candidate_id"]) + r"(?![\w-])", text):
            raise ValueError(f"excluded candidate may appear only in generated exclusion accounting: {row['candidate_id']}")


def assemble(run_dir: Path, manifest: dict, body: str, stage: str = "draft") -> str:
    if "## Threat-model exclusions" in body:
        raise ValueError("threat-model exclusion accounting is generated, not authored in the body")
    reject_excluded_presentation(run_dir, body)
    if "## Scope at a glance" in body or "## Top findings —" in body:
        raise ValueError("body already contains an assembled front section")
    lines = body.splitlines(keepends=True)
    index = next((i for i, line in enumerate(lines) if line.startswith("# ")), None)
    if index is None:
        raise ValueError("report body has no title heading")
    return "".join(lines[:index + 1]) + "\n" + canonical_front(run_dir, manifest, stage) + "".join(lines[index + 1:]) + "\n" + exclusions(run_dir)


def markdown_sections(report: str) -> list[tuple[str, int]]:
    """Find report sections without interpreting fenced source excerpts as headings."""
    result = []
    fence = ""
    for index, line in enumerate(report.splitlines()):
        marker = re.match(r"^ {0,3}(`{3,}|~{3,})(.*)$", line)
        if marker:
            token, suffix = marker.groups()
            if not fence:
                fence = token
            elif token[0] == fence[0] and len(token) >= len(fence) and not suffix.strip():
                fence = ""
        elif not fence and line.startswith("## "):
            result.append((line[3:].strip(), index))
    if fence:
        raise ValueError("report has an unclosed code fence")
    return result


def validate_assembled(run_dir: Path, manifest: dict, report: str, stage: str | None = None) -> None:
    if stage is None:
        stage = (read_json(run_dir / "run-state.json").get("report") or {}).get("stage", "draft")
    excluded = exclusions(run_dir)
    if excluded and report.count(excluded) != 1:
        raise ValueError("report must retain exact threat-model exclusion accounting")
    reject_excluded_presentation(run_dir, report.replace(excluded, "") if excluded else report)
    if not report.startswith("```text\n███████╗"):
        raise ValueError("Slot Zero NEAR banner missing from report start")
    banner = report.split("\n```", 1)[0]
    if ANNEX_SUBTITLE not in [line.strip() for line in banner.splitlines()]:
        raise ValueError("NEARShield annex banner subtitle missing")
    front = canonical_front(run_dir, manifest, stage)
    if report.count(front) != 1:
        raise ValueError("report front section differs from validated records")
    sections = markdown_sections(report)
    headings = [name for name, _ in sections]
    expected = [name for name, _ in markdown_sections(front)] + list(BODY_SECTIONS)
    if "Pending review" in headings:
        if stage == "approved":
            raise ValueError("approved report cannot contain pending review")
        expected.append("Pending review")
    if excluded:
        expected.append("Threat-model exclusions")
    if headings != expected:
        raise ValueError("report sections must match the streamlined annex order: " + ", ".join(expected))
    positions = dict(sections)
    details = "\n".join(report.splitlines()[positions["Findings"] + 1:positions["Unverified leads"]])
    findings = [row for row in read_jsonl(run_dir / "verdicts.jsonl") if row["verdict"] in {"valid", "valid_downgraded"}]
    for row in findings:
        if row["candidate_id"] not in details or f"{row['confidence']['total']}/13" not in details:
            raise ValueError(f"verified finding or its confidence absent from detailed report: {row['candidate_id']}")
    if details.count("#### Recommendation") < len(findings):
        raise ValueError("every verified finding requires a complete fix")
