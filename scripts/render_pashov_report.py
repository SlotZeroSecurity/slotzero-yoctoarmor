#!/usr/bin/env python3
"""Render a concise Pashov-v4-shaped review from a finalized NEAR evidence run.

The technical report remains the source of detailed proof and the NEP ledger.
This renderer only changes presentation; it cannot add or change verdicts.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile

THRESHOLD = 75
VALID = {"valid", "valid_downgraded"}
DISCLAIMER = (
    "> ⚠️ This draft was prepared with AI assistance. It does not establish the absence "
    "of vulnerabilities or approve deployment. Fix diffs are design sketches, not "
    "tested patches. Independent review, a bug bounty, and on-chain monitoring remain necessary."
)


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def read_jsonl(path: Path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def contained(run: Path, path: Path) -> Path:
    resolved = path.resolve() if path.is_absolute() else (run / path).resolve()
    if not resolved.is_relative_to(run.resolve()):
        raise ValueError(f"artifact must stay inside run directory: {path}")
    return resolved


def single_line(value: str, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or "\n" in value or "\r" in value:
        raise ValueError(f"{label} must be one nonempty line")
    return value.strip()


def load_content(path: Path, required: set[str]) -> dict[str, dict]:
    result: dict[str, dict] = {}
    for row in read_jsonl(path):
        cid = row.get("candidate_id")
        if cid in result:
            raise ValueError(f"duplicate presentation row: {cid}")
        if cid not in required:
            raise ValueError(f"presentation row is not a finding or lead: {cid}")
        for key in ("title", "location", "description"):
            single_line(row.get(key), f"{cid}.{key}")
        result[cid] = row
    missing = required - result.keys()
    if missing:
        raise ValueError(f"missing presentation rows: {', '.join(sorted(missing))}")
    return result


def pass_sightings(run: Path, manifest: dict, candidates: dict) -> dict[str, int]:
    # Same source-to-survivor accounting as the validated technical front section.
    from report_assembly import discovery_origins
    origins = discovery_origins(run, manifest)
    seen = {cid: set() for cid in candidates}
    for row in read_jsonl(run / "dispositions.jsonl"):
        source, target = row["candidate_id"], row.get("target_id")
        if target in seen and source in origins:
            seen[target].add(origins[source])
    return {cid: len(passes) for cid, passes in seen.items()}


def confidence_percent(total: int) -> int:
    if not isinstance(total, int) or not 0 <= total <= 13:
        raise ValueError(f"invalid 13-point confidence: {total}")
    return (total * 100 + 6) // 13


def validate_entry(row: dict, candidate: dict, confidence: int, target: Path) -> None:
    cid = row["candidate_id"]
    functions = {loc["function"] for loc in candidate.get("locations", [])}
    location = row["location"]
    if not re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*\.[A-Za-z_][A-Za-z_0-9]*", location):
        raise ValueError(f"{cid}: location must use Contract.function")
    if location.rsplit(".", 1)[1] not in functions:
        raise ValueError(f"{cid}: location function is absent from candidate source anchors")
    fix = row.get("fix")
    if confidence >= THRESHOLD:
        if not isinstance(fix, dict) or not fix.get("old") or not fix.get("new"):
            raise ValueError(f"{cid}: above-threshold finding requires source-backed diff fix")
        source_path = single_line(fix.get("source_path"), f"{cid}.fix.source_path")
        if source_path not in {loc["path"] for loc in candidate.get("locations", [])}:
            raise ValueError(f"{cid}: fix source is absent from candidate source anchors")
        source = (target / source_path).resolve()
        if not source.is_relative_to(target.resolve()) or not source.is_file():
            raise ValueError(f"{cid}: fix source unavailable")
        lines = {line.strip() for line in source.read_text(encoding="utf-8").splitlines()}
        for old in fix["old"]:
            if single_line(old, f"{cid}.fix.old").strip() not in lines:
                raise ValueError(f"{cid}: removed diff line is absent from frozen source: {old}")
        for new in fix["new"]:
            single_line(new, f"{cid}.fix.new")
    elif fix:
        raise ValueError(f"{cid}: below-threshold finding must not carry a Fix block")


def render(run: Path, content_path: Path, project: str | None = None) -> str:
    manifest = read_json(run / "run-manifest.json")
    state = read_json(run / "run-state.json")
    record = state.get("report") or {}
    if state.get("status") not in {"draft_ready", "complete"}:
        raise ValueError("the technical report must be finalized before the compact report")
    technical = contained(run, Path(record.get("path", "")))
    if not technical.is_file():
        raise ValueError("recorded technical report is missing")
    actual_hash = "sha256:" + hashlib.sha256(technical.read_bytes()).hexdigest()
    if actual_hash != record.get("sha256"):
        raise ValueError("technical report no longer matches its finalized hash")
    if record.get("input_fingerprint") != manifest.get("input_fingerprint"):
        raise ValueError("technical report is bound to a different source snapshot")
    if record.get("configuration_hash") != manifest.get("configuration_hash"):
        raise ValueError("technical report is bound to a different skill configuration")
    verdicts = {row["candidate_id"]: row for row in read_jsonl(run / "verdicts.jsonl")}
    candidates = {row["candidate_id"]: row for row in read_jsonl(run / "deduplicated.jsonl")}
    findings = {cid for cid, row in verdicts.items() if row["verdict"] in VALID}
    leads = {cid for cid, row in verdicts.items() if row["verdict"] == "lead"}
    content = load_content(content_path, findings | leads)
    omitted = set()
    confirmed = set()
    for cid in findings:
        row = content[cid]
        if row.get("omit") is True:
            single_line(row.get("omission_reason"), f"{cid}.omission_reason")
            omitted.add(cid)
        elif "omit" in row and row["omit"] is not False:
            raise ValueError(f"{cid}: omit must be boolean")
        if cid in omitted or row.get("review_status") is not None:
            single_line(row.get("reviewer"), f"{cid}.reviewer")
            reviewed_at = single_line(row.get("reviewed_at"), f"{cid}.reviewed_at")
            if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", reviewed_at):
                raise ValueError(f"{cid}: reviewed_at must be UTC ISO-8601")
        status = row.get("review_status")
        if status is not None:
            if status != "CONFIRMED":
                raise ValueError(f"{cid}: unsupported review_status")
            if cid in omitted:
                raise ValueError(f"{cid}: omitted finding cannot also be confirmed")
            confirmed.add(cid)
    for cid in findings:
        score = confidence_percent(verdicts[cid]["confidence"]["total"])
        validate_entry(content[cid], candidates[cid], score, Path(manifest["target"]))
    for cid in leads:
        if "omit" in content[cid] or "review_status" in content[cid]:
            raise ValueError(f"{cid}: lead cannot carry finding review edits")
        location = content[cid]["location"]
        functions = {loc["function"] for loc in candidates[cid].get("locations", [])}
        if not re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*\.[A-Za-z_][A-Za-z_0-9]*", location) or location.rsplit(".", 1)[1] not in functions:
            raise ValueError(f"{cid}: lead location is absent from candidate source anchors")
        if content[cid].get("fix"):
            raise ValueError(f"{cid}: lead cannot have a Fix block")
        smells = content[cid].get("code_smells")
        if not isinstance(smells, list) or not smells or any(not isinstance(x, str) or not x.strip() for x in smells):
            raise ValueError(f"{cid}: lead needs concrete code smells")
    sightings = pass_sightings(run, manifest, candidates)
    passes = manifest["discovery_passes_planned"]
    title = single_line(project, "project") if project is not None else Path(manifest["target"]).name
    stage = record["stage"].title()
    files = [f"`{path}`" for path in manifest["scope"]]
    chunks = [" · ".join(files[i:i + 3]) for i in range(0, len(files), 3)]
    files_cell = "<br>".join(chunks).replace("|", "\\|")
    lines = [f"# 🔐 {stage} Security Review — {title}", "", "---", "", "## Scope", "",
             "|  |  |", "| --- | --- |", f"| **Mode** | {manifest['mode']} |",
             f"| **Files reviewed** | {files_cell} |",
             f"| **Confidence threshold (1-100)** | {THRESHOLD} |"]
    if passes > 1:
        lines.append(f"| **Passes** | {passes} |")
    review_text = f"{stage}; human decisions {'pending' if stage == 'Draft' else 'recorded'}"
    if confirmed:
        review_text += f"; {len(confirmed)} user-confirmed in this presentation"
    lines += [f"| **Revision** | `{manifest['target_revision']}` |",
              f"| **Review status** | {review_text} |",
              f"| **NEAR evidence and NEP ledger** | [Technical annex]({technical}) |"]
    if omitted:
        lines.append(f"| **Presentation exclusions** | {len(omitted)} audited finding{'s' if len(omitted) != 1 else ''} omitted at the user's request; retained in the annex |")
    lines += ["", "---", "", "## Findings", ""]
    ordered = sorted(findings - omitted, key=lambda cid: (-confidence_percent(verdicts[cid]["confidence"]["total"]), cid))
    for number, cid in enumerate(ordered, 1):
        entry, verdict = content[cid], verdicts[cid]
        score = confidence_percent(verdict["confidence"]["total"])
        segments = [f"`{entry['location']}`", f"Confidence: {score}", f"Severity: {verdict['severity'].title()}"]
        if passes > 1:
            segments.append(f"seen in {sightings[cid]}/{passes} runs")
        marked_title = entry["title"] + (" — CONFIRMED" if cid in confirmed else "")
        lines += [f"[{score}] **{number}. {marked_title}**", "", " · ".join(segments), "",
                  "**Description**", entry["description"], ""]
        if score >= THRESHOLD:
            fix = entry["fix"]
            lines += ["**Fix**", "", "```diff"]
            lines.extend("- " + old.strip() for old in fix["old"])
            lines.extend("+ " + new.strip() for new in fix["new"])
            lines += ["```", ""]
        lines += ["---", ""]
    if not ordered:
        lines += ["_None — this scan raised no verified findings._", "", "---", ""]
    lines += ["Findings List", "", "| # | Confidence | Title |", "|---|---|---|"]
    below = False
    for number, cid in enumerate(ordered, 1):
        score = confidence_percent(verdicts[cid]["confidence"]["total"])
        if score < THRESHOLD and not below:
            lines.append("| | | **Below Confidence Threshold** |")
            below = True
        marked_title = content[cid]["title"] + (" — CONFIRMED" if cid in confirmed else "")
        lines.append(f"| {number} | [{score}] | {marked_title} |")
    if not ordered:
        lines.append("| | | _None._ |")
    lines += ["", "---", "", "## Leads", "",
              "_Concrete vulnerability trails whose full exploit path remains unverified. Not scored._", ""]
    for cid in sorted(leads):
        entry = content[cid]
        seen = f" · seen in {sightings[cid]}/{passes} runs" if passes > 1 else ""
        smells = ", ".join(entry["code_smells"])
        lines.append(f"- **{entry['title']}** — `{entry['location']}`{seen} — Code smells: {smells} — {entry['description']}")
    if not leads:
        lines.append("_None._")
    lines += ["", "---", "", DISCLAIMER, ""]
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_dir", type=Path)
    parser.add_argument("--content", type=Path, default=Path("pashov-content.jsonl"))
    parser.add_argument("--output", type=Path, default=Path("pashov-report.md"))
    parser.add_argument("--project", help="display name when the frozen target is an isolated copy")
    args = parser.parse_args()
    run = args.run_dir.resolve()
    content = contained(run, args.content)
    output = contained(run, args.output)
    technical_record = read_json(run / "run-state.json").get("report") or {}
    technical_path = contained(run, Path(technical_record.get("path", "")))
    if content == output or output == technical_path or output.suffix != ".md":
        raise ValueError("compact Markdown output must not overwrite input or finalized technical report")
    report = render(run, content, args.project)
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=output.parent, delete=False) as handle:
        temporary = Path(handle.name)
        handle.write(report)
    os.replace(temporary, output)
    # Pashov v4 prints the full small report; a large report gets a counted top-three slice.
    count = report.count("**Description**")
    if count <= 20:
        print(report, end="")
    else:
        head = report.split("## Findings\n", 1)[0]
        index = [line for line in report.split("Findings List\n", 1)[1].split("\n---\n", 1)[0].splitlines() if line.strip()]
        top = index[:2] + [row for row in index[2:] if re.match(r"\| [0-9]+ \|", row)][:3]
        print(head + f"## Findings List — top 3 of {count}\n\n" + "\n".join(top)
              + f"\n\nFull report: {output}\n\n{DISCLAIMER}")


if __name__ == "__main__":
    main()
