# Slot Zero report format

The Slot Zero report format uses this sequence and compact finding shape:
`# 🔐 NEARShield v1 Security Review — {project}`, Scope table, Findings sorted
by confidence, Findings List, unscored Leads. A finding has `[score] **number. Title**`, a
`Contract.function` meta line, one short `**Description**` stating actor, mechanism,
and harm, and a source-backed `**Fix**` diff when confidence is at least 75/100.
Below-threshold findings retain their description but no Fix block. A counted
`Below Confidence Threshold` row appears in the Findings List when needed.

NEAR severity remains separate from confidence and appears on each meta line.
The 0–13 evidence score converts to 1–100 by rounding `total * 100 / 13` to the
nearest integer. Repeat sightings appear as `seen in k/N runs`; they never add
confidence. The Scope table records revision. Review stage and pending human decisions
remain in the technical annex, not a compact Review status row. The
full technical report is linked as the annex for receipt proofs, detailed
findings, technical limitations, and scope exclusions. Complete NEP coverage
and all case dispositions remain in internal evidence ledgers. The compact report is a presentation of the finalized technical
verdicts, never another judging stage.

## Presentation rows

Write `<run-dir>/slotzero-content.jsonl` as one JSON object per verified finding and
one per lead. Each object has:

- `candidate_id`: an exact ID in `verdicts.jsonl`;
- `title`: a short specific finding or lead title;
- `location`: `Contract.function`, where `function` is in the candidate's source anchors;
- `description`: one short line of plain technical English. For a finding, name
  the actor, cause, and concrete harm. For a lead, name the observed mechanism
  and what remains unverified;
- `code_smells`: a nonempty list of concrete strings, for leads only;
- `fix`: for findings at or above 75/100 only, an object with `source_path`,
  nonempty `old` lines copied verbatim from that frozen source file, and
  nonempty `new` replacement lines. Keep a complete fix in the technical annex
  if it is too large for a short diff. Do not present an illustrative diff as a
  tested or deployable patch.

The renderer requires a presentation row for every valid/downgraded finding and
unscored lead, rejects extras and duplicates, and checks each removed diff line
against the frozen source. A user may explicitly label one finding
`review_status: "CONFIRMED"` or request that one be omitted from the compact
report with `omit: true` and a nonempty `omission_reason`. Both edits require
`reviewer` and UTC `reviewed_at` fields. A confirmed label appears in its title
and Findings List; omitted findings are excluded and the Scope table counts
them. The full technical annex and verdict ledgers remain unchanged. These
partial presentation edits do not complete the controller's all-case human
feedback gate or approve the audit. Severity, confidence, pass sightings, and inclusion come from
validated run ledgers, not the presentation rows. Refuted and duplicate cases
remain in the internal ledgers; meaningful standards-only deviations appear in
the annex's Standards and hardening notes. None of these become unverified leads.

The technical report must already be finalized in `run-state.json`. The renderer
checks its SHA-256 and source fingerprint before writing `slotzero-report.md`.
The compact file and finalized `technical-annex.md` stay in the run directory.
Always deliver both as clickable file links or attachments when the automated
audit finishes; output is mandatory and requires no request option. The annex
uses the same branded heading at both stages and retains a short scope-stage
note and pending human-review information. Preserve drafts when producing an
approved pair under `<run-dir>/approved/`. Existing recorded filenames remain
valid for old runs using their original package. The renderer prints that exact file
for at most 20 findings. At 21 or more, it prints a counted top-three list and
the full file path; the retained report still has every finding. Use `--project`
when a frozen target copy has a generated directory name.

Do not append an AI-assistance disclaimer or a branding/version-source line
beneath either report title. Preserve navigation links independently.

The Slot Zero report format keeps NEAR-specific evidence and terse finding
descriptions. Keep the NEAR audit's proof and human-approval limits explicit.
