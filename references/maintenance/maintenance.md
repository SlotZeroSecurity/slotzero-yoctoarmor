# Skill and Source Maintenance

Maintenance, ingestion, and qualification do not create target audit runs or
require the audit banner. Resolve `<skill>` from the invoked SKILL.md. Read the
section for the requested operation; source history is in [provenance](../sources/provenance.md).

Keep changes within the requested staged or installed skill and explicitly owned
files. Existing session authorization covers actions within its scope, including
installation when requested; ask only for necessary actions that exceed it.

## Skill edits and validation

Make the requested change and validate the affected behavior. For instruction
edits, check routing, relative links and section anchors, completion criteria,
and consistency with helper interfaces. Use relevant helper tests with disposable
fixtures when behavior changes. Independent review is useful for substantial
routing or completion changes; use inert scenarios with no target audit.

Runtime helpers require standard-library Python >=3.10 on macOS/Linux. The
read-only health check does not initialize a run:

```text
python3 <skill>/scripts/near_audit.py doctor
python3 <skill>/scripts/maintain.py check
```

Both health checks use the same external-URL policy: only the package's top-level
`README.md` may contain web links for installation and documentation. Instructions,
references, helpers, tests, and nested README files retain the URL restriction.
Health checks inspect the package without fetching links or writing bytecode caches.

PyYAML is optional for metadata validation only. If the optional validator is
unavailable, record that limitation rather than claiming it passed or installing
a dependency solely for a documentation edit.

Before replacing an installed package, preserve a versioned copy of its original
configuration-bound files. Instructions, helper code, metadata, and reference
content participate in run configuration hashes. Existing runs must use the
original package or restart under the updated package; do not rewrite saved
hashes or bypass drift checks. Preserve schema versions unless a schema change
is explicitly part of the task.

Distribute source/instructions/references/tests, not generated `__pycache__/`,
`*.pyc`, or `*.lock` artifacts. Keep runtime locks in place on active installations;
exclude them from package copies instead of deleting them during operation.

Completion means the requested edits, relevant validation, and installation when
authorized are finished. Report behavior changes, checks performed, checks not
run, and any remaining blockers. Continue independent in-scope work when an
input or permission is missing; do not stop at the first draft of the edit.
Skill maintenance does not itself require a target audit or benchmark qualification.

## Pattern changes

Follow [adding and maintaining patterns](adding-patterns.md) for source review,
semantic deduplication, stable IDs, card/index updates, and validation.

## PDF and corpus ingestion

Supply PDF files/directories, `<corpus-directory>` for original Markdown sources,
and `<report-conversions-directory>` for full extracted reports explicitly when
needed. Raw reports remain outside the installed skill. If an input is absent,
report it and continue independent documentation checks; do not substitute an
unrelated directory.

Rebuild the frozen original-corpus index only when the explicitly supplied `<corpus-directory>` was intentionally updated:

```text
python3 <skill>/scripts/maintain.py corpus index \
  <corpus-directory> \
  --output <skill>/references/sources/reports/original-findings-index.json
```

Review every new instance semantically before changing an attack-lens card; never auto-merge by title similarity. The active taxonomy is in `references/patterns/attack-lenses-index.json` and ten category files. `references/maintenance/historical-id-map.json` is translation-only; new findings use only `NA-<CATEGORY>-NNN`. `references/sources/reports/original-findings-index.json` covers the original Markdown corpus only. Keep curated PDF ledgers separate, including duplicate markers and explicitly non-NEAR entries.

For every new NEAR-ecosystem PDF, register its raw bytes before opening,
extracting, or semantically reviewing it:

```text
python3 <skill>/scripts/maintain.py corpus pdf register <pdf-or-directory>
```

`action: skip` means a terminal record with the same raw-file SHA-256 already
exists; stop without parsing the PDF or changing provenance. `action: resume`
means an interrupted `pending_review` or `extraction_failed` record exists;
continue that same review. `action: registered` creates one `pending_review`
record. Different bytes remain a new revision even when filenames or extracted
text match. Raw PDFs stay outside the installed skill.

The initial `%PDF-` check is signature screening, not PDF parsing or proof of
readability. Parsing failures belong to review-stage `extraction_failed` records.
`scan` and all-terminal-skip registration remain read-only. Registry writers use
the persistent lock beside the manifest, independent of `TMPDIR`; do not remove
that lock while writers may be active. Required metadata is trimmed and typed,
dates must be real calendar dates, and corpus references identify exact contained
report IDs or supported ledger prefixes. Index rebuilds require non-empty valid
external input and replace output atomically only after validation.

After reviewing a new PDF, update the appropriate date ledger and active
attack-lens cards only when semantic comparison warrants it, then finalize the record:

```text
python3 <skill>/scripts/maintain.py corpus pdf finalize <sha256> \
  --disposition ingested|already_represented|excluded \
  --title <title> --auditor <auditor> --report-date <YYYY-MM[-DD]> \
  --ecosystem-scope <scope> --corpus-ref 'reports/<ledger-file>#<ledger-id>' \
  --notes <review-disposition>
python3 <skill>/scripts/maintain.py corpus pdf validate
```

Use `extraction_failed` with a concrete note when content cannot be recovered;
future ingestion resumes rather than duplicating that record. The manifest is
the authority for exact-byte deduplication; the human ledgers and active
attack-lens cards remain the authority for semantic findings.

## Source refresh

Use explicitly supplied, reviewed local NEP/docs checkouts. Never fetch live
standards during a target audit or silently replace reviewed guidance.

Compare a reviewed local NEP checkout with the pinned registry using:

```text
python3 <skill>/scripts/maintain.py standards neps \
  <skill>/references/standards/neps/nep-registry.json \
  --source-root <local-neps-checkout>
```

Any added, removed, metadata-changed, or content-hash-changed NEP requires semantic checklist review before manually updating the registry pin and the affected category checklist.

For an official-docs refresh, compare a reviewed local `near/docs` checkout
without rewriting curated cards:

```text
python3 <skill>/scripts/maintain.py standards docs \
  <skill>/references/standards/official-docs/docs-registry.json \
  --source-root <local-near-docs-checkout> \
  --change-report <semantic-review-report.json>
```

Any added, removed, moved, or hash-changed page requires semantic review before
updating the pin, registry mapping, attacker guide, prompts, or patterns.

Review current official sources only during explicit maintenance. Source IDs,
commit pins, and SHA-256 digests belong inside the package; audit workers need
no network locations. Do not preserve old document counts as scope constants.
Final and Approved rules require target interface and version activation; Draft
and New proposals remain advisory. Record the target-specific exclusion reason
for every unactivated registry item.

## Qualification

For benchmark curation, permanent-role ablation, qualification commands, and release gates, follow [references/workflow/capability-model.md](../workflow/capability-model.md). Qualification requires explicit evaluation inputs and does not constitute a target audit or a measured claim by itself.

Use `scripts/maintain.py qualification benchmark|maturity|guidance|harness`
for qualification helpers; the controller's audit commands remain unchanged.

After material guidance-routing changes, follow the measured overhead gate in
[references/workflow/capability-model.md](../workflow/capability-model.md#official-guidance-performance-budget).
File-size reduction is not runtime or token telemetry. Prompt changes invalidate
prior qualification equivalence; do not carry measured claims to a new
configuration without the required evaluation evidence.
For Harness Playbook controller or prompt changes, use the paired
[worker-adapter release comparison](../workflow/runtime-adapter.md) as well. Public smoke
tests establish regression behavior only; representative adjudicated audits and
actual usage exports are required to claim an output gain.
