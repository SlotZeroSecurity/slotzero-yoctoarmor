# Package maintenance

Maintenance, ingestion, and qualification do not create target audit runs or
require the audit banner. Resolve `<skill>` from the invoked SKILL.md. Read the
section for the requested operation.

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

Distribute instructions, patterns, runtime resources, docs, helpers, tests, and benchmarks, not generated `__pycache__/`,
`*.pyc`, or `*.lock` artifacts. Keep runtime locks in place on active installations;
exclude them from package copies instead of deleting them during operation.

Completion means the requested edits, relevant validation, and installation when
authorized are finished. Report behavior changes, checks performed, checks not
run, and any remaining blockers. Continue independent in-scope work when an
input or permission is missing; do not stop at the first draft of the edit.
Skill maintenance does not itself require a target audit or benchmark qualification.

## Pattern intake

For supplied PDFs, reports, or findings, follow [adding patterns](adding-patterns.md).
Read the input, compare mechanisms across current cards, and update only useful
coverage. Do not register files or retain consumption history. Inputs stay outside
the package; temporary extraction is not a source archive.

## Evidence validation

Audit evidence remains validated independently of pattern intake:

```text
python3 <skill>/scripts/maintain.py evidence ledger <raw-candidates.jsonl> <deduplicated.jsonl> <verdicts.jsonl> <dispositions.jsonl>
```

Use the helper's `--help` for the existing evidence options. Removing source
archives does not remove target evidence, candidate checks, or report ledgers.

## Source refresh

Use explicitly supplied, reviewed local NEP/docs checkouts. Never fetch live
standards during a target audit or silently replace reviewed guidance.

Compare a reviewed local NEP checkout with the pinned registry using:

```text
python3 <skill>/scripts/maintain.py standards neps \
  <skill>/runtime/standards/neps/nep-registry.json \
  --source-root <local-neps-checkout>
```

Any added, removed, metadata-changed, or content-hash-changed NEP requires semantic checklist review before manually updating the registry pin and the affected category checklist.

Checklist paths resolve within the package containing the supplied registry.
For a standalone registry copy outside the normal package layout, pass
`--package-root <package-to-validate>` explicitly; the helper never borrows
checklists from its own installation to validate a different package.

For an official-docs refresh, compare a reviewed local `near/docs` checkout
without rewriting curated cards:

```text
python3 <skill>/scripts/maintain.py standards docs \
  <skill>/runtime/standards/official-docs/docs-registry.json \
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

For benchmark curation, permanent-role ablation, qualification commands, and release gates, follow [runtime/workflow/capability-model.md](../runtime/workflow/capability-model.md). Qualification requires explicit evaluation inputs and does not constitute a target audit or a measured claim by itself.

Use `scripts/maintain.py qualification benchmark|maturity|guidance|harness`
for qualification helpers; the controller's audit commands remain unchanged.

After material guidance-routing changes, follow the measured overhead gate in
[runtime/workflow/capability-model.md](../runtime/workflow/capability-model.md#official-guidance-performance-budget).
File-size reduction is not runtime or token telemetry. Prompt changes invalidate
prior qualification equivalence; do not carry measured claims to a new
configuration without the required evaluation evidence.
For Harness Playbook controller or prompt changes, use the paired
[worker-adapter release comparison](../runtime/workflow/runtime-adapter.md) as well. Public smoke
tests establish regression behavior only; representative adjudicated audits and
actual usage exports are required to claim an output gain.
