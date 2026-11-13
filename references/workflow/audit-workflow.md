# Target Audit Workflow

Use this reference only for a requested target audit. Resolve `<skill>` to the directory containing the invoked SKILL.md; resolve all other placeholders from the current request and runtime. Maintenance and qualification have separate routes in SKILL.md.

For a target audit, retain the existing Slot Zero banner only in the full
[technical annex](../reporting/technical-annex-template.md). The reader-facing
[Slot Zero report format](../reporting/slotzero-report-format.md) begins with its compact
security-review heading and does not repeat that banner. Do not print a second
report or preface during resumed phases.

## Inputs and scope

First enforce the [threat-model prerequisite](threat-model.md). Require the target
root's `THREAT_MODEL.md`, or stop for generation/restart or explicit per-scan
continuation. Only an explicit user choice permits the controller flag
`--allow-missing-threat-model`; record the limitation without inventing trust.
Every worker reads the supplied model first, including judges and rescans.
Apply evidence-backed threat-model assessments to every triage and every passed
survivor's verification. Exclusions remain in accounting, never findings.

Resolve the target root before acting. Never mutate audited source. Every scan
reviews all relevant source, or named primary files plus context needed to validate
them. Preserve all 12 core roles, all six conditional specialists for applicability
review, applicable active roles, seven NEP roles, two independent lenses per callable,
and the complete registry-derived NEP coverage ledger.

Every scan covers all supported applicable mutation operators, fresh post-discovery
pattern and chain agents, independent verification across every severity, and one
bounded rescan of excluded and unresolved paths. Follow [the review contract](review-contract.md).

- **Report delivery** (always enabled): deliver `slotzero-report.md` and `technical-annex.md` as clickable file links or attachments after every completed automated audit. Retain both in the run directory outside audited source. No output option is required. Internal evidence ledgers are supporting artifacts, not additional default deliverables.
- **Discovery passes** (`--loop [N]`): bare `--loop` selects 3; an explicit integer 1–10 selects that many without another question. Also honor a count stated in ordinary language. Otherwise ask before scope discovery or any expensive audit work: 1, **3 recommended**, 5, or a custom integer 1–10. One pass has no prior-pass context. This repeats fresh L2 and blind L3 discovery, not L0, L1, active testing, NEP review, counterexample rescan, or the human-informed rescan. It is not a claim of greater confidence.

Exclude generated `target/`, `node_modules/`, `dist/`, `build/`, vendored dependencies, and unrelated crates. Tests/examples are verification context. Include adjacent TypeScript/JavaScript/Solidity only when it affects signing, indexing, relaying, bridging, settlement, or user security.

If no NEAR surface is found, stop and explain. If multi-agent execution is unavailable, do not call a serial review a complete multi-agent audit. Never claim L4 unless a valid track-specific maturity attestation exists.

## Reference routing

Load only what the current phase needs:

- **Capability pipeline and active tests:** [L0-L4 capability model](capability-model.md) and [semantic pipeline](semantic-pipeline.md).
- **Scope/orchestration:** [security model](near-security-model.md), [agent catalog](agent-catalog.md), [finding schema](../schemas/finding-schema.md), [NEP registry](../standards/neps/nep-registry.json), and [official-docs registry](../standards/official-docs/docs-registry.json).
- **L1 pattern agent:** assigned source, L0 model, finding schema, the [attack-lens index](../patterns/attack-lenses-index.json), only the category files selected in `surface.json`, and relevant official cards. Blind L3 agents receive role rules and target context, never the attack-lens corpus.
- **L0 modeler / L2 intent agent:** target code/specifications/tests/manifests/dependency context, packet-permitted target-derived semantic IR, and [neutral schemas](../schemas/neutral-schemas.md). L0 receives `neutral-surface.json`; L2 additionally receives the target-grounded L0 artifact. Neither receives the security model, capability-model, finding-schema examples, registries, attacker cards, corpus, peer findings, or benchmark answers. The orchestrator supplies only the selected neutral prompt, not the catalog.
- **NEP agent:** `surface.json`, registry, only its category checklist, finding schema, and target evidence.
- **Corpus echo:** only after blind L2/L3 discovery is frozen, load the selected category files and any later-discovered categories justified by target evidence.
- **Historical source review:** L1 and post-blind echo use the [binding protocol](../patterns/target-binding.md) before consulting selected [historical examples](../sources/issues/omnibridge-satoshi/findings.md) and [source dispositions](../sources/issues/omnibridge-satoshi/findings.json). Do not load complete ledgers into workers. Training cases and answers are maintenance material, not target-audit inputs.
- **Judging:** minimal candidate packet, cited target context, security model, and [verification rules](../reporting/verification-reporting.md).
- **Reporting:** [Slot Zero report format](../reporting/slotzero-report-format.md) and [full technical annex template](../reporting/technical-annex-template.md).

## Phase 0 — Freeze scope and build L0

Create an isolated temporary run directory outside source. Prefer the local
controller, which records run-manifest schema 7 and run-state schema 4, the exact revision, dirty state, source
fingerprint, scope, exclusions, toolchain, SDK/standards versions, NEP and
official-docs pins, corpus/model/prompt/tool hashes, semantic extractor/driver/
work-packet hashes, runtime capacity, feedback policy, and trust assumptions.

Use the read-only `python3 <skill>/scripts/near_audit.py doctor` preflight before initializing. It reports local prerequisites and availability without creating a run, installing tools, using credentials, or accessing a network. Runtime helpers use standard-library Python >=3.10 on macOS/Linux; PyYAML is optional for skill metadata validation only. If this schema/interface is unavailable, report the tooling blocker. Inspect old runs read-only; restart in a fresh run directory instead of migrating them.

Run:

```text
python3 <skill>/scripts/near_audit.py run <target-root> \
  [--files explicit/path ...] \
  --loop <selected-pass-count> --run-dir <run-dir> --worker-capacity <capacity>
```

If constructing artifacts manually, run `map_surface.py`,
`build_semantic_ir.py`, and `select_official_cards.py` and reproduce all schema-7
manifest bindings, including the planned discovery pass count. Use `near_audit.py status <run-dir>` to inspect a run read-only and
`near_audit.py resume <run-dir>` only to advance a current-schema initialized run; the controller prepares hash-bound work packets but the
orchestrator still dispatches isolated workers.

Use the [Codex worker adapter](runtime-adapter.md) to inspect one minimal role
packet, record host-observed worker events, and read journal-derived progress.
The adapter does not itself enforce a sandbox or terminate a worker.

Schema-6 run packets explicitly list `candidate_outputs` and `additional_outputs`.
Honor every listed output, including empty candidate files for zero results:

| Role / artifact | Run-relative output |
|---|---|
| L0 target-context projection | `neutral-surface.json` (not signal/card `surface.json`) |
| NEP coverage / candidates | `nep/<role>.jsonl` / `nep/<role>-candidates.jsonl` |
| Active-role candidates | `discovery/<role>.jsonl` |
| Active-role coverage | Existing `async-schedules.jsonl`, `invariant-ledger.jsonl`, `mutation-results.jsonl`, `nep-differential.jsonl`, or `temporal-upgrade.jsonl`, as assigned |
| Official-guidance owner fragment | `guidance/<role>.jsonl` |
| Corpus echo candidates | `corpus-echo-candidates.jsonl`, accounted even when empty |

For more than one pass, L2 packets write `l2/pass-XX/candidates.jsonl` and blind
L3 packets write `discovery/pass-XX/<role>.jsonl`. Active-role outputs retain
their single paths. Each repeated candidate has `discovery_pass: N` and an
immutable `PXX-` ID prefix; keep `pass_origin: blind` for benchmark and human
feedback attribution. This pass number is separate from counterexample and
informed rescan provenance. A missing or malformed pass is incomplete, including
when an empty result file was expected.

Collect candidate outputs into raw-candidate accounting and combine NEP/guidance
fragments into their complete coverage ledgers. An absent file is not a zero-result
artifact. Close a worker only after all its assigned outputs are collected and
validated.

Review `semantic-ir.json`, signals, and selected attacker cards rather than
trusting them. Semantic edges are navigation hints: confirm security claims in
exact source, built ABI/Wasm, dependencies, or execution, and preserve every
unresolved/ambiguous edge as a blind spot. The routed
file is the only official attacker-card body supplied to L1/L3; never give it or
the registry to L2. Give L0 `neutral-surface.json` as its target-context projection, never the signal/card surface. Dispatch the `protocol-modeler` to produce `intent-model.json`: actors/keys, account/key capability matrix, assets/liabilities, exports/deposit rules, receipt state machines, yield/resume flows, standards, trust boundaries, global-contract dependencies, route-specific cross-chain trust, version claims, invariants, unresolved intent, and upgrade dependencies. For each asset map custody, tracked totals, claims, storage backing, fees, and pending reservations; compare actor cohorts and conversion rates, and reconcile conservation after every receipt. L0 cannot emit candidates or severity.

Create the exact file/method manifest, receipt-edge inventory, trust map, initial invariant ledger, and four-row `level-coverage.jsonl`. Run existing read-only build/test/lint commands only after inspecting configuration. Do not install dependencies or use live networks/credentials without existing authorization. Inspect build hooks first and execute tests only in an isolated copy when they write artifacts.

**Gate:** the surface and L0 artifacts validate; intent uncertainty is explicit; no L0 finding exists.

## Phase 1 — Isolated L1 and L2 passes

Create one fresh L1 context and a separate fresh L2 context for **each selected discovery pass**, with separate scratch directories. They may run concurrently but must not read each other's output or any earlier pass's candidates. L0 and L2 use target context and neutral schemas only; L2 additionally receives L0. Record whether the runtime enforces input/filesystem restrictions or isolation is prompt-only. Separate paths and allowed/forbidden input lists alone do not enforce access. Do not claim enforced isolation without runtime evidence; prompt-only runs cannot satisfy an enforced-isolation qualification gate.

- `pattern-matcher` (L1) may use its routed attack-lens categories, applicable NEP guidance, selected official attacker cards, deterministic signals, target code, and L0. Every candidate names `pattern_id`.
- `intent-reasoner` (L2) reads code, target specifications, tests, manifests, dependencies, L0, and neutral schemas only. It must not read the security model, capability-model, finding-schema examples, official-docs registry/cards, corpus patterns, historical ledgers, L1 output, or benchmark answers. It explains intended versus actual behavior, violated invariant, attacker path, harm, and blocking defenses checked.

Freeze all L1/L2 artifacts before L3. Pattern resemblance is never a finding; unrecoverable intent remains an explicit question. Repeated L2 contexts must be independently fresh and blind to each other, prior findings, and prior pass summaries.

```text
python3 <skill>/scripts/check_candidates.py \
  <run-dir>/l1/candidates.jsonl <each L2 packet candidate output>
```

**Gate:** isolation and schema checks pass; every L1 candidate has an active `NA-` pattern; every L2 candidate is corpus-blind and intent-anchored.

## Phase 2 — Blind L3 discovery and active testing

Select all 12 core roles plus all six conditional specialists; each must record applicability with target evidence. Repeat their blind discovery in fresh independent contexts for every planned pass; never disclose earlier candidates to later agents. Add `invariant-synthesis` and `mutation-analysis`; add `async-state-explorer`, `nep-differential`, and `temporal-upgrade` when their surfaces apply. Run these active roles only once against the frozen scope. Dispatch independent agents up to runtime capacity, refilling deterministic dependency-aware waves. Worker capacity counts spawned workers, excluding the parent orchestrator; do not subtract the parent again. Use available Codex subagents with the runtime's default model and role-specific prompts, without depending on global agent configuration. Record observed model/capacity values; leave unavailable runtime metadata explicitly unknown, never invented. If no worker limit is exposed, use sequential worker waves and record that scheduling choice separately from the unknown runtime limit. Close completed agents after collecting and validating their outputs. Do not delegate orchestration or omit a role because capacity is full.

Agents read only their role, complete assigned cluster, shared NEAR rules, schema, and assigned output paths. They cannot read peers, deduplicate, judge, or report. For large repositories, partition complete components rather than line ranges. Every callable needs two independent lenses; every value-bearing receipt chain needs `async-promises`, `token-accounting`, a seam hunter, and async state exploration.

Each selected official attacker card has one deterministic owner role from
`surface.json`. That existing role reads only its owned cards and pinned registry
rows, then emits one fragment row per card. Combine fragments into
`official-guidance-coverage.jsonl`; do not add a documentation-only worker.

Active testing follows the capability model:

- model every async operation and record success, failure, low-gas, malformed, duplicate/late, concurrent, and pending-state schedules in `async-schedules.jsonl`;
- write `invariant-ledger.jsonl` and execute high-value unit/property/stateful checks;
- mutate isolated copies only and account for every operator family in `mutation-results.jsonl`, covering all operators and their identified sites under schema-2 records in `references/workflow/review-contract.md`;
- differentially test applicable NEP-141/145/171/178 behavior against a pinned oracle and record `nep-differential.jsonl`;
- compare prior state/layout/source/deployed artifacts in `temporal-upgrade.jsonl` when upgrades or migrations exist.

Use the official cards to require a receipt custody matrix for value-moving
promises, a full/function-call/gas/MPC/relayer key-capability matrix, bounded
yield/resume schedules, version-gated global/host features, and a per-route
light-client/message-network/MPC/relayer responsibility map. Documentation-only
deviations remain advisories.

Counterexamples enter ordinary candidate JSONL. Surviving mutants are pipeline blind spots, not findings against the original target. A failed role is a coverage failure; retry once only for a safe environmental failure.
For current runs, record each worker start and terminal result through the
adapter. A submitted worker has passed syntax and size checks; phase validation
still decides complete schema and coverage acceptance.

Validate all new candidate artifacts with `scripts/check_candidates.py` before
freezing the phase.

**Gate:** all selected artifacts exist; candidate JSONL parses; every selected official card has exactly one coverage row; active-test, guidance, and role coverage pass.

## Phase 3 — Complete NEP attacker pass

Run all seven NEP roles in capacity waves. Each reads only its assigned checklist, registry, surface, schema, and target evidence, and emits one row for every owned NEP. Combine them into `nep-coverage.jsonl` and run:

```text
python3 <skill>/scripts/check_nep_coverage.py <run-dir>/nep-coverage.jsonl
```

Material mechanisms enter raw candidates with exact `nep_ids` and requirements. Harmless ABI/behavior drift stays unscored in conformance. Final/Approved rules are normative only when applicable; Draft/New are advisory; NEP-0001 is process-only and NEP-0021 superseded.

**Gate:** one row per bundled NEP validates; every disposition has evidence; security rows link candidates.

## Phase 4 — Post-blind corpus echo, chain construction, and lossless dedup

Record any newly derived candidates in `chain-candidates.jsonl` (an explicit empty file when none); include them unchanged in the raw ledger before deduplication. This is separate from the constructor's `deduplicated.jsonl` output.

After L2/L3 blind artifacts are frozen, run a post-blind corpus echo using the L1-routed pattern set plus any target features discovered later. This deliberately cross-checks the isolated L1 baseline without exposing patterns to blind agents. Historical frequency changes priority, never proof. Always use fresh host contexts for corpus and chain agents.

Compose feasible cross-function, cross-receipt, cross-contract, and cross-version chains. Normalize and group by:

`component cluster | causal root cause | violated invariant | attacker/control precondition`

Merge only one causal defect with the same phase/trust boundary, harm, and fix. Preserve all locations, variants, agents, discovery levels, tests, patterns, NEPs, and fixes. Create a complete raw-to-dedup disposition ledger; uncertainty means keep separate.

**Gate:** no raw candidate, location, mechanism, or fix disappears.

## Phase 5 — Two-stage judge

Stage 1 `evidence-triage` cheaply checks exact evidence, export/receipt reachability, attacker control, broken invariant, plausible harm, duplication/scope, standard classification, and counter-evidence. It rejects only with a concrete blocking fact.

Stage 2 gives each survivor to a fresh verifier that assumes it is false. Apply the five gates in [verification rules](../reporting/verification-reporting.md), reproduce the exact and one relaxed variant, and run a negative control. Every High/Critical also gets an independent skeptic. Compilation failure is a blocker, not refutation.

Every candidate receives triage and retains its disposition in the ledger.
Passed candidates continue to independent verification and embed both stages;
rejected or blocked triage outcomes retain their concrete blocking fact or
missing evidence without a fabricated verification stage. Use the
[verdict schema](../schemas/finding-schema.md#verifier-verdict). Medium+ requires executable
verification or an explicit blocker.

## Phase 6 — One counterexample-guided rescan

For rejected, excluded, blocked, or contested candidates, write `unresolved-assumptions.jsonl` containing only missing preconditions, unexamined callers/transitions, uncertain dependencies, coverage gaps, and alternate-path questions. A fresh `counterexample-rescan` reads those questions but not rejected conclusions.

Run exactly once and record `rescan-summary.json`, including zero-input or zero-result runs. New candidates re-enter deduplication and both judge stages. Do not loop again.

When these automated gates pass, deliver the Phase 8 draft immediately; do not
wait for Phase 7 human feedback. Phase 7 resumes only when real feedback arrives.

## Phase 7 — Human feedback and one verified-seed informed pass

After blind judging, a human labels reviewed candidates with `TP`, `FP`,
`DUPLICATE`, or `UNRESOLVED`, reason code, reviewer, and review time:

```text
python3 <skill>/scripts/near_audit.py feedback <run-dir> <human-labels.jsonl>
python3 <skill>/scripts/near_audit.py informed-rescan <run-dir>
```

Feedback is metrics-only. It cannot automatically change corpus entries,
prompts, role routing, thresholds, or mutation operators. The informed pass uses
only manually labelled blind TPs, strips severity/fix/report prose, and searches
bounded semantic neighborhoods for sibling writers/readers, alternate callers,
receipt variants, authority variants, and analogous value flows. Run exactly
once. Every result uses `discovery_technique: verified_seed_variant`, names its
seed, proves a new location/variant, and re-enters deduplication, both judge
stages, and human disposition. Pure rediscovery is invalid. Complete the pass:

```text
python3 <skill>/scripts/near_audit.py informed-rescan <run-dir> --complete
```

Pending human review defers the informed pass; it is not terminal `skipped`. Only when the complete blind review population has human dispositions and no TP remains may the pass be `skipped`. Keep unresolved human decisions explicit. Never seed from
FPs, unresolved items, informed findings, or benchmark answers, and never recurse.

## Phase 8 — Draft review, human approval, and completion

Each candidate ends as verified finding, standards-only deviation, advisory, duplicate, rejected, out-of-scope, or blocked. A human approves every finding and conformance deviation included in an approved report. The default delivery is a draft review with pending human decisions clearly separated from approved findings.

Validate technical coverage and ledger accounting for the selected stage. The controller performs stage-aware checks; approved completion additionally requires the human gates:

```text
python3 <skill>/scripts/near_audit.py finalize <run-dir> --stage draft --report <run-dir>/technical-annex.md
python3 <skill>/scripts/check_ledger.py \
  <run-dir>/raw-candidates.jsonl <run-dir>/deduplicated.jsonl \
  <run-dir>/verdicts.jsonl <run-dir>/dispositions.jsonl --stage draft
```

Score severity from Impact x Likelihood and confidence separately. Keep the
existing five-axis, 13-point confidence score; repeat sightings never add points.
Use short specific titles and an actor–cause–harm opening sentence for each
finding; preserve all identifiers, excerpts, code, receipt traces, and proof.
Report scope/revision, architecture, receipt paths, proof, remediation, meaningful
standards deviations, guidance observations, and testing limitations. Keep complete
coverage, raw dispositions, attribution, and qualification evidence in internal ledgers. Existing qualification
claims are configuration-bound and require fresh evidence after this change.
The final bounded rescan must disclose new Medium+ findings or blockers; never claim the zero-new-finding criterion was met when it was not.

Write the full technical body in the run directory using the report template,
but leave out `Scope at a glance` and `Top findings`; the controller generates
those from validated records. The controller-rendered `technical-annex.md` is the
**technical annex** and remains finalized and hash-bound. Full selected-NEP and
candidate dispositions remain in the validated internal ledgers.

After the technical annex is finalized, create `slotzero-content.jsonl` with one
concise presentation row for each verified finding and unscored lead. Follow
[Slot Zero report format](../reporting/slotzero-report-format.md) for the row contract and
source-backed diff rules. Render the reader-facing report deterministically:

```text
python3 <skill>/scripts/near_audit.py render-report <run-dir> \
  --body <run-dir>/report-body.md --output <run-dir>/technical-annex.md --stage draft
python3 <skill>/scripts/near_audit.py finalize <run-dir> \
  --report <run-dir>/technical-annex.md --stage draft
python3 <skill>/scripts/render_slotzero_report.py <run-dir> \
  --content <run-dir>/slotzero-content.jsonl \
  --output <run-dir>/slotzero-report.md
```

Deliver both `slotzero-report.md` and `technical-annex.md` as clickable file links
or attachments in the final response. Verify that both exist and that the annex
is the finalized report referenced by the compact report. Never claim completed
delivery with only a chat preview or one file. If a reporting gate fails, report
the blocker rather than fabricate a completed report.

The renderer's stdout provides the conversation preview. It prints the whole
reader-facing report for at most 20 findings, and a counted top-three slice plus
the full report path above that size. Always include both file links regardless of preview size so
readers can inspect receipt traces, source excerpts, NEP rows, and unresolved
human decisions. Do not reword or shorten the deterministic reader-facing
report in the conversation. Presentation cannot promote a lead, alter a
verdict, or replace the complete human-feedback gate. Explicit user requested
confirmation or omission in the compact report must follow
[presentation review edits](../reporting/slotzero-report-format.md#presentation-rows), remain
counted, and leave the technical evidence intact. If the renderer rejects a row, fix the
presentation input and rerun it; never weaken the technical ledger or bypass
its recorded report hash.

For approval, preserve the draft pair. After human gates, render and finalize
`<run-dir>/approved/technical-annex.md` with `--stage approved`, then render
`<run-dir>/approved/slotzero-report.md` bound to that approved technical report.
Deliver the two approved files together. The filenames do not imply approval;
headings and recorded stage must match the validated review status. Existing runs remain bound to the skill configuration
that created them; use that preserved package for their controller operations.

Follow [draft and approved finalization](../reporting/verification-reporting.md#draft-and-approved-finalization)
for the command interface, report containment and headings, retained hashes,
human approval, and evidence preservation. The default is a draft; approved
completion requires explicit `--stage approved` after the human gates pass.
