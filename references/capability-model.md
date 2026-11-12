# L0-L4 Capability and Active-Testing Model

## Purpose

L0-L4 are evidence-backed capability levels, not audit modes. `standard`,
`explicit-files`, and `deep` control scope and effort; the level labels describe
what the pipeline demonstrated. Never claim L4 from architecture, agent count,
or a self-authored checklist alone.

| Level | Capability | Boundary |
|---|---|---|
| L0 | Explain the target and recover intended behavior. | Cannot create a finding. |
| L1 | Match known NEAR and NEP mechanisms. | Pattern resemblance is an unverified candidate. |
| L2 | Find intent gaps in a corpus-blind whole-target pass. | Must not read L1 output or security-pattern references. |
| L3 | Orchestrate independent specialists and adversarial judges. | Findings still require human release approval. |
| L4 | Demonstrate measured performance on isolated ground truth. | Qualifies one benchmark track, not every NEAR surface. |

## Capability artifacts

All JSON and JSONL files use `schema_version: 1` unless their existing schema
specifies otherwise. New controlled runs use run-manifest schema 6, run-state
schema 4, and surface schema 3. Older runs are read-only inspection inputs;
restart with a fresh directory instead of migrating or resuming an older schema.

### `run-manifest.json`

Record the target root and revision, dirty-tree state, scope, exclusions, mode,
toolchain, NEAR SDK and standards versions, NEP source pin, corpus hash, model
identifiers, prompt hashes, tool versions, run-directory identifier, start time,
and configured worker capacity. Schema 2 additionally records
`official_docs_source_commit` and the exact bundled
`official_docs_registry_hash`. Schema 3 additionally binds the run ID, source
content fingerprint, semantic-IR and extractor hashes, driver hash, aggregate
work-packet hash, metrics-only feedback policy, and targeted verified-seed
second-pass mode. Schema 4 retains those bindings and records the current runtime,
worker-capacity meaning, isolation limitations, and stage-aware completion contract.
Run-state schema 2 distinguishes `draft_ready` from approved completion. Bind the
actual workflow and neutral-schema references in the prompt/input hashes.
Worker capacity counts spawned workers excluding the parent; missing runtime
model/limit/usage values remain explicitly unknown. Never substitute a guessed
model identifier, token estimate, or arbitrary limit for observed metadata.
Do not put credentials or private keys in the manifest.

### `semantic-ir.json`

Build a deterministic whole-target navigation graph before L0. It inventories
symbols/exports, state reads and writes, local calls, receipt/callback/yield
edges, authority checks, value flows, serializers, Cargo metadata, built ABI/Wasm
evidence, and unresolved edges. It improves routing and cross-file tracing but is
not a sound compiler IR: every security conclusion requires source, artifact, or
execution confirmation. Unsupported macro expansion, dynamic dispatch, generated
code, cross-language calls, runtime behavior, and absent build artifacts remain
declared blind spots. See `semantic-pipeline.md`.

### `intent-model.json` (L0)

The complete field contract is in [neutral-schemas.md](neutral-schemas.md).
L0 receives `neutral-surface.json`, a target-context projection without the full
surface's security signals, selected cards, or role routing.
The orchestrator supplies L0 only target source/specifications/tests/manifests/
dependency context and that neutral schema. Do not supply this capability model,
the security model, finding-schema examples, registries, corpus, peer findings,
or benchmark answers. L0 records facts and uncertainty, never candidate IDs,
finding titles, severity, or recommendations.

### `level-coverage.jsonl`

Emit one row for L0, L1, L2, and L3 with `level`, `status`, `roles`, `inputs`,
`artifacts`, `model_and_prompt_hashes`, `started_at`, `completed_at`, `cost`, and
`blockers`. Allowed status values are `complete`, `partial`, `blocked`, and
`not_run`. L4 is recorded only by a maturity attestation.

Active methods also emit `invariant-ledger.jsonl`, `async-schedules.jsonl`,
`mutation-results.jsonl`, `nep-differential.jsonl`, and
`temporal-upgrade.jsonl` when applicable. One `rescan-summary.json` accounts for
the single counterexample-guided pass, including a zero-input or zero-result run.
Surface-schema-3 runs also emit `official-guidance-coverage.jsonl`, with exactly
one disposition row for every selected attacker card. Current run-manifest-schema-6 runs also
emit `work-packets.jsonl`, `run-state.json`, `finding-feedback.jsonl`,
`feedback-summary.json`, and `informed-rescan-summary.json`.

## Isolated L1 and L2 passes

After L0, create distinct L1 and L2 scratch directories. They may run in
parallel, but neither may read the other's output. L0 and L2 must use fresh
contexts without inherited pattern material. Supply only their selected prompt,
not this reference or the complete agent catalog. Record the actual isolation
mechanism and limitations: separate scratch paths and prompt allowlists are
prompt-only controls unless the runtime enforces filesystem/tool/input access.
Do not describe prompt-only controls as enforced isolation or use them to satisfy
an enforced-isolation qualification requirement.

### L1 pattern pass

L1 may read `attack-lenses-index.json`, routed provenance variants, the NEP registry,
applicable NEP checklist, selected official-doc attacker cards, deterministic
surface signals, target code, and the L0 model. Every L1 candidate names a
canonical `pattern_id`. It cannot report a finding without the L3 judge.

### L2 intent pass

L2 reads target code, target-authored documentation, tests, manifests,
dependency context, the target-grounded L0 model, and neutral schemas only. It
must not read the security model, this capability model, finding-schema examples,
canonical patterns, historical ledgers, official-docs/NEP registries or checklists,
attacker cards, L1/peer artifacts, or benchmark answers. For each candidate, state:

1. intended behavior and its evidence;
2. actual implementation behavior;
3. violated invariant;
4. attacker capability and complete execution path;
5. terminal harm and the strongest blocking defense checked.

A familiar name or syntactic pattern is not sufficient. If intent is
unrecoverable, emit an unresolved-intent row rather than manufacture a finding.

## Active L3 detection methods

### Async receipt state-space exploration

Activate whenever the target creates, joins, chains, resumes, or consumes an
asynchronous receipt. For each value-moving operation, produce one
`async-schedules.jsonl` row with:

- operation and state-machine IDs;
- initiating export and every receipt/callback;
- reserved state and settlement token;
- success, business rejection, panic, malformed result, low-gas, missing-result,
  duplicate, late, and out-of-order schedules;
- public mutations possible while pending;
- concurrent same-account and same-asset schedules;
- refund/rollback destinations;
- generated test path, seed, execution status, harm assertion, and blockers.

At minimum execute or structurally prove success, failure, and one pending-state
public interleaving for every value-moving promise chain. Bound exploration by
state equivalence and minimize any counterexample before emitting a candidate.

### Executable invariant synthesis

`invariant-ledger.jsonl` contains one row per invariant with `invariant_id`,
`statement`, `scope`, `assets`, `writers`, `readers`, `receipt_boundaries`,
`test_class`, `test_path`, `seed`, `execution_status`, `counterexample`, and
`candidate_ids`.

Cover applicable conservation, supply/balance consistency, available/locked/
pending accounting, at-most-once settlement, exact compensation, storage
funding/refunds, authorization transitions, and callback terminal states. Prefer
existing unit/integration harnesses, then property/stateful tests in an isolated
copy. A failing invariant is a discovery source, not an automatically verified
finding.

### NEAR mutation analysis

Mutate only an isolated scratch copy and keep the audited revision unchanged.
Applicable operator families are:

- predecessor/signer substitution, plus MPC session participant/subset/message/tweak view substitution where applicable;
- removal of private/init/payable/one-yocto enforcement;
- debit or reservation moved after promise dispatch, removal of globally atomic presignature consumption, or removal/change of beneficiary/mode/filter binding from a mutating resume record;
- promise result ignored, inverted, or decoded incorrectly;
- callback gas under-reservation;
- resolver/refund cap removal;
- collection-prefix reuse and storage charge/cleanup removal;
- terminal Promise return removal;
- unchecked or rounding-sensitive arithmetic;
- incompatible serialization, layout, or migration changes.
- wrong key capability, receiver/method restriction, allowance/balance, or
  nonce-lane assumption;
- removal of yield requester/responder/payload/expiry/terminal-state binding;
- refund sent to the beneficiary or relayer instead of the actual payer or
  operation owner;
- inversion of FT receiver unused-amount versus caller spent-amount polarity;
- weakened route backend, finality, emitter, chain, or domain selection;
- serializer/schema mismatch at a receipt, relayer, or external-chain boundary;
- unverified deployed/global-contract code identity or version change.

Standard mode samples at least one mutation per applicable family. Deep mode
uses every applicable operator. A mutant is killed only when the audit pipeline
produces a human-adjudicated verified candidate matching the introduced
mechanism and affected path. Surviving mutants expose pipeline blind spots; they
are not findings against the original target.

`mutation-results.jsonl` contains one disposition row for each operator family,
including `not_applicable` and `blocked` families. Counts for killed, survived,
and blocked mutants must equal the generated total.

### Differential NEP testing

For applicable NEP-141, 145, 171, and 178 implementations, compare identical
state-transition sequences with a pinned behavioral oracle or reviewed reference
implementation. Compare ABI/payability, authorization, balances/supply,
registration, storage charges/refunds, resolver caps, events, return values, and
failure behavior. Record the oracle revision and version assumptions. Material
reachable differences enter candidate verification; harmless differences remain
standards-conformance rows.

### Temporal and upgrade analysis

When prior source, deployed Wasm, old state, or migration paths exist, compare
Borsh/JSON layouts, collection prefixes/types, state versioning, migration gas,
initialization, access checks, promise ordering/gas, token accounting, upgrade
keys, and built/deployed hashes. Exercise a real old snapshot where possible.
Missing historical evidence is a disclosed blocker, not proof of compatibility.

## Two-stage judge and bounded feedback

### Stage 1: evidence triage

Check exact source evidence, export and receipt reachability, attacker control,
broken invariant, plausible material harm, scope, duplication, NEP classification,
and relevant counter-evidence. It may reject only with a concrete blocking fact.
Survivors receive a minimal evidence packet.

### Stage 2: adversarial verification

A fresh verifier assumes the candidate is false, executes the five verification
gates, tries the claimed and one relaxed variant, and runs a negative control.
High/Critical candidates retain an independent skeptic. Both stages are recorded
in the final verdict.

Rejected, blocked, and contested candidates emit `unresolved-assumptions.jsonl`
rows containing only missing preconditions, unexamined callers/transitions,
uncertain dependency behavior, coverage gaps, and alternate-path questions. One
fresh rescan may read those rows but not the rejected conclusions. New candidates
re-enter deduplication and both judge stages. Never run a second feedback loop.

After ordinary judging, human TP/FP/duplicate/unresolved labels are recorded as
metrics only. Exactly one separate informed pass may use manually labelled blind
TP mechanisms to search bounded semantic neighborhoods for new variants. It
cannot see severity/fix/report prose, cannot re-emit the original location, and
cannot recursively seed itself. New candidates use
`discovery_technique: verified_seed_variant`, remain L3, and pass through normal
deduplication, both judge stages, and human release approval. Pending human
review defers the informed pass. Only a completely reviewed blind population
with no TP permits terminal `skipped`; unresolved human decisions remain explicit. Feedback never automatically mutates prompts, corpus,
routing, thresholds, or mutation operators.

## Scheduling and scaling

Use available Codex subagents with the runtime default model and role prompts;
no named global agent configuration is required. Worker capacity is the number
of spawned workers, excluding the parent orchestrator; do not subtract it again.
Use observed runtime values or record unknowns. If capacity is unavailable,
schedule one worker at a time and record this as an orchestrator choice, not a
measured runtime limit. Close completed agents after collecting/validating their
outputs and refill deterministic dependency-aware waves. Capacity never justifies
omitting any of the 12 core, selected conditional/active, or seven NEP roles.
Validate current-schema artifacts before resuming. Inspect older runs read-only
and restart them in a fresh run directory.

A permanent new role needs an ablation showing either a recovered Critical/High
root cause or at least two severity-weighted recall points without breaking the
triage budget.

## Official-guidance performance budget

Keep official guidance out of L2 and route only selected card bodies to their
existing L1/L3 owners. After a material registry, card, signal, or routing
change, record at least three configuration-equivalent standard-mode runs over a
representative contract/token/cross-chain suite. Each telemetry row contains a
unique run ID, fixture-suite ID, wall-clock seconds, and actual model input-token
count. `scripts/check_guidance_overhead.py` compares medians with the pinned
pre-upgrade baseline; both runtime and input-token overhead must be at most 20%.
Static file size or character/token estimates cannot satisfy this gate.

## L4 benchmark isolation and scoring

Public training fixtures may live with the skill. Hidden evaluation targets,
safe twins, and answer keys must not be mounted into audit-agent environments.
The isolated scorer receives predictions only after audit completion. Benchmark
schema 1 remains accepted only to reproduce the frozen v2 baseline; new release
claims use schema 2.

Ground truth uses one row per root cause and records project, track, vulnerable
and fixed revisions, safe-twin ID, severity, benchmark type, mechanism, affected
path, preconditions, provenance, and mutation family where applicable. A
detection requires a human-adjudicated accepted prediction with both mechanism
and affected-path matches.

Schema-2 predictions additionally record `target_kind` (`vulnerable`,
`safe_twin`, or `clean`), `target_id` for negatives, `pass_origin` (`blind` or
`informed`), and `predicted_severity`. A prediction may match multiple roots only
when one verified causal defect genuinely spans them. `duplicate_of` or repeated
accepted root coverage contributes to duplicate rate.

Schema-2 review metrics include the legacy coverage/review fields plus:

- raw-byte `dataset_hash` and canonical `target_manifest_hash`;
- exact configuration components for models, prompts, role topology, corpus,
  NEP/docs registries, semantic extractor, driver, and thresholds;
- vulnerable and safe/clean target identities, revisions, source hashes, and KLOC;
- whether the informed pass ran;
- blind and total wall-clock seconds and actual model input-token counts,
  reconstructed from unique hash-bound per-pass runtime/model usage exports.

The scorer reconstructs the configuration and target hashes and records its own
hash. Severity weights are Critical 8, High 4, Medium 2, and Low 1. The
schema-2 `smart-contracts` gate requires:

The changed configuration also binds `discovery_passes_planned` (1–10) and
`discovery_passes_completed` in review metrics. They must match. Include
`discovery_pass_plan_hash = SHA-256({"planned":N,"mode":"independent_blind_l2_l3"})`
among configuration components. Blind discovery telemetry rows name their
numeric `discovery_pass`; L0/L1, active tests, NEP review, judging, and
counterexample-rescan telemetry use null. There must be measured coverage for
every planned discovery pass.
Prediction rows may name their numeric discovery pass; use null for L1, active,
or informed results that do not originate in a blind discovery pass. Existing
`pass_origin: blind|informed` continues to distinguish human-informed search;
it is not the discovery-pass number. Equivalent qualifying repetitions must
share the same planned count. Prior qualification claims do not transfer to
this configuration without three fresh qualifying runs.

- at least 50 held-out root causes across 12 projects and 10 negative targets,
  with every referenced safe twin present;
- at least 85% severity-weighted recall, 100% Critical recall, and at least 90%
  High recall;
- at least 80% accepted-candidate precision, zero Critical/High negative-target
  false positives, at most 0.20 Medium+ false positives per 10 negative KLOC,
  and at most 10% duplicate accepted candidates;
- at least 85% overall mutation kill and 100% Critical/High authorization or
  settlement mutation kill;
- at least 90% declared-invariant execution coverage and complete success,
  failure, and pending-interleaving coverage for value-moving chains;
- at most 60 expert-review minutes per 10 KLOC and three rejected candidates per
  accepted finding;
- one informed pass adding at least three severity-weighted recall points with
  at least 70% incremental precision and no more than two points of overall
  precision regression;
- at most 20% measured wall-clock and actual input-token overhead;
- complete provenance and human adjudication.

Run public smoke regressions after material changes and isolated hidden
evaluation for release. Three repetitions must share configuration, dataset,
target manifest, scorer, and gate profile and pass every gate before
`check_maturity.py` issues `maturity-attestation.json`. Qualify contracts first;
bridges, wallets, MPC, runtime, consensus, and node tracks remain separate.
Until a track passes, report only capabilities evidenced by the run and list the
missing L4 evidence. Neither these gates nor this documentation establish a
runtime-performance or L4 result.

## Qualification commands and release maintenance

Public benchmark fixtures are training and regression material, never held-out L4
evidence. The bundled `benchmarks/public/async-auth-smoke` and
`benchmarks/public/official-guidance-smoke` fixtures are original and
intentionally small. The latter provides ten safe/vulnerable mechanisms spanning
key capabilities, refunds, yield/resume, storage, FT polarity, migration,
Intents, bridge routes, randomness, duplicates, and Sybil assumptions. Keep
hidden targets and answer keys outside every audit-agent
filesystem/context; score predictions only after an audit completes.

Score one isolated repetition with:

```text
python3 <skill>/scripts/score_benchmark.py \
  <ground-truth.jsonl> <predictions.jsonl> <review-metrics.json> \
  --output <benchmark-summary.json>
```

Create an attestation only from three distinct qualifying summaries with the
same configuration, dataset, target manifest, scorer, and gate profile:

```text
python3 <skill>/scripts/check_maturity.py \
  <summary-1.json> <summary-2.json> <summary-3.json> \
  --issued-at <ISO-8601> --output <maturity-attestation.json>
```

Any model, prompt, role topology, corpus, NEP/docs source, semantic extractor,
driver, scorer, threshold, dataset, or target-manifest change invalidates prior
equivalence and requires fresh qualification. New release claims use benchmark
schema 2; schema 1 is retained only for the frozen v2 baseline.

After any material official-guidance routing change, compare at least three
equivalent standard-mode runs over representative contract, token, and
cross-chain fixtures. Validate measured wall-clock and actual model input-token
telemetry—not byte estimates—with:

```text
python3 <skill>/scripts/check_guidance_overhead.py \
  <pre-upgrade-runs.json> <candidate-runs.json> --max-overhead 0.20
```

Do not release the configuration when either median exceeds the 20% budget.
