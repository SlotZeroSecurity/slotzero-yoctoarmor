# Semantic Pipeline, Feedback, and Informed Rescan

## Objective

Improve whole-codebase understanding without turning an audit into an unbounded,
self-confirming loop. The scanner first freezes a blind run, then may use only
manually verified true positives to perform one targeted same-target variant
search. Human feedback changes metrics for that run; it never edits the corpus,
prompts, routing, thresholds, or mutation operators automatically.

## Local controller

Use [run setup](audit-workflow.md#phase-0--freeze-scope-and-build-l0) for preflight,
initialization, schema compatibility, artifact collection, and status/resume.
Use [reference routing](audit-workflow.md#reference-routing) for L0/L2 neutral
inputs and [isolated passes](audit-workflow.md#phase-1--isolated-l1-and-l2-passes)
for honest accounting of prompt-only versus runtime-enforced isolation. Dispatch
and runtime metadata follow the [orchestration phase](audit-workflow.md#phase-2--blind-l3-discovery-and-active-testing).

The controller writes `surface.json` schema 3, `semantic-ir.json`, hash-bound
`work-packets.jsonl`, and empty feedback/rescan ledgers. It prepares work but does
not impersonate model workers. Each packet records allowed and forbidden inputs,
dependencies, explicit `candidate_outputs` and `additional_outputs`, output
ownership, one safe retry, and a canonical packet hash.
The [worker adapter](runtime-adapter.md) provides a minimal prompt view for each
packet and records only host-observed execution facts. The authoritative
`run-events/` journal replays to a replaceable `run-state.json` projection.

The manifest binds target revision/dirty state, source fingerprint, semantic
extractor, driver, work packets, models/prompts, corpus, standards registries,
tool versions, feedback policy, and second-pass mode. A changed extractor or
driver is therefore a changed audit configuration.

## Portable semantic IR

`build_semantic_ir.py` is a deterministic, standard-library-only extractor. It
does not require a successful build and never uses a live network. It combines:

- Rust impl/trait/module/function containers and NEAR source annotations;
- built ABI and Wasm exports when artifacts already exist;
- state-field reads/writes and local call resolution;
- Promise/callback/yield receipt edges;
- predecessor, signer, current-account, promise-result, and private boundaries;
- native/token/deposit/refund value-flow signals;
- Borsh/JSON/serde serialization boundaries;
- Cargo manifests and optional `cargo metadata --offline --no-deps`;
- explicit unresolved and ambiguous edges.

Agents use the IR as a navigation index, never as proof. They must confirm every
security claim in exact source, generated ABI/Wasm, dependency behavior, or an
executed test. Unsupported macros, dynamic dispatch, trait resolution, proc-macro
expansion, generated code, cross-language calls, runtime semantics, and missing
artifacts remain declared blind spots.

## Human feedback

After blind candidates have passed ordinary judging, a human may label candidate
IDs `TP`, `FP`, `DUPLICATE`, or `UNRESOLVED` with a reason code, reviewer, and
review time:

```text
python3 <skill>/scripts/near_audit.py feedback <run-dir> <human-labels.jsonl>
```

This writes `finding-feedback.jsonl` and aggregate `feedback-summary.json` by
role, pattern, pass, and reason code. The summary explicitly attests that corpus,
prompts, routing, and mutations did not change. Promotion of a recurring lesson
is an offline maintenance proposal requiring provenance, a safe twin, held-out
evaluation, regression tests, and human approval.

## One TP-seeded informed pass

Prepare exactly one pass:

```text
python3 <skill>/scripts/near_audit.py informed-rescan <run-dir>
```

Only manually labelled blind TPs become `verified-seeds.jsonl`. Severity,
recommendation, fix, and report prose are stripped. Each seed contains the causal
mechanism, invariant, preconditions, receipt trace, excluded original location,
and a bounded semantic neighborhood of sibling readers/writers, callers,
receipt edges, authority checks, and value flows. Each edge kind is capped at
120 deterministic rows and related symbols at 80; `truncated_rows` discloses any
omitted neighborhood evidence for manual follow-up.

The informed worker searches only for structural variants and must use
`origin_level: L3`, `discovery_technique: verified_seed_variant`,
`seed_source_candidate_id`, non-empty `variant_evidence`, and a genuinely new
location. Every result re-enters ordinary deduplication, evidence triage,
adversarial verification, and human disposition. Complete it once with:

```text
python3 <skill>/scripts/near_audit.py informed-rescan <run-dir> --complete
```

Pending human review leaves the informed pass deferred, not terminal `skipped`.
Only a completely reviewed blind population with no TPs permits `skipped`;
unresolved human decisions remain explicit. A prepared or completed pass cannot
be prepared again. Pure rediscovery is rejected. There is no recursive seed,
prompt rewrite, threshold tuning, or automatic corpus update.

## Draft and approved finalization

Follow [draft and approved finalization](verification-reporting.md#draft-and-approved-finalization)
for the stage default, command interface, report hash/containment, human gates,
and retained evidence. Draft delivery leaves pending human feedback and the
informed pass resumable; never turn missing feedback into a skipped pass or
create human labels to advance it.

## Release measurement

Qualification is a separate task. See the complete thresholds, isolation rules,
benchmark schema 2, telemetry requirements, and three equivalent repetitions in
[capability-model.md](capability-model.md#l4-benchmark-isolation-and-scoring).
Changes to configuration, dataset, target manifest, scorer, or gate profile
invalidate equivalence. Contracts, bridges, wallets, MPC, runtime, consensus, and
node tracks require their own evidence and attestations.
