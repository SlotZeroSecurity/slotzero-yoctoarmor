# Candidate and Dedup Schema

Discovery artifacts use JSON Lines: one complete object per line.

## Candidate

```json
{
  "schema_version": 2,
  "candidate_id": "async-promises-001",
  "role_id": "async-promises",
  "origin_level": "L3",
  "origin_role": "async-promises",
  "discovery_technique": "specialist_trace",
  "pattern_id": null,
  "intent_invariant_ids": ["INV-WITHDRAW-ONCE"],
  "root_cause_fingerprint": "sha256:<normalized-root-cause-and-path>",
  "model_and_prompt_hash": "sha256:<model-config-and-prompt>",
  "judge_stage": "unjudged",
  "verification_status": "unverified",
  "human_disposition": "pending",
  "kind": "finding",
  "component": "vault",
  "locations": [
    {"path": "contracts/vault/src/lib.rs", "function": "withdraw", "start": 120, "end": 134},
    {"path": "contracts/vault/src/lib.rs", "function": "on_withdraw", "start": 160, "end": 168}
  ],
  "bug_class": "late-reservation",
  "canonical_key": "vault | withdrawal entitlement reserved only in callback | at-most-once withdrawal | permissionless caller",
  "root_cause": "Spendable balance remains available until a later callback.",
  "broken_invariant": "One balance entitlement can authorize at most one pending withdrawal.",
  "attacker": "registered user",
  "preconditions": ["positive internal balance"],
  "receipt_trace": [
    "R1 caller -> withdraw: validates balance, emits transfer, no debit",
    "R2 caller -> withdraw: repeats validation before callback",
    "R3/R4 transfers settle: two payouts"
  ],
  "terminal_harm": "Contract pays twice for one recorded balance.",
  "evidence": [
    {"path": "contracts/vault/src/lib.rs", "start": 120, "end": 134, "excerpt": "..."}
  ],
  "defenses_checked": ["no pending lock", "callback is private but late"],
  "fix_class": "reserve-before-dispatch-and-compensate",
  "corpus_ids": ["NA-ASYNC-001"],
  "official_guidance_ids": ["DOC-ASYNC-002"],
  "guidance_evidence": [
    {
      "card_id": "DOC-ASYNC-002",
      "url_path": "smart-contracts/security/cross-contract-calls/refunds.md",
      "source_section": "Refund ownership and callback settlement"
    }
  ],
  "nep_ids": ["0141"],
  "standard_requirements": [
    {"nep_id": "0141", "requirement": "transfer-call settlement is resolved once", "source_section": "Fungible Token Resolver"}
  ],
  "open_questions": []
}
```

Candidate schema version 2 requires:

- `origin_level`: `L1`, `L2`, or `L3`. L0 cannot emit candidates and L4 is a
  measured qualification rather than a discovery origin.
- `origin_role`: the exact agent role; preserve all contributing origins after
  deduplication.
- `discovery_technique`: one of `pattern_match`, `intent_gap`,
  `specialist_trace`, `async_schedule`, `invariant_counterexample`,
  `differential_nep`, `temporal_upgrade`, `attack_chain`, `corpus_echo`, or
  `counterexample_rescan`, or `verified_seed_variant`.
- `pattern_id`: required for L1 and otherwise optional. It must identify a
  canonical pattern routed to the agent; historical titles are not pattern IDs.
- `intent_invariant_ids`: stable IDs from `intent-model.json` or
  `invariant-ledger.jsonl`; use an empty list only when the item is a lead and the
  missing invariant is named in `open_questions`.
- `root_cause_fingerprint`: a deterministic hash over normalized component,
  causal mechanism, violated invariant, attacker precondition, and affected path.
  It assists grouping but never overrides semantic deduplication.
- `model_and_prompt_hash`: identifies the exact discovery configuration without
  embedding hidden prompts or secrets.
- discovery-stage values `judge_stage: unjudged`,
  `verification_status: unverified`, and `human_disposition: pending`.

L2 candidates must not contain `pattern_id`, `corpus_ids`, or historical
precedent. They also must not contain `official_guidance_ids` or
`guidance_evidence`: the isolated L2 environment cannot read the official-docs
registry or attacker guide. They additionally include non-empty `intent_evidence` and
`implementation_behavior`. Deduplicated rows union `origin_role`,
`intent_invariant_ids`, patterns, techniques, and model/prompt hashes rather than
discarding provenance.

Use `kind: lead` when reachability, attacker control, receipt path, or material harm is incomplete. Name the missing item in `open_questions`.

Every discovery item uses `locations[]`, even when it has one location. A deduplicated item unions all constituent locations; never compress multiple methods into a single string.

`nep_ids` and `standard_requirements` are optional for non-standards mechanisms. When present, IDs must exist in `nep-registry.json`, and every requirement must name the exact pinned NEP plus a concise normative rule and source section. A NEP match is classification/provenance, not target proof.

`official_guidance_ids` and `guidance_evidence` are optional outside L2. When
present, every ID must exist in `official-docs-registry.json` and must have an
exact pinned URL path and source-section evidence item. Official guidance is
non-normative provenance: it cannot replace source evidence, reachability,
material harm, or adversarial verification.

## Official-guidance coverage row

Existing owner roles collectively emit exactly one row for every card selected
in `surface.json`; there is no documentation-only worker:

```json
{
  "schema_version": 1,
  "card_id": "DOC-ASYNC-002",
  "applicability": "applicable",
  "version_evidence": ["near-sdk and runtime behavior pinned in Cargo.lock and run manifest"],
  "target_evidence": ["src/vault.rs:withdraw schedules a native transfer and callback"],
  "checks_performed": ["traced returned-funds custody on transfer failure"],
  "test_status": "executed",
  "candidate_ids": [],
  "advisory_observations": [],
  "disposition": "conformant",
  "rationale": "The callback restores the original user's operation-bound credit exactly once."
}
```

Allowed applicability values are `applicable`, `not_applicable`, and `blocked`.
Allowed dispositions are `conformant`, `security_candidate`, `advisory`,
`quality_observation`, `not_applicable`, and `blocked`. A security candidate
requires linked candidate IDs; a recommendation without reachable material harm
is advisory or quality-only. The combined card set must exactly equal
`surface.json.selected_attacker_cards`.

## NEP coverage row

The seven NEP roles collectively emit exactly one JSONL row for every registry entry:

```json
{
  "nep_id": "0141",
  "role_id": "nep-token-assets",
  "source_commit": "dcc0bcbd452f68c936696e5f9552e567c3b162e0",
  "source_status": "Final",
  "applicability": "applicable",
  "version_evidence": ["contract exports the pinned NEP-141 interface"],
  "target_evidence": ["contracts/token/src/lib.rs exports ft_transfer_call"],
  "requirements_checked": ["exact transfer ABI and one yocto", "private resolver caps unused amount"],
  "deviations": [
    {"requirement": "resolver must be private", "classification": "security", "location": "contracts/token/src/lib.rs:on_resolve", "rationale": "external caller can forge settlement"}
  ],
  "candidate_ids": ["nep-token-assets-001"],
  "disposition": "security_candidate",
  "rationale": "The exported resolver is externally reachable and settles value."
}
```

Allowed applicability values: `applicable`, `not_applicable`, `advisory`, `superseded`, `process_only`, `blocked`.

Allowed dispositions: `conformant`, `security_candidate`, `conformance_deviation`, `advisory`, `superseded`, `process_only`, `not_applicable`, `blocked`.

- `not_applicable` requires concrete repository/runtime evidence and a reason.
- `source_commit` must equal the bundled registry pin. Applicable runtime/node behavior also needs concrete `version_evidence`.
- `security_candidate` requires linked candidate IDs entering the ordinary dedup/verification pipeline.
- A `superseded` NEP-0021 row may still link a security candidate when reachable legacy code is unsafe; NEP-141 remains the conformance baseline.
- `conformance_deviation` requires deviations but no vulnerability severity.
- Draft/New NEPs use `advisory` unless implemented code has an independently material security candidate.
- NEP-0001 is `process_only`; NEP-0021 is `superseded` by NEP-0141.
- Validate the combined file with `scripts/check_nep_coverage.py`.

## Verifier verdict

Verifier artifacts also use JSONL:

```json
{
  "candidate_id": "async-promises-001",
  "judge_stage": "adversarial_verification",
  "triage": {
    "status": "passed",
    "evidence": ["[SOURCE] export and guard confirmed"],
    "blocking_fact": null,
    "packet_hash": "sha256:<minimal-evidence-packet>"
  },
  "verification_status": "verified",
  "human_disposition": "pending",
  "verdict": "valid",
  "proof_status": "VERIFIED_EXECUTED",
  "severity": "critical",
  "impact": "Severe",
  "likelihood": "Likely",
  "confidence": {
    "source_anchoring": 2,
    "reachability": 3,
    "material_harm": 3,
    "execution": 3,
    "counter_evidence": 2,
    "total": 13
  },
  "rationale": "Two runtime-valid withdrawal receipts spend one entitlement.",
  "evidence": ["[SOURCE] ...", "[TRACE] ...", "[EXPLOIT-REPRODUCED] ..."],
  "blocking_defense": null,
  "poc_status": "EXPLOIT_REPRODUCED",
  "external_assumptions": []
}
```

Allowed triage statuses are `passed`, `rejected`, and `blocked`. A passed triage
must continue to adversarial verification. A rejected triage requires a concrete
`blocking_fact`; a blocked triage names missing evidence. Allowed verification
statuses are `verified`, `downgraded`, `lead`, `refuted`, `blocked`, and
`contested`. Allowed human dispositions are `pending`, `approved`, `rejected`,
`standards_only`, `advisory`, `duplicate`, `out_of_scope`, and `blocked`. Approved
report generation cannot proceed while a reportable finding or conformance
deviation remains `pending`; a draft may retain clearly labelled pending decisions.
Follow [finalization rules](verification-reporting.md#draft-and-approved-finalization).

Allowed verdicts: `valid`, `valid_downgraded`, `lead`, `false_positive`. Allowed proof statuses are listed in `verification-reporting.md`. A false positive must name `blocking_defense`; a blocked build uses `poc_status: BUILD_BLOCKED` and is not automatically false.

## Unresolved-assumption row

Rejected, blocked, or contested candidates emit questions rather than rejected
conclusions:

```json
{
  "schema_version": 1,
  "assumption_id": "assumption-001",
  "candidate_id": "async-promises-001",
  "category": "unexamined_transition",
  "question": "Can another public method mutate the reserved balance while the receipt is pending?",
  "target_context": ["contracts/vault/src/lib.rs"],
  "evidence_needed": ["all public writers of reserved_balances"],
  "rescan_iteration": 1,
  "status": "open"
}
```

Categories are `missing_precondition`, `unexamined_caller`,
`unexamined_transition`, `external_behavior`, `coverage_gap`, and
`alternate_path`. Only iteration 1 is valid. The rescan cannot read the rejected
candidate's conclusion or start another feedback loop.

## Human feedback and informed-rescan rows

Human-authored feedback input uses one row per candidate:

```json
{"schema_version":1,"candidate_id":"async-promises-001","label":"TP","reason_code":"receipt_failure_reproduced","reviewer":"reviewer-id","reviewed_at":"2026-08-30T00:00:00Z","pass_origin":"blind","notes":"optional"}
```

Labels are `TP`, `FP`, `DUPLICATE`, or `UNRESOLVED`; pass origin is `blind` or
`informed`. The input dispositions every deduplicated review candidate (and any
informed candidates when feedback is refreshed). `record_feedback.py` validates
candidate IDs and writes the canonical ledger plus aggregate metrics. Feedback does not authorize automatic prompt,
corpus, routing, threshold, or mutation changes.

Each manually verified blind TP may produce one stripped seed in
`verified-seeds.jsonl`. A seed contains `seed_id`, `source_candidate_id`, source
fingerprint, causal mechanism, broken invariant, invariant IDs, attacker/
preconditions, receipt trace, defenses checked, affected symbols, excluded
original locations, bounded semantic neighborhood, `seed_hash`, and the list of
removed report fields. It must not contain severity, recommendation, report
title, or fix prose.

An informed candidate is an ordinary schema-2 candidate plus:

```json
{
  "origin_level": "L3",
  "discovery_technique": "verified_seed_variant",
  "seed_source_candidate_id": "async-promises-001",
  "variant_evidence": ["Sibling pending-state writer omits the same terminal transition"],
  "locations": [{"path":"contracts/vault/src/admin.rs","function":"cancel","start":88,"end":103}]
}
```

The seed ID must be known, `variant_evidence` must be non-empty, and at least one
path/function must differ from every excluded seed location. Pure rediscovery is
invalid. The candidate re-enters normal deduplication and both judge stages; an
informed finding cannot seed another pass.

`informed-rescan-summary.json` uses schema 1, `iteration: 1`, status `prepared`,
`complete`, `skipped`, or `blocked`, `seed_count`, `new_candidate_ids`, and
`rediscovery_candidate_ids`. Final validation accepts only complete, skipped, or
blocked. Exactly one iteration is allowed.

## Active-test rows

`invariant-ledger.jsonl` and `async-schedules.jsonl` use the fields defined in
`capability-model.md`. Each counterexample links ordinary `candidate_ids`.
Mutation results additionally record `mutation_id`, `operator_family`,
`target_path`, `expected_mechanism`, `mode`, `outcome` (`killed`, `survived`, or
`blocked`), and matching candidate IDs. A killed mutant is benchmark evidence,
not a defect in the unchanged target.

## Canonical key and lossless dedup

Use:

`component cluster | causal root cause | violated invariant | attacker/control precondition`

Merge only when root cause, invariant, trust boundary/receipt phase, terminal harm, and fix class are the same. Do not merge merely because titles or recommendations match.

Preserve on merge:

- every affected location and method
- every distinct precondition, attack variant, and harm
- every fix alternative
- every agent and corpus ID
- all primary evidence excerpts

Split candidates when different fixes, receipt phases, trust boundaries, preconditions, or harms are required. Cross-method bugs may merge only when one causal defect and one fix spans the entire receipt/state machine.

## Completeness ledger

Every raw `candidate_id` maps exactly once to:

- `REPORT:<finding-id>`
- `MERGED:<survivor-candidate-id>`
- `CHAIN_ABSORBED:<finding-id>`
- `REFUTED:<reason-id>`
- `QUALITY:<observation-id>`
- `DEFERRED:<blocker-id>`

No candidate disappears silently. `scripts/check_ledger.py` requires one verifier verdict per deduplicated candidate before reporting.

The Phase 4 disposition JSONL has:

```json
{"candidate_id":"role-001","disposition":"merged","target_id":"dedup-001","rationale":"Same root cause, receipt phase, harm, and fix."}
```

Allowed dispositions are `survives`, `merged`, `chain_absorbed`, `quality`, and `deferred`. The first three require a valid deduplicated `target_id`; the others omit it. The final report ledger then records whether each deduplicated item became `REPORT`, `REFUTED`, or remained blocked/contested.

## Evidence tags

- `[SOURCE]` exact reviewed source/commit
- `[EXPORT]` actual contract ABI exposure
- `[TRACE]` complete concrete receipt/state sequence
- `[EXPLOIT-REPRODUCED]` local sandbox harm assertion succeeds
- `[EXPLOIT-NOT-REPRODUCED]` exact and relaxed variants fail
- `[NEGATIVE-CONTROL]` defended/patched path blocks the harm
- `[FUZZ-COUNTEREXAMPLE]` property violation with seed/minimized sequence
- `[BUILD-BLOCKED]` executable verification unavailable
- `[EXTERNAL-ASSUMPTION: ...]` dependency outside scope
- `[CORPUS-PRECEDENT]` historical analogue; contributes no target proof
