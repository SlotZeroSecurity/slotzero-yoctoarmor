# Neutral Artifact Schemas

## Common shape

JSON artifacts are objects. JSONL artifacts contain one complete object per line.
Locations use `path: string`, `function: string`, and source line numbers
`start: integer`, `end: integer`. Evidence uses source references and excerpts.
IDs are stable non-empty strings. No worked instances are included.

## L0 input: neutral-surface.json

A target-context projection with file/scope metadata only; no deterministic
security signals, selected cards, role routing, or pattern/registry content.
Required fields: `schema_version: 1`, `root: string`, and `files: object[]`.
Each file object requires `path: string`, `language: string`, and `lines: integer`.
It is distinct from the orchestrator's full `surface.json`.

## L0 output: intent-model.json

Required `schema_version: 1` and these top-level arrays:

| Field | Item fields / content |
|---|---|
| `actors` | principal, capabilities, keys, direct and indirect authority |
| `assets` | one row per asset/claim: custodian, payer, beneficiary, tracked total, actual balance or external custody, pending reservation, refundable storage backing, fees, reward reserve, unit/precision, and all writers/readers |
| `entrypoints` | exported method, intended caller, beneficiary, deposit rule |
| `receipt_state_machines` | operation ID, initiating/dependent receipts, commit boundary, custody and claim at each receipt, pending state, terminal states, failed/ambiguous/late/replay recovery |
| `standards` | claimed interface/NEP, version evidence |
| `trust_boundaries` | dependency, trusted property, evidence, failure behavior |
| `invariants` | unique `invariant_id`, `statement`, assets/state covered, evidence; include conservation equations that reconcile actual custody, tracked totals, fees, pending claims, and refunds |
| `unresolved_intent` | question, affected surface, evidence needed |
| `upgrade_dependencies` | prior revision/state, authority, migration evidence |
| `account_key_capabilities` | full-access/function-call/gas/relayer/contract/MPC key restrictions, allowances/balances, nonce lanes, recovery |
| `yield_resume_flows` | yield ID, requester, authorized responder, payload schema, expiry, pending state, terminal states |
| `global_contract_dependencies` | code hash/account reference, owner authority, expected version, deployed-code evidence |
| `cross_chain_routes` | direction, asset, verification backend, finality source, emitter/domain, relayer/fee payer, retry, refund behavior |
| `version_claims` | SDK/protocol/host/global-contract versions, docs/NEP activation evidence |

Arrays remain present when empty. L0 has no `candidate_id`, `findings`,
finding title, severity, or recommendation fields.

For each value flow, L0 records an accounting map in the existing `assets`,
`receipt_state_machines`, and `invariants` arrays. Distinguish current custody
from a user's enforceable claim; list actor cohorts (early/late depositors,
pending/settled claimants, storage payers, fee recipients, and privileged
operators) and what each is owed at each transition. Reconcile tracked totals
with actual holdings and pending external effects. Record asymmetries where an
action grants a claim before custody arrives, debits a claim before a transfer
settles, or updates one cohort's conversion rate without the others. Include
first/last claimant, zero balance, failed callback, retry, and upgrade states.

## L2 output: candidate JSONL

Required fields:

| Fields | Type / required value |
|---|---|
| `schema_version` | integer `2` |
| `candidate_id`, `role_id`, `origin_role` | non-empty strings; role `intent-reasoner` |
| `origin_level`, `discovery_technique` | `L2`, `intent_gap` |
| `judge_stage`, `verification_status`, `human_disposition` | `unjudged`, `unverified`, `pending` |
| `kind` | `finding` or `lead` |
| `component`, `bug_class`, `root_cause` | strings describing target context |
| `root_cause_fingerprint` | `sha256:` plus 64 lowercase hexadecimal characters |
| `model_and_prompt_hash` | recorded configuration digest prefixed `sha256:` |
| `intent_invariant_ids` | string array of stable invariant IDs |
| `locations` | non-empty location-object array |
| `evidence`, `intent_evidence` | non-empty evidence arrays |
| `implementation_behavior` | non-empty string |
| `attacker`, `preconditions` | principal/control string, condition-string array |
| `open_questions` | string array; missing evidence required for leads |

A `finding` also requires non-empty `canonical_key`, `broken_invariant`,
`receipt_trace` (string array), `terminal_harm`, `defenses_checked` (string
array), `fix_class`, and `intent_invariant_ids`. A `lead` may leave invariant
IDs empty only with the missing invariant in `open_questions`.

Fingerprint inputs, in order: normalized component, causal mechanism, violated
invariant, control precondition, affected path. Canonical-key shape:
`component cluster | causal root cause | violated invariant | control precondition`.

L2 omits `pattern_id`, `corpus_ids`, `official_guidance_ids`,
`guidance_evidence`, and historical precedent. Optional standards fields are
`nep_ids: string[]` and `standard_requirements: object[]`; each requirement
has `nep_id`, `requirement`, and `source_section`. IDs and requirements must
correspond and have target-supplied evidence.

## Unresolved intent output

The assigned unresolved-intent artifact contains question records with
`question`, `affected_surface`, and `evidence_needed`; no fabricated finding
or severity fields.
