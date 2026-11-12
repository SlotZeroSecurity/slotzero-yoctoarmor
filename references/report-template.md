```text
███████╗██╗      ██████╗ ████████╗    ███████╗███████╗██████╗  ██████╗
██╔════╝██║     ██╔═══██╗╚══██╔══╝    ╚══███╔╝██╔════╝██╔══██╗██╔═══██╗
███████╗██║     ██║   ██║   ██║          ███╔╝ █████╗  ██████╔╝██║   ██║
╚════██║██║     ██║   ██║   ██║         ███╔╝  ██╔══╝  ██╔══██╗██║   ██║
███████║███████╗╚██████╔╝   ██║        ███████╗███████╗██║  ██║╚██████╔╝
╚══════╝╚══════╝ ╚═════╝    ╚═╝        ╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝

███████╗███████╗ ██████╗██╗   ██╗██████╗ ██╗████████╗██╗   ██╗
██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██║╚══██╔══╝╚██╗ ██╔╝
███████╗█████╗  ██║     ██║   ██║██████╔╝██║   ██║    ╚████╔╝
╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██║   ██║     ╚██╔╝
███████║███████╗╚██████╗╚██████╔╝██║  ██║██║   ██║      ██║
╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝   ╚═╝      ╚═╝

               NEAR MULTI-AGENT SECURITY SCANNER

```

# `<Draft|Approved>` Security Review — `<project>`

> This AI-assisted, time-boxed review cannot prove the absence of vulnerabilities. Independent review, bug bounties, monitored deployment, and incident response remain necessary.

## Scope at a glance

`<repository/revision>` · `<files and components>` · `<standard/explicit/deep>` · `<N planned discovery passes, N completed>` · `<key exclusions and trust assumptions>`

## Top findings — top `<min(3, verified finding count)>` of `<verified finding count>`

| ID | Severity | Finding in one sentence | Seen in discovery passes |
|---|---|---|---|
| `<existing finding ID>` | `<verified severity>` | `<attacker or controlling actor> can <action> because <specific cause>, harming <victim or asset>` | `k/N` |

If there are no verified findings, write `Top 0 of 0 — no verified findings.`
Count distinct blind L2/L3 discovery passes contributing to each deduplicated
finding; L1, active tests, and rescans are separate origins and do not increase
`k`. State `0/N` when a finding came only from those sources. Report this count
separately from confidence; repeated discovery never changes the five-axis score.
Derive the index and totals from validated dedup/verdict/ledger records, then
reuse the exact same text in the retained report and conversation. Keep the full
technical report below this compact front section.

## Audit metadata

| Field | Value |
|---|---|
| Reviewed repository / commit | |
| Mode | standard / explicit files / deep |
| Review stage / run status | draft / draft_ready OR approved / complete |
| Run manifest / state schema | 6 / 4 |
| Discovery passes | N planned / N completed; L2 and blind L3 per-pass artifacts |
| Report path / content hash | run-directory-contained Markdown / recorded hash |
| Pending human decisions | count / ledger references |
| Runtime model / worker capacity | observed values or unknown; workers exclude parent |
| Isolation | prompt-only / runtime-enforced; mechanism, evidence, limitations |
| Scope | |
| Exclusions | |
| Toolchain / build | |
| Tests | |
| Verification environment | LOCAL_SANDBOX / structural / blocked |
| NEP source snapshot | `near/NEPs@dcc0bcbd452f68c936696e5f9552e567c3b162e0` |
| Official docs snapshot | `near/docs@11c29513bb67017b0d98a8fef8eaf481d4712675` / registry hash |
| Demonstrated capability | recorded L0-L3 coverage / valid track-specific L4 attestation ID |
| Run / corpus / prompt hashes | |
| Source / semantic extractor / driver hashes | |

## Executive summary

State the highest-risk verified mechanisms, affected assets, trust assumptions, verification blockers, and remediation order. A draft is for review and is not an approved audit. Identify pending human decisions separately from human-approved findings. Do not give a “safe to deploy” verdict.

## Severity and proof summary

| Severity | Verified | Conditional/contested |
|---|---:|---:|
| Critical | | |
| High | | |
| Medium | | |
| Low | | |
| Informational | | |

## Architecture and trust assumptions

Summarize actors, assets/liabilities, full-access/function-call/gas/relayer/contract/MPC key capabilities, allowances/balances/nonce lanes, upgrade/pause/incident authority, predecessor-versus-signer rules, callback-only exports with self/external predecessor guards and operation binding, caller-controlled list set/multiset and per-item charge semantics, every one-account-one-participant assumption, Sybil defenses with their cost/trust/tradeoffs and residual attacks, pending-input visibility and ordering authority, commit/reveal or fixed-clearing assumptions, ties/deadlines/cancellation/non-reveal behavior, randomness seed/input/resolver/producer-censorship model and entropy-provider trust, external contracts, promise/receipt graph and receipt custody matrix, storage payers/refund policy, yield/resume authorization and expiry, global-contract code/version trust, token standards, route-specific cross-chain verification backends, off-chain components, coordinated-abuse monitoring, and explicit out-of-scope dependencies.

## L0 intent and invariant model

Summarize evidence-backed intended behavior, unresolved intent, receipt state
machines, asset/liability representations, and stable invariant IDs. L0 content
does not receive finding severity.

## Semantic understanding and blind spots

Summarize source/export coverage, resolved and unresolved call edges, receipt
edges, state readers/writers, authority/value/serialization boundaries, ABI/Wasm
evidence, and offline Cargo metadata status. Name unsupported macro expansion,
dynamic dispatch, generated code, cross-language/runtime behavior, missing build
artifacts, or other blind spots. Semantic-IR signals are navigation evidence,
not proof of safety or vulnerability.

## Findings index

| ID | Severity | Proof status | Confidence | Seen in discovery passes | Human disposition | Title |
|---|---|---|---:|---|---|---|

## Findings

### `[H-01] Title`

| Field | Value |
|---|---|
| Severity | |
| Proof status | |
| Confidence | `N/13 (High/Medium/Low)` |
| Impact / Likelihood | |
| Affected code | |
| Affected assets / users | |
| Discovery origin | L1 / L2 / L3 role and technique |
| Seen in discovery passes | `k/N`; list contributing `PXX-` candidate IDs separately from confidence |
| Pattern / invariant / NEP links | |
| Human disposition | pending in draft / approved by identified human |
| Human reviewer / review time | actual recorded values or pending |

#### Root cause

Open with one short actor–cause–harm sentence. Use a specific title naming the
broken condition and consequence. Preserve exact source excerpts, identifiers,
code, receipt trace, and proof detail in their technical sections.

#### Attack preconditions

#### Receipt-level attack path

Number every receipt and include predecessor, signer, current account, state change, promises, callback result, and compensation/finalization.

#### Impact

Name the victim and quantify value, privilege, corruption, or liveness duration.

#### Evidence and PoC

Include exact source lines, harm assertion, local command/seed, receipt results, balance/state delta, negative control, and limitations.

#### Recommendation

Give the smallest complete fix. Preserve alternative fixes when they address distinct mechanisms.

#### Remediation status and fix verification

Use `OPEN`, `ACKNOWLEDGED`, `FIX_PROPOSED`, or `FIX_VERIFIED`. Mark `FIX_VERIFIED` only after reviewing the remediation commit and rerunning the harm test plus negative control.

## Pending human review (draft only)

List pending findings and conformance decisions separately from human-approved
items, linking their evidence and requested decisions. Pending review is not a
rejection or a completed audit. Do not invent reviewer identities or dispositions.
Use `Draft` in the first heading for a draft and `Approved` for an approved report;
resolve the title placeholder to exactly the chosen label. Finalize a Markdown
file contained in the run directory and record its content hash. Retain the draft,
run evidence, and resumable human stages when producing a separate approved file.
All automated phase statuses through counterexample-rescan must be complete for
`draft_ready`.

## Leads and contested items

List high-signal partial paths, the proven mechanism, and exactly what remains unverified. Do not assign vulnerability severity to unsupported leads.

## NEP standards conformance

Summarize applicable standards and all non-material deviations separately from vulnerability findings. Cross-link any material deviation to its verified finding ID.

| NEP | Source status | Applicability | Disposition | Evidence / linked finding |
|---|---|---|---|---|

Include all registry-selected registry NEPs. Keep N/A rationales concise but evidence-based. Use `advisory` for Draft/New proposals, `superseded` for NEP-21, and `process_only` for NEP-1. A conformance deviation receives no vulnerability severity unless its reachable material mechanism passed ordinary verification.

## Quality and hardening observations

Missing tests/docs, performance, monitoring gaps, reproducible/deployed-hash blockers, incident-response assumptions, and defense-in-depth belong here. Put NEP-governed event or interface deviations in standards conformance instead. Keep syntax/tooling preferences here—such as compact AccountId storage, `require!` or logging/panic APIs, crate re-export style, and integration-test framework—unless the report proves a reachable material mechanism.

## Official-guidance advisories

List applicable non-normative attacker cards that produced an advisory or
quality observation. Include the exact pinned page/section, version evidence,
target evidence, and why no reachable material harm was established. Do not mix
these observations with NEP standards conformance.

## Active-testing coverage

Report, without turning blind spots into target findings:

| Method | Applicable | Executed / total | Counterexamples | Blockers |
|---|---|---:|---:|---|
| Async success/failure/pending schedules | | | | |
| Executable invariants | | | | |
| Mutation families | | | | |
| NEP differential sequences | | | | |
| Temporal/upgrade comparisons | | | | |
| Official attacker-card checks | | | | |

List surviving mutants as scanner/test blind spots. Never describe them as bugs
in the unmodified target.

## Human feedback and informed-pass coverage

Report blind TP/FP/duplicate/unresolved labels and reason-code totals; do not
expose reviewer-sensitive notes unnecessarily. State whether the one verified-TP
informed pass was deferred pending human review (draft only), complete, skipped,
or blocked, its seed count, new candidate
count, pure rediscoveries/duplicates, final human dispositions, and measured
blind-versus-informed recall/precision/cost only when a benchmark supplies ground
truth. Use `skipped` only after the complete blind review population has human
dispositions and no TPs. Do not infer precision/recall from a target review or
invent runtime/token telemetry. Confirm that feedback did not mutate corpus,
prompts, routing, thresholds, or mutation operators during the run.

## L0-L3 capability coverage

| Level | Status | Roles | Artifacts | Isolation / blockers |
|---|---|---|---|---|
| L0 | | | | |
| L1 | | | | |
| L2 | | | | |
| L3 | | | | |

If a valid `maturity-attestation.json` is supplied, name its track, configuration
hash, benchmark size, three qualifying run IDs, and headline metrics. Otherwise
state: “No valid L4 attestation supplied for this track.” Report L0-L3 only to the
extent supported by coverage; documentation changes establish no runtime gain.

## Priority remediation order

Order by verified business harm and dependency between fixes.

## Verification and coverage ledger

Report selected roles, deterministic wave order, role status, callable-method
coverage, semantic-IR/export/receipt/unresolved-edge coverage, raw/deduplicated/
reported/refuted/quality/deferred counts, merge survivors, build blockers, PoC
commands/seeds, every candidate disposition, both judge stages,
counterexample-rescan accounting, metrics-only feedback and informed-pass
accounting, human dispositions, NEP validator result and disposition counts
across all registry-selected NEPs, official-doc registry pin/hash, selected attacker-card count,
and every card's coverage disposition.
List every planned discovery pass and L2/L3 packet with complete, failed, or
missing status. Count raw candidates per pass, unique deduplicated candidates,
and verified findings separately. Never mark coverage complete when a pass,
packet, source binding, or record validation failed.
