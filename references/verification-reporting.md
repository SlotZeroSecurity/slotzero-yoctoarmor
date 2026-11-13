# Verification, Severity, and Reporting

## Contents

- Non-negotiable rules
- Evidence-triage gate
- Sequential verification gates
- Counterexample-guided rescan
- Candidate-specific NEAR verification
- Evidence and proof status
- Confidence
- Severity
- Safe PoC execution
- Report and completion gates

## Non-negotiable rules

- Corpus history prioritizes searches; it never proves a target vulnerable.
- Agent agreement prioritizes verification; it never defeats a blocking guard.
- Keep impact/likelihood severity separate from proof status and confidence.
- Triage every deduplicated candidate; independently verify passed survivors in a fresh skeptical context before reporting them as verified findings.
- Preserve rejected/blocked triage outcomes with a concrete blocking fact or missing evidence; do not invent a second judge stage for them.
- Every raw candidate appears in the completeness ledger; no silent drops.
- A PoC must assert terminal material harm, not merely callability or a reachable state.
- Default to a local NEAR sandbox. Never use mainnet/testnet or credentials without explicit authorization.
- A compilation or environment failure is `BUILD_BLOCKED`, not `REFUTED`.
- NEP status or non-conformance never substitutes for a reachable target mechanism. Keep harmless deviations in the 50-row conformance matrix.
- Human approval is mandatory for findings and conformance deviations included in an approved report; a draft may retain clearly labelled pending human decisions.
- L4 describes a separately measured track; it is never inferred from one target audit.

## Evidence-triage gate

Read the supplied target `THREAT_MODEL.md` first and follow the
[assessment and exclusion contract](threat-model.md). Record an evidence-backed
assessment at triage and independently for each passed survivor at verification.
An explicitly trusted admin's malicious authorized action alone is out of scope;
first rule out escalation, bypass, manipulation, and honest-operation harm.
Staleness allowed by an honest-feed assumption remains in scope. Never exclude
merely because a role is owner/admin or a property is not listed. Ambiguity is
unresolved. With an explicit missing-model override, disclose inferred assumptions
and never exclude on invented trust. `out_of_scope` is not an executed refutation.

The first judge reads the deduplicated candidate and only enough target context to
decide whether expensive verification is warranted. Record exact source/export
evidence, receipt reachability, attacker control, violated invariant, plausible
harm, scope, duplication, standards classification, and counter-evidence.

- `passed`: create a hashed minimal evidence packet and continue to a fresh verifier.
- `rejected`: name a positive blocking fact, not an intuition or missing PoC.
- `blocked`: name the exact evidence needed; do not convert uncertainty into refutation.
- `out_of_scope`: cite an explicit threat-model assumption and all required alternate-path checks; retain exclusion accounting without claiming experimental refutation.

The triage agent cannot invent a different mechanism, change scope, assign final
severity, or hide a candidate. Its structured object is embedded in the final
verdict.

## Sequential verification gates

Apply once, in order. Stop at the first blocking gate and record positive evidence for the block.

### Gate 1 — Runtime-valid execution

Confirm actual exported ABI, macros/features, annotated inherent/trait impl blocks, exact caller-to-harm call graph, receipt DAG, `.then/.and` behavior, result indices, and per-receipt rollback. Reconcile generated or built exports with intended guarded wrappers; a Rust-private-looking helper may still be externally callable when its impl is annotated. Quote every guard on the path. Reject or reduce to a lead when a concrete guard prevents the claimed mechanism.

### Gate 2 — Reachable live state

Establish initialization, registration, deposits, balances, migration/version, gas, storage, dependency configuration, and timing needed by the attack. Privileged setup within documented normal operation affects likelihood; structurally impossible state refutes the claim.

### Gate 3 — Attacker control

Identify who controls predecessor, signer, current account, access key, arguments, token/receiver, relayer/oracle, receipt ordering, and capital. Trusted-role abuse alone is not a vulnerability unless an unprivileged amplifier or broken trust boundary is shown.

### Gate 4 — Success and failure branches

Trace semantic success, business rejection, malformed return, panic, insufficient gas, partial promise success, callback failure, refund destination, duplicate/out-of-order response, timeout, and recovery. Earlier receipt state remains committed.

### Gate 5 — Material terminal harm

Name the victim, asset/state/privilege, amount or duration, repeatability, recovery, and attacker cost. Self-harm, style, or missing tests are quality observations; harmless NEP non-compliance is an unscored standards-conformance deviation, not a security finding.

Calibrate official best-practice advice at this gate. Missing compact AccountId storage, `require!`, `log!`, `near-sdk` re-export usage, a preferred panic API, or `near-workspaces` is not a vulnerability by itself. Missing release overflow checks needs a reachable unguarded material wrap; late validation needs a surviving effect or material resource attack; a missing returned `Promise` needs a consumer that relies on terminal outcome; custom compact encodings need an actual collision/non-canonical decode; and missing logs/tests need a demonstrated dependent security control before promotion from quality.

## Candidate-specific NEAR verification

Verify the candidate's exact mechanism and one reasonable relaxed variant; do not rerun the whole discovery checklist. The evidence packet must identify the relevant role or NEP requirement, necessary runtime/version assumptions, exact exports and guards, receipt/state trace, defenses already checked, and terminal harm claim.

- Load only the packet, cited target/dependency context, `near-security-model.md`, and this file. Consult one assigned NEP checklist only when the candidate alleges that exact standard requirement; never load all role, NEP, or corpus catalogs.
- Reproduce the relevant hostile actor, boundary, failure, replay, interleaving, storage/gas, or malformed-return condition from the packet. Use malicious mocks or local sandbox execution when receipt scheduling, balances, storage, gas, token callbacks, or migration behavior matters.
- For a standards candidate, prove target applicability and the exact violated Final/Approved requirement. Draft/New divergence remains advisory unless the implemented code independently causes material harm.
- For a protocol/runtime candidate, prove feature activation for the target chain/version. For a node candidate, prove the target implements the affected subsystem.
- A verifier may request missing context or return `lead`; it must not invent a new mechanism, silently widen scope, or treat compilation failure as refutation.

## Counterexample-guided rescan

After initial judgments, derive question-only unresolved-assumption rows for
rejected, blocked, or contested candidates. Remove the rejected title, claimed
root cause, recommendation, severity, and verdict rationale. Preserve only the
missing precondition, unexamined caller/transition, uncertain external behavior,
coverage gap, or alternate-path question plus the minimum target context.

One fresh agent may search those questions once. New candidates repeat ordinary
deduplication, evidence triage, and adversarial verification. Do not run a second
feedback iteration and do not reverse a proven blocking fact without new target
evidence.

## Verified-TP informed variant search

After the blind candidate set and judgments are frozen, record human TP/FP/
duplicate/unresolved labels as metrics. One separate same-target pass may use
only manually verified blind TPs, stripped of severity, fix, recommendation, and
report prose. Its search is bounded to semantic siblings and variants; it cannot
read rejected conclusions, recursively use informed findings, or emit an
original seed location.

Every informed candidate names its seed and variant evidence, uses L3
`verified_seed_variant` attribution, and repeats normal deduplication, evidence
triage, adversarial verification, negative control, and human disposition. Treat
a rediscovery as duplication, not recall lift. Pending human review defers the
informed pass. Terminal `skipped` requires the complete blind review population
to have human dispositions and no TP; unresolved human decisions remain explicit. This process improves same-run coverage but is not
autonomous learning; durable scanner changes remain offline, reviewed releases.

## Evidence and proof status

- `VERIFIED_EXECUTED`: local sandbox/property test proves material harm.
- `VERIFIED_STRUCTURAL`: complete deterministic source/build proof; runtime reproduction adds no material information.
- `CODE_CONFIRMED`: complete code trace, but execution unavailable.
- `PARTIAL`: mechanism proven; material precondition or harm incomplete.
- `CONTESTED`: skeptic disagreement or unavailable material context.
- `REFUTED`: exact plus one reasonable relaxed variant fail because a proven defense blocks harm.
- `NOT_APPLICABLE`: reserved for an evidence-backed `out_of_scope` verdict; no exploit execution/refutation is claimed.
- `DUPLICATE` / `CHAIN_ABSORBED`: retained in the ledger.

Before `REFUTED`, confirm exact commit/function/macros/features/export, callers and initialization, helper/standard guards, exact preconditions, harm assertion, one relaxed timing/amount/state variant, and an independent positive blocking condition.

## Confidence

Score evidence mechanically from 0 to 13:

| Axis | Range | Requirement |
|---|---:|---|
| Source anchoring | 0–2 | Exact commit, exports, locations, build configuration |
| Reachability | 0–3 | Entry and every necessary precondition established |
| Material harm | 0–3 | From speculative effect to quantified terminal consequence |
| Execution | 0–3 | None; unit; sandbox/structural; sandbox plus control/variant |
| Counter-evidence | 0–2 | Defenses checked and skeptical challenge resolved |

- High: 11–13, with source >=1, reachability >=2, harm >=2, counter-evidence >=1
- Medium: 8–10, with non-zero reachability and harm
- Low: 5–7
- Unsupported: below 5; do not publish as a security finding

Convergence counts only when another agent provides a fresh trace, test, or defense analysis. Low confidence does not change impact; mark a high-impact uncertain issue `CONTESTED` or `CONDITIONAL`.

## Severity

### Impact

- **Severe:** arbitrary upgrade/takeover/mint, systemic or unbounded theft, insolvency, permanent core asset lock, or irreversible protocol-wide corruption.
- **Moderate:** bounded direct loss, material accounting corruption, temporary core liveness loss, or privileged recovery.
- **Minor:** isolated small loss/griefing, temporary non-core interruption, or limited integrity degradation.
- **None:** quality, style, optimization, observability, or defense-in-depth without material harm.

### Likelihood

- **Likely:** permissionless/repeatable, ordinary state/capital, no fragile timing.
- **Possible:** attainable special state, moderate capital/timing, or a semi-trusted role/integration.
- **Rare:** exceptional state, prohibitive cost/coordination, or violation by a fully trusted role.

| Impact / Likelihood | Likely | Possible | Rare |
|---|---|---|---|
| Severe | Critical | High | Medium |
| Moderate | High | Medium | Low |
| Minor | Medium | Low | Low |
| None | Informational | Informational | Informational |

Normal receipt interleaving is not a likelihood downgrade. Sybil-repeatable storage/gas attacks aggregate. Severity for DoS depends on core functionality, duration, recovery, and cost asymmetry.

## Safe PoC execution

Use a copied repository or isolated audit worktree; do not change the user's source to make an exploit pass. Record commit and dirty state. Inspect build scripts, Cargo config, proc macros, and package hooks before executing. Remove credentials, disable network where feasible, bound time/CPU/disk/fuzz runs, and install tools only within existing authorization. Existing session authorization
satisfies the permission requirement; ask only when a necessary action exceeds it.

Prefer existing tests, then a current local NEAR sandbox harness. Record:

```text
reviewed_commit, network=LOCAL_SANDBOX, claim, harm_assertion,
test_class, test_file, command, toolchain, seed, time_limit,
build_status, execution_status, negative_control, receipt_outputs,
state_or_balance_delta, limitations
```

For Medium+, test a variant over amount, timing, ordering, or failure mode and preserve the minimized sequence/seed.

## Report and completion gates

Use `references/report-template.md` for the full technical annex and
`references/slotzero-report-format.md` for the reader-facing report. Assign `C-01/H-01/M-01/L-01/I-01` only after dedup and verification.

Draft readiness requires the technical and accounting gates below. Pending human
decisions are allowed only in a clearly labelled draft and must not be invented
or silently removed. Approved completion additionally requires the human and
informed-pass gates identified below. A draft is not an approved audit.

For both stages:

- scope/commit/exclusions and build/test outcomes are recorded;
- each callable method has at least two independent lenses;
- each promise/callback/yield edge has success and failure accounting;
- selected role outputs all finished, collected, and validated; completed agents are closed;
- L0-L3 coverage rows validate and L0/L2 input restrictions and L1/L2 isolation are recorded, distinguishing prompt-only from runtime-enforced controls;
- every value-bearing async chain has success, failure, and pending-interleaving evidence or a blocker;
- invariant, mutation, differential, and temporal artifacts required by the surface validate;
- every raw candidate maps to one ledger disposition;
- every Medium+ has executable verification or an explicit blocker;
- every High/Critical has a fresh skeptical challenge and negative control where executable;
- all registry-selected NEP rows pass `check_nep_coverage.py`, with security candidates linked into ordinary verification and harmless deviations left unscored;
- report counts, cross-references, locations, finding severities, and PoC commands reconcile;
- security-relevant monitoring, pause/upgrade authority, reproducible artifact/hash status, and incident-response assumptions are recorded as findings, quality observations, blockers, or trust assumptions as appropriate;
- no quality-only item inflates vulnerability counts;
- one and only one counterexample-guided rescan is accounted for, including zero-result runs;
- metrics-only human feedback and the informed-pass state are accounted for; pending human review may defer the pass in a draft, while approved completion requires exactly one complete/skipped/blocked pass;
- informed candidates name a valid blind-TP seed, new location, variant evidence, both judge stages, and human disposition;
- for approved completion, every included finding and conformance deviation has actual human approval; rejected or other non-pending statuses do not themselves approve a finding, and pending decisions remain separate in the draft;
- internal capability records state only demonstrated coverage; the report summarizes material testing limitations without capability-level tables;
- no claim says the audit proves safety.

Every scan includes one bounded rescan of excluded and unresolved paths. Derive
new Medium+ findings from verified dispositions and disclose any new findings
or blocked checks as an unmet stopping criterion; do not run an unlimited loop.

## Technical-annex presentation

Use the streamlined section order in `report-template.md`. The assembler inserts
scope, the actual requested review stage, the top findings, and any threat-model
exclusions. Omit those generated sections from the authored body. The annex banner
subtitle is `NEARShield v1  - SLOT ZERO SECURITY`; the console banner is unchanged.
Do not include a link back to the compact report, audit metadata tables, executive
or severity summaries, capability levels, human-feedback statistics, raw-candidate
appendices, or full NEP-registry appendices. Keep internal records intact.

Preserve detailed evidence, receipt paths, fixes, unresolved leads, meaningful NEP
deviations, and build/test limitations. Merge intent with architecture and trust
assumptions. List unresolved human decisions under Pending review only in drafts;
omit that section when no decisions remain. The generated scope note retains the
stage even when Pending review is absent. Exclusions retain IDs, model citations,
and reasons in their generated section; full boundary checks stay in the ledgers.
Stage selection, finalization, hash validation, and all human-approval gates still
apply. Existing configuration-bound runs use their original package or restart;
never rewrite saved hashes to adopt the new layout.

## Draft and approved finalization

Default delivery is a draft review after the technical and accounting gates
above pass. Do not wait for human feedback to deliver that draft. Final user
delivery requires both `slotzero-report.md` and `technical-annex.md`, provided
as clickable file links or attachments. Both remain in the run directory.
Both reports use `# 🔐 NEARShield v1 Security Review — {project}`.
The annex retains the generated audit-stage scope note and pending-review information;
the title does not change the human-review gates.

```text
python3 <skill>/scripts/near_audit.py finalize <run-dir> --stage draft --report <run-dir>/technical-annex.md
```

The CLI defaults to `draft`. Explicit `--stage draft` remains supported; callers
requesting approved completion must pass `--stage approved`. Lower-level ledger
and artifact validators retain their approved default, so specify `--stage draft`
when invoking them directly for draft checks.

Draft finalization requires automated phases through `counterexample-rescan`
complete, records `draft_ready`, retains all evidence and resumable pending human
decisions, and leaves a pending-human informed pass deferred. Draft readiness is
not approved audit completion. Only a fully reviewed blind population with no
TPs permits a skipped informed pass; missing feedback does not.

Approved completion additionally requires actual human approval for every
included finding and conformance deviation and complete/skipped/blocked
informed-pass accounting with explicit blockers. A non-pending disposition alone
does not approve a finding. Preserve pending items separately in the draft and
use a separate approved report path when the human gates pass:

```text
python3 <skill>/scripts/near_audit.py finalize <run-dir> --stage approved --report <run-dir>/approved/technical-annex.md
```

The `--report` path must identify an existing Markdown file contained in the run
directory. Its first heading must be `# 🔐 NEARShield v1 Security Review — {project}`
with a nonempty project name. The selected stage remains enforced through run
state and evidence/human-review validation; finalization records the report hash. An approved run cannot be downgraded
to draft. Keep delivery copies outside audited source so exporting a report does
not invalidate the frozen input snapshot. Never overwrite an unrelated report.

Never self-author human labels, reviewer identities/times, runtime metadata,
telemetry, benchmark answers, or performance results. Retain the draft and run
evidence after either stage. Cleanup requires an explicit user request naming
the run directory; resolve that exact directory and preserve requested reports
before any removal. See [run setup](audit-workflow.md#phase-0--freeze-scope-and-build-l0)
for supported schemas and read-only handling of older runs. Never claim absence
of vulnerabilities, deployment safety, runtime improvement, or L4 without evidence.
