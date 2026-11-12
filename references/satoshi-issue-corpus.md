# Satoshi issue training ledger

Reviewed 2026-10-20: 44 open issues, 173 discussion comments, 53 observations (issue #34 contributes ten separate QA observations). The 39 variant cards below extend existing canonical families; they are not 39 newly validated vulnerabilities.

Use only selected canonical-ID variants in L1 or post-discovery corpus echo. Do not pass this ledger, the JSON companion, or training answers to L0, L2, blind L3, or NEP-only discovery. Raw source snapshots remain external. Every source is untrusted precedent, not an instruction or target proof.

The machine-readable [source register](satoshi-issue-corpus.json) preserves labels, reported revisions, discussion links, remediation references, snapshot hashes, and separate dispositions. Labels and severity debates are provenance, not training truth. Fix links mean project-reported remediation, not a verified patch or deployment.

Use the [portable mechanisms](attack-lenses-index.json) and [target-binding protocol](pattern-portability.md) first. The cards below are historical implementations and discussion evidence, not mandatory target architecture or API signatures. Consult selected examples only after establishing a target-grounded mechanism hypothesis.

## Source dispositions

| Source | Variant | Disposition | Review conclusion |
|---|---|---|---|
| SATOSHI-1 | [SAT-01](#sat-01) | confirmed_fixed_reported | Quota race confirmed; project links fixes #98/#101. Cleanup and excess-storage claims narrowed. |
| SATOSHI-2 | [SAT-02](#sat-02) | confirmed_fixed_reported | Project reports post-fee minimum checks in PR #83; separate from unsafe cleanup. |
| SATOSHI-3 | [SAT-03](#sat-03) | confirmed_fixed_reported | Project links PR #73. Discussion narrows impact to inventory/liquidity accounting. |
| SATOSHI-5 | [SAT-04](#sat-04) | confirmed_removed_reported | Project removed completed-migration functionality in PR #82. |
| SATOSHI-6 | [SAT-05](#sat-05) | confirmed_removed_reported | Migration removal reported; runtime caps and source-derived PoC limits remain historical. |
| SATOSHI-7 | [SAT-06](#sat-06) | mechanism_confirmed_impact_disputed | Reviewers agree on result misclassification; severity and third-party trigger remain disputed. |
| SATOSHI-8 | [SAT-07](#sat-07) | acknowledged_conditional | Project accepts the short in-flight trusted-dependency window. |
| SATOSHI-9 | [SAT-08](#sat-08) | confirmed_removed_reported | Project removed migration; source and mock/sandbox evidence have different coverage. |
| SATOSHI-10 | [SAT-09](#sat-09) | hardening_negative_control | Missing global cap alone does not prove overload; project notes finite UTXOs and plans removal of account caps. |
| SATOSHI-11 | [SAT-10](#sat-10) | mechanism_confirmed_impact_disputed | Missing authorization verification accepted by reviewers; broad freeze claims exceed some PoCs. |
| SATOSHI-12 | [SAT-11](#sat-11) | confirmed_fixed_reported | Project links PR #85; unrelated-user freeze was not isolated by the submitted control. |
| SATOSHI-13 | [SAT-12](#sat-12) | intentional_negative_control | Project explicitly confirms optional templates and persistent restrictions are intentional. |
| SATOSHI-14 | [SAT-12](#sat-12) | intentional_negative_control | Project explicitly confirms optional templates and persistent restrictions are intentional. |
| SATOSHI-15 | [SAT-13](#sat-13) | confirmed_fixed_reported | Project links PR #88; retain bounded overpayment and denomination caveat. |
| SATOSHI-16 | [SAT-14](#sat-14) | confirmed_fixed_reported | Project links PR #99; concrete safe-mint zero result establishes retry inflation. |
| SATOSHI-17 | [SAT-15](#sat-15) | acknowledged_integration_limit | Project supports only all-or-zero receivers; preserve partial-use conservation test. |
| SATOSHI-18 | [SAT-16](#sat-16) | confirmed_fixed_reported | Project links PR #100; rejecting before marking preserves refund or later admission, subject to fees. |
| SATOSHI-19 | [SAT-17](#sat-17) | confirmed_removed_reported | Project removed migration in PR #82; separate from user activity during one migration. |
| SATOSHI-20 | [SAT-18](#sat-18) | confirmed_fixed_reported | Project links PR #87; review distinguishes PendingSign and PendingVerify cleanup. |
| SATOSHI-21 | [SAT-14](#sat-14) | confirmed_fixed_reported | Project links PR #99; concrete safe-mint zero result establishes retry inflation. |
| SATOSHI-22 | [SAT-19](#sat-19) | acknowledged_risk_tradeoff | Project accepts resize behavior to prioritize finalization; no reorg or loss demonstrated. |
| SATOSHI-23 | [SAT-20](#sat-20) | qa_conditional | Operator-only empty-output validation gap; signed original may still complete. |
| SATOSHI-24 | [SAT-08](#sat-08) | confirmed_removed_reported | Project removed migration; source and mock/sandbox evidence have different coverage. |
| SATOSHI-25 | [SAT-16](#sat-16) | confirmed_fixed_reported | Project links PR #100; rejecting before marking preserves refund or later admission, subject to fees. |
| SATOSHI-26 | [SAT-21](#sat-21) | acknowledged_conditional | Team reports no planned token rotation; future rotation must preserve original token binding. |
| SATOSHI-27 | [SAT-01](#sat-01) | confirmed_fixed_reported | Quota race confirmed; project links fixes #98/#101. Cleanup and excess-storage claims narrowed. |
| SATOSHI-28 | [SAT-10](#sat-10) | mechanism_confirmed_impact_disputed | Missing authorization verification accepted by reviewers; broad freeze claims exceed some PoCs. |
| SATOSHI-29 | [SAT-06](#sat-06) | mechanism_confirmed_impact_disputed | Reviewers agree on result misclassification; severity and third-party trigger remain disputed. |
| SATOSHI-34/QA-01 | [SAT-QA-01](#sat-qa-01) | acknowledged_subsidy | Project accepts fee-funded standard-flow registration subsidy. |
| SATOSHI-34/QA-02 | [SAT-QA-02](#sat-qa-02) | qa_fixed_reported | Project reports exact user-output accounting. |
| SATOSHI-34/QA-03 | [SAT-QA-03](#sat-qa-03) | qa_scope_conditional_fixed_reported | Release hardening reported; CI was outside stated contract scope. |
| SATOSHI-34/QA-04 | [SAT-QA-04](#sat-qa-04) | qa_fixed_reported | Project reports configuration-validation changes. |
| SATOSHI-34/QA-05 | [SAT-QA-05](#sat-qa-05) | qa_acknowledged | Project retains existing diagnostics. |
| SATOSHI-34/QA-06 | [SAT-QA-06](#sat-qa-06) | qa_fixed_reported | Project reports expiry visibility changes. |
| SATOSHI-34/QA-07 | [SAT-QA-07](#sat-qa-07) | qa_deployment_condition_absent | Project reports direct relayers only, so signer equals payer. |
| SATOSHI-34/QA-08 | [SAT-QA-08](#sat-qa-08) | qa_scope_conditional_fixed_reported | Project reports one-yocto setter change; token contract scope caveat retained. |
| SATOSHI-34/QA-09 | [SAT-QA-09](#sat-qa-09) | qa_deployment_requirement | Project acknowledges recommendation and considers redeployment sufficient for an initialization race. |
| SATOSHI-34/QA-10 | [SAT-QA-10](#sat-qa-10) | qa_fixed_reported | Documentation correction was followed by an additional fix to describe retry rather than lost-and-found. |
| SATOSHI-35 | [SAT-22](#sat-22) | confirmed_fixed_reported | Project links PR #76 removing embedded bytes from new UTXOs. |
| SATOSHI-36 | [SAT-24](#sat-24) | confirmed_fixed_reported | Project accepted the expired-cancel case and links PR #97 allowing repeated cancellation. |
| SATOSHI-37 | [SAT-06](#sat-06) | mechanism_confirmed_impact_disputed | Reviewers agree on result misclassification; severity and third-party trigger remain disputed. |
| SATOSHI-39 | [SAT-25](#sat-25) | confirmed_fixed_reported | Project links PR #84; mint retry does not restore refund cost or waiting time. |
| SATOSHI-40 | [SAT-23](#sat-23) | confirmed_partial_legacy_subsidy | PR #91 adds pricing; discussion demonstrates old change-UTXO undercharge and project accepts residual legacy subsidy. |
| SATOSHI-41 | [SAT-05](#sat-05) | confirmed_removed_reported | Migration removal reported; runtime caps and source-derived PoC limits remain historical. |
| SATOSHI-42 | [SAT-08](#sat-08) | confirmed_removed_reported | Project removed migration; source and mock/sandbox evidence have different coverage. |
| SATOSHI-43 | [SAT-21](#sat-21) | acknowledged_conditional | Team reports no planned token rotation; future rotation must preserve original token binding. |
| SATOSHI-44 | [SAT-26](#sat-26) | confirmed_fixed_reported | Project links PR #90; ordinary deposit completion can remain available. |
| SATOSHI-45 | [SAT-27](#sat-27) | acknowledged_mitigated_reported | Intentional optimistic mode; project reports a 100-year unsafe-refund timelock. Deployment not independently verified. |
| SATOSHI-46 | [SAT-15](#sat-15) | acknowledged_integration_limit | Project supports only all-or-zero receivers; preserve partial-use conservation test. |
| SATOSHI-47 | [SAT-03](#sat-03) | confirmed_fixed_reported | Project links PR #73. Discussion narrows impact to inventory/liquidity accounting. |
| SATOSHI-48 | [SAT-28](#sat-28) | confirmed_fixed_reported | Project links PR #81 prohibiting rejection after execution rather than trying to revoke signatures. |
| SATOSHI-49 | [SAT-16](#sat-16) | confirmed_fixed_reported | Project links PR #100; rejecting before marking preserves refund or later admission, subject to fees. |
| SATOSHI-50 | [SAT-29](#sat-29) | confirmed_fixed_reported | Project links PR #81; valid non-dust control establishes independence from #2. |

## Variant cards

### SAT-01

**Capacity must be reserved across asynchronous admission**

Canonical mappings: `NA-ASYNC-001`, `NA-RESOURCE-001`.
Sources: #1, #27.

- **Invariant:** Pending work plus dispatched reservations stays within the configured account capacity.
- **Activation:** An entrypoint checks a quota before an external height/proof request; its callback creates the record.
- **Failure sequence:** Submit two distinct replacements before either callback; both observe the same free slot.
- **Required evidence:** Show both accepted records, a sequential rejection control, and marginal excess storage against one allowed replacement.
- **Recovery checks:** Exercise losing PendingSign siblings and the actual cleanup caller; distinguish relayer-only cleanup from permissionless cleanup.
- **False-positive exclusions:** A bounded same-owner RBF family does not prove unbounded growth, forced MPC work, or third-party disruption.
- **Fix family:** Reserve before dispatch, release on failure, and revalidate capacity at insertion without double charging.

### SAT-02

**Refund outputs need chain-specific post-fee validity**

Canonical mappings: `NA-INTEGRATION-003`, `NA-STATE-004`.
Sources: #2.

- **Invariant:** An admitted refund can produce a usable output after fees.
- **Activation:** Default or custom fees can leave a positive but sub-policy output.
- **Failure sequence:** Choose amount just above the fee; execution builds a dust output that ordinary relaying rejects.
- **Required evidence:** Test fee-minus-one, fee, fee-plus-one, and script-specific output bounds using the pinned chain policy.
- **Recovery checks:** Trace rejection and cleanup independently; the orphaned-marker defect is SAT-29, including for non-dust outputs.
- **False-positive exclusions:** Relay dust policy is not universally a consensus prohibition; direct miner inclusion and script differences matter.
- **Fix family:** Validate post-fee output value at admission and execution against the configured chain and script.

### SAT-03

**Mint success can survive a dead bookkeeping callback**

Canonical mappings: `NA-ASYNC-005`, `NA-ACCOUNT-002`, `NA-INTEGRATION-003`.
Sources: #3, #47.

- **Invariant:** Every issued token liability has registered backing or an authenticated recoverable registration state.
- **Activation:** Replay reservation, external mint, and backing registration occur in different receipts.
- **Failure sequence:** Mint commits; the later callback fails for storage balance or gas; the marker survives while inventory is absent.
- **Required evidence:** Demonstrate durable transferable tokens, the callback failure reason, absent inventory, and blocked retry after funding; measure gas separately from storage.
- **Recovery checks:** Reconcile the exact token issuance and outpoint before idempotent finalization; never clear the marker and mint again blindly.
- **False-positive exclusions:** Real deposited BTC remains in custody: missing spendable inventory alone is not fabricated BTC backing or direct theft.
- **Fix family:** Persist operation context and provide bounded, funded, idempotent finalization after verified mint success.

### SAT-04

**Supply equality does not prove allocation integrity**

Canonical mappings: `NA-STATE-004`, `NA-STATE-003`.
Sources: #5.

- **Invariant:** Every legitimate holder receives its entitlement exactly once, not once per supplied occurrence.
- **Activation:** Migration accepts a caller-provided holder vector and checks only the sum of queried balances.
- **Failure sequence:** Repeat one holder and omit others so the occurrence-weighted sum still equals total supply.
- **Required evidence:** Use unequal holder balances, all-equal duplicates, and an honest unique-list control; inspect ownership as well as supply.
- **Recovery checks:** A cutover must not strand omitted holders on a token the bridge no longer accepts.
- **False-positive exclusions:** Preserve the DAO/MigrationOperator prerequisite; this is not arbitrary public theft.
- **Fix family:** Reject duplicate identifiers before queries and reconcile a complete, consistent holder snapshot.

### SAT-05

**One-shot migration hits independent runtime limits**

Canonical mappings: `NA-RESOURCE-005`, `NA-STATE-003`, `NA-ASYNC-008`.
Sources: #6, #41.

- **Invariant:** Every supported holder population can complete allocation-preserving migration.
- **Activation:** All balances are queried and all mints batched without persisted progress; each call must sum to total supply.
- **Failure sequence:** Grow or fragment the holder set beyond action, dependency, or prepaid-gas bounds; smaller independent calls fail the supply equality.
- **Required evidence:** Pin runtime limits; derive promise gas, receipt actions, and input dependencies separately; test boundary-minus-one/boundary/plus-one.
- **Recovery checks:** Verify resumable batches bind snapshot, source/destination token, epoch, processed holders, and reconciled totals.
- **False-positive exclusions:** Historical 100-action and gas figures are not universal constants. Failed oversized receipts do not execute a successful prefix of their actions.
- **Fix family:** Use bounded idempotent batches and activate the destination only after complete snapshot reconciliation.

### SAT-06

**Unknown mint outcome is neither success nor safe refund**

Canonical mappings: `NA-ASYNC-004`, `NA-INTEGRATION-003`.
Sources: #7, #29, #37.

- **Invariant:** Settlement follows proven token delivery; uncertainty cannot authorize duplicate issuance or refund.
- **Activation:** A helper recognizes only decoded zero as failure and negates that test to infer success.
- **Failure sequence:** Feed outer failure, malformed/oversized result, zero, partial, full, and over-range amounts through the exact pinned ABI.
- **Required evidence:** Separate a known pre-mint rejection from a failed outer chain that may include a committed mint; trace token balances and each receipt.
- **Recovery checks:** Keep ambiguous outcomes pending and reconcile issuance before mint retry or source-chain refund.
- **False-positive exclusions:** Ordinary receiver panic or malformed receiver output may resolve to valid zero under NEP-141; self-selected bridge recipients do not prove a third-party trigger.
- **Fix family:** Use explicit known-before-mint failure, delivered, partial, and unresolved states with operation-bound recovery.

### SAT-07

**Dependency rotation has an in-flight authority policy**

Canonical mappings: `NA-ASYNC-004`, `NA-INTEGRATION-003`.
Sources: #8.

- **Invariant:** A proof result is accepted under the request-generation policy actually promised by the protocol.
- **Activation:** A mutable trusted verifier can be rotated while a proof request is in flight.
- **Failure sequence:** Dispatch to A, rotate to B, then deliver A's result; determine whether rotation promises revocation of old requests.
- **Required evidence:** Identify the verifier, generation, decision receipt, callback window, pause behavior, and compromise assumption.
- **Recovery checks:** Reject or explicitly grandfather old generations; support retry through the authorized verifier without double settlement.
- **False-positive exclusions:** A trusted dependency compromise and a short already-dispatched window are conditional assumptions, not evidence the production verifier is compromised.
- **Fix family:** Bind request identity and generation where revocation is required; otherwise document grandfathering and incident-response limits.

### SAT-08

**A live migration snapshot can duplicate one economic claim**

Canonical mappings: `NA-STATE-003`, `NA-ASYNC-006`, `NA-ECON-001`.
Sources: #9, #24, #42.

- **Invariant:** A snapshotted balance cannot fund both an old-token withdrawal and a replacement-token entitlement.
- **Activation:** Migration reads balances asynchronously while old-token ingress remains active and pending operations omit funding-token identity.
- **Failure sequence:** Snapshot a holder, accept its old-token withdrawal, mint the copied replacement balance, cut over, then settle the withdrawal.
- **Required evidence:** Prove a reachable receipt ordering; distinguish observed calls from simulated balances or printed payouts; inspect both burn-success and burn-failure branches.
- **Recovery checks:** Drain or reconcile old liabilities before cutover; settle each pending withdrawal against its original token and epoch.
- **False-positive exclusions:** A migration-only lock does not stop user withdrawals. Conversely, a documented, enforced pause-and-drain process may close this path.
- **Fix family:** Require quiescence before the snapshot and bind token/epoch to all pending value operations.

### SAT-09

**Per-account limits are not evidence of global overload**

Canonical mappings: `NA-STATE-004`, `NA-RESOURCE-005`.
Sources: #10.

- **Invariant:** Shared resource admission remains usable under the documented economic and capacity model.
- **Activation:** Many accounts can each create funded work, with a finite shared UTXO pool.
- **Failure sequence:** Measure attacker-controlled reservations across accounts and compare locked shared liquidity with committed attacker capital.
- **Required evidence:** Demonstrate disproportionate cost or an actual victim failure; distinguish expected concurrent users from an attack.
- **Recovery checks:** Exercise signing, replacement, cancellation, and release rather than assuming pending means unrecoverable.
- **False-positive exclusions:** The absence of a global cap is not itself a vulnerability; adding one can create a global blocking slot.
- **Fix family:** Choose bounds, collateral, fairness, or recovery from demonstrated bottlenecks rather than requiring a universal global counter.

### SAT-10

**Parsed Orchard data is not verified authorization**

Canonical mappings: `NA-INTEGRATION-003`, `NA-ASYNC-005`.
Sources: #11, #28.

- **Invariant:** Consensus-invalid caller data cannot irrecoverably reserve shared withdrawal liquidity.
- **Activation:** The bridge recovers recipient/value from an Orchard bundle without verifying all required authorization.
- **Failure sequence:** Verify a valid original bundle, mutate its proof while preserving recipient/value, then submit it to reserve pooled UTXOs.
- **Required evidence:** Use the exact active circuit/verifier, honest withdrawal control, fully backed token distribution, and measured input-value-to-escrow amplification.
- **Recovery checks:** Exercise signing through PendingVerify and the real replacement/cancellation path; distinguish inability to confirm from inability to recover.
- **False-positive exclusions:** A test stopping at PendingSign does not prove signing cannot proceed or that all recovery is impossible.
- **Fix family:** Validate proof, required authorization signatures and transaction binding before durable reservation, or use an authenticated verifier plus safe recovery.

### SAT-11

**Confirmation and spendability are separate checks**

Canonical mappings: `NA-INTEGRATION-003`, `NA-ECON-001`.
Sources: #12.

- **Invariant:** Assets classified as active backing meet source-chain spendability requirements.
- **Activation:** A bridge accepts coinbase outputs using ordinary confirmation tiers.
- **Failure sequence:** Supply an included immature coinbase output; observe issuance and active-inventory classification.
- **Required evidence:** Detect the coinbase structure, use transaction index zero, and compare maturity boundary controls; pin the chain's counting convention.
- **Recovery checks:** Quarantine immature backing or defer admission until the source-chain maturity rule is met.
- **False-positive exclusions:** A mock inclusion response proves bridge handling only. A victim selecting an already-reserved UTXO does not isolate immaturity impact.
- **Fix family:** Enforce the source chain's coinbase maturity independently of normal value-based confirmation tiers.

### SAT-12

**Optional restrictions and persistent policy are not missing authorization**

Canonical mappings: `NA-STATE-004`, `NA-STATE-001`, `NA-OFFCHAIN-007`.
Sources: #13, #14.

- **Invariant:** Acceptance matches the documented distinction between trust membership and optional restrictions.
- **Activation:** A DAO whitelist and message-template map have separate lifecycles.
- **Failure sequence:** Test absent templates, removal, and re-whitelisting; compare resulting acceptance with the intended unrestricted or retained-policy mode.
- **Required evidence:** Establish whether templates are restrictions or permissions and whose tokens the message can affect.
- **Recovery checks:** Verify separate template removal exists and that non-whitelisted receivers remain blocked.
- **False-positive exclusions:** The project confirmed optional templates and retained restrictions are intentional; clearing templates may make reactivation less restricted.
- **Fix family:** Document and test the intended modes; require mandatory templates only when the target's policy actually demands them.

### SAT-13

**Attached surplus needs a payer and disposition**

Canonical mappings: `NA-RESOURCE-001`, `NA-ACCOUNT-003`.
Sources: #15.

- **Invariant:** Every accepted attached amount is consumed, refunded, or credited under a documented policy.
- **Activation:** Admission accepts at least a fixed allowance but failure refunds only that allowance.
- **Failure sequence:** Attach exact and excess amounts on successful and failed operations; inspect payer balances and any credit.
- **Required evidence:** Read the actual denomination and configured requirement; do not import the report's inconsistent 1.2 versus 0.0012 NEAR figures.
- **Recovery checks:** Check all failure branches and whether the original attached amount and predecessor payer survive callbacks.
- **False-positive exclusions:** Self-directed bounded overpayment is not third-party reserve theft; intentionally documented fees are not surplus.
- **Fix family:** Reject excess or record and refund/credit it to the actual payer, with failure-safe settlement.

### SAT-14

**Retries must not multiply risk accounting**

Canonical mappings: `NA-ASYNC-002`, `NA-ACCOUNT-002`.
Sources: #16, #21.

- **Invariant:** A unique source outpoint contributes to cumulative confirmation accounting at most as intended.
- **Activation:** A pre-mint ring increment survives while mint failure clears only the replay marker.
- **Failure sequence:** Repeat a zero-result safe mint, then submit a distinct same-block victim deposit near a tier boundary.
- **Required evidence:** Use a concrete mint-failure trigger and a one-attempt control; prove committed increments and separate blocks.
- **Recovery checks:** Compensation must target the same height/amount and not decrement a reused ring slot belonging to another block.
- **False-positive exclusions:** A confirmation-check panic rolls back that receipt's tentative increment; not every same-block deposit is delayed.
- **Fix family:** Use outpoint-idempotent accounting or operation-bound reversal without weakening pre-mint confirmation admission.

### SAT-15

**Partial token use preserves the user's remainder**

Canonical mappings: `NA-ASYNC-009`, `NA-ACCOUNT-003`, `NA-ASYNC-004`.
Sources: #17, #46.

- **Invariant:** Delivered value plus recoverable user credit equals the user's intended entitlement.
- **Activation:** Safe mint uses transfer-call with the bridge as sender and treats every positive used amount as full success.
- **Failure sequence:** A receiver accepts part; the resolver returns the remainder to the bridge; no user claim is recorded.
- **Required evidence:** Resolve used-versus-unused polarity from the pinned ABI and test zero, partial, full, and out-of-range values.
- **Recovery checks:** Attribute the returned remainder to its depositor and token; check retry, refund, lost-and-found, and fee paths.
- **False-positive exclusions:** The project acknowledges an all-or-zero integration requirement; establish whether a partial receiver is supported/reachable before scoring.
- **Fix family:** Reconcile partial use with an explicit user credit/refund, or enforce a safe all-or-zero integration contract.

### SAT-16

**Rejecting issuance must not erase legitimate recovery**

Canonical mappings: `NA-ACCOUNT-003`, `NA-INTEGRATION-003`.
Sources: #18, #25, #49.

- **Invariant:** An unminted recoverable source output retains a safe terminal spend or refund path.
- **Activation:** Below-minimum deposits are marked processed and parked outside normal inventory.
- **Failure sequence:** Compare refund before verification with standard/safe verification, then lower the minimum and attempt all recovery paths.
- **Required evidence:** Use an output that can cover fees; distinguish a bridge policy minimum from actual dust or uneconomic refund value.
- **Recovery checks:** Check existing refund execution as well as new requests and prevent concurrent mint/refund during recovery.
- **False-positive exclusions:** Intentional no-mint behavior does not prove no-refund intent; extremely small transfers may legitimately be uneconomic.
- **Fix family:** Reject before consuming the marker or retain an authenticated recoverable unavailable-output state.

### SAT-17

**Overlapping migration executions require independent idempotency**

Canonical mappings: `NA-ASYNC-001`, `NA-STATE-003`.
Sources: #19.

- **Invariant:** One source migration allocation is minted no more than once across retries and concurrent operators.
- **Activation:** Configuration cutover occurs only after asynchronous mints; no migration lock or completion identity exists.
- **Failure sequence:** Start two authorized migrations before either resolves and compare destination balances and supply.
- **Required evidence:** Use real destination mint results; respect atomicity of actions within a single receipt instead of assuming partial execution.
- **Recovery checks:** After an ambiguous resolver outcome, reconcile completed destination issuance before retrying.
- **False-positive exclusions:** This requires an authorized operator; it is distinct from SAT-08's user race during one migration.
- **Fix family:** Reserve a unique migration epoch before dispatch and track idempotent completed allocations and cutover.

### SAT-18

**Winning transaction cleanup includes every losing phase**

Canonical mappings: `NA-STATE-001`, `NA-ASYNC-005`.
Sources: #20.

- **Invariant:** Finalizing a transaction family releases obsolete descendants and their account signing capacity.
- **Activation:** Cleanup handles PendingVerify siblings but omits PendingSign children.
- **Failure sequence:** Create an unsigned replacement/cancel, finalize the original, and attempt a fresh withdrawal.
- **Required evidence:** Show retained records and indexes, the exact quota failure, and caller permissions of each cleanup method.
- **Recovery checks:** Test original-wins, replacement-wins, repeated cleanup, and a user without relayer privileges.
- **False-positive exclusions:** Relayer-recoverable withdrawal unavailability is not automatically permanent token freezing.
- **Fix family:** Remove obsolete descendants and coupled indexes across phases, or expose authenticated safe orphan cleanup.

### SAT-19

**Resizing security history cannot silently forget its meaning**

Canonical mappings: `NA-STATE-001`, `NA-INTEGRATION-003`.
Sources: #22.

- **Invariant:** A security decision handles evicted history consistently with the accepted confirmation policy.
- **Activation:** A bounded ring grows and an evicted height now maps to an empty cell.
- **Failure sequence:** Record a deposit, evict with a colliding verified deposit, grow capacity, then submit a delayed same-height output.
- **Required evidence:** Pin the PR/revision that contains the ring; compare actual cumulative exposure with the selected tier.
- **Recovery checks:** Preserve a forgotten-history watermark or use an explicit conservative policy across configuration changes.
- **False-positive exclusions:** Time alone does not evict this ring. Under-confirmation is not proof of a reorg/double spend; the project accepted the bounded policy tradeoff.
- **Fix family:** Make resize semantics explicit and test them against the chosen risk policy; document any deliberate relaxation.

### SAT-20

**Universal validation over an empty vector proves nothing**

Canonical mappings: `NA-STATE-004`, `NA-INTEGRATION-003`.
Sources: #23.

- **Invariant:** Replacement transactions satisfy structural constraints before committing cancellation state.
- **Activation:** A replacement constructor omits the nonempty-output guard enforced by the original constructor.
- **Failure sequence:** Submit an empty output list; per-output checks pass vacuously.
- **Required evidence:** Compare original/replacement constructors and trace the actual authorized call and resulting state.
- **Recovery checks:** Check whether the already-signed original remains confirmable and verifiable before claiming a terminal lock.
- **False-positive exclusions:** Operator-only malformed input and a surviving original support operational hardening, not an established public fund-loss exploit.
- **Fix family:** Validate required cardinality at replacement construction and admission, before durable state changes.

### SAT-21

**Compensation must use the asset that funded the operation**

Canonical mappings: `NA-ECON-001`, `NA-ASYNC-002`, `NA-STATE-003`.
Sources: #26, #43.

- **Invariant:** Cleanup burns or refunds the same token generation used by the initiating receipt.
- **Activation:** A safe mint reads token A at dispatch, while cleanup rereads mutable configuration after rotation to B.
- **Failure sequence:** Return a full unused amount across cutover and inspect the actual burn target and balances on A and B.
- **Required evidence:** Establish rotation reachability, token balances, and receipt timing; separate wrong-asset bookkeeping from proven insolvency/profit.
- **Recovery checks:** Drain pending operations before rotation or retain token/epoch identity through cleanup and retries.
- **False-positive exclusions:** The project removed migration entrypoints and does not plan rotation; retain this as a conditional future-change check.
- **Fix family:** Persist immutable funding-token identity for every external effect and its compensation.

### SAT-22

**Repeated embedded payloads amplify storage and callback work**

Canonical mappings: `NA-RESOURCE-001`, `NA-RESOURCE-005`.
Sources: #35.

- **Invariant:** Persistent representation does not duplicate unused variable-length transaction data across every output without a justified budget.
- **Activation:** Each change or migrated UTXO embeds a full signed transaction that consumers do not require.
- **Failure sequence:** Finalize transactions with many outputs and large payloads, then measure storage, view response sizes, and callback work.
- **Required evidence:** Trace actual readers and repeated clone sites; use realistic maximum payloads and core-operation bounds.
- **Recovery checks:** Plan compatibility for already-stored records and existing off-chain consumers.
- **False-positive exclusions:** Unused bytes alone are an efficiency observation unless material cost, undercharge, or liveness is shown.
- **Fix family:** Store the required outpoint metadata or one shared transaction record; migrate or safely retire legacy payloads.

### SAT-23

**Storage pricing must include legacy variable-length records**

Canonical mappings: `NA-RESOURCE-001`.
Sources: #40.

- **Invariant:** The responsible caller covers actual marginal state cost, including cloned legacy fields.
- **Activation:** RBF descendants clone UTXOs while charging one yocto or a fixed estimate based on newer compact records.
- **Failure sequence:** Compare identical input counts using fresh deposit UTXOs and old change UTXOs carrying full transaction bytes.
- **Required evidence:** Measure byte delta, byte cost, deposit, shortfall, family cap, and attacker capital; distinguish all replacements from excess replacements.
- **Recovery checks:** Track payer and refunds across sibling cleanup; test old records after the write format is fixed.
- **False-positive exclusions:** A finite RBF limit bounds amplification; a new-write fix does not retroactively shrink historical records.
- **Fix family:** Charge bounded actual growth or a worst-case estimate that includes every supported stored version, with explicit legacy handling.

### SAT-24

**Expired cancellation can strand both liquidity and fee reservations**

Canonical mappings: `NA-ASYNC-005`, `NA-ACCOUNT-003`, `NA-STATE-004`.
Sources: #36.

- **Invariant:** Every reserved transaction family has a safe terminal settlement or rescue path.
- **Activation:** Cancellation prevents further replacements while every member can expire without confirming.
- **Failure sequence:** Create a reserved transaction, cancel it, let all competing Zcash candidates expire, then attempt fresh replacement/cancellation.
- **Required evidence:** Exercise assert-not-canceled separately from replacement-count bounds; inspect locked UTXOs as well as reserved fees.
- **Recovery checks:** Keep reservations until safe resolution; account for every signed/in-flight candidate and inclusion before expiry.
- **False-positive exclusions:** An ordinary unconfirmed original can often be rescued. Bitcoin age alone does not invalidate signatures, and late verification can prove timely inclusion.
- **Fix family:** Allow safe repeated cancellation with fresh expiry and reconcile the family maximum reservation exactly once on winning settlement.

### SAT-25

**Temporary deposit reservations cannot destroy refund rights**

Canonical mappings: `NA-STATE-001`, `NA-ASYNC-002`.
Sources: #39.

- **Invariant:** Recoverable mint failure preserves an existing refund entitlement, paid request cost, and elapsed waiting time.
- **Activation:** Permissionless rejection interprets an in-flight deposit marker as final settlement.
- **Failure sequence:** Create a refund, reserve deposit verification, reject during the mint window, then resolve mint to zero.
- **Required evidence:** Compare no-interference and interference runs; inspect deletion, request cost, original timestamp, and renewed timelock.
- **Recovery checks:** Retrying minting is an alternative outcome, not restoration of a previously purchased refund path.
- **False-positive exclusions:** Successful finalization and executed requests follow different rules; the demonstrated harm is cost/delay, not necessarily lost BTC.
- **Fix family:** Separate pending from settled deposits and retain refund state until settlement justifies its removal.

### SAT-26

**Validate refund destinations before irrevocable commitment**

Canonical mappings: `NA-STATE-004`, `NA-ACCOUNT-003`.
Sources: #44.

- **Invariant:** A committed refund destination is parseable and valid for the configured chain/network.
- **Activation:** Address derivation or request storage accepts a raw string and parsing first occurs at execution.
- **Failure sequence:** Commit a malformed destination, wait, execute, and repeat; contrast a caller-selected unbound destination.
- **Required evidence:** Show the parse point, any equality constraint, and the ability or inability to replace the request.
- **Recovery checks:** Check normal deposit finalization separately; authenticate any destination supersession.
- **False-positive exclusions:** A pre-mutation panic preserves state and may leave deposit finalization available; do not call all recovery permanently lost.
- **Fix family:** Parse/network-check at commitment and request time and define authorized repair for legacy invalid destinations.

### SAT-27

**Optimistic beneficiary selection is an explicit trust boundary**

Canonical mappings: `NA-STATE-004`, `NA-ECON-003`.
Sources: #45.

- **Invariant:** A refund beneficiary follows either verifiable owner authorization or an explicitly accepted optimistic review policy.
- **Activation:** A deposit omits a committed refund address and the first requester selects the destination.
- **Failure sequence:** Reconstruct an enumerable/default message or observe published calldata, capture the slot, and model the full review window.
- **Required evidence:** Identify exact message knowledge, permissions, veto, finalization guard, retry cost, active timelock, and attacker-controlled beneficiary.
- **Recovery checks:** Distinguish an unexecuted request that can be rejected from post-execution signing; rejection restarts a race rather than proving irreversible denial.
- **False-positive exclusions:** The team acknowledged this design and reported a 100-year timelock mitigation; do not claim a timelock bypass or independently verified deployed state.
- **Fix family:** Bind recipient authorization or committed destination; otherwise document and test the optimistic review assumption and actual disabling configuration.

### SAT-28

**Deleting a request does not revoke signing authority**

Canonical mappings: `NA-CRYPTO-002`, `NA-STATE-001`, `NA-INTEGRATION-003`.
Sources: #48.

- **Invariant:** Cancellation policy agrees with every pending signing request and externally usable authorization.
- **Activation:** Request deletion leaves a pending refund transaction signable by a separate entrypoint.
- **Failure sequence:** Execute, reject, then sign the stale candidate; also test an already-dispatched signing callback.
- **Required evidence:** Show actual signing authorization, immutable destination, replay protection, and whether a completed signature can still spend.
- **Recovery checks:** Never restore mint eligibility merely because local pending records were removed; external signatures may survive.
- **False-positive exclusions:** Signing a refund to the depositor does not alone prove theft or double spend. The project chose to prohibit rejection after execution.
- **Fix family:** Enforce a non-cancelable in-flight boundary, or implement generation-bound revocation before signature issuance and safe external disposition afterward.

### SAT-29

**Cleanup must not orphan an unsigned refund's replay marker**

Canonical mappings: `NA-STATE-001`, `NA-ACCOUNT-003`, `NA-INTEGRATION-003`.
Sources: #50.

- **Invariant:** A consumed marker always has a completed external disposition or a usable authorized recovery operation.
- **Activation:** Executed refunds can be rejected and all unsigned candidates removed while the marker remains.
- **Failure sequence:** Use a valid non-dust refund, execute/reject/clean it, and try mint, new request, re-execution, and signing.
- **Required evidence:** Prove every usable candidate was removed and no usable signed refund remains; compare rejection before execution.
- **Recovery checks:** Clearing a marker requires reconciling prior and in-flight signatures, not just observing no finalization.
- **False-positive exclusions:** Distinct from SAT-02's dust check and SAT-28's surviving signing path; shared cleanup code does not imply identical causality.
- **Fix family:** Prevent unsafe post-execution rejection or preserve recoverable refund state until the source UTXO disposition is established.

### SAT-QA-01

**Sponsored registration refund ownership**

Canonical mappings: `NA-RESOURCE-001`, `NA-INTEGRATION-002`.
Sources: #34/QA-01.

- **Invariant:** Released storage value follows the intended sponsor/subsidy policy.
- **Activation:** Minting auto-registers recipients using token-contract funds.
- **Failure sequence:** Register, mint, empty, unregister, then repeat a genuinely new sponsored registration.
- **Required evidence:** Identify sponsor, refund beneficiary, fees that fund the subsidy, and marginal cost.
- **Recovery checks:** Verify safe mint's user-registration path separately.
- **False-positive exclusions:** The team accepts standard-flow sponsorship as a fee-funded subsidy; finalized proof replay is not another sponsored registration.
- **Fix family:** Track sponsorship if refunds must return to the sponsor, or explicitly account for and bound the subsidy.

### SAT-QA-02

**Unassigned output-relaxation remainder**

Canonical mappings: `NA-ACCOUNT-002`, `NA-ACCOUNT-003`.
Sources: #34/QA-02.

- **Invariant:** User entitlement equals external payout, explicit fees, and recoverable remainder.
- **Activation:** Output validation tolerates a shortfall while burning only actual payout plus gas.
- **Failure sequence:** Choose the minimum tolerated payout and reconcile BTC custody, supply, bridge tokens, and fee/user ledgers.
- **Required evidence:** Calculate the unassigned remainder without confusing retained assets with insolvency.
- **Recovery checks:** Find a user credit/refund or a documented intentional fee classification.
- **False-positive exclusions:** The report establishes unassigned value, not extraction or insolvency.
- **Fix family:** Require exact output accounting or explicitly attribute and recover the delta.

### SAT-QA-03

**Host release tooling remains a separate trust surface**

Canonical mappings: `NA-OFFCHAIN-004`.
Sources: #34/QA-03.

- **Invariant:** Published artifacts derive from reviewed tools and intended publishing authority.
- **Activation:** Workflow actions or host installers use mutable references with release permissions.
- **Failure sequence:** Trace action tags, installer source, permissions, build inputs, and deployment hash comparison.
- **Required evidence:** Separate reproducible container inputs from mutable host-side execution.
- **Recovery checks:** Verify artifact comparison and recovery of compromised release authority.
- **False-positive exclusions:** CI was outside the stated production-contract scope; retain as conditional supply-chain hardening, not a demonstrated compromise.
- **Fix family:** Pin and verify tools, restrict publishing authority, and verify built/deployed hashes.

### SAT-QA-04

**Configuration combinations need documented semantics**

Canonical mappings: `NA-STATE-004`, `NA-ECON-002`.
Sources: #34/QA-04.

- **Invariant:** Accepted configuration combinations support the promised operations.
- **Activation:** Zero limits/delays or minimum amounts below fee floors pass validation.
- **Failure sequence:** Exercise zero, minimum, and cross-field combinations through the real update path.
- **Required evidence:** Identify intentional disable switches and the exact operation affected.
- **Recovery checks:** Verify updates revalidate and recovery remains possible.
- **False-positive exclusions:** DAO-controlled choices and intentional zero values are not untrusted-attacker bypasses.
- **Fix family:** Document allowed modes and validate cross-field requirements without rejecting deliberate disable values.

### SAT-QA-05

**Bounded response reads need compatibility and diagnostics**

Canonical mappings: `NA-OFFCHAIN-006`, `NA-OFFCHAIN-005`.
Sources: #34/QA-05.

- **Invariant:** Supported responses fit bounds and operational failures remain diagnosable.
- **Activation:** MPC callbacks return false without an event on failed/oversized responses.
- **Failure sequence:** Exercise actual supported response encodings immediately below, at, and above the cap.
- **Required evidence:** Measure the pinned ABI payload and distinguish return-value observability from emitted events.
- **Recovery checks:** Confirm retries remain possible and signature slots are not falsely populated.
- **False-positive exclusions:** Response bounds are defensive; missing events alone do not demonstrate attacker-triggered loss.
- **Fix family:** Document size assumptions, test compatibility, and emit useful failure diagnostics where appropriate.

### SAT-QA-06

**Expiry is about inclusion, not later verification**

Canonical mappings: `NA-OFFCHAIN-006`, `NA-INTEGRATION-003`.
Sources: #34/QA-06.

- **Invariant:** Expiry monitoring distinguishes unmined expired transactions from timely inclusion awaiting proof.
- **Activation:** Pending views expose serialized transactions without explicit expiry status.
- **Failure sequence:** Compare unmined expiry, inclusion before expiry with late verification, and zero-expiry refunds.
- **Required evidence:** Pin chain rules and actual configured window; do not generalize illustrative hours or block gaps.
- **Recovery checks:** Exercise replacement/cancel availability at the actual stage.
- **False-positive exclusions:** Contracts do not emit an event merely because time advances, and expired unmined status does not imply every recovery is closed.
- **Fix family:** Expose decoded expiry and monitor inclusion-aware status without rejecting timely included transactions.

### SAT-QA-07

**Refunds follow predecessor payer rather than persistent signer**

Canonical mappings: `NA-AUTH-001`, `NA-ASYNC-003`.
Sources: #34/QA-07.

- **Invariant:** Failure compensation returns value to the account that actually funded it.
- **Activation:** A forwarding relayer attaches its funds while retaining a different transaction signer.
- **Failure sequence:** Forward a zero-result safe mint and inspect the storage refund recipient.
- **Required evidence:** Prove a deployed authorized forwarding contract and unintended sponsorship, not merely a hypothetical identity difference.
- **Recovery checks:** Carry the storage payer through every callback and excess-refund branch.
- **False-positive exclusions:** The team reports only direct relayers, where signer equals payer; retain as a conditional test.
- **Fix family:** Snapshot and authorize the predecessor payer or explicit sponsor at the payable boundary.

### SAT-QA-08

**Sensitive setters need the intended key boundary**

Canonical mappings: `NA-AUTH-003`.
Sources: #34/QA-08.

- **Invariant:** Controller authority and any required deposit-capable-key confirmation are both enforced.
- **Activation:** A legacy payout setter is controller-gated but accepts zero deposit.
- **Failure sequence:** Model a restricted function-call key permitted to call the setter and inspect later payout routing.
- **Required evidence:** Establish active legacy usage and actual receiver/method key permissions.
- **Recovery checks:** Check safe restoration of the payout destination.
- **False-positive exclusions:** Missing one yocto alone is hardening unless the key exposure and required confirmation boundary are established.
- **Fix family:** Use payable plus exact one-yocto validation when required, retaining controller authorization.

### SAT-QA-09

**Deployment initialization needs atomic authority binding**

Canonical mappings: `NA-AUTH-005`.
Sources: #34/QA-09.

- **Invariant:** The first initialization assigns only intended authority.
- **Activation:** Public initializers are deployed in a transaction separate from initialization.
- **Failure sequence:** Race a first caller against deployment; compare an atomic deploy-and-init batch.
- **Required evidence:** Inspect actual deployment transactions and preexisting funds/state assumptions.
- **Recovery checks:** Determine whether redeployment is a complete recovery before asserting loss.
- **False-positive exclusions:** Already initialized deployments and atomic batches are negative controls; one-time guards do not authenticate the first caller.
- **Fix family:** Initialize atomically or authenticate a precommitted deployer/factory.

### SAT-QA-10

**Documentation must reflect receipt-level recovery**

Canonical mappings: `NA-OFFCHAIN-007`.
Sources: #34/QA-10.

- **Invariant:** Operational instructions describe actual entrypoints, roles, token placement, and failure recovery.
- **Activation:** Docs retain stale method names, permission claims, or whole-transaction rollback language.
- **Failure sequence:** Compare docs with exported methods and standard/safe mint callback behavior.
- **Required evidence:** Distinguish real lost-and-found credit from clearing a marker for retry.
- **Recovery checks:** Document the actual user/relayer recovery step for each outcome.
- **False-positive exclusions:** Documentation drift alone is not an independent runtime exploit.
- **Fix family:** Correct names, permissions, transfer-call requirements, and non-atomic receipt semantics.
