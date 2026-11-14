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

                NEAR YoctoArmor v1  - SLOT ZERO SECURITY

```

# 🔐 NEAR YoctoArmor v1 Security Review — fundraiser

## Scope at a glance

`/fundraiser` · revision `unborn-HEAD` · src/lib.rs · 3 planned discovery passes, 3 completed

**Review stage:** Draft — pending human review.

Threat model: `THREAT_MODEL.md` · `sha256:e5714c32462cd433d450aa4b2d97b6bf707bd85df2ae6149aa5775164ef5a6a5`. Explicit trust assumptions constrain reportable findings.

**Review limitations:** Final rescan validation was blocked or unresolved; the stopping criterion was not established. Testing recorded in invariant-ledger.jsonl was blocked; the stopping criterion was not established. Testing recorded in nep-differential.jsonl was blocked; the stopping criterion was not established. Testing recorded in official-guidance-coverage.jsonl was blocked; the stopping criterion was not established. Asynchronous schedule testing was blocked; the stopping criterion was not established.

## Top findings — top 3 of 4

| ID | Severity | Finding in one sentence | Seen in discovery passes |
|---|---|---|---|
| `P01-entrypoints-auth-001` | High | any unprivileged NEAR account, including one with no donor record or beneficiary role can exploit this path because the exported set_near_fee_recipient accepts an arbitrary AccountId and overwrites near_fee_recipient without checking predecessor against the beneficiary or another authorized fee-policy owner, harming users through accrued campaign fees that initially belonged to the beneficiary are transferred to an unrelated attacker. The in-repository receipt test confirms a 0.1 NEAR transfer action to the attacker. | 3/3 |
| `P03-token-accounting-002` | High | no malicious actor is needed; any registered donor who contributes to a successful campaign reaches the affected state can exploit this path because successful beneficiary payout marks the asset withdrawn but never clears donor contribution amounts, while withdraw_storage requires both contribution fields to be zero, harming users through every contributing donor in a successful campaign permanently loses access to its recorded storage deposit through the contract API. | 3/3 |
| `P03-state-storage-001` | Medium | unprivileged caller controlling distinct donor accounts; no beneficiary or token control is needed can exploit this path because a successful storage withdrawal returns the donor's entire recorded deposit and clears only the temporary LookupSet marker; the donor's LookupMap entry remains permanently allocated with a zero storage_deposit. Registration also has no deadline gate, allowing fresh donor records after an already settled campaign, harming users through sybil donors can consume the contract's finite storage backing at essentially refundable principal cost. Once retained byte obligations exceed the free balance buffer, a later honest donor's storage withdrawal cannot be paid in full without new outside funding; the contract provides no cleanup method for the exited records. | 3/3 |


## Architecture and trust assumptions

The reviewed source is a single-campaign `near-sdk` contract. `new` fixes the beneficiary, configured YOLO token, independent NEAR and YOLO goals, and deadline (`src/lib.rs:133-175`). Donors register with an attached NEAR deposit, then contribute native NEAR or the configured token through `ft_on_transfer` (`src/lib.rs:180-337`). The beneficiary can claim an asset whose goal succeeds; donors claim their own asset when its goal fails. Native and token transfers reserve accounting before a promise and settle in a private callback (`src/lib.rs:339-580,628-756`). `THREAT_MODEL.md:9-23,33-43` identifies contributions, fees, storage deposits, and pending state as protected interests.

The creator is the initial beneficiary and fee recipient; no separate admin, guardian, upgrade policy, or production deployment is established (`THREAT_MODEL.md:17-25,45-47`). An unprivileged caller can call public methods, register multiple donors, choose an API recipient, and stop acting after donating (`THREAT_MODEL.md:27-31`). The NEAR runtime enforces predecessor identity and private callback origin. The configured token and deployed runtime version are external dependencies. Target README prose and source comments were treated as context, never as proof or authority.

## Findings index

| ID | Severity | Proof status | Confidence | Seen in discovery passes | Review disposition | Title |
|---|---|---|---:|---|---|---|
| [H-01](#h-01-any-caller-can-divert-accrued-near-fees) | High | VERIFIED_STRUCTURAL | 12/13 | 3/3 | Pending human review | Any caller can divert accrued NEAR fees |
| [H-02](#h-02-successful-payout-locks-donor-storage-deposits) | High | VERIFIED_STRUCTURAL | 11/13 | 3/3 | Pending human review | Successful payout locks donor storage deposits |
| [M-01](#m-01-one-unclaimed-refund-blocks-other-donors-storage) | Medium | VERIFIED_EXECUTED | 11/13 | 2/3 | Pending human review | One unclaimed refund blocks other donors’ storage |
| [M-02](#m-02-full-storage-refund-retains-a-funded-record) | Medium, conditional | VERIFIED_STRUCTURAL | 11/13 | 3/3 | Pending human review | Full storage refund retains a funded record |

## Findings

### H-01 Any caller can divert accrued NEAR fees

| Field | Value |
|---|---|
| Candidate | `P01-entrypoints-auth-001` |
| Severity / proof | High / VERIFIED_STRUCTURAL |
| Confidence | 12/13 (High) |
| Impact / likelihood | Moderate / Likely |
| Affected code | `Contract.set_near_fee_recipient`, `Contract.withdraw_near_fees` (`src/lib.rs:369-394`) |
| Affected users | Beneficiary or other authorized fee owner; the accrued NEAR fee pool |
| Seen in discovery passes | 3/3; sightings do not add confidence |
| Human disposition | Pending; no human reviewer or approval recorded |

#### Root cause

An ordinary caller can replace `near_fee_recipient` without an authority check and divert the campaign’s accrued NEAR fee. The setter writes `self.near_fee_recipient = recipient_id` at `src/lib.rs:369-371`; fee withdrawal later reads that field at `:388-394`. The initializer sets the beneficiary as the original recipient (`:154-167`).

#### Attack preconditions

The campaign has a positive NEAR fee and meets its NEAR goal. The attacker controls an existing recipient account and calls the public setter before fee withdrawal. No beneficiary signature, deposit, or special role is required. A failed transfer restores the fee but leaves the changed recipient for retry (`src/lib.rs:543-553`).

#### Receipt-level attack path

1. The beneficiary initializes; a registered donor contributes 10 NEAR, accruing a 0.1 NEAR fee (`src/lib.rs:265-292`).
2. The attacker, as transaction predecessor, calls `set_near_fee_recipient(attacker)`. No promise is needed and the field changes immediately.
3. After the deadline and successful goal, any caller invokes `withdraw_near_fees`; the fundraiser reserves the fee, creates a native transfer to the attacker, and chains a self-callback (`src/lib.rs:374-394,735-756`).
4. On successful transfer, the callback leaves the fee debit final. On failure it restores the fee amount, but no authorization or recipient reset occurs.

#### Impact

A single successful call can redirect the entire accrued fee pool. The isolated 10 NEAR case scheduled a 0.1 NEAR attacker-directed transfer; a 12 NEAR variant scheduled 0.12 NEAR. These are bounded direct losses, not arbitrary access to donor principal. The external balance delta was not measured in a local chain.

#### Evidence and PoC

The frozen `src/lib.rs` SHA-256 is `9e6fefaab80b799d7b53b07af2b1e2ba14badb840af479834004396c24bcc828`. In an isolated source copy, `cargo test --locked --offline outsider_ -- --nocapture` passed exact and amount/timing variants. A negative-control copy added a beneficiary guard: the outsider test then failed at that guard while the beneficiary payout test still passed. A separate skeptical review upheld High with its own 0.12 NEAR receipt and guard control; its record is `scratch/skeptic/P01-entrypoints-auth-001.json`. The native receipt and callback were unit simulated, not executed in a local NEAR sandbox.

#### Recommendation

Require the intended fee authority (at minimum, the immutable beneficiary) as the predecessor for fee-recipient changes; validate the recipient and document any authorized delegation. Preserve the guarded setter in the exported ABI, then rerun outsider and beneficiary controls. Do not infer a separate fee-policy owner from this repository.

#### Remediation status and fix verification

**OPEN.** No target-code change or remediation commit was requested or tested. The guard experiment was in an isolated copy only.

### H-02 Successful payout locks donor storage deposits

| Field | Value |
|---|---|
| Candidate | `P03-token-accounting-002` |
| Severity / proof | High / VERIFIED_STRUCTURAL |
| Confidence | 11/13 (High) |
| Impact / likelihood | Moderate / Likely |
| Affected code | `Contract.withdraw_near`, `Contract.withdraw_yolo`, `Contract.withdraw_storage` (`src/lib.rs:339-459`) |
| Affected users | Contributors to a successful asset goal; their recorded NEAR storage deposits |
| Seen in discovery passes | 3/3; sightings do not add confidence |
| Human disposition | Pending; no human reviewer or approval recorded |

#### Root cause

An honest donor whose campaign goal succeeds cannot reclaim its storage deposit because successful payout clears aggregate availability but leaves that donor’s `near_amount` or `yolo_amount` positive. `withdraw_storage` requires both fields to be zero (`src/lib.rs:449-455`), while their clearing refunds are allowed only when the relevant goal failed (`:641-669`).

#### Attack preconditions

A donor registers, contributes to an asset whose goal is met, and waits for beneficiary payout plus any NEAR fee payout to complete. No hostile actor is needed; the loss arises during honest settlement. The recorded deposit remains in `get_contribution`, but no reviewed public path clears the successful donor amount.

#### Receipt-level attack path

1. Donor registers and contributes 10 NEAR to a 10 NEAR goal, or 20 YOLO to a 20 YOLO goal.
2. After the deadline, a caller starts the beneficiary payout. The originating call sets the asset’s available balance to zero and marks it withdrawn; the transfer and private callback run (`src/lib.rs:353-365,408-420,514-541`).
3. Successful callback decrements pending count and leaves per-donor amount unchanged. `all_assets_settled` can become true (`src/lib.rs:759-773`).
4. Donor calls `withdraw_storage`; the zero-contribution guard panics before any storage transfer. Its refund call also panics because the goal was met.

#### Impact

The donor’s recorded NEAR storage deposit remains unreachable through the reviewed contract API after a successful campaign. The isolated exact and relaxed tests used a 1 NEAR deposit; the defect applies to the positive deposit each successful contributor supplied. “Permanent” here means absent a source-defined recovery path; no production upgrade authority is evidenced.

#### Evidence and PoC

`cargo test --offline --locked p03_storage_verifier -- --nocapture` passed 3/3 in an isolated copy: successful NEAR, successful YOLO, and a missed-goal negative control. The first two rejected both storage withdrawal and successful-goal refund; the control cleared the donor amount and queued a storage transfer. An independent skeptic repeated both successful-asset paths and the missed-goal control (`scratch/skeptic/P03-token-accounting-002.json`). Transfer callbacks were simulated using `near-sdk` test context; configured-token and full chain receipts were not executed.

#### Recommendation

Make storage release depend on the donor’s asset-specific entitlement being settled. A contribution is settled either after its successful asset payout and callback, or after that donor’s failed-goal refund and callback. Keep pending-refund protection. Refactor the guard so successful donors can withdraw after global payout without clearing historical contribution information prematurely, and test both assets plus failure rollback.

#### Remediation status and fix verification

**OPEN.** No target-code change was made; isolated tests only characterized the behavior.

### M-01 One unclaimed refund blocks other donors’ storage

| Field | Value |
|---|---|
| Candidate | `P03-token-accounting-003` |
| Severity / proof | Medium / VERIFIED_EXECUTED |
| Confidence | 11/13 (High) |
| Impact / likelihood | Moderate / Possible |
| Affected code | `Contract.withdraw_storage`, `Contract.all_assets_settled` (`src/lib.rs:434-459,759-773`) |
| Affected users | Other donors who have already reclaimed their failed-goal contributions |
| Seen in discovery passes | 2/3; sightings do not add confidence |
| Human disposition | Pending; no human reviewer or approval recorded |

#### Root cause

One donor can leave a tiny failed-goal refund unclaimed, keeping global `near_available` nonzero and blocking every other donor’s `withdraw_storage` before their own record is checked. The storage gate at `src/lib.rs:439` calls `all_assets_settled`, which requires global zero availability on a missed goal (`:765-773`). Only the contributing account can initiate its refund (`:628-645`).

#### Attack preconditions

The NEAR goal misses. The attacker registers (the minimum deposit is 0.01 NEAR), contributes at least 1 yoctoNEAR before the deadline, and declines to claim the refund. An honest donor separately refunds its contribution. The attacker’s deposit is refundable if it later cooperates; gas and a dust contribution are the demonstrated costs.

#### Receipt-level attack path

1. Honest donor and attacker register; the honest donor contributes 1 NEAR and the attacker contributes 1 yoctoNEAR toward a 10 NEAR goal.
2. After the missed deadline, the honest donor invokes `refund_near`; the contract reserves its amount, schedules a native transfer, and the successful callback leaves its donor amount at zero (`src/lib.rs:628-685,487-512`).
3. The attacker does nothing. `near_available` remains 1 yoctoNEAR, so global settlement is false even though the honest donor has no pending refund.
4. Honest donor invokes `withdraw_storage`; it panics at the global gate and creates no storage transfer. Only the attacker can release the block by refunding its own dust.

#### Impact

A single idle donor can hold every other fully refunded donor’s storage deposit without an in-contract timeout. The isolated test blocked a 1 NEAR deposit with 1 yoctoNEAR left unclaimed. The victim can recover only after the attacker completes its refund or external intervention absent from the reviewed API.

#### Evidence and PoC

In an isolated copy, `CARGO_NET_OFFLINE=true cargo test --locked --offline p03_ -- --nocapture` passed 3/3: exact dust claim, 100 yoctoNEAR relaxed variant, and negative control where the attacker refunds and the honest donor’s storage transfer is queued. The blocking guard runs before the storage promise, so the test directly observes the rejection; native refund callbacks were simulated, not run in a full sandbox.

#### Recommendation

Gate a donor’s storage withdrawal on that donor’s own settled contribution and pending-refund state, plus any campaign-level payout obligations that actually secure its storage. Do not require other donors to claim voluntary failed-goal refunds. Reserve sufficient storage backing independently so removing the global gate does not create M-02’s liability.

#### Remediation status and fix verification

**OPEN.** No remediation in the target was requested or verified.

### M-02 Full storage refund retains a funded record

| Field | Value |
|---|---|
| Candidate | `P03-state-storage-001` |
| Severity / proof | Medium, conditional / VERIFIED_STRUCTURAL |
| Confidence | 11/13 (High) |
| Impact / likelihood | Moderate / Possible, conditional on low net free balance |
| Affected code | `Contract.register_donor`, `Contract.withdraw_storage`, `Contract.on_transfer_complete` (`src/lib.rs:180-213,434-485`) |
| Affected users | Later donor storage claimants; contract storage backing |
| Seen in discovery passes | 3/3; sightings do not add confidence |
| Human disposition | Pending; no human reviewer or approval recorded |

#### Root cause

A donor can receive its entire recorded storage deposit while its `LookupMap` record stays persisted. The storage callback removes only the pending marker (`src/lib.rs:474-485`); no donor-record removal exists. A later withdrawal can cross the NEAR state-stake floor if the contract’s free-balance buffer is small enough.

#### Attack preconditions

The contract has settled and holds another donor’s refundable deposit. An unprivileged account registers with a deposit, then calls `withdraw_storage` after the deadline. The attacker’s original deposit returns; its zero-deposit record stays. Actual failure depends on deployed free balance, runtime storage byte cost, gas rewards, account costs, and ordering. No deployed account state was supplied.

#### Receipt-level attack path

1. Honest donor and attacker register. Isolated 64-character AccountId probes measured 182 bytes per donor entry and 127 bytes for the temporary withdrawal marker at 1e19 yoctoNEAR per byte.
2. After settlement, attacker starts storage withdrawal. The call zeros its deposit credit, adds a pending marker, and schedules its full deposit transfer (`src/lib.rs:434-459`). Successful callback removes the marker but retains its 182-byte donor entry.
3. Honest donor later starts its storage withdrawal. In a low-buffer balance range, the full transfer would leave less than the stake required by retained records and pending marker. NEAR’s documented `LackBalanceForState` check would fail the *originating* action receipt, rolling back its state and generated promise. It is not a failed child transfer repaired by the callback.

#### Impact

The honest donor’s claim can be temporarily blocked until extra NEAR funds the account or storage is released. An independent counterfactual found a net free buffer of 0.004 NEAR where the honest withdrawal would pass alone but fails after one attacker withdrawal; this is a conditional structural calculation, not an observed deployed failure. Do not infer permanent loss or a specific production attacker cost.

#### Evidence and PoC

Isolated `cargo +1.93.0 test --offline --locked p03_isolated_probe -- --nocapture` passed 2/2: both long and short AccountId variants retained donor bytes after a full scheduled deposit return. The verifier and independent skeptic calculated the state-stake inequality (`scratch/skeptic/P03-state-storage-001.json`). No nearcore sandbox `LackBalanceForState` receipt or deployed balance snapshot was available. This is the main validation blocker for the conditional finding.

#### Recommendation

Release a donor record when its full deposit has been returned, or retain a measured storage-cost reserve and refund only genuine surplus. If deleting after a successful callback, block registration/top-ups while a storage withdrawal is pending and handle failed transfers by restoring the claim. Recheck serialized storage deltas, callback ordering, and minimum balance against the target runtime.

#### Remediation status and fix verification

**OPEN.** No source patch or deployed remediation was tested.

## Unverified leads

- `P01-NEAR-FEE-SPLIT` — `donate_near` floors the 100 bps fee per receipt (`src/lib.rs:265-292`). Exact, relaxed, and negative-control unit tests establish a partition difference. With the initial beneficiary also the fee recipient, combined payout is unchanged; any separate fee owner and gas-adjusted material harm remain unproved. The maximum difference across *n* receipts is *n−1* yoctoNEAR.
- `nep-token-assets-001` — `register_yolo_receiver` forwards the beneficiary’s entire attached NEAR to token `storage_deposit`, while its callback records only a Boolean (`src/lib.rs:216-246,583-593`). A conforming NEP-145 token may return registration excess to its caller, the fundraiser, and failed child deposits may do likewise. Isolated tests show no beneficiary claim path; configured-token receipts and terminal balance deltas are missing.
- `P03-trust-gap-002` — `new` binds the first caller as beneficiary (`src/lib.rs:133-167`). A takeover requires a reachable uninitialized deployment interval and intended initializer identity; deployment action order and key policy are absent.
- `async-state-explorer-003` — `promise_result_checked(0, 32)` classifies transfer success (`src/lib.rs:462-472`). A successful configured token transfer with an oversized result might be classified as failure and restore accounting. The token implementation, result bytes, runtime behavior, and second-payment trace are absent.

## Standards and hardening notes

### NEP deviations

The registry-backed 51-row matrix is retained in `nep-coverage.jsonl`: three conformant, 41 not applicable, four advisory, one process-only, one superseded, and one security-candidate row. NEP-141 receiver behavior accepted the configured token and returned the unused amount on rejection in isolated tests. The NEP-145 payer/excess mechanism is the unverified lead above, so it is not counted as a verified standards deviation or vulnerability. Final NEP-330 metadata is present, but both reviewed Wasm artifacts embed null link/build information; no mandatory non-null requirement or dependent security control was established. New/Draft proposals were advisory only.

### Guidance and quality observations

The 21 selected official guidance cards have explicit coverage in `official-guidance-coverage.jsonl`. The contract has no source-defined independent fee authority, deployment key inventory, pause route, or incident recovery role. Those gaps limit recovery and deployment claims; their absence alone was not scored as a vulnerability. The existing metadata source-identity gap makes artifact provenance harder to check. No monitoring consumer or off-chain service was supplied, so missing logs/tests were not promoted into findings.

## Testing and limitations

The frozen target has no Git HEAD. Its seven non-`target/` source/context files were fingerprinted before review and were not edited. `cargo test --offline --locked` in an isolated baseline copy passed all 14 existing tests. Focused copied-source unit tests reproduced the verified fee and storage paths, amount/timing variants, and negative controls; their commands and observations appear above and in retained `scratch/` evidence. The NEP differential receiver tests passed target-only, but the full configured-token oracle comparison was blocked. The async explorer generated receipt schedules and passed mock unit probes; a full `near-workspaces` receipt test was blocked by the unavailable local sandbox binary and dependency unpack restriction. No production token, deployment account balance, access-key history, node version, or deployed Wasm hash was supplied. Native and token callback outcomes were simulated in `near-sdk` where noted.

Active-test ledgers retain 14 invariants, seven async schedule rows, NEP differential observations, and 103 isolated mutation sites across 17 families. Mutation outcomes were not manually adjudicated, so surviving mutants are test blind spots rather than vulnerabilities. Seven worker-owned artifact files were normalized after worker submission to satisfy the controller schema; their current hashes differ from the submitted journal hashes. The exact files, old/new digests, and normalization reasons are retained in `artifact-normalization-ledger.jsonl`. The original worker bytes were not retained, so this is a provenance limitation despite the successful final artifact gates. Three independent L2/L3 discovery passes, 51 NEP coverage rows, 100 raw candidates, eight deduplicated groups, eight triage/verdict rows, and one bounded counterexample rescan passed the controller checks. The rescan produced zero new candidates and left five external-evidence questions blocked; it did not establish that every possible Medium+ path was eliminated. All four findings and four leads await human review. The audit is a **draft**, not an approved safety claim.

## Remediation priorities

1. Guard fee-recipient changes and retest attacker-directed fee payout (`H-01`).
2. Make successful donor storage claims releasable after the relevant payout callback (`H-02`).
3. Decouple a donor’s storage withdrawal from other donors’ unclaimed refunds (`M-01`), while preserving storage solvency.
4. Remove fully refunded donor records or retain enough storage backing (`M-02`), then confirm the exact runtime balance behavior.
5. Resolve the configured-token deposit and deployment-order leads with production artifacts before any deployment decision.

## Pending review

A human reviewer must decide whether to approve, downgrade, or reject `H-01`, `H-02`, `M-01`, and conditional `M-02`, and disposition the four leads. The reviewer should inspect the external-evidence blockers in `unresolved-assumptions.jsonl`, especially the absent configured token and deployed storage balance. No reviewer identity, timestamp, or approval has been invented; the verified-seed informed pass remains deferred until real human feedback arrives.
