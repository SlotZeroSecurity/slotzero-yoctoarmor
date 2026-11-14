# NEAR Security Model

## Contents

- Runtime model
- Executable invariant classes
- Standards behavior-to-concern method
- Identity and access keys
- Receipts, promises, and callbacks
- Storage and persistent state
- Tokens and standards
- Upgrades and migration
- Gas, liveness, and yield/resume
- Feature-triggered surfaces

## Runtime model

Audit NEAR at receipt boundaries. A transaction produces receipts; a cross-contract call and its callback execute independently. Earlier receipt state is not rolled back when a later receipt fails. Other operations can interleave before a callback.

Model value-bearing operations as a state machine:

`Idle -> Pending(reserved) -> Succeeded | Failed(compensated)`

The invariant is not simply “write before calling” or “write in the callback.” Reserve or deduct reusable entitlement before dispatch, expose final credit only after verified success, and make failure compensation complete and idempotent.

For each externally callable method record:

- `signer_account_id`, `predecessor_account_id`, and `current_account_id`
- attached deposit and storage delta
- assets or privileges read, reserved, debited, or credited
- every emitted promise and callback
- state visible between receipts
- success, malformed-return, failure, panic, and low-gas behavior

Treat decoding as part of the trust boundary. Security-sensitive bytes, messages, account IDs, chain IDs, and asset IDs must have one canonical meaning. Require complete input consumption, typed identifiers, explicit normalization, and identical serialization from signature/validation through execution.

Apply development best practices through security impact, not syntax preference. Validate untrusted context before durable effects and expensive attacker-controlled work, but `require!` versus an equivalent assertion is not itself a vulnerability. Compact AccountId encoding can reduce storage, but ordinary typed `AccountId` storage is valid; if a custom encoding is used, prove canonical injective round trips for every valid maximum-length ID. Likewise, `log!`, `near-sdk` crate re-exports, panic API choice, and a particular integration-test framework are not automatic findings. Escalate only when the target choice changes authorization, serialization, arithmetic, receipt settlement, material resource use, or another security invariant.

Use `runtime/standards/official-docs/docs-registry.json` only as pinned, version-gated guidance. Route
the cards selected by deterministic surface evidence to their existing owner
roles; do not load the entire guide into every agent. A page recommendation is
not normative and cannot establish a finding without target evidence, a
reachable exploit, and material harm. Keep harmless deviations as advisories or
quality observations, and keep NEP conformance governed separately by the NEP
registry.

Treat transaction ordering, account multiplicity, and randomness as adversarial. One account does not imply one person. Inventory every vote, reward, airdrop, quota, referral, review, reputation, admission, or rate limit that intends to represent participants rather than accounts; calculate the minimum profitable Sybil set and its funding/timing path. Token weighting, deposits/fees, age/reputation, membership, rate limits, and anomaly detection change attacker cost or trust but do not by themselves prove uniqueness. Test snapshots, eligibility windows, farming, delegation, and tie-breaking; document residual attacks and defense tradeoffs. Validators can observe pending arguments and expected state changes, control transaction order in their blocks, and the producer for a block can predict that block's deterministic/verifiable random seed. Test copied, reordered, delayed, replayed, aborted, split, and selectively included actions. For randomness, separately test producer-chosen input after seed prediction and an earlier bet whose later resolution is included only on favorable producer opportunities. A safe commit-reveal binds a secret/payload to claimant, domain, and round across distinct windows, consumes it once, and defines deadline, cancellation, and non-reveal behavior. Randomized multi-stage flows also need bounded permissionless/forced resolution and explicit timeout/default behavior. Consider fixed clearing or batch allocation when arrival order should not decide value; delay or higher gas alone does not defeat producer ordering.

## Executable invariant classes

Use stable IDs shared by `intent-model.json`, candidates, tests, and the final
report. Instantiate only applicable classes and replace symbolic terms with the
target's actual state:

- `INV-CONSERVATION-*`: contract custody plus external transfers and recoverable
  claims equals user liabilities, protocol reserves, and earned fees.
- `INV-PENDING-*`: available, locked, and pending representations neither double
  count nor omit the same entitlement at any receipt boundary.
- `INV-SETTLE-ONCE-*`: one operation/event/nonce authorizes at most one terminal
  payout, mint, unlock, refund, or state transition.
- `INV-COMPENSATE-*`: failure restores exactly the state reserved by that
  operation and cannot consume another operation's state.
- `INV-SUPPLY-*`: total supply equals the sum of live balances plus explicitly
  modeled burned, escrowed, or pending amounts.
- `INV-STORAGE-*`: every positive byte delta has a responsible payer and every
  released liability follows the documented one-time refund policy.
- `INV-AUTH-*`: every privileged transition is authorized by the intended direct
  caller/key and preserves a recoverable authority lifecycle.
- `INV-CALLBACK-*`: each callback is authenticated, operation-bound, semantically
  result-checked, idempotent, and terminal under success and failure.
- `INV-MIGRATION-*`: decoding old state and applying migration preserves every
  live balance, role, pending operation, prefix, and version invariant.

Map all writers/readers and execute high-value classes using unit, property,
stateful, differential, or bounded receipt-schedule tests. An unexecuted invariant
is a coverage blocker, not evidence that it holds.

## Standards behavior-to-concern method

For every claimed NEP method, turn each normative behavior into an adversarial row before searching for syntax:

- **Principals:** distinguish immediate caller, original signer, owner, approved operator, beneficiary, storage payer, refund recipient, token contract, receiver, and cached off-chain consumer. A method can be correct for one identity and unsafe for another.
- **Branch contract:** enumerate omitted, `null`, `false`, `true`, zero, minimum, maximum, already-existing, and not-existing cases. Record whether the standard requires success, panic, `false`, `null`, a refund, or a no-op, and assert no unintended state survives a rejecting branch.
- **Receipt timing:** record which state commits before every cross-contract notification and whether downstream failure is supposed to compensate, preserve the committed state, or only change the visible promise outcome. Never infer rollback from a failed later receipt.
- **Liability and cleanup:** pair every state byte, approval, balance, and refundable deposit with its payer, owner, release condition, and bounded deletion path. Admission must preserve the future ability to revoke, unregister, refund, and settle within gas limits.
- **Authoritative observation:** distinguish value from existence, live on-chain authority from marketplace/indexer caches, and state from events or promise status. A zero balance, failed notification, or stale event consumer may not mean the underlying registration, approval, or transfer failed.
- **Representation:** pin the exact NEP version, argument optionality, JSON encoding, return polarity, event version, and numeric bounds. Apply general JSON-safe-integer rules only after checking for a standard-defined bounded numeric exception.

A standards deviation is a FINDING only when the target exposes a reachable authorization, asset, state, storage-solvency, or critical-integration failure. Otherwise retain it as an unscored standards-conformance deviation.

For NEP status, applicability, activation, dependencies, supersession, ownership, and checklist routing, use `runtime/standards/neps/nep-registry.json`. Its automated signals only prioritize reads. Prove applicability or N/A from target interface, dependency, runtime/version, or node-subsystem evidence; never let a NEP number split or merge causal findings by itself.

## Identity and access keys

- Inventory every exported method and record why it is public, its intended caller/beneficiary, chosen `predecessor_account_id` or `signer_account_id` rule, deposit/one-yocto boundary, and administrative policy. Internal-only methods and callbacks require `#[private]` or an equivalent exact caller check.
- Treat `#[near]`/`#[near_bindgen]` as export generators. Reconcile annotated inherent and trait impl blocks with the generated/built ABI; an internal trait helper inside an annotated impl can bypass a guarded public wrapper.
- Authorize the immediate caller with `predecessor_account_id` unless the protocol intentionally authenticates the transaction origin. `signer_account_id` survives intermediary calls and is unsafe as a generic caller or beneficiary.
- In a self-callback, predecessor is the contract, not the original user. Persist and bind the original principal to the pending operation.
- Protect callbacks, resolvers, migration, and internal endpoints with `#[private]` or an equivalent exact predecessor check.
- Use `#[payable]` plus exactly one yoctoNEAR when a sensitive direct user method must exclude ordinary function-call keys and require a deposit-capable confirmation path. This is a key-capability boundary, not RBAC: retain the predecessor/owner/role check, and do not treat it as proof of human intent through arbitrary intermediary calls. A contract or relayer attaching one yoctoNEAR to a child receipt proves only that the intermediary could fund that receipt, not that the original signer approved the child action.
- Full-access keys can transfer NEAR, change keys, and deploy code. An owner or governance rotation is incomplete while stale keys retain those powers.
- Function-call key receiver, method allowlist, and allowance are part of the attack surface. An empty/omitted method list may allow every method on the receiver; inventory the actual key configuration rather than inferring it from source alone.
- Model full-access, function-call, gas, relayer, contract, and MPC keys as
  different capabilities. For gas keys, reconcile prepaid balances, permitted
  receivers/methods, lane count, lane-specific nonces, nonce-version encoding,
  withdrawal-before-deletion, allowance exhaustion, stale-key revocation, and
  the recovery path when no full-access key remains. A successful one-yocto
  check proves deposit capability only; it does not replace ownership, role,
  signature, route, or operation authorization.
- Initialization is a privileged transition: prove deploy/init ordering, `#[init]` and state-existence behavior, first-caller authority, `ignore_state` reachability, and validation of every initial role, account, asset, and bound. For factories and bridge subcontracts, deployment and initialization must be one atomic action batch or the uninitialized account/address needs an equivalent non-raceable authority design.
- For critical ownership/role handoffs, decide whether direct assignment is intentional. Where mistaken assignment would irrecoverably strand authority, require a recoverable proposal/acceptance/cancellation lifecycle; do not treat two-step transfer as universal RBAC.
- Bound account IDs, amounts, strings, collection sizes, and batch cardinality according to their semantic and resource risks. Treat every caller-controlled list as containing duplicates until proven otherwise. Declare set versus multiset semantics and compare per-identifier charge/entitlement consumption with benefit occurrences. For set semantics, reject or canonicalize duplicates before any payment, promise, or state mutation; for intentional multiplicity, reserve/deduct per occurrence before granting its benefit. Prefer one identifier per call when batching adds no required atomicity.

## Receipts, promises, and callbacks

Check these invariants:

- Each operation ID moves monotonically to one terminal state.
- A callback is authenticated, idempotent, and bound to caller, token, amount, resource, and expected branch.
- One nonce, event, entitlement, or authorization causes at most one release, payout, mint, refund, or unlock.
- A proof, event, authorization, or request is consumed only at a boundary where every required downstream effect has either succeeded or remains recoverable through the same operation.
- Available assets plus reserved assets cover liabilities at every receipt boundary.
- Failure restores only what was reserved by that operation and cannot consume another operation's funds.
- A lock, lease, unlock epoch, or deadline is bound to one operation. An unrelated ping, retry, user action, or callback cannot release it or refresh the deadline governing another pending operation.
- Callbacks reload live state and apply an operation-bound delta. Never write a cached whole struct, share count, rate, balance, or validator record over intervening receipt mutations.
- Callback failure or out-of-gas cannot permanently poison a lock without a recovery path.
- A callback validates the exact expected `env::promise_results_count()`, every required `PromiseResult`, and decoded business result before final credit, release, or authority change. Reservation needed to prevent interleaving still occurs before dispatch.
- Treat `#[callback_result]`, `#[callback_unwrap]`, and `env::promise_result` as result-data plumbing, never caller authentication. A hostile contract can arrange a successful or failed predecessor promise and schedule an exposed method as its callback. Self-callbacks therefore require `#[private]` or the exact self-predecessor check even when an ordinary direct call would have zero results and panic.
- Promise success is interpreted using callee semantics. `PromiseResult::Successful(bytes)` can still encode unused tokens, malformed data, or a business-level rejection.
- Public success/return state must represent the terminal operation rather than only the first receipt. A callback that failed after a successful external action needs an observable, recoverable pending state instead of a false-success result.
- Require a callback whenever a result affects settlement, state, authority, refund, or liveness. An intentional fire-and-forget notification may omit one only when failure has no such consequence.
- A failed downstream native transfer refunds the calling contract; compensating the user may require another explicit transfer.
- Promise composition uses the intended `then`/`and` dependency graph and the returned promise represents the full operation when callers depend on completion.
- Not returning a `Promise` is material only when a caller, indexer, relayer, or automation relies on the terminal chain result for settlement, retry, or safety. Intentional fire-and-forget work with no dependent accounting may be valid.

For every value-moving chain, build a receipt custody matrix. At each receipt,
record the current custodian, contractual owner, outstanding liability,
available/locked/pending accounting bucket, and recovery claimant for every
asset. Include native transfers that fail and return NEAR to the calling
contract, child-call attached deposits, FT unused amounts, relayer-funded fees,
and callback/refund failures. Generate conservation and at-most-once settlement
assertions from the matrix.

Adversarial tests: duplicate calls before callback, conflicting methods in the interleaving window, ordinary direct callback call, attacker-scheduled callback after attacker-controlled successful/failed promise, forged callback arguments, duplicate/out-of-order result, downstream failure after proof admission, retry after partial completion, a foreign callback or public ping that releases another operation's lock, repeated actions that extend another user's deadline, receiver panic, malformed result, partial refund, low callback gas, account deletion/unregistration, and an intervening update to every object or rate captured by callback arguments.

## Storage and persistent state

- Charge the responsible principal for attacker-controlled positive byte deltas using measured before/after storage and current `env::storage_byte_cost()`; refund excess and deletion savings.
- Storage staking locks part of the contract's balance; it is not a fee paid away. Deleting bytes unlocks that balance to the contract, not automatically to the user. Track refundable user storage deposits as explicit liabilities and transfer or credit refunds exactly once under the documented policy.
- Measure an operation-local delta around only the responsible mutation. Do not compare whole-contract current usage with a long-lived per-user baseline or charge one account for bytes created by another/interleaved operation.
- Include every user-controlled nested collection, key length, maximum account ID/string, and worst-case variant in measurement. Do not charge only the obvious balance sub-ledger while omitting account lists, indexes, metadata, approvals, or auxiliary maps grown by the same call.
- Never infer business deposits or revenue from raw account balance; direct NEAR transfers can change it.
- Keep enough liquid NEAR after storage staking and attached deposits promised to child calls.
- Use collision-free persistent collection prefixes. Prefix derivation must be injective; ambiguous concatenation, timestamps, and block heights are unsafe uniqueness sources.
- Prefer `BorshStorageKey`/typed enum prefixes and confirm each instantiated collection is anchored in contract state or otherwise persists its metadata intentionally. Detached SDK collection values can be written while length/metadata is lost.
- Check both modern `near_sdk::store` and legacy `near_sdk::collections`; legacy/nested collections have extra edge cases and migration risk.
- Treat collection choice as a semantics and scale decision, not a fixed ranking. Small bounded values accessed together may remain native. For scalable state, prefer the pinned SDK's current store collections; use non-iterable lookup maps/sets when enumeration is unnecessary, iterable variants only when needed, and tree/ordered variants only for ordering or range requirements. Measure real access patterns because SDK caching and implementations change.
- Most current `near_sdk::store` collections cache mutations until `Drop` or explicit `flush`; verify successful paths do not use `mem::forget`, static retention, or another lifetime escape that loses writes. Confirm exceptions such as the current direct-writing `LookupSet`. `Lazy`/`LazyOption` can isolate large rarely read fields but still require unique prefixes, persistence, cleanup, and the target SDK's actual mutation semantics.
- Legacy `near_sdk::collections` lookups commonly return owned/deserialized values. Mutating a returned struct or nested field does not persist unless the exact API writes through or the value is explicitly reinserted/replaced. Verify persistence with a fresh collection read; do not transfer modern `store` guard assumptions to legacy APIs.
- Clear nested raw keys before deleting their parent record or collection handle; dropping metadata does not garbage-collect prefixed storage. If the child collection is non-iterable, track its keys or choose a lifecycle-compatible collection, and paginate cleanup when necessary.
- Bound native `HashMap`, `HashSet`, and `Vec` fields because the whole `STATE` value is Borsh-deserialized into memory and serialized back on each mutable call.
- Bound third-party state creation and allow safe cleanup of zero/dead records.
- For NEP-145 `storage_deposit`, separate the beneficiary (`account_id` or predecessor) from the attached-deposit payer and excess-refund recipient (predecessor). `registration_only=true` gives a new account only the minimum and refunds excess, while an already registered account receives no balance change and the payer receives the full new deposit back. Without registration-only, add only within the advertised maximum and refund the rest to the payer.
- Reconcile `storage_balance_bounds`, `total`, `available`, and actual bytes: `0 <= available <= total`, minimum registration produces `total=min, available=0`, and growth/removal changes available without inventing or deleting the deposited liability. `storage_balance_of=null` means unregistered; do not infer registration from an FT balance of zero.
- NEP-145 `storage_withdraw` is exactly-one-yocto, predecessor-scoped, defaults to all available when amount is omitted, panics above available or when unregistered, and must not delete account data. A ledger decrement is not a withdrawal: match it to one outbound transfer or explicit recoverable pull-credit and test transfer failure.
- NEP-145 `storage_unregister` returns `false` without panic for an unregistered caller, panics on live data when force is false/omitted, and—when force is supported—applies the documented burn/cleanup/accounting policy in the initiating receipt before scheduling or crediting the storage refund. Reconcile token supply, events, approvals, nested keys, pending operations, and one-time refund/failure recovery; never assume `force=true` makes unbounded cleanup executable.
- Inspect read-like uses of `Option::take`, legacy `LazyOption::take`, remove, and replace. These APIs intentionally consume/delete values; require a corresponding lifecycle transition or use a non-destructive read.

## Tokens and standards

For NEP-141/145 and NEP-171/178-family flows:

- FT receiver hooks trust `sender_id` only after predecessor is the exact expected FT contract. NFT receivers additionally distinguish `sender_id` (the account authorized to call `nft_transfer_call`) from `previous_owner_id` (the owner whose token moved); an approved marketplace can make these differ. Bind credits, refunds, listings, and provenance to the identity required by the protocol rather than substituting one for the other.
- Unsupported tokens/configurations return the full unused amount rather than trapping assets.
- A contract designed to account deposits only through `ft_transfer_call` must not accept direct FT transfers into an untracked balance without a documented recovery/reconciliation path. Test the underlying token's ordinary `ft_transfer` route as well as the receiver hook.
- Resolvers are private, bind to the initiating operation, clamp malformed or oversized refunds, and conserve balances. For NEP-141 transfer-call resolution, failure means full attempted refund; success decodes unused amount and refunds no more than both the original transfer and receiver's current balance. The result returned to the original caller is the amount actually spent, not the unused amount.
- Callers of `ft_transfer_call` interpret the actual used/refunded result rather than top-level receipt success.
- NFT owner maps, per-owner indexes, approvals, escrow, marketplace, and treasury mirrors have one consistent owner across transfer, refund, burn, and redeem.
- For `nft_transfer_call`, receiver `true` or promise failure requests return to the original owner. Revert only while the receiver still owns the token; an intervening valid retransfer or burn must not be overwritten by a stale resolver. Restore the captured approval map and IDs only when ownership is actually reverted.
- NFT approval mutation is authorized by the current owner. An approved transfer binds the caller to a live approval entry and, when supplied, requires the exact current monotonic `approval_id`; every approval attempt, including re-approving the same account, advances the ID. Transfer clears approvals and resolver rollback restores only the correct prior approval state.
- NEP-178 `nft_approve` requires at least one yocto and may require more to pay measured approval storage; `nft_revoke` and `nft_revoke_all` require exactly one and refund any separately charged approval storage exactly once. Bound approvals when adding them so `nft_revoke_all` always remains executable.
- With `msg`, approval state commits before the fire-and-forget `nft_on_approve` receipt. A failed notification can make the returned promise chain look failed while approval remains live. There is no revoke notification, so marketplaces and other caches must refresh live approval state and submit the current approval ID rather than infer authority from callbacks or cached listings.
- NEP-171/178 `approval_id` is a deliberate JSON number below `2^53`, not a decimal-string `U64`. Prove the monotonically increasing counter remains below that bound and cannot wrap or reuse an old authorization. NEP-141 amounts and NEP-145 storage balances remain decimal-string `U128` values.
- `ft_balance_of` returns `"0"` for both unregistered and registered-zero accounts. Any path that needs registration must query or enforce storage registration separately rather than treating a zero balance as proof either way.
- Treat free-form FT/NFT `msg` as untrusted application data. The receiver must schema-validate and bound it after authenticating the token predecessor; the token contract must not reinterpret receiver-specific contents as token authority.
- Apply each standard's exact deposit rule, storage registration, metadata, payout-length/sum, and royalty behavior. A marketplace or settlement contract must treat an NFT contract's payout map as untrusted: do not assume it contains the seller or an acceptable royalty split; enforce recipient-count, total, seller-proceeds, and remainder policy before releasing funds. Treat non-compliance as security only when it causes material interoperability or asset harm.
- A custom FT transfer must not silently create an unregistered receiver at contract expense. Reject it without state growth unless intentional auto-registration has an explicit responsible payer, correct measured price, bound, cleanup, and refund policy.
- In custom transfers, test when logical roles alias the same storage key (`sender == receiver`, payer == beneficiary, owner == recipient). Compute one net delta per unique key or reject/no-op; two stale snapshots followed by two writes can erase a debit or inflate supply.
- In custom NEP-145 registration, apply the already-registered rule before optional `registration_only` branching. A third-party deposit must not overwrite an existing target account's stored balance or data.
- Pin the intended NEP/version and compare the exact exported ABI: argument names and optionality, serializer, return type, `#[payable]`, one-yocto rule, callbacks, resolver order, and lifecycle state. A manual look-alike interface is not assumed compatible.
- Pair every amount with an exact asset ID, decimal scale, collateral class, price source, and accounting bucket. Never substitute global liquidity or an underlying asset for collateral-specific state.
- Keep monetary accounting in checked integer or explicitly defined fixed-point/rational arithmetic with documented units and rounding. Treat `f32`/`f64` value paths as precision risks. At JSON ABI boundaries, encode `u64`/`u128` values with decimal-string `U64`/`U128` wrappers or an equivalent schema unless the pinned standard deliberately defines a bounded JSON number such as NEP-171/178 `approval_id`; keep wrappers distinct from the internal arithmetic model.

Use malicious token and receiver contracts in verification. Exercise 0, full, greater-than-amount, malformed, panic, retransfer, burn, and unregister branches.

For NEP-621 vaults, treat shares as a claim on net managed NEP-141 assets, including assets deployed to external strategies. Keep the underlying asset and adapter identities immutable or explicitly governed before capitalization; defend first-deposit and donation inflation with a nontrivial initial deposit or virtual decimal offset; reject deposits/mints that round to an unsafe zero result; round shares/assets paid out down and amounts required from users up. `total_asset_amount`, previews, and limits must include the intended fees and bounded external value without trusting arbitrary adapter return values. Bind deposit/redeem minimums, maximums, receiver, and slippage to the initiating operation. Async withdrawal/redemption reserves shares or liabilities before dispatch and finalizes or compensates after the actual transfer result. A preview is advisory across receipt boundaries, not a settlement guarantee.

## Upgrades and migration

- Enumerate every deploy-code and key-management path; effective authority includes remaining full-access keys and self-upgrade methods.
- Prefer explicit governance, delay/emergency policy, code hash, staging lifecycle, and observable changes.
- Version persistent state. Migration must read the exact old Borsh layout, preserve accounting/roles/pending operations, clear orphan data, and fit gas bounds.
- Protect migration with `#[private]` and `#[init(ignore_state)]` as appropriate; test repeated and unauthorized calls.
- Put deploy and migrate into the intended atomic action batch/receipt.
- Verify against serialized production-like old snapshots, including every supported historical version.
- Record who can pause, upgrade, recover, and communicate during an incident. Missing monitoring or response documentation is normally a quality/trust observation; promote it only when it causes a concrete material failure or contradicts the implemented authority model.
- For global contracts, distinguish immutable hash references from mutable
  account references. Bind the expected code hash/version and reference owner,
  prove upgrades preserve state/ABI/host-feature compatibility, and compare the
  reproducible artifact with deployed code before treating repository source as
  the executed program.

## Gas, liveness, and yield/resume

- Hard-bound user-controlled inputs, loops, logs, serialization, persistent iteration, and child receipt counts, or paginate with an idempotent cursor.
- A mutating pagination checkpoint is a pending operation, not merely an integer. Bind its owner, beneficiary, mode, filters, resource/version, and next cursor; authenticate every continuation; reject context changes and overlapping operations; and test resume with a different recipient or recovery mode.
- Validate items before they can become a mandatory queue/heap head. A permanently invalid item needs bounded retry plus skip, quarantine, cancellation, or removal so it cannot block every later valid operation.
- Compare JSON and Borsh only within the actual ABI contract: JSON is interoperable but larger/costlier, while Borsh is compact and canonical but requires an exact shared schema. Measure maximum attacker-controlled input, return, callback, and repeated-(de)serialization cost; a serializer preference without material gas/liveness or compatibility impact is quality-only.
- Model the “million cheap additions” shape explicitly: calculate the attacker's marginal gas/deposit and the contract's marginal storage stake/liquidity loss per write, then the repetitions, time, cleanup gas, and capital needed to block a core operation.
- Validate duplicate-sensitive batches before effects. Test all-identical IDs, duplicates at the start/middle/end, permutations, and maximum cardinality. Repeated items must not multiply redemptions, payments, mints, votes, claims, rewards, refunds, or storage benefit unless multiplicity is explicit and the corresponding resource is consumed for every occurrence.
- Budget the entire promise chain from measured build/runtime behavior. Do not treat a fixed TGas number as universally safe.
- Allocate explicit, profiled callback/refund/cleanup gas for worst-case branches (for example, an appropriate static or bounded allocation supported by the SDK version). Do not rely blindly on remaining-gas distribution or a universal fixed TGas constant. A lock set before a gas-heavy path needs recovery.
- For DoS, prove attacker cost, affected population, duration, recovery, and which core asset operation is blocked.
- Yield/resume requires an authenticated responder, operation binding, duplicate/late-response handling, timeout cleanup, and coherent pre-yield state. Callback panic must not undo necessary timeout cleanup.
- Bind each yield identifier to requester, authorized responder, payload schema,
  purpose/domain, operation state, expiry, and one terminal transition. Test
  unauthorized resume, ID collision/reuse, malformed or cross-purpose payload,
  timeout-versus-response races, duplicate/late responses, cleanup failure, and
  state migration while the operation remains pending.

## Feature-triggered surfaces

### Intents and passkeys

Signatures must bind domain/network, verifying target, signer/key, ordered payload, nonce, deadline, token, amount, recipient, and fees. Consume authorization exactly once before any durable profitable effect. Check failed-bundle replay/recomposition, bounded key/nonce state, curve-specific malleability, WebAuthn challenge/origin/rpId/flags, solver quote expiry/inventory/min-out, and callback URL handling.

### DeFi accrual, claimability, and MEV

- Settle global and per-user accrual under old rates, weights, boosters, debt indexes, and exchange ratios before changing any value-sensitive parameter or position. Verify lazy formulas algebraically if settlement is intentionally deferred.
- Every fee, reward, treasury balance, failed transfer, and trapped asset needs an authorized terminal claim or recovery transition that remains usable across pause, unregister, callback failure, and upgrade states.
- Public challenges, answers, reveals, solutions, proofs, first-come claims/mints, auctions, and price-sensitive trades must remain safe when pending inputs and expected state changes are visible. Bind canonical commit-reveal data to secret/payload, claimant, domain, and round across explicit windows; consume once and define deadlines, ties, cancellation, non-reveal, and deposit forfeiture. Otherwise use order-independent batch/fixed clearing, enforce slippage and deadlines, or make rewards non-stealable and idempotent. Private submission is a trust assumption, while delay and higher gas bidding are not protocol-level ordering defenses.
- Treat `env::random_seed()` as deterministic and verifiable, not as unbiased against the current producer. Map the exact seed block, every attacker-selected input, who may resolve, resolution window, censorship/timeout path, and repeated producer opportunities. Quantify the changed win probability and expected value rather than copying the coin-flip example universally. Prefer an external/VRF/multi-party source appropriate to value at risk, or design bounded permissionless resolution and an outcome/default that the producer cannot profitably select by inclusion.

### Bridges and Aurora

A finalized source event `(chain, contract, transaction, log index or nonce)` releases destination value at most once. Cryptographic proof validity establishes inclusion, not that the emitting contract is authorized: verify the exact configured per-chain factory/locker/emitter, event type, asset route, destination, address format, and decimals before binding a token or releasing value. Hash and bind all security-relevant header and event metadata, and scope sequence/reset state to the authenticated emitter and route. Fast fill, proof settlement, recipient acceptance, and timeout refund must be mutually exclusive. If delivery uses `ft_transfer_call`, settlement follows the semantic used/refunded result; consuming the bridge nonce before a receiver rejection is safe only when the returned tokens remain operation-bound and recoverable. Attribute every bridge fee, storage deposit, and attached NEAR amount to its actual payer; cap or fully collateralize caller-controlled values before a prefunded relayer/shared account can be charged. Validate finality, proof identity, expiry boundaries, fee-beneficiary binding, idempotent callbacks, collection insertion/update semantics, and reorg behavior. Transaction inclusion is not proof that every spawned receipt finished successfully.

Build a separate responsibility row for each chain, direction, asset, and route.
Name the actual verification backend—light client, Wormhole, MPC, relayer, or
hybrid—and its independent finality, quorum, emitter/domain, nonce, fee payer,
refund, retry, and terminal-settlement assumptions. Never transfer a security
claim from one route to another merely because both are exposed by OmniBridge or
the same frontend.

### Off-chain indexers and relayers

Treat actions, receipt arguments, logs, encoding, and failed outcomes as attacker input. Match exact receiver IDs, ingest only relevant successful outcomes, checkpoint final blocks, deduplicate receipt/event identities, tolerate replay/reorg/restart, and commit idempotency state before or atomically with irreversible payout. Bound queues and parsing; avoid `unwrap`/`expect` on chain data; manage concurrent access-key nonces.

### Chain signatures

Bind MPC requests and returned signatures to requester, application/path, protocol/domain version, chain, verifier, action/function purpose, complete canonical payload hash, participant/session identity, and operation ID. Authenticate the peer-to-participant/index mapping at every transcript hop; recompute rather than trust response hashes; prove two accepted action schemas cannot serialize to the same signed bytes/hash; and distinguish intentionally reusable metadata signatures from authorization over value or privilege. Check asynchronous failures, authorized resume, duplicate/late response, timeout, gas, signature encoding, and off-chain relay assumptions. Never store private keys on-chain.

Threshold reasoning must be phase-specific. Write the safety/liveness inequalities for DKG, reliable broadcast, signing, refresh, resharing, response aggregation, and recovery; reconcile old/new participant sets and thresholds; preserve the group public key when required; count authenticated unique parties; and test threshold-one, minimum quorum, offline/Byzantine schedules, membership changes, and coordinator equivocation. Waiting for every participant or accepting the first threshold-matching responses can violate the intended protocol even when the arithmetic looks locally valid.

Presignature and nonce-bearing material must have globally atomic one-time reservation and consumption. Before any response share is released, all parties must agree on the message, key tweak/path, signer subset and indices, threshold, protocol version, and session. Test coordinator equivocation, disjoint signer views, and participant counts outside the protocol proof's stated bounds; related ECDSA equations under a reused presignature can reveal the long-term key.

Treat secret and encrypted state as its own trust boundary. Inventory private shares, randomness, database keys/nonces, API credentials, CI artifacts, process arguments, logs, files, memory lifetime, rotation, and recovery. Require per-key nonce uniqueness for nonce-sensitive AEADs, record/type/version identity in authenticated data, and a standard domain-separated KDF where derivation is needed. Prove a realistic disclosure or cryptographic misuse before scoring zeroization, permissions, or operational-hardening observations.

### TEE-backed services

An attestation claim is only as strong as the verifier policy and measured boundary. Bind the expected platform/hardware identity, acceptable current TCB status, code measurement, security-relevant configuration and tags, freshness/collateral, service key, and protocol purpose. Treat SDK, RPC, and multichain balance responses as hostile structured input: validate presence, type, bounds, token identity, and missing-method behavior without crashing the solver or incorrectly reporting terminal success. Test revoked/out-of-date TCBs, altered environment/configuration, stale/replayed evidence, wrong service key, malformed SDK responses, and privilege outside the enclave boundary. Host/container hardening is a trust assumption unless the attestation claim or reachable attacker path makes it part of the security guarantee.

### Runtime and consensus components

For nearcore-like scope, place every contract/network-controlled length, index, count, account/Wasm byte string, receipt dependency, serialized message, and state transition on an adversarial boundary. Validate and bound first, use checked cost arithmetic, charge proportional gas/compute before or atomically with allocation/read/parse work, return deterministic fallible errors, and compare every supported runtime/backend/architecture. Fuzz malformed and maximum inputs, then run cross-implementation/state-root differentials. A contract-local out-of-gas event is not the same as a node-wide underpriced allocation, panic, or consensus divergence.

Model consensus as authenticated deterministic state transitions, not isolated helper correctness. Reconcile producer selection, validator-set changes, fork choice, finality thresholds, stake/reward calculations, persisted state, epoch activation, restart/recovery, partitions, equivocation, censorship schedules, and quorum intersection. A node issue becomes a finding only when the activated protocol and adversary assumptions yield concrete safety, bounded-liveness, or node-wide availability harm.
