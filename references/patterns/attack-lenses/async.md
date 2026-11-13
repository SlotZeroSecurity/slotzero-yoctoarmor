# Async attack lens

Activate only when target code exposes the stated behavior. Historical sources are examples, not target evidence.

## NA-ASYNC-001 — Late reservation enables split-receipt double spend

- **Kind:** security
- **Root cause:** Late reservation enables split-receipt double spend.
- **Activation:** a method checks available state, emits a promise, and only debits/locks/consumes in a callback.
- **Broken invariant:** an entitlement, nonce, claim, liquidity position, or unlock authorization is spendable at most once across every receipt boundary.
- **Concrete sequence:** invoke the same or a conflicting method again before the first callback; both validations observe the same availability.
- **Required evidence:** withdrawals, borrows, swaps, claims, refunds, unlocks, redemptions, batch calls, `pending` flags written late.
- **Exclusions:** reusable capacity is fully reserved before dispatch and all failure branches compensate safely.
- **Recovery:** Fail and retry either operation; release only its own reservation and reconcile quota and storage.
- **Fix family:** create a uniquely bound pending operation and reserve/debit before dispatch; finalize or compensate idempotently.

## NA-ASYNC-002 — Missing or incomplete failure compensation

- **Kind:** security
- **Root cause:** Missing or incomplete failure compensation.
- **Activation:** state changes before a promise and no complete callback handles failure, malformed return, or low gas.
- **Broken invariant:** failed external effects restore every reserved balance, score, lock, index, and accounting component exactly once.
- **Concrete sequence:** make the callee fail so user funds remain deducted, state becomes corrupt, or a lock persists.
- **Required evidence:** Separate committed increments from rolled-back tentative writes and compare one retry with two legitimate operations.
- **Exclusions:** the operation is intentionally fire-and-forget and failure has no accounting, authority, or liveness consequence.
- **Recovery:** Reverse only the original contribution in its original epoch; do not subtract from a reused slot.
- **Fix family:** private callback with operation-bound compensation; avoid callback panic before cleanup.

## NA-ASYNC-003 — Callback authority or identity mismatch

- **Kind:** security
- **Root cause:** Callback authority or identity mismatch.
- **Activation:** a callback/resolver/migrate/internal endpoint lacks `#[private]`, trusts callback arguments or injected promise results as caller authentication, or uses predecessor as the original user.
- **Broken invariant:** only the intended self-callback can finalize an operation, using the original bound principal rather than receipt-local identity.
- **Concrete sequence:** first try an ordinary external call, then have an attacker contract schedule the method as `.then(...)` after attacker-controlled successful and failed promises. Forge user, amount, token, operation, and result-dependent branches. `#[callback_result]`/`#[callback_unwrap]` supplies predecessor-result data; it is not an origin check, and an ordinary call panicking for zero promise results does not prove safety.
- **Required evidence:** every exported method used only after `.then(...)`, `#[callback_result]`, `#[callback_unwrap]`, or `env::promise_result`; require `#[private]` or an equivalent exact `predecessor_account_id() == current_account_id()` guard for self-callbacks. Being Rust `pub`/ABI-exported is necessary for runtime invocation but does not mean unrestricted callers are authorized.
- **Exclusions:** prove the method is exported and no equivalent exact predecessor check exists. If an external contract is intentionally authorized to call the endpoint, verify its exact predecessor allowlist and operation binding rather than requiring self-only `#[private]`.
- **Recovery:** Persist the relevant principal through deferred completion and failed refunds.
- **Fix family:** private self-callback (or the explicit intended caller check) plus stored operation context, result-count/semantics validation, and one-time operation ID. `#[private]` authenticates the receipt caller but does not by itself bind arguments, prevent duplicate settlement, or make a result semantically valid.

## NA-ASYNC-004 — Promise graph or return semantics are misinterpreted

- **Kind:** security
- **Root cause:** Promise graph or return semantics are misinterpreted.
- **Activation:** wrong or unchecked `promise_results_count`, wrong `promise_result` index, missing `and/then`, no returned terminal promise, unchecked `PromiseResult` bytes, top-level execution success is treated as business success, a proof/event/authorization is consumed before every required downstream effect succeeds, or settlement applies a fee, route, oracle bound, protocol version, or external configuration that changed after the initiating receipt without binding the user's accepted bounds.
- **Broken invariant:** final state reflects every required promise branch and the callee interface's semantic result.
- **Concrete sequence:** malicious receiver returns malformed/oversized unused amount, downstream rejection is ignored, one branch fails while value is credited, a caller-facing result reports success although its settlement callback failed, or a valid one-time proof is irrecoverably burned without delivering its intended effect.
- **Required evidence:** Trace each committed effect and response; determine whether a failed outer operation can hide an earlier success.
- **Exclusions:** A downstream rejection may be normalized to a valid result by a resolver. A status code or exception alone is insufficient evidence.
- **Recovery:** Keep ambiguous outcomes reconcilable, and settle or compensate only after establishing the actual effect.
- **Fix family:** construct and return the intended DAG; in the callback validate the exact result count, each required `PromiseResult`, decoded business result, and range before final credit, proof consumption, or release; bind results plus accepted configuration/version/slippage bounds to operation context and handle partial refunds. If an irreversible marker must be written before dispatch, retain an operation-bound retry/recovery transition until terminal success.

## NA-ASYNC-005 — Pending state can be permanently poisoned

- **Kind:** security
- **Root cause:** Pending state can be permanently poisoned.
- **Activation:** lock is set before unbounded work, log/serialization, low-gas callback, yield, or external dependency.
- **Broken invariant:** every pending operation has a bounded terminal or recovery transition.
- **Concrete sequence:** force callback panic/out-of-gas/timeout so future value operations remain blocked.
- **Required evidence:** Establish the durable effect and missing record separately; observe each system's commit boundary and the exact failure.
- **Exclusions:** A single atomic transaction may roll back both. Missing bookkeeping alone does not prove missing assets, theft, or permanent loss.
- **Recovery:** Reconcile by operation identity and repeat recovery without repeating the effect or releasing an already-consumed entitlement.
- **Fix family:** allocate explicit, profiled gas to the callback/refund/cleanup receipt, keep cleanup bounded and non-panicking, expose safe timeout/recovery, and make it idempotent. Do not assume one fixed TGas value or unused-gas distribution is universally sufficient.

## NA-ASYNC-006 — Stale callback snapshot overwrites intervening state

- **Kind:** security
- **Root cause:** Stale callback snapshot overwrites intervening state.
- **Activation:** an initiating receipt serializes a mutable struct or derived share/rate value into callback arguments and the callback later writes it back after another receipt can mutate the same record.
- **Broken invariant:** a callback applies only its operation-bound delta to current state; it never restores a cached whole object, balance, share count, exchange rate, or validator record over intervening writes.
- **Concrete sequence:** interleave a deposit, withdrawal, rate update, reward accrual, or configuration change so the callback erases the newer state or mints/restores value using a stale ratio.
- **Required evidence:** prove the record or value can change before callback and that writeback is not a commutative operation-bound delta.
- **Exclusions:** Exclude immutable operation records and writebacks expressed as commutative, operation-bound deltas that remain correct after intervening changes.
- **Recovery:** Fail and retry around cutover; drain pending writes or replay them exactly once in the correct generation.
- **Fix family:** store a unique operation ID and immutable inputs, reload live state in callback, apply a bounded delta, and reject duplicate or superseded settlement.

## NA-ASYNC-007 — A foreign operation releases or extends another operation's lock

- **Kind:** security
- **Root cause:** A foreign operation releases or extends another operation's lock.
- **Activation:** a shared boolean lock has no operation token; a public ping/retry or unrelated callback unconditionally calls `unlock`; or a later user's action refreshes a shared deadline that governs earlier pending withdrawals.
- **Broken invariant:** a lock, lease, unlock epoch, or deadline belongs to one operation and only that operation's authenticated terminal transition can release or extend it.
- **Concrete sequence:** start operation A, schedule operation B whose callback clears A's lock, then enter a conflicting value path before A settles; or repeatedly refresh the shared deadline so prior users cannot withdraw.
- **Required evidence:** prove the foreign path can execute while the original operation is pending and that conflicting state or value becomes reachable. A deliberately serialized queue is safe when every releaser identifies the current operation and no unrelated action can renew another user's deadline.
- **Exclusions:** Exclude serialized queues or paths that cannot execute until the first operation settles, and schedules without conflicting material state.
- **Recovery:** Trace failure, retry, cancellation, and authorized recovery without duplicating value or authority.
- **Fix family:** store an operation token with owner/resource/phase/deadline, compare-and-release only from that operation's callback, keep claimant deadlines independent, and make timeout/recovery idempotent.

## NA-ASYNC-008 — Resumable cursor is not bound to operation context

- **Kind:** security
- **Root cause:** Resumable cursor is not bound to operation context.
- **Activation:** a public method stores one shared iterator/cursor but accepts the recipient, transfer-versus-recovery mode, filter, limit, or asset again on later calls; initial-only validation is skipped on resume; or concurrent callers can advance or replace the same checkpoint.
- **Broken invariant:** a paginated or resumable transition continues only the exact operation that created its checkpoint, with immutable actor, beneficiary, mode, filters, resource, and cursor progression.
- **Concrete sequence:** begin a valid multi-call transfer or cleanup, then resume it with a banned/different beneficiary or destructive mode, redirect later pages, skip entries, process entries twice, or make another user's operation unrecoverable.
- **Required evidence:** a stateless pagination view or caller-supplied read cursor is not vulnerable by itself. Prove that continued calls mutate state or value and that security-relevant context is neither persisted nor revalidated for every page.
- **Exclusions:** Exclude stateless pagination and read-only cursors; a mutable continuation must have a reachable security consequence.
- **Recovery:** Resume after each batch failure, preserving snapshot identity, processed members, totals, and final activation.
- **Fix family:** persist a unique operation record containing owner, beneficiary, mode, filters, resource/version, next cursor, and terminal status; authenticate each continuation, reject context changes and overlapping operations, and make page application idempotent.

## NA-ASYNC-009 — Resolver refund/ownership semantics break conservation

- **Kind:** security
- **Root cause:** Resolver refund/ownership semantics break conservation.
- **Activation:** resolver public, malformed result unchecked, FT failure does not attempt full refund, FT refund is not capped by both the original transfer and receiver's current balance, actual-spent return polarity is inverted, an NFT resolver overwrites an intervening retransfer/burn, mirrors are not restored, NFT approval mutation is not restricted to the current owner, an approved transfer accepts a stale/mismatched supplied `approval_id`, re-approval reuses an ID, transfer fails to clear approvals, approval notification failure is incorrectly treated as rollback, or a bridge/escrow consumes its proof/nonce and marks settlement terminal before learning the actual amount used versus refunded by `ft_transfer_call`.
- **Broken invariant:** used amount + refund equals transferred amount, and all FT/NFT ownership and approval indexes agree after every resolver and approval lifecycle branch.
- **Concrete sequence:** Complete only part of an operation and return the remainder to an intermediary with no claimant record.
- **Required evidence:** a receiver rejection is not fund loss when the caller retains an operation-bound retry, alternate receiver, pull-claim, or cancellation path and the returned tokens remain fully attributable. Prove that finalization makes the refund trapped, misattributed, or unrecoverable.
- **Exclusions:** Exclude receiver rejection when value remains bound to an authorized retry, alternate receiver, claim, or cancellation path.
- **Recovery:** Trace remainder ownership through retry, refund, fee, and unclaimed-value paths.
- **Fix family:** settle from the resolver's semantic used/refunded amount, retain an idempotent operation-bound recovery state until recipient acceptance is known, revert NFT ownership only if the receiver still owns it, and centralize owner/approval authorization plus approval clearing/restoration.

## NA-ASYNC-010 — Reserve capacity before concurrent work

- **Kind:** security
- **Root cause:** A deferred effect and its local state commit are not bound to one authenticated, one-time operation.
- **Activation:** A bounded resource is checked before allocation; Another operation can pass the check before the first allocation commits
- **Broken invariant:** Committed allocations plus outstanding reservations never exceed the intended capacity.
- **Concrete sequence:** Pause A after its check, admit B against the same capacity, then complete both.
- **Required evidence:** Show the actual interleaving and both allocations, a sequential rejection control, and marginal resource cost.
- **Exclusions:** An atomic conditional allocation or serializable transaction may already prevent the schedule. Bounded over-admission is not proof of unbounded denial of service.
- **Recovery:** Fail and retry either operation; release only its own reservation and reconcile quota and storage.
- **Fix family:** Reserve atomically before dispatch, bind a reservation to its operation, and consume or release it exactly once.

## NA-ASYNC-011 — Recover when the effect commits but bookkeeping fails

- **Kind:** security
- **Root cause:** A deferred effect and its local state commit are not bound to one authenticated, one-time operation.
- **Activation:** The business effect and local accounting can commit independently; The accounting step can fail after the effect
- **Broken invariant:** Every completed effect has matching accounting or an authenticated, recoverable reconciliation state.
- **Concrete sequence:** Commit the effect, then fail the acknowledgement, callback, or ledger update.
- **Required evidence:** Establish the durable effect and missing record separately; observe each system's commit boundary and the exact failure.
- **Exclusions:** A single atomic transaction may roll back both. Missing bookkeeping alone does not prove missing assets, theft, or permanent loss.
- **Recovery:** Reconcile by operation identity and repeat recovery without repeating the effect or releasing an already-consumed entitlement.
- **Fix family:** Use an operation journal, idempotent effect identifiers, reconciliation, and bounded completion retries.

## NA-ASYNC-012 — Separate transport success from business completion

- **Kind:** security
- **Root cause:** A deferred effect and its local state commit are not bound to one authenticated, one-time operation.
- **Activation:** Completion depends on an external or deferred result; The interface can fail, return malformed data, or report partial work
- **Broken invariant:** State follows proven business effects; unknown outcomes authorize neither duplicate execution nor unconditional compensation.
- **Concrete sequence:** Exercise failed delivery, malformed response, zero, partial, full, and out-of-range results through the real interface.
- **Required evidence:** Trace each committed effect and response; determine whether a failed outer operation can hide an earlier success.
- **Exclusions:** A downstream rejection may be normalized to a valid result by a resolver. A status code or exception alone is insufficient evidence.
- **Recovery:** Keep ambiguous outcomes reconcilable, and settle or compensate only after establishing the actual effect.
- **Fix family:** Model explicit unsuccessful, partial, completed, and unknown outcomes with identity-bound reconciliation.

## NA-ASYNC-013 — Define authority across dependency rotation

- **Kind:** security
- **Root cause:** A deferred effect and its local state commit are not bound to one authenticated, one-time operation.
- **Activation:** Work is dispatched to a trusted dependency; Its identity or authority can change before the result is applied
- **Broken invariant:** A delayed result is accepted only under the request-generation policy actually promised by the system.
- **Concrete sequence:** Dispatch to dependency A, rotate to B, then deliver A's result.
- **Required evidence:** Establish whether rotation revokes in-flight work or explicitly permits it, and whether an attacker can influence the old dependency.
- **Exclusions:** Dependency compromise is a separate assumption; intentional acceptance of already-authorized work is not automatically a bypass.
- **Recovery:** Reject or grandfather old work consistently and permit an authorized retry without duplicate effects.
- **Fix family:** Bind requests to a dependency generation and enforce explicit revocation or grandfathering semantics.

## NA-ASYNC-014 — Count logical work once across retries

- **Kind:** security
- **Root cause:** A deferred effect and its local state commit are not bound to one authenticated, one-time operation.
- **Activation:** A logical operation can be retried; A derived counter can commit independently of its business outcome
- **Broken invariant:** Each logical operation contributes to derived accounting exactly as policy intends, regardless of delivery attempts.
- **Concrete sequence:** Fail after accounting commits, retry the same operation, then observe a later distinct operation affected by inflated state.
- **Required evidence:** Separate committed increments from rolled-back tentative writes and compare one retry with two legitimate operations.
- **Exclusions:** Per-attempt billing or metrics may intentionally count retries. A same-transaction rollback may already remove the increment.
- **Recovery:** Reverse only the original contribution in its original epoch; do not subtract from a reused slot.
- **Fix family:** Use idempotent logical-operation accounting or bound reversal records with explicit epochs.

## NA-ASYNC-015 — Preserve entitlement after partial completion

- **Kind:** security
- **Root cause:** A deferred effect and its local state commit are not bound to one authenticated, one-time operation.
- **Activation:** A downstream operation can accept part of an input; Returned or unused value is held by an intermediary
- **Broken invariant:** Delivered value plus recoverable claimant credit equals the intended entitlement after documented costs.
- **Concrete sequence:** Complete only part of an operation and return the remainder to an intermediary with no claimant record.
- **Required evidence:** Resolve result polarity and bounds from the actual interface; test zero, partial, full, and invalid values.
- **Exclusions:** First establish partial completion is reachable; an enforced all-or-nothing integration excludes this case.
- **Recovery:** Trace remainder ownership through retry, refund, fee, and unclaimed-value paths.
- **Fix family:** Record per-claimant remainders and reconcile partial results, or enforce a safe all-or-nothing contract.

## NA-ASYNC-016 — Serialize or deduplicate overlapping bulk operations

- **Kind:** security
- **Root cause:** A deferred effect and its local state commit are not bound to one authenticated, one-time operation.
- **Activation:** An authorized bulk operation has deferred effects; Another invocation can begin before completion is recorded
- **Broken invariant:** An allocation or transformation is applied at most once despite overlapping authorized invocations or retries.
- **Concrete sequence:** Start A and B against the same source snapshot before either completion callback.
- **Required evidence:** Show actual destination effects and the permitted concurrent schedule; preserve the operator prerequisite.
- **Exclusions:** This differs from ordinary users mutating one snapshot. A destination idempotency key or effective operation lock may prevent duplication.
- **Recovery:** Reconcile ambiguous completion before retrying and respect each execution unit's atomicity.
- **Fix family:** Reserve an operation epoch before dispatch and persist idempotent progress and cutover.

## NA-ASYNC-017 — Recover when cancellation itself expires or fails

- **Kind:** security
- **Root cause:** A deferred effect and its local state commit are not bound to one authenticated, one-time operation.
- **Activation:** An operation reserves resources; Its cancellation or replacement is a separate operation that can become unusable
- **Broken invariant:** Failure of a recovery attempt does not permanently remove safe recovery of the original reservation.
- **Concrete sequence:** Start cancellation, let that attempt expire or fail, then try recovery again.
- **Required evidence:** Enumerate all competing attempts and actual expiry predicates; prove when each can still execute.
- **Exclusions:** Age alone does not revoke an authorization. Do not release resources while a competing attempt can still consume them.
- **Recovery:** Repeat cancellation safely, reconcile fees once, and accept late evidence of an action validly completed before expiry when policy permits.
- **Fix family:** Make recovery operations retryable and terminal release conditional on all relevant authority becoming harmless.
