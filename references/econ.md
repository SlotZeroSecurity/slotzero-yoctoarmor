# Econ attack lens

Activate only when target code exposes the stated behavior. Patterns guide investigation; only target evidence establishes a finding.

## NA-ECON-001 — Asset identity, unit, or collateral type is confused

- **Kind:** security
- **Root cause:** Asset identity, unit, or collateral type is confused.
- **Activation:** generic tuples/strings or shared maps let collateral types merge, code assumes underlying equals collateral, global liquidity substitutes for asset-specific liquidity, chain-specific recipient/address encodings are accepted under the wrong chain kind, or logs/metadata disagree with execution.
- **Broken invariant:** every amount is paired with the correct asset, decimal scale, collateral class, price source, and accounting bucket across storage and receipts.
- **Concrete sequence:** spend one asset's backing for another, bypass a limit, misprice a position, or settle in the wrong unit.
- **Required evidence:** naming or log-only mismatches are quality issues unless a security control or off-chain settlement consumes them.
- **Exclusions:** Exclude naming and log-only mismatches when no security control or settlement system consumes the misleading value.
- **Recovery:** Reconcile claims and compensation in the original asset and unit, including after configuration rotation; preserve separate buckets and drain or version-bind pending operations across cutover.
- **Fix family:** typed asset IDs/newtypes, explicit decimals and bucket keys, exact metadata uniqueness, and cross-asset conservation properties.

## NA-ECON-002 — Rounding, precision, overflow, or unit error changes value

- **Kind:** security
- **Root cause:** Rounding, precision, overflow, or unit error changes value.
- **Activation:** division precedes multiplication, `f32`/`f64` or float-derived configuration participates in monetary accounting, APY/unit semantics are ambiguous, intermediates overflow, casts truncate, decimal scaling or exponentiation can panic or underflow a nonzero value to zero, caps disagree, or an increase/decrease delta subtracts operands in the wrong direction and permanently reverts or credits the wrong amount.
- **Broken invariant:** formulas use declared units, release-profile checked arithmetic, protocol-appropriate rounding, and safe multiply/divide ordering.
- **Concrete sequence:** Use adjacent boundary values and repeated deposits, conversions, repayments, fees, or slashing to expose truncation, wrong rounding, swapped operands, overflow, or zeroed output; compare with the intended formula in its declared units.
- **Required evidence:** concrete boundary values and material/compounding harm; dust-only issues are informational or omitted.
- **Exclusions:** a missing `overflow-checks = true` line is not enough. Resolve the effective workspace/package release profile and prove that a reachable material arithmetic path can wrap without a complete checked-operation guard.
- **Recovery:** Determine whether a failed calculation reverts atomically or leaves earlier receipt effects pending; reconcile affected claims with checked arithmetic and test retries without compounding the error.
- **Fix family:** use checked integer or explicitly specified fixed-point/rational arithmetic with documented units and rounding; use `U128`/`U64` wrappers at JSON ABI boundaries without confusing serialization wrappers for the internal arithmetic model.

### Variants and safe controls

Use adjacent boundaries for casts, exponent limits, fee floors, zero, and maximum values. Test repeated division-before-multiplication loss, directional share/debt rounding, double upward rounding during slashing, and wrong min/max or subtraction operands. Show material or compounding impact; decimal wrappers at the ABI do not repair internal arithmetic.

## NA-ECON-003 — Public input, reveal, reward, or randomness can be ordered, copied, or biased

- **Kind:** security
- **Root cause:** Public input, reveal, reward, or randomness can be ordered, copied, or biased.
- **Activation:** challenge/proof/reveal/answer/solution data is public before inclusion and the first valid submitter receives value or changes exclusive state; a permissionless finalization/signing call lets the transaction sender choose an unbound fee beneficiary that a copier can replace; auctions, first-come mints/claims, or trades expose predictable price impact; or `env::random_seed()` influences material value while the producer for that block can predict the seed and choose matching inputs, transaction order/inclusion, or whether to include a later resolve. The seed's deterministic/verifiable derivation does not remove this producer advantage.
- **Broken invariant:** a value-bearing submission or randomized outcome is bound to claimant, domain, round/event, payload, and deadline, and cannot be profitably copied, reordered, delayed, selectively included, aborted, or replayed using pending-transaction or producer-visible information. Allocation and pricing do not accidentally depend on arrival order when the intended rule is order-independent. Randomness remains fair under the documented block-producer prediction, input-selection, and censorship capabilities.
- **Concrete sequence:** copy a victim's pending payload and order it first; reorder or delay bids, mints, trades, or claims; choose a winning input after predicting the seed; or place a bet earlier and include/withhold its later resolution depending on the outcome. Repeat, abort, replay, or wait for additional producer opportunities to amplify bias.
- **Required evidence:** Prove access to the pending payload or predictable seed, control over beneficiary/order/inclusion/abort, and a profitable or materially harmful outcome after costs. Establish actual timing, producer powers, replay limits, and any configured veto or disabling window.
- **Exclusions:** Effective claimant/domain binding, hidden unpredictable inputs with bounded resolution, or enforced clearing rules may block manipulation. Intentional optimistic approval is not a bypass merely because no veto occurs; reported mitigations are not deployment evidence.
- **Recovery:** Test cancellation, non-reveal, timeout, delayed inclusion, and repeated rounds without freeing a consumed claim or allowing selective resolution to bias payouts; verify any emergency disabling control on the target.
- **Fix family:** use commit-reveal whose canonical commitment binds secret/payload, account, domain, and round; separate commit/reveal windows; consume once; and define deadlines, cancellation, non-reveal, and any forfeitable deposit. Where appropriate use batch auctions/fixed clearing rules, slippage plus deadlines, non-stealable/idempotent rewards, or an external/VRF/multi-party randomness design sized to value at risk. Randomized multi-stage flows need permissionless or otherwise forced bounded resolution plus explicit timeout/default behavior; merely moving `bet` and `resolve` to different blocks does not prevent selective inclusion. Document private-submission and randomness-provider trust. A delay, higher gas bid, or two-stage flow without secrecy/binding/liveness does not prevent producer ordering or selective inclusion/abort.

### Variants and safe controls

For copied submissions or biased randomness, demonstrate access to the pending value, control over beneficiary/order/inclusion, and a profitable or materially harmful outcome. Keep optimistic-review assumptions separate: a reachable configured veto or disabling window may block a claimed bypass, but a reported mitigation is not deployment evidence.

## NA-ECON-004 — Bind compensation to the original resource generation

- **Kind:** security
- **Root cause:** A value decision uses unbounded inputs, incorrect precision, or an exploitable ordering rule.
- **Activation:** An operation can settle or compensate later; A configured resource can be replaced while it is pending
- **Broken invariant:** Settlement and compensation apply to the resource, unit, and owner that funded the original operation.
- **Concrete sequence:** Start work on resource A, rotate configuration to B, then trigger a delayed refund, debit, or cleanup.
- **Required evidence:** Prove rotation reachability and inspect real effects on both resources; trace identity through every boundary.
- **Exclusions:** A deployment that cannot rotate excludes the schedule; wrong-resource bookkeeping alone does not establish profit or insolvency.
- **Recovery:** Drain pending work or retain immutable resource identity through success, failure, retry, and cleanup.
- **Fix family:** Persist original resource identity and epoch rather than rereading mutable global configuration.
