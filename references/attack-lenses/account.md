# Account attack lens

Activate only when target code exposes the stated behavior. Historical sources are examples, not target evidence.

## NA-ACCOUNT-001 — Global storage delta is charged to the wrong account

- **Kind:** security
- **Root cause:** Global storage delta is charged to the wrong account.
- **Activation:** per-user accounting compares current whole-contract `env::storage_usage()` with a user baseline, spans an external/interleaved operation, or assigns another account's growth during liquidation/cleanup.
- **Broken invariant:** each principal is charged or refunded only for the operation-local bytes attributable to that principal.
- **Concrete sequence:** one actor shifts storage cost to another, receives an excessive refund, or fails validation because unrelated writes changed global usage.
- **Required evidence:** a global before/after delta is valid when captured in one non-interleaved receipt around only the responsible mutation; prove cross-user or cross-operation contamination.
- **Exclusions:** Exclude a single-receipt balance delta that cannot interleave with another mutation and is attributed to exactly that operation.
- **Recovery:** Trace failure, retry, cancellation, and authorized recovery without duplicating value or authority.
- **Fix family:** measure tightly around the exact mutation, track per-account deposits and released bytes, and avoid long-lived absolute global-usage baselines.

## NA-ACCOUNT-002 — Liability, reserve, fee, or supply accounting is inconsistent

- **Kind:** security
- **Root cause:** Liability, reserve, fee, or supply accounting is inconsistent.
- **Activation:** raw account balance is used as deposits, refundable depositor principal also funds storage or rewards, time-based rewards are not bounded by earned fees or a separately funded reserve, balances are sampled after untrusted calls, an adapter or external market can report assets/proceeds without reconciliation to observed token deltas or a bounded authoritative source, protocol or a shared relayer account subsidizes caller-controlled attached deposits/fees (including repeated one-yocto child calls), paths omit a ledger update or external transfer, a terminal fee can be bypassed by leaving dust, or a caller-controlled list charges/burns/consumes an entitlement once while granting a payout, mint, vote, claim, refund, or other benefit per occurrence.
- **Broken invariant:** per asset, on-chain holdings and reserved/pending amounts cover all user/protocol liabilities; fees and supply changes conserve value.
- **Concrete sequence:** Commit the effect, then fail the acknowledgement, callback, or ledger update.
- **Required evidence:** Establish the durable effect and missing record separately; observe each system's commit boundary and the exact failure.
- **Exclusions:** A single atomic transaction may roll back both. Missing bookkeeping alone does not prove missing assets, theft, or permanent loss.
- **Recovery:** Reconcile by operation identity and repeat recovery without repeating the effect or releasing an already-consumed entitlement.
- **Fix family:** explicit typed ledgers and stateful conservation tests across every lifecycle transition; separate refundable principal, storage backing, earned fees, and reward reserves, and cap reward accrual by its funded source; prefer a single identifier when batching is unnecessary.

## NA-ACCOUNT-003 — Accumulated value has no safe claim or recovery transition

- **Kind:** security
- **Root cause:** Accumulated value has no safe claim or recovery transition.
- **Activation:** value accrues in state or contract balance but no exported method can release it, the only recipient can become unregistered, or emergency/pause states disable recovery permanently.
- **Broken invariant:** every protocol fee, treasury balance, beneficiary reward, failed withdrawal, and trapped asset has a reachable, authorized, bounded terminal claim or recovery path.
- **Concrete sequence:** Submit exact and excess amounts on success and each failure path.
- **Required evidence:** intentional immutability or burn is not a vulnerability unless it contradicts the asset model or creates material liabilities.
- **Exclusions:** Exclude intentional immutability or burns that satisfy the documented asset and liability model.
- **Recovery:** Preserve original payer and amount through deferred work; recover failed returns without duplicate credit.
- **Fix family:** explicit pull-based claim/recovery transitions with correct authority, storage registration, failure compensation, and observability.

## NA-ACCOUNT-004 — Accrual or reward snapshot is not settled before mutation

- **Kind:** security
- **Root cause:** Accrual or reward snapshot is not settled before mutation.
- **Activation:** rate/weight/config/position changes do not call the relevant accrue/snapshot function for every affected asset and account, or a time-chunk/snapshot design accounts only finalized periods so borrowing, repaying, supplying, withdrawing, liquidating, or changing collateral within the open period receives free time or loses earned value.
- **Broken invariant:** value earned under old rates, weights, boosters, debt indexes, or exchange ratios is settled before any parameter or position mutation changes the basis.
- **Concrete sequence:** time a deposit, withdrawal, owner update, or booster change to capture excess rewards, avoid debt, or erase another user's accrual.
- **Required evidence:** prove the lazy-accrual formula does not algebraically preserve the same result across the mutation.
- **Exclusions:** Exclude algebraically equivalent lazy-accrual implementations that preserve each participant’s value across the mutation.
- **Recovery:** Trace failure, retry, cancellation, and authorized recovery without duplicating value or authority.
- **Fix family:** checkpoint global and per-user indexes before mutation; pro-rate or settle the current partial period at every value-bearing boundary; make one canonical transition update all affected assets.

## NA-ACCOUNT-005 — Vault share conversion or managed-asset accounting dilutes claimants

- **Kind:** security
- **Root cause:** Vault share conversion or managed-asset accounting dilutes claimants.
- **Activation:** the first depositor or a direct donor can manipulate price-per-share; zero-share deposits are accepted; paid-out versus required amounts use the wrong rounding direction; `total_assets` omits direct donations or trusts mutable adapter-reported values without balance-delta/bounded reconciliation; a positional market-to-adapter mapping can silently change after reordering; virtual offsets, underlying asset identity, or conversion basis can change after capitalization; preview/max results omit limits or fees; or async withdrawal burns/finalizes shares without an operation-bound rollback/recovery path.
- **Broken invariant:** share supply represents the vault's net managed underlying assets—including safely valued external deployments—at every receipt boundary, and conversions cannot let one account capture value already attributable to another.
- **Concrete sequence:** front-run the first deposit, donate before a victim deposit, inflate/deflate external assets, reorder adapters, or exploit rounding/async failure to dilute shares, capture surplus, over-withdraw, strand redemption, or make liabilities exceed managed assets.
- **Required evidence:** prove an attacker-controlled value path and claimant loss. Intentional uncapturable donations, an immutable nontrivial seed/virtual offset, or a trusted adapter assumption with independently enforced bounds may block the mechanism; a view-only preview changing between receipts is expected unless execution omits user-specified slippage/minimum bounds.
- **Exclusions:** Exclude intentional uncapturable donations, effective seed or virtual-offset protections, and trusted adapters that block the attacker-controlled value path.
- **Recovery:** Trace failure, retry, cancellation, and authorized recovery without duplicating value or authority.
- **Fix family:** immutable underlying and explicit adapter IDs, nontrivial initial liquidity or virtual decimal offset, reject zero-share results, round shares/assets paid out down and amounts required up, reconcile external realization to token-balance deltas or bounded authoritative valuation, bind min/max/slippage to the operation, and settle async withdrawal through an idempotent pending state with compensation.

## NA-ACCOUNT-006 — Preserve recovery when the primary operation is rejected

- **Kind:** security
- **Root cause:** User claims or tracked totals change independently of actual custody, fees, or pending liabilities.
- **Activation:** The system already controls a user's resource; A policy threshold rejects normal processing while consuming an admission marker
- **Broken invariant:** Rejecting the normal operation does not erase a legitimate, feasible recovery path.
- **Concrete sequence:** Provide a resource below the normal processing threshold, consume its marker, then try recovery before and after policy changes.
- **Required evidence:** Separate business minima from actual recovery costs and test a resource valuable enough to recover.
- **Exclusions:** Some resources are genuinely uneconomic to recover; do not assume every policy rejection promises a cost-free refund.
- **Recovery:** Exercise both new and already-pending recovery requests, preventing concurrent recovery and normal settlement.
- **Fix family:** Reject before consuming rights or retain an authenticated recovery state with safe replay protection.

## NA-ACCOUNT-007 — Assign all residual value after allocation

- **Kind:** quality
- **Root cause:** User claims or tracked totals change independently of actual custody, fees, or pending liabilities.
- **Activation:** An allocation leaves a remainder after requested outputs and costs; The remainder can become unowned or inaccessible
- **Broken invariant:** Inputs equal allocated outputs, documented costs, and an explicitly owned recoverable remainder.
- **Concrete sequence:** Choose inputs larger than requested outputs and costs, then inspect the residual allocation.
- **Required evidence:** Reconcile the entire value equation and distinguish actual surplus from rounding or required reserve.
- **Exclusions:** A documented reserve or intentionally assigned change is not lost value.
- **Recovery:** Ensure later sweep, refund, or reuse preserves the rightful owner and cannot duplicate value.
- **Fix family:** Represent and assign residual value explicitly and test conservation across all branches.
