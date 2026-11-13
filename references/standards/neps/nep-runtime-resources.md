# NEP Runtime, Storage, and Gas Attacker Checklists

Protocol/runtime proposals are enforceable only when activated on the target chain/version. Contract audits still use them to challenge environmental assumptions; node audits verify implementation and transition behavior directly.

## NEP-0264 — Unspent Gas Weights for Promises

- **Trigger / attacker:** weighted unused-gas distribution or promises relying on dynamic gas; attacker controls branch cost and callback payload/work.
- **Invariant:** every required promise and cleanup callback receives enough gas under the worst valid execution path without oversubscription or starvation.
- **Probe:** many weighted promises, zero/equal/extreme weights, high pre-dispatch work, branch-dependent used gas, callback failure path, and SDK/runtime version mismatch.
- **Conformance:** compare weight semantics, static gas, unused pool calculation, and activation.
- **Gate / verify:** profile real receipt gas in sandbox/protocol tests; fixed historical TGas constants are not proof.

## NEP-0399 — Flat Storage

- **Trigger / attacker:** flat-storage implementation, migration/catch-up, trie fallback, or tools relying on flat-head state.
- **Invariant:** flat and trie views agree at the selected block; reorg, restart, and migration cannot serve stale or corrupt state.
- **Probe:** fork/reorg, missing delta, interrupted migration, flat-head lag, shard split, deletion/recreation, cache corruption, and concurrent reads during catch-up.
- **Conformance:** verify flat-state lifecycle, delta application, head selection, fallback, and persistence.
- **Gate / verify:** differential state reads against trie roots across restart/reorg/migration sequences.

## NEP-0418 — `attached_deposit` in View Calls

- **Trigger / attacker:** contracts or off-chain services whose view behavior depends on `attached_deposit` panicking.
- **Invariant:** view results remain safe when the activated runtime returns zero rather than panicking.
- **Probe:** call every deposit-sensitive export as view and transaction, check zero-deposit branches, SDK wrappers, cached view results, and off-chain authorization based on panic/success.
- **Conformance:** compare target runtime behavior and contract assumptions at the activation version.
- **Gate / verify:** state cannot change in view; escalate only when an off-chain material decision incorrectly treats the changed result as authorization/value.

## NEP-0455 — Parameter Compute Costs

- **Trigger / attacker:** runtime parameter accounting, host functions, or contracts with compute-heavy underpriced operations.
- **Invariant:** compute limits and gas charging bound chunk execution consistently across nodes.
- **Probe:** inputs maximizing compute per charged gas, parameter transition boundaries, host/Wasm cost mismatch, overflow, mixed-version nodes, and adversarial workload composition.
- **Conformance:** compare parameter tables, compute counters, limit enforcement, and activation.
- **Gate / verify:** benchmark worst-case shapes and differential node execution; a price disagreement needs a feasible DoS or consensus consequence.

## NEP-0491 — Non-Refundable Storage Staking

- **Trigger / attacker:** non-refundable balance/account storage creation or global-contract predecessor behavior.
- **Invariant:** non-refundable funds can stake storage only as specified and cannot be transferred, refunded, double-counted, or bypass normal balance constraints.
- **Probe:** account deletion, transfer, key/code/state growth, refund actions, failed creation, overflow, legacy account transition, and interaction with global contracts.
- **Conformance:** verify account fields, charging priority, action validation, and replacement by NEP-591 where applicable.
- **Gate / verify:** state-transition tests preserve total supply/accounting and reject spend/refund paths.

## NEP-0519 — Yield Execution

- **Trigger / attacker:** yield/resume host APIs or contracts waiting for later transactions; requester, responder, timeout caller, and duplicate responder may be hostile.
- **Invariant:** a unique pending yield resolves at most once by an authorized validated response or timeout, then cleans up without panic.
- **Probe:** unauthorized/duplicate/late resume, timeout race, unknown ID, oversized response, callback low gas/panic, responder rotation, concurrent waits, and congestion delay.
- **Conformance:** verify create/resume ABI, 200-block timeout behavior for the pinned version, result semantics, and gas/receipt flow.
- **Gate / verify:** sandbox fast-forward and intermediate receipt-state assertions; initiating state is not rolled back by callback failure.

## NEP-0536 — Reduced Gas Refunds

- **Trigger / attacker:** fee estimation/accounting or node refund receipt creation across activation.
- **Invariant:** charged/refunded gas and receipt outcomes match the active model without minting value, rejecting funded actions, or breaking relayer solvency.
- **Probe:** pessimistic-versus-actual price boundaries, failed actions, multi-receipt chains, congestion, pre-activation in-flight receipts, relayer quotations, and integer rounding.
- **Conformance:** compare refund creation/elision and balance accounting at the protocol version.
- **Gate / verify:** supply/balance differential tests; changed user cost alone is expected conformance behavior.

## NEP-0591 — Global Contracts

- **Trigger / attacker:** deploy/reference-by-hash/account global contract actions, factories, or upgrade/reproducibility assumptions.
- **Invariant:** referenced code identity is exact and available, charging cannot be evaded, and initialization/state/upgrade authority remains account-specific.
- **Probe:** missing/wrong hash, publisher/account deletion, same hash across versions, deploy/init failure, reference before availability, cross-shard propagation, storage undercharge, and governance assuming shared code implies shared state/owner.
- **Conformance:** verify action variants, code identity, storage charging, availability, and protocol activation; account for NEP-491 replacement semantics.
- **Gate / verify:** multi-account/shard deployment tests plus Wasm-hash comparison and failure recovery.

## NEP-0611 — Pending Transaction Queue and Gas Keys (Draft)

- **Trigger / attacker:** draft pending-queue/gas-key implementation; attacker floods invalid/future/conflicting transactions and exploits nonce lanes.
- **Invariant:** admission and later execution validate signature, permission, nonce, and funds once; queues and per-key resources remain bounded and fair.
- **Probe:** duplicate/conflicting nonces, insufficient funds revealed later, key deletion/rotation, allowance exhaustion, many gas keys, expiry, restart/reorg, queue starvation, and cheap invalid spam.
- **Conformance:** advisory only; compare queue state, validation stages, eviction, charging, and key/nonce semantics.
- **Gate / verify:** model-based queue tests under adversarial ordering and state changes; no mandatory finding against unactivated Draft behavior.

## NEP-0638 — `chain_id()` Host Function (Draft)

- **Trigger / attacker:** contracts use or emulate chain ID for signed messages, proofs, or cross-chain routing.
- **Invariant:** every security domain uses the unique correct chain ID and binds it into the authorized payload before consumption.
- **Probe:** same ID across networks/forks, hardcoded mismatch, missing domain field, migration/fork boundary, serializer ambiguity, and fallback when host function is unavailable.
- **Conformance:** advisory and activation-gated; compare host ABI and configured genesis chain ID.
- **Gate / verify:** cross-network negative tests; host correctness does not cure an application that omits chain ID from signatures.

## NEP-0642 — Account Cost Increase (New)

- **Trigger / attacker:** prototype account-creation charging or services subsidizing account creation.
- **Invariant:** charge never exceeds available surplus, old in-flight receipts remain valid, and storage underpricing is not reintroduced through another creation path.
- **Probe:** exact/minimum gas price, insufficient surplus, pre-activation receipts, refunds, relayed creation, batch action failure, alternate account paths, and arithmetic boundaries.
- **Conformance:** advisory only; compare proposed min/cap calculation and activation transition.
- **Gate / verify:** balance/supply tests around activation; application subsidy economics are separate unless exploitable.
