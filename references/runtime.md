# Runtime attack lens

Activate only when target code exposes the stated behavior. Patterns guide investigation; only target evidence establishes a finding.

## NA-RUNTIME-001 — Untrusted host/runtime work can panic, allocate, or execute before proportional charging

- **Kind:** security
- **Root cause:** Untrusted host/runtime work can panic, allocate, or execute before proportional charging.
- **Activation:** gas is deducted after allocation/read/serialization; lengths or multiplication overflow before a bound; attacker-controlled receipt/account/Wasm data drives large allocation; deserialization or storage imports panic; or runtime backends/architectures disagree on accepted input or result.
- **Broken invariant:** every contract-controlled host/runtime input is validated and bounded, its worst-case CPU/memory/I/O cost is charged before or atomically with work, and malformed input returns a deterministic protocol error on every supported implementation.
- **Concrete sequence:** cheaply crash or exhaust nodes, exceed chunk execution budgets, or create deterministic-state disagreement/consensus failure.
- **Required evidence:** benchmark the activated runtime and prove attacker-controlled cost, panic, or differential behavior reaches a node-wide boundary. Contract-local out-of-gas with proportional charging belongs to `NA-RESOURCE-005`.
- **Exclusions:** Exclude contract-local out-of-gas with proportional charging; route that case to the resource lens.
- **Recovery:** Trace failure, retry, cancellation, and authorized recovery without duplicating value or authority.
- **Fix family:** validate sizes and indices first, checked cost arithmetic, precharge/refund metering, fallible allocation/parsing, deterministic error mapping, fuzz/property/differential tests, and activation-aware regression vectors.

## NA-RUNTIME-002 — Block production, fork choice, finalization, or validator-set transitions violate agreement/liveness

- **Kind:** security
- **Root cause:** Block production, fork choice, finalization, or validator-set transitions violate agreement/liveness.
- **Activation:** producer scheduling can be sped up/manipulated, block acceptance enables systematic censorship, validator removal/update crashes or diverges, mutable process state substitutes for consensus state, or finalization logic permits conflicting forks.
- **Broken invariant:** all honest nodes deterministically derive the same eligible producer, validator set, fork choice, finality threshold, reward/stake transition, and terminal block state from the same authenticated inputs, while a bounded faulty set cannot censor indefinitely or finalize conflicting forks.
- **Concrete sequence:** halt production, exclude transactions/validators, corrupt stake/reward state, or finalize inconsistent histories.
- **Required evidence:** identify the activated consensus version, adversary/stake assumption, message schedule, and exact safety or bounded-liveness violation. Centralization or theoretical unfairness without a protocol breach is a trust observation.
- **Exclusions:** Exclude theoretical unfairness or centralization observations without an activated safety or bounded-liveness violation.
- **Recovery:** Trace failure, retry, cancellation, and authorized recovery without duplicating value or authority.
- **Fix family:** make transitions deterministic and on-state, validate epoch/validator invariants, domain-bind votes, enforce quorum intersection, persist/recover protocol state, and verify with multi-node adversarial schedule, restart, partition, and fork simulations.
