# NEP Protocol, Node, and Sharding Attacker Checklists

These checks apply to nearcore-like node/runtime implementations, protocol forks, validators, indexers that reproduce protocol state, and systems that rely on a specific activated layout. Ordinary contracts normally record `not_applicable` with repository and runtime evidence.

## NEP-0508 — Resharding V2

- **Trigger / attacker:** state split/layout transition implementation or tooling across the activation epoch; malicious state and receipts stress the split boundary.
- **Invariant:** every account/key/value and delayed receipt moves to exactly one child shard with identical state roots and no double execution.
- **Probe:** boundary accounts, large trie nodes, delayed/congestion receipts, restart mid-resharding, old/new node mixtures, missing chunks, and rollback across the transition epoch.
- **Conformance:** compare the activated shard layout, split boundary, state transformation, and protocol-version gates.
- **Gate / verify:** replay production-like snapshots across the transition and compare roots/supply/receipt conservation on all supported restart points.

## NEP-0509 — Stateless Validation Stage 0

- **Trigger / attacker:** state witness generation/validation, chunk endorsements, or validator assignment; adversary proposes malformed or withheld witnesses/chunks.
- **Invariant:** an endorsed chunk has a complete valid witness and deterministic state transition, while insufficient endorsement cannot become canonical.
- **Probe:** omitted/extra trie nodes, wrong roots, oversized witnesses, equivocation, duplicate/stale endorsements, biased validator assignment, delayed witness delivery, and endorsement/chunk mismatch.
- **Conformance:** verify witness limits, selection, endorsement threshold, signature/domain binding, and block inclusion rules.
- **Gate / verify:** differential execution with full state, adversarial witness mutation, and liveness tests under missing/slow validators.

## NEP-0514 — Testnet Block-Producer Seats

- **Trigger / attacker:** testnet genesis/configuration or security assumptions derived from testnet decentralization.
- **Invariant:** configured seats match the activated testnet policy and trust assumptions disclose increased centralization.
- **Probe:** wrong network config, zero chunk-only producers, threshold calculations copied to mainnet, and failover under concentrated stake.
- **Conformance:** compare network-specific seat counts and epoch configuration.
- **Gate / verify:** this is normally operational/conformance, not a production vulnerability, unless the target materially trusts testnet finality or diversity.

## NEP-0539 — Cross-Shard Congestion Control

- **Trigger / attacker:** congestion info, delayed receipt queues, forwarding limits, or chunk validation; attacker creates many cross-shard receipts and adversarial sizes/gas.
- **Invariant:** all nodes compute identical congestion state, enforce gas/byte limits, preserve receipt order/eventual delivery, and bound memory.
- **Probe:** threshold off-by-one, stale congestion info, forwarded/delegated receipt bypass, shard-target skew, queue growth, missing chunks, restart, and cheap cyclic receipt amplification.
- **Conformance:** verify congestion metrics, admission/forwarding rules, serialization, and protocol activation.
- **Gate / verify:** multi-shard simulation must prove both safety and eventual progress; workload cost must be compared with resulting resource pressure.

## NEP-0568 — Resharding V3

- **Trigger / attacker:** V3 shard-layout transition and trie/state migration.
- **Invariant:** transition preserves state and receipts exactly while old/new layouts cannot be confused across epoch or restart boundaries.
- **Probe:** extreme state distribution, delayed receipts, flat/trie state disagreement, epoch rollback, interrupted resharding, mixed-version nodes, and duplicate/missing child-shard data.
- **Conformance:** match the pinned V3 layout, transition schedule, validation, and recovery behavior.
- **Gate / verify:** snapshot replay and state-root/receipt/supply conservation across clean and interrupted transitions.

## NEP-0584 — Cross-Shard Bandwidth Scheduler

- **Trigger / attacker:** bandwidth requests/grants/buffers or chunk validation; attacker concentrates receipts across shard pairs and missing-chunk patterns.
- **Invariant:** deterministic fair allocation stays within effective limits, buffers are bounded, and every valid receipt eventually leaves the buffer.
- **Probe:** all-to-one traffic, integer rounding, stale grants, `num_shards * limit` corners, missing chunks, layout changes, starvation, buffer corruption, and panic-inducing inputs.
- **Conformance:** compare scheduler state, request/grant calculation, per-pair accounting, serialization, and activation.
- **Gate / verify:** deterministic multi-node simulations must include long-run liveness, bounded memory/witness size, and restart/reorg sequences.

## NEP-0639 — Dynamic Resharding (Draft)

- **Trigger / attacker:** draft automatic split proposals, candidate selection, or two-epoch activation logic.
- **Invariant:** all validators deterministically choose the same eligible split, schedule it once, and preserve state/receipts through activation.
- **Probe:** threshold oscillation, conflicting candidates, manipulated memory measurement, missing last-block chunks, reorg/epoch boundary, duplicate scheduling, restart, and witness disagreement.
- **Conformance:** advisory only; compare draft selection, delay, state-witness validation, and NEP-568 dependency.
- **Gate / verify:** deterministic simulations over adversarial measurements and epoch forks; never enforce Draft behavior as current production conformance.

## NEP-0652 — Early Chunk Producer Reassignment (Draft)

- **Trigger / attacker:** a target node or simulator explicitly implements early per-shard reassignment after producer misses, with protocol-version evidence for the feature.
- **Invariant:** all honest nodes derive the same eligible producer for each affected slot from finalized statistics; reassignment preserves at least one producer per shard and does not corrupt later epoch accounting.
- **Probe:** threshold boundary, missing chunks around the start-of-epoch grace window, finality-derived decision input, restart persistence, producer recovery, and adversarial concentration of remaining load.
- **Conformance:** advisory while Draft. The source document describes in-epoch reassignment separately from existing end-of-epoch validator kickout; do not treat its proposed thresholds as a current network rule.
- **Gate / verify:** compare target feature gate and protocol version, then use deterministic multi-node replay with a producer outage and restart. Record non-activation as an exclusion.
