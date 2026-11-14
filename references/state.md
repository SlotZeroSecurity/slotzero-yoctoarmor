# State attack lens

Activate only when target code exposes the stated behavior. Patterns guide investigation; only target evidence establishes a finding.

## NA-STATE-001 — Coupled indexes or lifecycle state diverge

- **Kind:** security
- **Root cause:** Coupled indexes or lifecycle state diverge.
- **Activation:** one path updates a primary map but not secondary index, manual token/NFT transfer bypasses protocol mirrors, two logical roles such as sender/receiver resolve to the same storage key and independently computed stale snapshots are written sequentially, code mutates an owned/deserialized value returned by a legacy `near_sdk::collections` lookup without reinserting/replacing it in the collection, a destructive full-object replacement silently erases fields that should survive, or an in-flight sale, bid, bond, liquidation, promise, or queue entry references an object that another public path can merge, delete, replace, or renumber before settlement.
- **Broken invariant:** every representation of ownership, membership, balance, role, pause state, market state, or pending operation changes together.
- **Concrete sequence:** choose `sender == receiver`, payer == beneficiary, owner == recipient, or another aliased role so the second write overwrites the first and mints value, erases a debit, or corrupts coupled state.
- **Required evidence:** Identify the authoritative record and every dependent index or mirror; show committed divergence after the reachable transition and a material read, settlement, or cleanup that consumes it.
- **Exclusions:** Intentional eventual consistency is safe when stale views cannot authorize incorrect effects and reconciliation is guaranteed. An absent optional restriction alone is not missing authorization.
- **Recovery:** Repair all coupled records together without erasing valid intervening changes; retain the context needed to settle pending references and test repeated cleanup.
- **Fix family:** centralize transitions, explicitly define same-principal behavior (usually reject or no-op a self-transfer), aggregate deltas per unique key before writing, reinsert/replace owned legacy collection values after mutation, preserve fields during partial updates, lock or version-bind objects referenced by outstanding operations, assert invariants, and test every alternate branch and callback outcome.

### Variants and safe controls

Also compare all primary/secondary records after burn, unregister, object merge, queue removal, and partial cleanup. A gas-bounded early return must persist completed removals and its cursor. Test identical keys for two roles, partial-object replacement, deactivated objects retained in default lists, and pending references to objects another path can delete.

## NA-STATE-002 — Getter or validation path mutates/creates state

- **Kind:** security
- **Root cause:** Getter or validation path mutates/creates state.
- **Activation:** `or_insert`/lazy initialization appears in getters, checks, or rejected paths, or a read-like method uses `Option::take`, legacy `LazyOption::take`, or an equivalent destructive accessor and unintentionally replaces/removes live state.
- **Broken invariant:** reads and failed validations do not create attacker-controlled persistent entries or alter accounting.
- **Concrete sequence:** Call a getter or validation helper on an absent record and compare storage usage, state root, and later authorization with a no-call control.
- **Required evidence:** Show a reproducible storage or state delta caused by the read-like call and a material downstream effect; a harmless cache is excluded.
- **Exclusions:** `take()` is valid when consuming the value is the intended atomic transition. Prove the method is expected to preserve the value or that deletion changes authority, metadata, accounting, or liveness.
- **Recovery:** Trace failure, retry, cancellation, and authorized recovery without duplicating value or authority.
- **Fix family:** use a non-destructive borrow/get/clone for reads; reserve `take`/remove for explicit lifecycle transitions whose replacement, cleanup, and rollback behavior are tested.

## NA-STATE-003 — Migration corrupts or strands persistent state

- **Kind:** security
- **Root cause:** Migration corrupts or strands persistent state.
- **Activation:** no versioning/migration, wrong old struct, public/repeatable migration, unbounded migration, or orphaned state.
- **Broken invariant:** upgrade reads the exact old Borsh schema and preserves balances, supply, roles, keys, pending operations, prefixes, and cleanup.
- **Concrete sequence:** Construct state using the exact old version, including balances, roles, nested collections, and pending work; upgrade and migrate, then exercise normal reads, writes, claims, cleanup, and a repeated migration.
- **Required evidence:** Pin both layouts and the actual deployment/migration authority, compare per-owner rights and raw storage keys before and after cutover, and demonstrate corrupted, inaccessible, duplicated, or stranded state. Equal supply alone does not prove individual allocation integrity.
- **Exclusions:** An enforced version gate and compatible transformation preserving all rights can exclude the defect. Preserve privileged-caller prerequisites; a consistent snapshot or pause-and-drain process may close concurrency paths.
- **Recovery:** Test interrupted, repeated, and concurrent migration plus pending callbacks; preserve progress and old claims until cutover is complete, and verify rollback compatibility rather than assuming old code can read new state.
- **Fix family:** Use explicit versioned layouts and migration authorization, preserve namespaces and per-owner entitlements, reconcile pending operations, and make bounded progress idempotent before activating the new representation.

### Variants and safe controls

Check exact old storage layouts, version gates, key namespaces, roles, balances, pending operations, and old storage claims across cutover. Test repeated migration, concurrent operators, and ordinary user writes during a snapshot separately. A migration-only lock does not stop users; atomic deploy-and-migrate or enforced pause-and-drain can be valid controls.

## NA-STATE-004 — Missing state-machine transition or validation bypass

- **Kind:** security
- **Root cause:** Missing state-machine transition or validation bypass.
- **Activation:** missing, inconsistent, or bypassable lifecycle checks govern pause/denylist, roles, amounts, deadlines, batches, liquidation, recovery, or dependent configuration; an input can also become unusable after costs or transformations.
- **Broken invariant:** protocol-specific lifecycle transitions are complete, ordered, and mutually exclusive.
- **Concrete sequence:** Enter through an alternate method or delayed callback while paused, expired, unregistered, or otherwise ineligible; vary amount, recipient, role, and batch boundaries, then attempt the next transition or recovery and compare with an allowed control.
- **Required evidence:** Derive the intended transition and forbidden state from target behavior and policy, prove the reachable bypass or missing exit, and show material harm. Cover auctions, listings, payouts, farms, liquidation, pause/denylist, roles, bounds, timestamps, participant identity assumptions, and batch-wide validation.
- **Exclusions:** Intentional disable modes, optional restrictions, and explicitly trusted administrator powers are not defects without a violated target guarantee. A documented best-effort path or usable post-fee result can exclude an admission claim.
- **Recovery:** Exercise cancellation, expiry, terminal closure, and emergency repair from each reachable state; retain valid claims and prevent repeated settlement or unauthorized reopening.
- **Fix family:** Enforce one coherent transition policy at every entrypoint and delayed completion; validate individual and cross-field constraints, accepted net outputs, and aggregate exposure, and retain authorized exits and recovery.

### Variants and safe controls

Exercise pause/denylist checks on every entrypoint and delayed completion, expiry and amount boundaries, liquidation and terminal-close paths, bid/order priority, supported token identity, role transitions, and empty or duplicate batch members. Include bounds on total existing exposure, not just the new increment. Compare intentional disable modes and explicit trust assumptions before treating a missing restriction as a vulnerability.

## NA-STATE-005 — Check individual allocation as well as aggregate totals

- **Kind:** security
- **Root cause:** A state transition updates one view or version without preserving its dependent state.
- **Activation:** A supplied list determines allocations; Validation checks aggregate totals without establishing unique complete membership
- **Broken invariant:** Each eligible principal receives its entitlement exactly once, and totals alone cannot substitute for ownership.
- **Concrete sequence:** Repeat a principal and omit another while preserving the aggregate accepted by validation.
- **Required evidence:** Use unequal allocations and a unique complete-list control; compare each principal's result, not only the total.
- **Exclusions:** A privileged caller prerequisite must remain explicit. Deduplicated identities backed by complete membership exclude this mechanism.
- **Recovery:** Check omitted principals can recover after activation and that repair cannot duplicate earlier allocations.
- **Fix family:** Validate uniqueness and completeness against an authoritative snapshot and reconcile per-principal allocations.

## NA-STATE-006 — Reconcile mutations during snapshot migration

- **Kind:** security
- **Root cause:** A state transition updates one view or version without preserving its dependent state.
- **Activation:** A snapshot is copied to a new representation; The old representation can change before cutover
- **Broken invariant:** One economic claim or logical entitlement remains one claim across snapshot, intervening writes, and cutover.
- **Concrete sequence:** Mutate ownership or balance after the snapshot but before copied state becomes authoritative.
- **Required evidence:** Construct a reachable schedule and compare individual ownership and totals across both representations.
- **Exclusions:** Locking migration admission does not stop ordinary mutations. Consistent snapshots with correct change capture can be safe without a global pause.
- **Recovery:** Fail and retry around cutover; drain pending writes or replay them exactly once in the correct generation.
- **Fix family:** Quiesce relevant writes or use a consistent snapshot plus ordered change capture and epoch-bound cutover.

## NA-STATE-007 — Prove resource amplification before reporting missing limits

- **Kind:** applicability
- **Root cause:** A state transition updates one view or version without preserving its dependent state.
- **Activation:** Users can request resource-consuming work; A proposed finding depends on aggregate demand or missing quotas
- **Broken invariant:** Resource use is assessed against the system's documented budget, pricing, and availability commitments.
- **Concrete sequence:** Compare legitimate demand with adversarial repetition, including concurrency, retained state, and cleanup.
- **Required evidence:** Measure marginal cost, attacker cost, enforced bounds, and harm to another principal or a promised service.
- **Exclusions:** Many funded users or absence of a global cap alone is not an exploit. A global cap may itself enable contention.
- **Recovery:** Test expiry and cleanup under load; establish whether resources are recoverable and who can recover them.
- **Fix family:** Choose pricing, backpressure, fair scheduling, quotas, or bounded retention according to demonstrated harm.

## NA-STATE-008 — Distinguish optional restrictions from required permissions

- **Kind:** applicability
- **Root cause:** A state transition updates one view or version without preserving its dependent state.
- **Activation:** Membership and restriction configuration have independent lifecycles; An absent rule has defined policy semantics
- **Broken invariant:** Acceptance matches the documented meaning of membership, optional constraints, and retained policy.
- **Concrete sequence:** Remove a restriction, remove membership, and reactivate membership in different orders; compare resulting access.
- **Required evidence:** Establish whether a rule grants permission or narrows existing permission, whose resources are affected, and intended defaults.
- **Exclusions:** An absent optional restriction is not missing authorization. Automatically clearing retained restrictions may broaden access.
- **Recovery:** Check explicit policy removal and membership enforcement independently.
- **Fix family:** Document and test defaults and lifecycle semantics; require a rule only when the target's policy requires it.

## NA-STATE-009 — Clean every losing attempt after a winner completes

- **Kind:** security
- **Root cause:** A state transition updates one view or version without preserving its dependent state.
- **Activation:** Several attempts represent one logical operation; Attempts occupy different states and share quota or indexes
- **Broken invariant:** A terminal winner makes losing attempts harmless and releases their obsolete reservations consistently.
- **Concrete sequence:** Leave a replacement in an early phase, complete another attempt, then request fresh work against the same quota.
- **Required evidence:** Inspect all indexes, retained records, actual capacity failure, and caller access to cleanup.
- **Exclusions:** Operator-recoverable unavailability is not automatically permanent loss. Externally executable losers require separate revocation analysis.
- **Recovery:** Test each winner ordering, repeated cleanup, and a caller without maintenance privileges.
- **Fix family:** Reconcile losing attempts across every phase and clear coupled indexes through authenticated idempotent cleanup.

## NA-STATE-010 — Preserve decision semantics when bounded history changes

- **Kind:** security
- **Root cause:** A state transition updates one view or version without preserving its dependent state.
- **Activation:** Security or risk decisions rely on bounded historical data; Resizing or eviction can change the meaning of missing entries
- **Broken invariant:** Missing or evicted history is interpreted consistently with the promised decision policy.
- **Concrete sequence:** Record an event, evict it through an actual collision, resize the history, then submit a delayed related event.
- **Required evidence:** Show the exact eviction and resulting decision under the current version; elapsed time alone may not evict data.
- **Exclusions:** A deliberate documented forgetting policy may be acceptable; relaxed risk classification is not proof that downstream loss occurred.
- **Recovery:** Preserve epoch markers or conservative forgotten-history state across resizing and recovery.
- **Fix family:** Define resize semantics, preserve relevant history or watermarks, and test decisions against the chosen policy.

## NA-STATE-011 — Validate collection cardinality before per-item checks

- **Kind:** security
- **Root cause:** A state transition updates one view or version without preserving its dependent state.
- **Activation:** A nonempty collection is required for a valid operation; A path relies only on checks applied to each member
- **Broken invariant:** Required structural properties hold even when no element exists to trigger a per-item check.
- **Concrete sequence:** Submit an empty collection through the alternative or replacement path.
- **Required evidence:** Compare constructor paths, required cardinality, caller authority, and resulting state.
- **Exclusions:** Empty input may intentionally mean no-op or cancel-all. Privileged malformed input does not establish public exploitation.
- **Recovery:** Check whether the original operation remains valid and recoverable before claiming terminal failure.
- **Fix family:** Enforce cardinality and aggregate constraints explicitly before durable state changes.

## NA-STATE-012 — Preserve rights across provisional-to-final transitions

- **Kind:** security
- **Root cause:** A state transition updates one view or version without preserving its dependent state.
- **Activation:** A provisional operation coexists with a paid or time-dependent recovery claim; Finalization deletes or overwrites that claim
- **Broken invariant:** Changing operational state preserves owed rights or settles them according to explicit policy.
- **Concrete sequence:** Create a recovery claim, then finalize the primary operation through a path that removes it.
- **Required evidence:** Compare ownership, fees, deadlines, and remaining rights before and after each transition.
- **Exclusions:** Successful primary-operation retry does not restore a lost independent right. A documented claimant-preserving settlement can be valid.
- **Recovery:** Verify retries do not reset waiting periods or silently consume paid rights; reconcile concurrent settlement and recovery.
- **Fix family:** Represent claims separately or atomically settle all coupled rights during the transition.

### Variants and safe controls

Reserve a provisional operation while an independent paid recovery claim is pending, delete that claim as if settlement were final, then fail the primary operation. Compare the original fee, timestamp, and waiting period with a no-interference control: retrying the primary operation does not restore the lost recovery right.

## NA-STATE-013 — Validate destinations before committing to delivery

- **Kind:** security
- **Root cause:** A state transition updates one view or version without preserving its dependent state.
- **Activation:** A user supplies a destination for later recovery or delivery; The system stores or charges for it before validating usability
- **Broken invariant:** An accepted destination is usable for the promised operation, or the claimant retains a safe correction path.
- **Concrete sequence:** Persist malformed, wrong-namespace, or unsupported destination data, then attempt execution.
- **Required evidence:** Use the actual destination parser and delivery rules; separate semantic invalidity from a transient service outage.
- **Exclusions:** One broken recovery path does not prove every settlement path is frozen. Delayed validation can be safe when rights and costs are preserved.
- **Recovery:** Test authenticated correction and ordinary completion, preserving ownership and avoiding replay.
- **Fix family:** Validate early and again where mutable constraints matter; permit safe owner-bound correction if required.

## NA-STATE-014 — Make optimistic approval assumptions explicit

- **Kind:** applicability
- **Root cause:** A state transition updates one view or version without preserving its dependent state.
- **Activation:** An action becomes executable unless a reviewer vetoes it; Its safety depends on timely review rather than fully automated validity
- **Broken invariant:** The implemented optimistic policy matches its documented trust and availability assumptions.
- **Concrete sequence:** Submit an invalid request under the exact required knowledge and observe the review and execution boundaries.
- **Required evidence:** Prove the real admission prerequisites, operator-veto capability, configured window, and whether the mode is enabled.
- **Exclusions:** Expected execution without a veto is not automatically an authorization bypass. A project-reported mitigation is not deployment evidence.
- **Recovery:** Check rejection before execution and recovery after review outages; verify disabling mitigations on the actual target.
- **Fix family:** Use explicit automated evidence requirements or a documented, monitored optimistic review policy with appropriate limits.

## NA-STATE-015 — Keep replay protection compatible with recovery

- **Kind:** security
- **Root cause:** A state transition updates one view or version without preserving its dependent state.
- **Activation:** Cleanup deletes an operation or recovery record; A consumed marker survives and blocks every legitimate retry
- **Broken invariant:** Replay prevention blocks duplicate effects without erasing the only safe path to satisfy an existing claim.
- **Concrete sequence:** Reject an otherwise valid operation, delete its recovery record, then retry through all authorized paths.
- **Required evidence:** Use valid input to isolate cleanup from admission defects; inspect marker, claimant, inventory, and remaining authority together.
- **Exclusions:** Blindly deleting the marker is unsafe when effects or authorizations survive. Existing authenticated recovery may exclude the defect.
- **Recovery:** Recover exactly once without enabling both primary completion and compensation.
- **Fix family:** Retain a recoverable terminal record or safely transition replay state after reconciling every outstanding effect.

## NA-STATE-016 — Validate configuration combinations

- **Kind:** quality
- **Root cause:** A state transition updates one view or version without preserving its dependent state.
- **Activation:** Several settings jointly determine an operational invariant; Individual type checks allow incompatible combinations
- **Broken invariant:** Every accepted configuration has the semantics promised by its enabled mode.
- **Concrete sequence:** Exercise boundary combinations and updates that temporarily or permanently violate cross-field relationships.
- **Required evidence:** Derive constraints from actual behavior and documented disabled modes rather than assuming every zero is invalid.
- **Exclusions:** Privileged intentional disablement is not necessarily a vulnerability; preserve administrative authority assumptions.
- **Recovery:** Verify rollback, atomic configuration update, and restoration of service.
- **Fix family:** Validate related settings together and make disabling states explicit.
