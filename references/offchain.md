# Offchain attack lens

Activate only when target code exposes the stated behavior. Patterns guide investigation; only target evidence establishes a finding.

## NA-OFFCHAIN-001 — Indexer trusts failed, foreign, or malformed chain data

- **Kind:** security
- **Root cause:** Indexer trusts failed, foreign, or malformed chain data.
- **Activation:** substring contract match, tx acceptance without receipt checks, untrusted decode with panic, optimistic data used for irreversible payout, or failed outcome args/logs are ingested.
- **Broken invariant:** only exact, successful, relevant finalized receipt outcomes mutate off-chain business state.
- **Concrete sequence:** Feed an indexer failed, foreign, malformed, or oversized events and amounts; trace unauthorized credits, parser crashes, or a poison event that stalls subsequent legitimate processing.
- **Required evidence:** Show the reachable input, finality/status/source checks, decoder behavior, and resulting unauthorized business-state change or material service failure; compare valid and rejected control events and restart behavior.
- **Exclusions:** Do not report without a reachable path and material target-specific harm.
- **Recovery:** Trace failure, retry, cancellation, and authorized recovery without duplicating value or authority.
- **Fix family:** Authenticate exact source and finalized successful receipts, parse bounded data fallibly, isolate poison events with recoverable progress, and gate credits on durable event IDs.

## NA-OFFCHAIN-002 — Relayer retry, persistence, or nonce ordering loses/doubles funds

- **Kind:** security
- **Root cause:** Relayer retry, persistence, or nonce ordering loses/doubles funds.
- **Activation:** pub/sub loss, Redis/DB outage, send-before-persist, parallel access-key nonces, retry without event identity, or ABI parameter drift.
- **Broken invariant:** irreversible send and durable idempotency state are atomic or safely recoverable across restart, outage, retry, and concurrency.
- **Concrete sequence:** Crash a relayer after network submission but before durable acknowledgement, restart it, and show whether retry repeats a value effect or loses a claim.
- **Required evidence:** Record durable queue state before and after the crash and the chain outcome for both submissions; distinguish idempotent retries from duplicate effects.
- **Exclusions:** Do not report without a reachable path and material target-specific harm.
- **Recovery:** Trace failure, retry, cancellation, and authorized recovery without duplicating value or authority.
- **Fix family:** Persist a unique source-event key before or atomically with submission, reconcile uncertain sends against chain state, serialize nonce allocation, and make retries idempotent.

### Variants and safe controls

Test lost subscriptions, database outages, skipped heights, unsynced providers, stale submissions exhausting quotas, restart, and retries after ambiguous remote success. Persist progress only at the intended confirmation boundary; distinguish durable acknowledgements from merely appending an error or marking a task finished.

## NA-OFFCHAIN-003 — Unsafe off-chain input or authorization reaches a dangerous sink

- **Kind:** security
- **Root cause:** Unsafe off-chain input or authorization reaches a dangerous sink.
- **Activation:** string-interpolated SQL, source/client-side password authorization, unsafe callback URL, public mutation route, or production mock/test endpoint.
- **Broken invariant:** attacker-controlled requests, chain-derived data, URLs, SQL values, secrets, and administrative subjects are parsed, authenticated, and constrained before sensitive effects.
- **Concrete sequence:** Pass attacker-controlled API, wallet, or event data through the authentication and parsing boundary into a privileged database, command, or signing action.
- **Required evidence:** Show the untrusted input, missing validation or escaping, reached sink, and unauthorized action or data exposure; reject speculative injection labels.
- **Exclusions:** Do not report without a reachable path and material target-specific harm.
- **Recovery:** Trace failure, retry, cancellation, and authorized recovery without duplicating value or authority.
- **Fix family:** parameterized queries, server-side secret/role enforcement, scheme/host/network URL policy, exact subject authorization, and production route removal.

## NA-OFFCHAIN-004 — Dependency/build/release configuration changes security semantics

- **Kind:** security
- **Root cause:** Dependency/build/release configuration changes security semantics.
- **Activation:** dependency, macro, toolchain, feature, release-profile, or deployment inputs can change security-relevant build or runtime behavior.
- **Broken invariant:** audited source equals built Wasm and release behavior; dependencies/macros/toolchain do not silently alter exports, arithmetic, serialization, or standards behavior.
- **Concrete sequence:** Resolve the production dependency, macro, feature, compiler, and release-profile inputs; exercise a security-sensitive path under the built artifact, or trace a mutable tool through the actual release pipeline.
- **Required evidence:** Show the effective build inputs and reachable change to authorization, exports, arithmetic, serialization, or other protected behavior, or prove an altered release input can affect production output. A stale version label alone is insufficient.
- **Exclusions:** Keep release-tooling scope separate from runtime contract scope; a hypothetical unused script is not deployment evidence.
- **Recovery:** Retain reproducible provenance and a rollback or replacement procedure for a bad artifact.
- **Fix family:** Pin and verify inputs, configure and test effective release semantics, compare generated ABI and built artifacts with reviewed source, retain reproducible provenance, and enforce release authorization.

### Variants and safe controls

Resolve effective workspace/package profiles, release overflow behavior, macro/serializer versions, generated exports, feature flags, and source-to-Wasm reproducibility. Mutable host installers and release actions remain separate from pinned container inputs. A stale dependency label is not proof of a reachable exploit.

## NA-OFFCHAIN-005 — Missing or incomplete security tests

- **Kind:** quality_only
- **Root cause:** Missing or incomplete security tests.
- **Activation:** tests omit material lifecycle, failure, authorization, or boundary scenarios, or use mocks with different production semantics.
- **Broken invariant:** Security tests exercise the relevant production authority, state transitions, failure boundaries, and expected outcomes without silently replacing them with permissive mocks.
- **Concrete sequence:** Compare a material production path with its tests; introduce or identify a failing authorization, callback, or boundary condition and determine whether the suite exercises and detects it.
- **Required evidence:** Identify the omitted path, permissive mock, unexecuted test, or incorrect oracle and its coverage consequence. Missing tests alone do not establish a production exploit.
- **Exclusions:** Equivalent coverage elsewhere or a justified nonapplicable path can exclude the gap. Test counts and implementation-mirroring assertions alone do not measure security coverage.
- **Recovery:** Add a realistic failing scenario and a safe control, then confirm both run under representative production semantics without inventing exploit execution.
- **Fix family:** Exercise real authorization, receipt failures, lifecycle transitions, and boundary values with independent assertions and realistic integration fixtures; keep unsupported security claims in the quality ledger.

### Variants and safe controls

Evaluate whether tests exercise real callback failure, production authorization, supported encodings, high-value ranges, and complete lifecycle paths. Mocks that bypass onboarding or duplicate implementation formulas do not validate production behavior. Missing tests remain quality-only unless an independent defect is demonstrated.

## NA-OFFCHAIN-006 — Missing or inconsistent security observability

- **Kind:** quality_only
- **Root cause:** Missing or inconsistent security observability.
- **Activation:** security-relevant events or diagnostics are absent, inconsistent with committed state, or insufficient to distinguish actionable bounded failures.
- **Broken invariant:** Events and diagnostics represent committed security-relevant state with correct origin, type, units, version, and ownership while preserving confidentiality and resource bounds.
- **Concrete sequence:** Execute success, failure, migration, and authority changes; compare emitted or absent events and diagnostics with committed state and the actual consumers that rely on them.
- **Required evidence:** Show the missing or misleading observation and its concrete monitoring, recovery, or integration consequence. Prove downstream reliance before promoting an event defect to security impact.
- **Exclusions:** Intentional size limits and the absence of an event merely because time passes are not defects by themselves. Missing logs without a security consequence remain quality-only.
- **Recovery:** Reconcile missed or ambiguous observations from authoritative state, retaining bounded correlation IDs without leaking secrets or causing duplicate downstream effects.
- **Fix family:** Emit accurate versioned events at the appropriate commit boundary, expose bounded actionable failure reasons, and test consumer compatibility across failure and migration.

### Variants and safe controls

Compare event type, origin, units, version, and ownership metadata with committed state across migration and failed receipts. Missing logs are quality-only unless a real settlement, cache, or monitoring control relies on them. Passing time alone does not emit a contract event; expiry monitoring must distinguish timely inclusion from late proof submission.

## NA-OFFCHAIN-007 — Documentation or specification is incomplete

- **Kind:** quality_only
- **Root cause:** Documentation or specification is incomplete.
- **Activation:** documentation or operational assumptions disagree with actual entrypoints, authority, units, receipt outcomes, policy, or recovery.
- **Broken invariant:** Documented methods, authority, units, trust assumptions, timing, receipt outcomes, and recovery instructions agree with the implemented and deployed behavior.
- **Concrete sequence:** Follow the documented setup, operation, failure, and recovery steps against the actual ABI and receipt graph; identify stale names, incorrect permissions, or claims of rollback or credit that do not occur.
- **Required evidence:** Cite the conflicting documentation and implementation plus the operational consequence. Distinguish an actual refund or lost-and-found credit from permission to retry.
- **Exclusions:** Intentional immutability, optional restrictions, unsupported features, and disclosed centralization are not independent runtime exploits. Documentation drift stays quality-only without separately proven security harm.
- **Recovery:** Document the actual owner, user, or relayer action for each failure outcome and verify that the steps preserve rights rather than repeating an already committed effect.
- **Fix family:** Correct and test examples, ABI names, units, authority, defaults, policy, and receipt-level recovery instructions against the supported version.

### Variants and safe controls

Compare documented entrypoints, roles, trust assumptions, units, delays, and recovery with the actual ABI and receipt graph. Distinguish returned credit from permission to retry. Do not convert centralization, unsupported features, or intentional immutability into a runtime exploit without a violated target guarantee.

## NA-OFFCHAIN-008 — Non-material code quality or efficiency issue

- **Kind:** quality_only
- **Root cause:** Non-material code quality or efficiency issue.
- **Activation:** The target implements the interface or state transition named in this card, and an untrusted actor can reach it.
- **Broken invariant:** The documented authorization, accounting, and state transition remain consistent.
- **Concrete sequence:** No attack is presumed: compare behavior before and after the code-quality issue and promote it only if a separate, reachable security invariant fails.
- **Required evidence:** Record the exact code path and any proven material effect; style, efficiency, or missing tests alone stay quality-only.
- **Exclusions:** Do not report without a reachable path and material target-specific harm.
- **Recovery:** Trace failure, retry, cancellation, and authorized recovery without duplicating value or authority.
- **Fix family:** Keep the issue in the quality ledger unless an independently demonstrated material invariant fails; repair the specific defect only after that causal path is known.

## NA-OFFCHAIN-009 — Bind release artifacts to reviewed inputs

- **Kind:** quality
- **Root cause:** An off-chain component crosses an untrusted data or operational boundary without maintaining chain-linked state.
- **Activation:** Deployment or release tooling consumes external tools or mutable build inputs; Those inputs can affect shipped artifacts
- **Broken invariant:** Released artifacts correspond to the reviewed source and intended build inputs.
- **Concrete sequence:** Trace a mutable download or unpinned tool through the build and release pipeline.
- **Required evidence:** Establish the actual release path, integrity controls, and ability of an altered input to affect production output.
- **Exclusions:** Keep release-tooling scope separate from runtime contract scope; a hypothetical unused script is not deployment evidence.
- **Recovery:** Retain reproducible provenance and a rollback or replacement procedure for a bad artifact.
- **Fix family:** Pin and verify build inputs, retain artifact provenance, and enforce release authorization.

## NA-OFFCHAIN-010 — Expose useful diagnostics without removing bounds

- **Kind:** quality
- **Root cause:** An off-chain component crosses an untrusted data or operational boundary without maintaining chain-linked state.
- **Activation:** Responses or operations have intentional bounds; Failures do not expose enough information for correct recovery
- **Broken invariant:** Callers and operators can distinguish actionable failures while resource and confidentiality bounds remain enforced.
- **Concrete sequence:** Trigger a bounded-response or validation failure and inspect the information available to recover.
- **Required evidence:** Show the actual recovery or monitoring gap, not merely the existence of a limit.
- **Exclusions:** Intentional size limits are not defects by themselves; weak error text is usually quality work absent concrete security impact.
- **Recovery:** Support bounded diagnostics and correlated operation identifiers without leaking secrets or amplifying output.
- **Fix family:** Return stable bounded error reasons and safe correlation metadata.

## NA-OFFCHAIN-011 — Distinguish validity deadlines from observation deadlines

- **Kind:** quality
- **Root cause:** An off-chain component crosses an untrusted data or operational boundary without maintaining chain-linked state.
- **Activation:** An operation has an execution-validity deadline; Operators or clients must observe status and may submit evidence later
- **Broken invariant:** Monitoring reflects actual validity, and late observation does not incorrectly invalidate timely completed work.
- **Concrete sequence:** Complete just before expiry and deliver evidence after expiry; also inspect an operation that never completed.
- **Required evidence:** Pin clock or height semantics, inclusion versus observation rules, and exposed status.
- **Exclusions:** Expiry may constrain execution but not later proof submission; status visibility alone is generally a quality concern.
- **Recovery:** Make expired work visible and recoverable without releasing resources consumed by a timely completion.
- **Fix family:** Expose deadlines and states and validate evidence against the correct event time.

## NA-OFFCHAIN-012 — Keep documented recovery aligned with implemented states

- **Kind:** quality
- **Root cause:** An off-chain component crosses an untrusted data or operational boundary without maintaining chain-linked state.
- **Activation:** Users or operators depend on recovery instructions; Documentation may describe an obsolete failure branch
- **Broken invariant:** Operational guidance describes reachable recovery behavior for the reviewed version.
- **Concrete sequence:** Follow the documented recovery after the actual failure path and compare resulting state.
- **Required evidence:** Trace implementation and tests; distinguish a retryable pending operation from a separately credited claim.
- **Exclusions:** Documentation mismatch alone is a quality finding unless it causes demonstrable security or operational harm.
- **Recovery:** Update instructions and examples after semantic changes and preserve guidance for supported old versions.
- **Fix family:** Document exact failure states, authorized recovery actions, and prerequisites, backed by tests.
