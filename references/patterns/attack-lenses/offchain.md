# Offchain attack lens

Activate only when target code exposes the stated behavior. Historical sources are examples, not target evidence.

## NA-OFFCHAIN-001 — Indexer trusts failed, foreign, or malformed chain data

- **Kind:** security
- **Root cause:** Indexer trusts failed, foreign, or malformed chain data.
- **Activation:** substring contract match, tx acceptance without receipt checks, untrusted decode with panic, optimistic data used for irreversible payout, or failed outcome args/logs are ingested.
- **Broken invariant:** only exact, successful, relevant finalized receipt outcomes mutate off-chain business state.
- **Concrete sequence:** Feed an indexer a failed receipt, foreign contract event, or malformed amount that resembles a deposit; trace whether it credits spendable user balance.
- **Required evidence:** Trace the finality and execution-status checks, source account/contract binding, parser result, and resulting credit against a rejected control event.
- **Exclusions:** Do not report without a reachable path and material target-specific harm.
- **Recovery:** Trace failure, retry, cancellation, and authorized recovery without duplicating value or authority.
- **Fix family:** Authenticate exact source contract and event type, require finalized successful receipts, parse bounded amounts fallibly, and gate credits on durable event IDs.

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
- **Activation:** Deployment or release tooling consumes external tools or mutable build inputs
- **Broken invariant:** audited source equals built Wasm and release behavior; dependencies/macros/toolchain do not silently alter exports, arithmetic, serialization, or standards behavior.
- **Concrete sequence:** Trace a mutable download or unpinned tool through the build and release pipeline.
- **Required evidence:** Establish the actual release path, integrity controls, and ability of an altered input to affect production output.
- **Exclusions:** Keep release-tooling scope separate from runtime contract scope; a hypothetical unused script is not deployment evidence.
- **Recovery:** Retain reproducible provenance and a rollback or replacement procedure for a bad artifact.
- **Fix family:** Pin and verify build inputs, retain artifact provenance, and enforce release authorization.

## NA-OFFCHAIN-005 — Missing or incomplete security tests

- **Kind:** quality_only
- **Root cause:** Missing or incomplete security tests.
- **Activation:** Responses or operations have intentional bounds
- **Broken invariant:** Callers and operators can distinguish actionable failures while resource and confidentiality bounds remain enforced.
- **Concrete sequence:** Trigger a bounded-response or validation failure and inspect the information available to recover.
- **Required evidence:** Show the actual recovery or monitoring gap, not merely the existence of a limit.
- **Exclusions:** Intentional size limits are not defects by themselves; weak error text is usually quality work absent concrete security impact.
- **Recovery:** Support bounded diagnostics and correlated operation identifiers without leaking secrets or amplifying output.
- **Fix family:** Return stable bounded error reasons and safe correlation metadata.

## NA-OFFCHAIN-006 — Missing or inconsistent security observability

- **Kind:** quality_only
- **Root cause:** Missing or inconsistent security observability.
- **Activation:** Responses or operations have intentional bounds
- **Broken invariant:** Callers and operators can distinguish actionable failures while resource and confidentiality bounds remain enforced.
- **Concrete sequence:** Trigger a bounded-response or validation failure and inspect the information available to recover.
- **Required evidence:** Show the actual recovery or monitoring gap, not merely the existence of a limit.
- **Exclusions:** Intentional size limits are not defects by themselves; weak error text is usually quality work absent concrete security impact.
- **Recovery:** Support bounded diagnostics and correlated operation identifiers without leaking secrets or amplifying output.
- **Fix family:** Return stable bounded error reasons and safe correlation metadata.

## NA-OFFCHAIN-007 — Documentation or specification is incomplete

- **Kind:** quality_only
- **Root cause:** Documentation or specification is incomplete.
- **Activation:** Membership and restriction configuration have independent lifecycles
- **Broken invariant:** Acceptance matches the documented meaning of membership, optional constraints, and retained policy.
- **Concrete sequence:** Remove a restriction, remove membership, and reactivate membership in different orders; compare resulting access.
- **Required evidence:** Establish whether a rule grants permission or narrows existing permission, whose resources are affected, and intended defaults.
- **Exclusions:** An absent optional restriction is not missing authorization. Automatically clearing retained restrictions may broaden access.
- **Recovery:** Check explicit policy removal and membership enforcement independently.
- **Fix family:** Document and test defaults and lifecycle semantics; require a rule only when the target's policy requires it.

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
