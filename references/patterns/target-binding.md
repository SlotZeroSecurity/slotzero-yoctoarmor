# Bind mechanisms to the target

Use this protocol only in corpus-informed L1 and post-discovery corpus echo.
Do not give it, the mechanism library, source ledgers, or exercise answers to
L0, L2, blind L3, or NEP-only discovery. No additional discovery phase is needed.

The [mechanism library](attack-lenses-index.json) is the primary representation of
the lessons. [Historical source cards](../sources/issues/omnibridge-satoshi/findings.md) preserve specific
implementations and discussions. Read examples only after forming a
target-grounded mechanism hypothesis; do not require the target to contain the
example's API, terminology, or architecture.

## Three layers

1. **Mechanism:** invariant, required behaviors, causal sequence, recovery,
   exclusions, and fix family expressed independently of an implementation.
2. **Target binding:** identify concrete actors, state, effects, execution
   boundaries, policy, and code paths satisfying the mechanism's prerequisites.
3. **Evidence:** demonstrate that sequence and harm in the target, compare a
   safe control, and adjudicate all reachable recovery paths. Source reports are
   provenance, not a substitute for this evidence.

The library is portable; the NEAR controller, its surface extraction, and NEP
checks remain specialized. Do not claim that adding these cards turns the
controller into a scanner for every language or runtime. Outside NEAR, use an
appropriate review workflow and independently establish execution semantics.

## Binding checklist

For each selected card, collect the following in working notes and the existing
candidate evidence fields where a candidate is justified. No new run artifact
or finding-schema field is required.

| Binding | Questions to resolve from the target |
|---|---|
| Actors and trust | Who can initiate, interleave, rotate, cancel, recover, or forge a result? Which prerequisites require privileged or compromised components? |
| Resources and ownership | What is reserved, consumed, produced, credited, or returned? Who owns the remainder? Which identifiers, units, and generations must remain immutable? |
| State and authority | Which records, counters, indexes, replay markers, claims, credentials, and externally usable authorizations must change together? |
| Execution and atomicity | Which effects commit together? Can callbacks, transactions, threads, workers, queues, external services, or reentrant calls interleave? What actually rolls back on failure? |
| Outcomes and delivery | What does the interface return? Is delivery at-most-once, at-least-once, or ambiguous? Does transport success imply business success? Can partial completion occur? |
| Time and readiness | What does expiry constrain: admission, execution, inclusion, observation, or proof submission? Does accepted mean usable? Which clock and boundary convention apply? |
| Configuration and policy | Which options are restrictions versus permissions? Are disabled modes, subsidies, revocation rules, and operator review intentional? What is promised to the user? |
| Limits and costs | Which size, action, time, memory, storage, and quota bounds apply to this exact environment? Who funds marginal work and who can clean it up? |
| Recovery and harm | What can complete, compensate, revoke, retry, or repair the operation? Does the actual effect reach another principal or violate a documented guarantee? |

Map behavior through implementation and call graphs, not a fixed keyword list.
Different names can implement the same invariant; identical names can have
different semantics. Candidate selection must not require a particular project,
asset, endpoint name, chain, or historical severity label. Example contexts are
teaching aids, not an allowlist of supported applications.

For a portable card, its own prerequisites determine applicability. A legacy
canonical tag such as `NA-INTEGRATION-003` records its catalog lineage; it does not
add a requirement that the target be a bridge. Select the matching mechanism
from target behavior, then carry its existing canonical tag for compatibility.
Other runtime-specific catalog checks still require their own runtime-specific
prerequisites; this rule does not make every legacy check universal.

## Applicability decisions

- **Applicable:** every required predicate has target evidence, including the
  relevant interleaving or failure boundary. This licenses investigation, not
  publication or a severity.
- **Not applicable:** a prerequisite is absent or a verified control rules out
  the causal sequence. Record the specific absence or control rather than
  forcing the historical exploit onto the target.
- **Unresolved:** a required fact is unknown. Seek the exact configuration,
  dependency, deployment, or execution evidence; preserve uncertainty and use
  the existing candidate/judging dispositions. Do not count it as a confirmed
  finding.

For each applicable mechanism: construct the smallest reachable sequence, trace
all commits and rollbacks, compare an otherwise equivalent safe control, then
exercise recovery and repeated delivery. State the broken invariant and
demonstrated harm using the target's own symbols. Quality and policy cards stay
quality or policy observations unless concrete security impact is established.

## Runtime-specific checks are adapters, not universal rules

| Source-specific concept | Portable question | Required target check |
|---|---|---|
| Promise receipt or callback | Can an effect commit before acknowledgement or accounting? | Determine actual transaction, queue, service, and retry boundaries. A single atomic transaction may exclude the sequence. |
| Mint, burn, backing, or refund | Do effects, liabilities, inventory, and claims reconcile? | Bind actual units, ownership, result semantics, and conservation equations. |
| Outpoint or replay marker | What identifies a logical effect and prevents duplication? | Inspect actual uniqueness enforcement, persistence, and cleanup behavior. |
| Token cutover | Can resource identity or state generation change while work is pending? | Bind the original asset, account, namespace, version, or deployment epoch. |
| Orchard authorization | Is readable input semantically valid and authorized? | Use the target's actual proof, signature, capability, or integrity verifier. Do not introduce cryptography where none is required. |
| Coinbase maturity | Is accepted state usable for the next operation? | Enforce the actual settlement hold, maturity, readiness, or finality predicate. |
| One-yocto guard or signer/predecessor | Which credentials and principals can perform the action? | Use the target's real capability and identity model; do not prescribe NEAR payment guards elsewhere. |
| Gas, receipt actions, storage stake | What limits and prices bound supported work? | Derive current limits from the reviewed target/runtime; no universal numeric constants. |

Never transplant rollback, finality, signature revocation, expiry, consensus,
credential, or fee semantics from the historical project. A source mitigation
may be inapplicable to another runtime. Prefer a fix family until the target's
constraints justify a concrete implementation.

## Maintenance and testing

Keep source dispositions and canonical mappings intact when adding new examples.
Generalization must preserve the distinct causes: admission versus cleanup,
execution authority versus local records, overlapping operations versus live
snapshot mutation, and bookkeeping failure versus business-effect failure.

Use informed examples from different application domains, renamed APIs, atomic
safe controls, and missing-prerequisite cases to review transferability. Static
fixtures and reference/routing tests do not measure model recall or establish
exploit reproduction. Claims of broader detection need independent target
evaluations and actual runtime/token telemetry.
