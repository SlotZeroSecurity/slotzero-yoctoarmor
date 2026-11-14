# NEP Process and Legacy Attacker Checklists

## NEP-0001 — NEP Purpose and Guidelines

- **Trigger / attacker:** always account for this document; it governs proposal lifecycle, not target execution.
- **Invariant:** process metadata is never mistaken for an activated runtime or contract requirement.
- **Probe:** check whether the audit or target treats Draft/New text as deployed behavior, or silently ignores an applicable Approved/Final replacement.
- **Conformance:** record `process_only`; preserve status, dependency, and source-commit provenance.
- **Gate / verify:** no target security finding can cite NEP-0001 alone. Report only provenance or review-process blockers.

## NEP-0021 — Legacy Fungible Token Standard

- **Trigger / attacker:** legacy allowance/escrow exports or an explicit NEP-21 compatibility claim; an attacker exploits stale allowance or asynchronous external-state assumptions.
- **Invariant:** legacy integrations cannot bypass NEP-141-era authorization, storage, transfer-call, or refund invariants.
- **Probe:** identify old allowance methods, escrow races, mixed NEP-21/141 ABI, stale approvals, and adapters that treat remote balance views as current state.
- **Conformance:** mark `superseded`; NEP-141 is the current baseline. Record legacy behavior only when it remains reachable or relied upon.
- **Gate / verify:** refute when no legacy exports/state/adapters are reachable. Use integration traces for mixed-standard paths; compatibility-only remnants are not vulnerabilities.
