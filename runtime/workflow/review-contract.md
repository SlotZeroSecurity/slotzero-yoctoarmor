# Comprehensive review contract

Every scan uses the same review requirements. File selection limits primary scope;
discovery passes repeat independent searches. Neither reduces verification requirements.
The host dispatches workers and runs tests; the controller does not launch AI workers.

## Specialist applicability

Schedule all six specialists in every discovery pass: upgrade-keys, intents-auth,
bridge-relayer, chain-signatures-yield, runtime-consensus, and oracle-freshness.
Surface signals help navigation but absence of a signal is not an N/A decision.
Investigate applicable and uncertain surfaces within the target and permitted context.

Alongside each candidate output, write its assigned `-applicability.json`:
`schema_version: 1`, `role_id`, `discovery_pass` (1–10), `applicability`
(`applicable`, `not_applicable`, `uncertain`, or `blocked`), `rationale`, and
`target_evidence`. Uncertain/blocked rows also require a concrete `limitation`.
N/A rows cannot emit candidates. Every evidence citation has a target-relative
`path`, one-based inclusive `start`/`end`, and an exact complete-line `quote`.
Citations must resolve inside the frozen input snapshot. They establish provenance,
not the semantic truth of the worker's reasoning.

## Mutation inventory

[The operator inventory](mutation-operators.json) defines 52 supported operators
in 17 existing families, derived from [the mutation guidance](capability-model.md).
Review every operator and identify its applicable target locations. Test all
identified sites in isolated copies, never in the audited source. Do not interpret
this finite inventory as every possible mutation of every expression.

`mutation-results.jsonl` uses schema 2: one row per family with `operator_family`,
`applicability`, `rationale`, `mutations_total`, `killed`, `survived`, `blocked`,
`candidate_ids`, and an `operators` list. There is no scan selector.
Each operator appears exactly once in its family and contains:

- `operator_id`: exact ID from the inventory.
- `applicability`: `applicable`, `not_applicable`, or `blocked`.
- `rationale` and `target_evidence`: exact target citations as above.
- `locations`: all identified mutation sites, using the same citation shape.
- `outcomes`: one or more tests covering every listed location, each containing
  `location_index`, `result` (`killed`, `survived`, or `blocked`), `evidence`,
  `evidence_path` (an existing nonempty contained run artifact), and `candidate_ids`.

Evidence artifacts record the changed scratch copy/diff, expected mechanism,
command/seed, actual detector/test outcome, and limitations. A killed mutant needs
candidate evidence and an `adjudication` object with `reviewer`, UTC
`reviewed_at`, and true `mechanism_match` / `path_match`, never a claim
against the unmodified target. Retain those mutation-only candidates in the evidence
artifact, outside target findings and severity totals.

N/A operators have no locations or outcomes and need an evidence-backed reason.
Blocked operators require `blocker`; if no location can be established, record
empty locations/outcomes rather than inventing execution. A known blocked location
requires a blocked outcome with its evidence artifact. Family applicability is
applicable if any operator applies, otherwise blocked if any is blocked, otherwise
N/A. Family counts and candidate IDs must reconcile with the operator outcomes.
A blocked operator without an executable site contributes no fabricated mutant count
but still triggers a report limitation. Validators cannot prove all relevant sites
were identified; agents and human reviewers must assess that coverage.

## Independent follow-up and bounded rescan

Post-discovery pattern review and chain construction each require a fresh host
context and a new worker identity. Preserve corpus-blind discovery isolation.
Every surviving candidate, regardless of severity, proceeds through independent
verification; retain the extra skeptical review for High/Critical findings.

Run exactly one counterexample rescan. Build neutral questions for original rejected,
excluded, and unresolved candidates; include trust-boundary bypasses without passing
rejected conclusions to the worker. Keep input questions and append the review's
`status` (`complete` or `blocked`) and `review_evidence` target citations to each
unresolved-assumption row. New candidates re-enter deduplication and both judging
stages; they do not trigger another rescan.

`rescan-summary.json` uses schema 2, retaining `iteration: 1`, `status`
(`complete` or `blocked`), `input_count`, and `new_candidate_ids`.
The controller derives new Medium-or-higher findings through candidate dispositions
and verified verdicts. Duplicate rediscoveries do not count as new findings.
Blocked/unresolved checks or new Medium+ findings prevent a claim that the stopping
criterion was met; disclose the limitation in both reports. This does not hide the
findings or indefinitely delay a clearly limited draft. Human approval gates remain.

## Version and compatibility

New runs use manifest schema 7 and state schema 4. Older runs are read-only under
this controller and need their original package or a new run directory. Never
rewrite saved hashes or migrate existing evidence. Overhead measurement inputs
and outputs use schema 2 without a scan selector; comparison still requires matching
fixture sets and audit configuration IDs. Existing measurements are not upgraded.
