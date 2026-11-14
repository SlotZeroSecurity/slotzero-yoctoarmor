# NEP Contract Interface and Event Attacker Checklists

## NEP-0297 — Contract Events

- **Trigger / attacker:** `EVENT_JSON:` logs or an indexer/bridge/monitor that consumes them; hostile contracts and failed receipts can emit deceptive logs.
- **Invariant:** consumers bind a valid event envelope to the exact contract and successful receipt; live state and event data agree.
- **Probe:** malformed JSON, duplicate prefix, wrong standard/version/event, oversized data, event-before-panic, foreign emitter, duplicate/replayed event, and missing event on a critical transition.
- **Conformance:** compare prefix, JSON shape, standard/version/event/data and dependent standard schema exactly.
- **Gate / verify:** a malformed or missing event is security only when a material consumer trusts it. Reconcile receipt outcome, emitter, event identity, and state.

## NEP-0330 — Contract Source Metadata

- **Trigger / attacker:** `contract_source_metadata`, claimed reproducible source, or governance that approves upgrades by source/build identity.
- **Invariant:** metadata identifies the code actually deployed and cannot mislead auditors or upgrade controls.
- **Probe:** wrong standard/version, stale repository/commit, non-reproducible build, metadata function not matching deployed Wasm, and upgrade paths that leave metadata stale.
- **Conformance:** verify the exported view response and pinned source/build fields against the audited artifact.
- **Gate / verify:** absence is normally conformance/quality because adoption is discretionary; escalate only when a security control materially relies on the claim.

## NEP-0452 — Linkdrop Standard

- **Trigger / attacker:** access keys embedded in links, claim/create-account-and-claim exports, FT/NFT/NEAR bundles, or refund paths; the link holder and key generator are adversaries.
- **Invariant:** one limited key claims only its mapped assets at most once, and every partial failure has a bounded refund/recovery path.
- **Probe:** overbroad method allowlists, reused/misbound keys, concurrent claims, invalid account creation, partial multi-asset failure, callback failure, deleted/expired key, and claim-versus-refund races.
- **Conformance:** compare claim methods, key permissions, asset mapping, lifecycle, and supported asset return semantics to the pinned interface.
- **Gate / verify:** inspect actual access-key actions and run sandbox receipt interleavings. A private-link confidentiality warning alone is not a contract vulnerability.
