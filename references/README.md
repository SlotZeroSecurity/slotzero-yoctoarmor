# Reference catalog

Use this catalog to navigate the package or maintain its references. It is not a
worker input bundle. Start audits from [the workflow](workflow/audit-workflow.md),
maintenance from [maintenance](maintenance/maintenance.md), and pattern additions
from [adding patterns](maintenance/adding-patterns.md).

## Reading boundaries

L0/L2 receive neutral schemas and permitted target context. L1 receives the pattern
index, selected lenses, and target-binding guidance. Blind specialist discovery
retains its assigned security-model and official-guidance inputs, without
historical attack lenses or peer results. NEP workers receive their own checklist.
After blind results are frozen, corpus echo can consult selected patterns and
source variants. Verification and reporting receive their phase-specific inputs.
The existing packet permissions and audit workflow remain authoritative.

Sources are bundled to preserve examples, corrections, and duplicate-ingestion
history; no source ledger is proof about a new target. Ordinary workers do not
load every file below. Raw PDFs and full source checkouts remain external inputs.

## Maintenance ownership

Markdown pattern cards own the detailed mechanism. The attack index owns routing
metadata; shared titles and kinds must agree. Source registries own source identity
and disposition. The central Python path module names fixed package locations;
registries retain their existing path conventions and schemas.

This layout changes package hashes. Existing runs require their original package;
new runs use this layout. Never rewrite an existing run's saved hashes.

## Navigation

| File | Purpose | Consumer and permitted phase | Maintenance relationship |
|---|---|---|---|
| [README.md](README.md) | Complete file catalog and reading routes. | Maintainer/operator; navigation only. | Update with every reference move or addition. |
| [usage-guide.md](usage-guide.md) | Installation, command usage, reports, and troubleshooting. | Operator; setup and operation. | Keep examples aligned with CLI and report contracts. |

## Workflow

| File | Purpose | Consumer and permitted phase | Maintenance relationship |
|---|---|---|---|
| [workflow/audit-workflow.md](workflow/audit-workflow.md) | Audit phases, dependencies, worker routing, and completion. | Coordinator; target audit. | Preserve phase and isolation contracts. |
| [workflow/agent-catalog.md](workflow/agent-catalog.md) | Role instructions and bounded prompt sections. | Coordinator/adapter; assigned worker phase only. | Adapter extracts selected sections; never send the entire catalog to neutral workers. |
| [workflow/capability-model.md](workflow/capability-model.md) | L0–L4 evidence model and active-testing/qualification rules. | Coordinator; audit planning and explicit qualification. | Keep artifact requirements aligned with validators. |
| [workflow/review-contract.md](workflow/review-contract.md) | Mandatory specialist, mutation, and follow-up requirements. | Coordinator and assigned specialists; review/testing. | Paired with operator inventory and review-policy checks. |
| [workflow/threat-model.md](workflow/threat-model.md) | How the supplied target threat model is read and applied. | Coordinator and workers; prerequisite, triage, verification. | This is a contract, not a target-specific threat model. |
| [workflow/near-security-model.md](workflow/near-security-model.md) | NEAR execution, identity, asset, and recovery semantics. | Assigned specialists and verification; not L0/L2. | Maintain against reviewed standards and target semantics. |
| [workflow/runtime-adapter.md](workflow/runtime-adapter.md) | Worker events, packets, journal, and observed execution metadata. | Coordinator; dispatch, collection, status/resume. | Keep consistent with worker adapter and journal. |
| [workflow/semantic-pipeline.md](workflow/semantic-pipeline.md) | Target model, frozen inputs, feedback, and informed rescan. | Coordinator; modeling and follow-up. | Preserve metrics-only feedback and bounded-rescan rules. |
| [workflow/mutation-operators.json](workflow/mutation-operators.json) | Supported mutation operators grouped by family. | Mutation worker and validators; active testing. | New operators require implementation and regression review. |

## Patterns

| File | Purpose | Consumer and permitted phase | Maintenance relationship |
|---|---|---|---|
| [patterns/attack-lenses-index.json](patterns/attack-lenses-index.json) | Category membership, metadata, related IDs, and routing paths. | L1, post-blind corpus echo, routing/validation tools. | Detailed mechanisms live in the category Markdown; validate shared metadata. |
| [patterns/target-binding.md](patterns/target-binding.md) | Map reusable mechanisms to concrete target actors and behavior. | L1 and post-blind corpus echo only. | Preserve mechanism → target binding → evidence separation. |
| [patterns/attack-lenses/auth.md](patterns/attack-lenses/auth.md) | Caller, key, privilege, initialization, and authorization mechanisms. | L1 and post-blind corpus echo; selected categories only. | Preserve permanent IDs; follow the adding-patterns procedure. |
| [patterns/attack-lenses/async.md](patterns/attack-lenses/async.md) | Receipt interleaving, settlement, callbacks, retries, and recovery. | L1 and post-blind corpus echo; selected categories only. | Preserve permanent IDs; follow the adding-patterns procedure. |
| [patterns/attack-lenses/account.md](patterns/attack-lenses/account.md) | Balances, liabilities, claims, storage attribution, and shares. | L1 and post-blind corpus echo; selected categories only. | Preserve permanent IDs; follow the adding-patterns procedure. |
| [patterns/attack-lenses/state.md](patterns/attack-lenses/state.md) | Coupled state, lifecycle transitions, migration, and configuration. | L1 and post-blind corpus echo; selected categories only. | Preserve permanent IDs; follow the adding-patterns procedure. |
| [patterns/attack-lenses/econ.md](patterns/attack-lenses/econ.md) | Units, arithmetic, rounding, incentives, and ordering. | L1 and post-blind corpus echo; selected categories only. | Preserve permanent IDs; follow the adding-patterns procedure. |
| [patterns/attack-lenses/resource.md](patterns/attack-lenses/resource.md) | Storage funding, collections, bounded work, gas, and sponsorship. | L1 and post-blind corpus echo; selected categories only. | Preserve permanent IDs; follow the adding-patterns procedure. |
| [patterns/attack-lenses/integration.md](patterns/attack-lenses/integration.md) | Token hooks, interfaces, bridges, proofs, prices, and dependency outcomes. | L1 and post-blind corpus echo; selected categories only. | Preserve permanent IDs; follow the adding-patterns procedure. |
| [patterns/attack-lenses/crypto.md](patterns/attack-lenses/crypto.md) | Encoding, signatures, cryptographic binding, secrets, and attestation. | L1 and post-blind corpus echo; selected categories only. | Preserve permanent IDs; follow the adding-patterns procedure. |
| [patterns/attack-lenses/runtime.md](patterns/attack-lenses/runtime.md) | Runtime charging and consensus/liveness mechanisms. | L1 and post-blind corpus echo; selected categories only. | Preserve permanent IDs; follow the adding-patterns procedure. |
| [patterns/attack-lenses/offchain.md](patterns/attack-lenses/offchain.md) | Indexers, relayers, backend inputs, builds, diagnostics, and quality. | L1 and post-blind corpus echo; selected categories only. | Preserve permanent IDs; follow the adding-patterns procedure. |

## Schemas

| File | Purpose | Consumer and permitted phase | Maintenance relationship |
|---|---|---|---|
| [schemas/finding-schema.md](schemas/finding-schema.md) | Candidates, verdicts, coverage, evidence, and deduplication shapes. | Assigned non-neutral workers and validators; evidence production. | Contains worked examples; never provide to L0/L2. |
| [schemas/neutral-schemas.md](schemas/neutral-schemas.md) | Neutral target-model and L2 output shapes. | L0/L2; independent modeling and discovery. | Keep free of attack examples and historical guidance. |

## Standards

| File | Purpose | Consumer and permitted phase | Maintenance relationship |
|---|---|---|---|
| [standards/neps/nep-registry.json](standards/neps/nep-registry.json) | Pinned proposal inventory, status policy, categories, and mappings. | Coordinator, NEP workers, and coverage validators. | Use explicit maintenance to refresh; no live audit-time refresh. |
| [standards/neps/nep-process-legacy.md](standards/neps/nep-process-legacy.md) | Proposal lifecycle and legacy token checks. | Assigned NEP worker; standards coverage only. | Preserve registry IDs, applicability gates, and target-specific exclusions. |
| [standards/neps/nep-token-assets.md](standards/neps/nep-token-assets.md) | FT/NFT/multi-token, storage, metadata, royalty, and vault checks. | Assigned NEP worker; standards coverage only. | Preserve registry IDs, applicability gates, and target-specific exclusions. |
| [standards/neps/nep-contract-interfaces.md](standards/neps/nep-contract-interfaces.md) | Events, source metadata, and linkdrop checks. | Assigned NEP worker; standards coverage only. | Preserve registry IDs, applicability gates, and target-specific exclusions. |
| [standards/neps/nep-wallet-auth.md](standards/neps/nep-wallet-auth.md) | Wallet, delegated-action, account, and authorization checks. | Assigned NEP worker; standards coverage only. | Preserve registry IDs, applicability gates, and target-specific exclusions. |
| [standards/neps/nep-runtime-resources.md](standards/neps/nep-runtime-resources.md) | Gas, storage, yield/resume, and runtime feature checks. | Assigned NEP worker; standards coverage only. | Preserve registry IDs, applicability gates, and target-specific exclusions. |
| [standards/neps/nep-crypto-host.md](standards/neps/nep-crypto-host.md) | Cryptographic host-function and encoding checks. | Assigned NEP worker; standards coverage only. | Preserve registry IDs, applicability gates, and target-specific exclusions. |
| [standards/neps/nep-protocol-node.md](standards/neps/nep-protocol-node.md) | Sharding, witnesses, scheduling, and validator checks. | Assigned NEP worker; standards coverage only. | Preserve registry IDs, applicability gates, and target-specific exclusions. |
| [standards/official-docs/docs-registry.json](standards/official-docs/docs-registry.json) | Pinned documentation pages, hashes, classifications, and card mappings. | Routing tools and assigned guidance owners. | Paired with review cards; source refresh requires semantic review. |
| [standards/official-docs/review-cards.md](standards/official-docs/review-cards.md) | Documentation-derived attacker questions, tests, and exclusions. | Assigned specialist owners; selected cards only, never L0/L2. | Documentation guidance is not independently a normative standard. |

## Historical sources

| File | Purpose | Consumer and permitted phase | Maintenance relationship |
|---|---|---|---|
| [sources/provenance.md](sources/provenance.md) | Source origins, pins, dispositions, and review limits. | Maintainers; provenance and maintenance. | Keep historical precedent distinct from target evidence. |
| [sources/report-registry.json](sources/report-registry.json) | Exact PDF identity, duplicate-ingestion status, and ledger references. | Ingestion tools, health checks, and post-blind source review. | References are relative to sources/ and must remain contained there. |
| [sources/reports/original-findings-index.json](sources/reports/original-findings-index.json) | Frozen original Markdown report finding index. | Source maintenance and selected historical review. | Rebuild only from intentionally updated explicit source inputs. |
| [sources/reports/findings-2022-2023.md](sources/reports/findings-2022-2023.md) | Historical report observations and mappings for this batch. | Maintainers and selected post-blind corpus echo. | Preserve duplicate/exclusion labels and original source IDs. |
| [sources/reports/findings-2024-2026.md](sources/reports/findings-2024-2026.md) | Later report batches, variants, and review dispositions. | Maintainers and selected post-blind corpus echo. | Retain cross-runtime exclusions; do not equate them with NEAR evidence. |
| [sources/reports/legacy-report-review.json](sources/reports/legacy-report-review.json) | Review accounting for the legacy report collection. | Maintainers and integrity checks. | Retain raw-PDF hashes, mappings, and exclusions. |
| [sources/issues/omnibridge-satoshi/findings.md](sources/issues/omnibridge-satoshi/findings.md) | Readable Omnibridge/Satoshi observation and variant ledger. | L1 or post-blind corpus echo; selected examples after target binding. | Paired with structured findings and review records. |
| [sources/issues/omnibridge-satoshi/findings.json](sources/issues/omnibridge-satoshi/findings.json) | Structured source snapshot, observations, variants, and mappings. | Selected corpus-informed review and integrity checks. | Retain source identities, dispositions, and snapshot hashes. |
| [sources/issues/omnibridge-satoshi/review.json](sources/issues/omnibridge-satoshi/review.json) | Source-review decisions and discussion evidence. | Maintainers and integrity checks. | Must remain consistent with the issue observation registry. |

## Reporting

| File | Purpose | Consumer and permitted phase | Maintenance relationship |
|---|---|---|---|
| [reporting/verification-reporting.md](reporting/verification-reporting.md) | Triage, skeptical verification, severity, confidence, and completion. | Triage/verifier and coordinator; post-discovery review. | Keep evidence gates separate from presentation. |
| [reporting/technical-annex-template.md](reporting/technical-annex-template.md) | Detailed technical-annex structure. | Report author/assembler; reporting. | Output remains technical-annex.md. |
| [reporting/slotzero-report-format.md](reporting/slotzero-report-format.md) | Compact report format and presentation-row requirements. | Report author/renderer; reporting. | Output remains slotzero-report.md. |

## Maintenance

| File | Purpose | Consumer and permitted phase | Maintenance relationship |
|---|---|---|---|
| [maintenance/maintenance.md](maintenance/maintenance.md) | Skill edits, source ingestion/refresh, checks, and qualification. | Maintainers; explicitly selected maintenance route. | No target audit is initialized for maintenance. |
| [maintenance/historical-id-map.json](maintenance/historical-id-map.json) | Translation from historical IDs to permanent active IDs. | Maintenance and integrity checks only. | Never emit historical identifiers in new audit findings. |
| [maintenance/adding-patterns.md](maintenance/adding-patterns.md) | Source review, mechanism comparison, card addition, and validation. | Maintainers; deliberate pattern-library changes. | No automatic learning from audit feedback. |
