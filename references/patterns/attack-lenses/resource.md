# Resource attack lens

Activate only when target code exposes the stated behavior. Historical sources are examples, not target evidence.

## NA-RESOURCE-001 — Attacker-induced storage is unpaid or underpriced

- **Kind:** security
- **Root cause:** Attacker-induced storage is unpaid or underpriced.
- **Activation:** public/hook methods grow state for free, use constants/partial key sizes, subsidize third-party storage deposits, let a caller choose a fee or deposit charged to a shared relayer/storage account, permit Sybil records, or let an attacker repeat individually cheap writes whose storage stake is borne disproportionately by the contract.
- **Broken invariant:** the responsible principal pays actual worst-case marginal storage, while contract storage stake, liquid NEAR, and refundable user storage-deposit liabilities remain separately solvent and correctly accounted.
- **Concrete sequence:** Pause A after its check, admit B against the same capacity, then complete both.
- **Required evidence:** identify the actual payer versus the controlling caller/beneficiary; measure byte delta or attached fee, marginal attacker gas/deposit per addition, marginal shared-payer stake/liquidity loss, profitable/reasonable repetition count, user deposit liability, excess-deposit behavior, cleanup behavior, and realistic exhaustion/bloat consequence. Self-funded overpayment without a victim is not this pattern.
- **Exclusions:** An atomic conditional allocation or serializable transaction may already prevent the schedule. Bounded over-admission is not proof of unbounded denial of service.
- **Recovery:** Fail and retry either operation; release only its own reservation and reconcile quota and storage.
- **Fix family:** tightly scoped before/after measurement with current `env::storage_byte_cost()`, bounded inputs, responsible-principal-funded growth, explicit refund/credit of excess, and a documented deletion/refund policy; implement NEP-145 semantics when exposing the storage-management interface. Deleting bytes unlocks balance to the contract and does not by itself refund the user.

## NA-RESOURCE-002 — Persistent prefix collision or orphaned nested state

- **Kind:** security
- **Root cause:** Persistent prefix collision or orphaned nested state.
- **Activation:** raw string concatenation, timestamp/height uniqueness, reused enum prefix, or removal of a parent record/collection handle without deleting the child collection's prefixed raw keys.
- **Broken invariant:** each persistent collection namespace is injective and parent/child lifecycle stays consistent.
- **Concrete sequence:** Create two nested collections with a colliding storage prefix, write distinct keys, then delete or replace one parent and observe overwritten or unreachable child state.
- **Required evidence:** Show the exact serialized storage prefixes and raw keys, the colliding or orphaned bytes, and the affected retrieval/cleanup path.
- **Exclusions:** Do not report without a reachable path and material target-specific harm.
- **Recovery:** Trace failure, retry, cancellation, and authorized recovery without duplicating value or authority.
- **Fix family:** use typed injective prefixes and bounded/paginated child cleanup before parent deletion. For non-iterable collections such as `LookupMap`, track the keys needed for cleanup or choose a collection/lifecycle design that can delete them; dropping parent metadata alone is not garbage collection.

## NA-RESOURCE-003 — Detached SDK collection loses metadata or aliases state

- **Kind:** security
- **Root cause:** Detached SDK collection loses metadata or aliases state.
- **Activation:** a method constructs `Vector`, `LookupMap`, `UnorderedMap`, `IterableMap`, `LookupSet`, `Lazy`, `LazyOption`, or a similar collection locally with an existing/raw prefix; modifies it without persisting its metadata; or prevents a `near_sdk::store` value from running its version-specific `Drop`/`flush` path through `mem::forget`, static retention, or equivalent control flow.
- **Broken invariant:** every SDK collection's contents, cached writes, and metadata persist through one authoritative field in contract state, with a unique prefix.
- **Concrete sequence:** hidden keys can remain readable by a later collection while length/index metadata says they do not exist, or a successful call can silently lose cached mutations, causing corruption, unexpected reads, bloat, or broken cleanup/migration.
- **Required evidence:** a short-lived collection with a fresh private prefix and no later reader may be harmless; prove aliasing, lost cleanup, accounting drift, or material liveness/storage consequence.
- **Exclusions:** Exclude fresh private prefixes and short-lived collections with no alias, persistent reader, lost cleanup, or material cost.
- **Recovery:** Trace failure, retry, cancellation, and authorized recovery without duplicating value or authority.
- **Fix family:** define collection prefixes with `BorshStorageKey`/typed enums, keep persistent collections as contract-state fields, allow normal `Drop` or call the supported explicit `flush` before bypassing it, clear before replacing, and migrate legacy prefixes explicitly. Confirm the exact SDK collection because caching and flush behavior differ; for example, current `near_sdk::store::LookupSet` writes directly.

## NA-RESOURCE-004 — Native root collection bloats `STATE` and bricks execution

- **Kind:** security
- **Root cause:** Native root collection bloats `STATE` and bricks execution.
- **Activation:** contract state contains attacker-growable native `Vec`, `HashMap`, `HashSet`, `BTreeMap`, `String`, or nested native collections instead of SDK persistent collections.
- **Broken invariant:** root contract state stays bounded enough to deserialize, mutate, and serialize under realistic gas and memory limits.
- **Concrete sequence:** repeated writes make every mutable call load and write an oversized `STATE`, producing denial of service or migration failure.
- **Required evidence:** small fixed-size native fields are normal; prove attacker-controlled growth, production-scale bounds, and a blocked core operation.
- **Exclusions:** Exclude bounded fixed-size native fields and allocations that stay below production limits for all attacker-controlled inputs.
- **Recovery:** Trace failure, retry, cancellation, and authorized recovery without duplicating value or authority.
- **Fix family:** keep small bounded all-at-once fields native; move scalable data to the target SDK's persistent collections, preferring modern `near_sdk::store` for new contracts. Select the least expensive semantics the protocol actually needs: non-iterable lookup collections when enumeration is unnecessary, iterable collections only when required, and ordered/tree structures only for ordering/range behavior. Use `Lazy`/`LazyOption` for large rarely accessed fields where the pinned SDK supports the required mutation lifecycle; they are not constructor-only in current near-sdk. Hard-cap inputs, paginate cleanup/migration, and charge storage for growth.

## NA-RESOURCE-005 — Unbounded work, logs, or state serialization blocks core operations

- **Kind:** security
- **Root cause:** Unbounded work, logs, or state serialization blocks core operations.
- **Activation:** unbounded args/collections, root native collections, unnecessarily iterable/ordered structures, batch iteration, large logs or JSON/Borsh payloads, repeated full serialization, stale gas constants, callback gas starvation, or approval/state admission can grow beyond what a mandatory future revoke/unregister/cleanup operation can process.
- **Broken invariant:** worst-case user-controlled work and full receipt-chain gas stay bounded and resumable.
- **Concrete sequence:** Grow the population beyond an action, payload, time, dependency, or memory limit and attempt smaller batches.
- **Required evidence:** production-like size, attacker cost, exact blocked function/population, duration, and recovery.
- **Exclusions:** unbounded view iteration is usually RPC/client risk unless critical infrastructure or on-chain consumers depend on it.
- **Recovery:** Resume after each batch failure, preserving snapshot identity, processed members, totals, and final activation.
- **Fix family:** hard-bound or paginate work, enforce cleanup feasibility when admitting each new item (for example, cap per-token approvals so `nft_revoke_all` remains executable), choose collection functionality and message serialization from measured target-SDK behavior plus ABI requirements, and profile the full receipt chain. JSON is the normal interoperable external ABI; use Borsh overrides only when every caller/callee agrees exactly and the benefit matters. Allocate explicit worst-case gas to value-sensitive callbacks and their failure cleanup instead of relying on whatever gas remains.

## NA-RESOURCE-006 — Make mandatory bulk work bounded and resumable

- **Kind:** security
- **Root cause:** Admission accepts work without reserving or bounding the resources needed to finish or recover it.
- **Activation:** A required operation processes a growing population in one execution; Smaller independent executions cannot satisfy its global completion check
- **Broken invariant:** Every supported population can complete the operation within actual execution limits without losing or duplicating work.
- **Concrete sequence:** Grow the population beyond an action, payload, time, dependency, or memory limit and attempt smaller batches.
- **Required evidence:** Derive each actual bound independently and test adjacent boundaries; identify the precise atomic rollback unit.
- **Exclusions:** Do not import fixed limits from another runtime or assume a failed atomic batch commits a prefix.
- **Recovery:** Resume after each batch failure, preserving snapshot identity, processed members, totals, and final activation.
- **Fix family:** Persist bounded, idempotent progress and activate only after complete reconciliation.

## NA-RESOURCE-007 — Assign every accepted surplus to a payer and policy

- **Kind:** security
- **Root cause:** Admission accepts work without reserving or bounding the resources needed to finish or recover it.
- **Activation:** Admission accepts more than a required amount; Success or failure accounts for only the required portion
- **Broken invariant:** Accepted value is consumed, credited, or returned under the documented payment policy.
- **Concrete sequence:** Submit exact and excess amounts on success and each failure path.
- **Required evidence:** Use actual units and configured costs; reconcile payer balances and persistent credits across boundaries.
- **Exclusions:** Intentional disclosed charges are not surplus; self-directed overpayment alone is not third-party theft.
- **Recovery:** Preserve original payer and amount through deferred work; recover failed returns without duplicate credit.
- **Fix family:** Reject excess or persist and refund or credit it according to explicit payer policy.

## NA-RESOURCE-008 — Budget repeated variable-length payloads

- **Kind:** security
- **Root cause:** Admission accepts work without reserving or bounding the resources needed to finish or recover it.
- **Activation:** User-influenced variable-length data is persisted; One logical object is copied into multiple records or responses
- **Broken invariant:** Persistent duplication and processing costs stay within the justified budget for admitted work.
- **Concrete sequence:** Increase payload size and fan-out independently, then exercise write, read, and cleanup paths.
- **Required evidence:** Measure byte, time, memory, and response deltas; establish realistic bounds and actual consumers of the copies.
- **Exclusions:** Intentional bounded redundancy may be necessary. Storage growth is not automatically a security vulnerability without cost or liveness impact.
- **Recovery:** Preserve compatibility for existing records and downstream readers when removing redundant fields.
- **Fix family:** Store shared payloads once, retain only needed fields, bound fan-out, and price or reserve actual costs.

## NA-RESOURCE-009 — Account for old records in new pricing paths

- **Kind:** security
- **Root cause:** Admission accepts work without reserving or bounding the resources needed to finish or recover it.
- **Activation:** Creation or copying consumes metered resources; Legacy objects were stored under a different charging rule
- **Broken invariant:** New allocations are funded under the current policy even when derived from legacy objects.
- **Concrete sequence:** Copy or replace a large legacy record through a newly priced path and compare its charge with actual allocation.
- **Required evidence:** Measure short and long records, old and new formats, all copies, and attached payments or credits.
- **Exclusions:** A documented funded legacy subsidy is not hidden undercharging. New-record correctness does not prove legacy-path correctness.
- **Recovery:** Reconcile deletion refunds and migration credits without double reimbursement.
- **Fix family:** Charge actual deltas, migrate old records with explicit funding, or bound and document the legacy subsidy.

## NA-RESOURCE-010 — Make sponsorship and refund attribution explicit

- **Kind:** policy
- **Root cause:** Admission accepts work without reserving or bounding the resources needed to finish or recover it.
- **Activation:** One principal funds setup or registration for another; The beneficiary may later withdraw or reclaim the funding
- **Broken invariant:** Funding and return flows match the explicit sponsorship policy and its sustainable budget.
- **Concrete sequence:** Sponsor setup, then let the beneficiary release the resource and claim its refundable deposit.
- **Required evidence:** Trace actual payer and refund balances, repeatability, fees, and intended subsidy.
- **Exclusions:** An accepted fee-funded subsidy is not unauthorized theft merely because the beneficiary receives the refund.
- **Recovery:** Reconcile teardown credits without charging one principal and silently refunding another contrary to policy.
- **Fix family:** Document the subsidy or bind refunds to the intended funder; budget repeatable sponsorship.
