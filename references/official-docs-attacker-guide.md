# Official NEAR Documentation Attacker Guide

## Purpose and use

These cards are original audit guidance derived from the pinned official-docs
registry. They are not target evidence and, except where a pinned NEP is named,
are not normative requirements. Load only cards selected in `surface.json`.
A documentation mismatch becomes a security candidate only after proving a
reachable attacker, a broken invariant, and material harm. Otherwise record an
advisory or quality observation.

Each card records source and activation, attacker model and invariant, bounded
attack trace, search and test strategy, false-positive gate, and routing. Card
IDs are evidence provenance; canonical pattern IDs remain the deduplication
taxonomy. Its matching machine-readable card record in
`official-docs-registry.json` supplies the exact signal, canonical-pattern,
role, NEP, invariant-family, and mutation-family mappings. An empty mutation
list means no existing mutation operator faithfully models that card; it is not
permission to invent an unrelated mutant.

## Identity, accounts, and key capabilities

### DOC-AUTH-001 — Direct caller, original signer, and beneficiary stay distinct

- **Source / activation:** `smart-contracts/anatomy/environment`, security checklist, and account/receipt pages; activate for exported methods, callbacks, factories, relayers, and meta-transactions.
- **Attacker / invariant:** an intermediary contract or relayer controls the immediate call; every privileged transition authorizes the intended principal and credits/refunds the intended beneficiary.
- **Attack trace:** an origin-based `signer_account_id` check survives an attacker-controlled intermediate receipt, or callback code treats the contract predecessor as the original user.
- **Search / probes:** inventory `signer_account_id`, `predecessor_account_id`, `current_account_id`, persisted principals, refund recipients, and every caller-to-beneficiary substitution; test direct, proxied, self-callback, and relayed calls.
- **Gate / verify:** signer checks are valid when the policy explicitly concerns the original transaction signer. Prove the unintended intermediary path and terminal authority or value change.
- **Routes:** `entrypoints-auth`, `async-promises`; `NA-AUTH-001`, `NA-ASYNC-003`; `INV-AUTH-*`, `INV-CALLBACK-*`.

### DOC-KEY-001 — One yocto proves deposit capability, not authorization

- **Source / activation:** `smart-contracts/security/one_yocto` and access-key pages; activate for transfers, withdrawals, approvals, ownership/permission changes, and other confirmation-sensitive methods.
- **Attacker / invariant:** a third-party application holds an allowed function-call key; the method must require both the intended account authority and, where policy requires it, a deposit-capable confirmation path.
- **Attack trace:** ownership by predecessor passes, but a delegated application triggers the action without wallet confirmation; or an intermediary attaches one yocto to a child receipt and the contract mistakes that for original-user approval.
- **Search / probes:** verify `#[payable]`, exact one-yocto enforcement, owner/role checks, and which key actually signs; test zero, one, excess, function-call-key, full-access-key, and intermediary-funded paths.
- **Gate / verify:** not every sensitive method needs one yocto. Establish the product's confirmation/key-capability policy and retain independent RBAC.
- **Routes:** `entrypoints-auth`; `NA-AUTH-003`; `INV-AUTH-*`; mutation `access-macro-removal`.

### DOC-KEY-002 — Access-key permissions, budgets, and lifecycle cannot strand or drain authority

- **Source / activation:** `protocol/accounts-contracts/access-keys`; pin protocol/SDK support before applying gas-key rules.
- **Attacker / invariant:** a shared application, relayer, bot, stale administrator, or compromised key controls an allowed key; receiver, methods, gas budget, nonce lanes, balance, and deletion lifecycle remain within policy and recoverable.
- **Attack trace:** omitted method names grant every receiver method; unlimited allowance or a funded gas key sponsors attacker work; exhausted sole function-call keys lock an account; deleting a funded gas key burns residual balance; stale full-access keys bypass new governance; unsafe lane allocation creates replay/race handling errors in clients.
- **Search / probes:** inspect deployed key state plus `AddKey`, `DeleteKey`, gas-key fund/withdraw actions, allowance semantics, `num_nonces`, `nonce_index`, key rotation, and recovery keys. Test exhaustion, deletion, concurrent lanes, mismatched key/nonce variants, and compromised workers.
- **Gate / verify:** protocol-defined small burns and rejected nonce variants are not bugs. Prove application policy, reachable key control, and material loss/lockout/sponsorship.
- **Routes:** `entrypoints-auth`, `upgrade-keys`, `periphery-build`; `NA-AUTH-004`, `NA-ACCOUNT-002`, `NA-STATE-004`; `INV-AUTH-*`.

### DOC-INIT-001 — Deployment, initialization, and authority installation are one safe lifecycle

- **Source / activation:** smart-contract anatomy, deploy, upgrade, factory, and global-contract pages; activate for `#[init]`, factories, subaccounts, key actions, or state replacement.
- **Attacker / invariant:** a first caller or deployment observer races initialization; code, state, keys, and initial roles must become usable in one non-raceable authority transition.
- **Attack trace:** deployment and initialization occur in separate transactions/receipts, an untrusted caller initializes first, `ignore_state` overwrites live state, or a factory installs code without the intended key/role lifecycle.
- **Search / probes:** trace deploy/init action batches, `state_exists`, `#[init(ignore_state)]`, default state, initial principals, key additions/deletions, and retry behavior after partial failure.
- **Gate / verify:** separately initialized accounts can be safe when pre-existing keys or exact predecessor checks make the race impossible.
- **Routes:** `entrypoints-auth`, `upgrade-keys`, `temporal-upgrade`; `NA-AUTH-005`, `NA-AUTH-006`; `INV-AUTH-*`, `INV-MIGRATION-*`.

### DOC-META-001 — Delegated actions bind signer, relayer economics, nonce variant, and validity window

- **Source / activation:** `protocol/transactions/meta-tx` and the meta-transaction relayer tutorial; activate for NEP-366/DelegateV2 or custom sponsored transactions.
- **Attacker / invariant:** a user, relayer, or observer controls a signed delegate payload or submission timing; one authorization executes only its exact actions, receiver, key/nonce lane, and validity window, while sponsor costs stay bounded.
- **Attack trace:** replay or cross-context reuse, gas-key/plain-nonce mismatch in custom handling, reordered sponsor payment, stale max-block-height acceptance, or an attacker consumes relayer gas/deposits without sufficient compensation.
- **Search / probes:** hash/domain fields, sender/receiver, action ordering, nonce and `nonce_index`, `max_block_height`, duplicate cache, fee action, balance prechecks, retry state, and terminal receipt status.
- **Gate / verify:** runtime-rejected malformed delegates are not application findings unless pre-validation or sponsor accounting creates harm.
- **Routes:** `entrypoints-auth`, `intents-auth`, `bridge-relayer`; `NA-AUTH-007`, `NA-OFFCHAIN-002`, `NA-ACCOUNT-002`; `INV-SETTLE-ONCE-*`.

### DOC-WALLET-001 — Wallet/backend challenges resist replay and origin confusion

- **Source / activation:** `web3-apps/backend/backend`, wallet-login, NEAR Auth, and social-login pages; activate for off-chain authentication or passkeys.
- **Attacker / invariant:** an observer or malicious origin controls callback URLs, sessions, or old signatures; authentication binds account, recipient/origin, unpredictable challenge, purpose, expiry, and one-time server state.
- **Attack trace:** reuse a signed challenge across sessions/services, substitute recipient or callback context, accept a stale challenge, or treat account ownership as authorization for a different privileged action.
- **Search / probes:** nonce generation/storage/consumption, recipient/domain, timestamp/expiry, callback allowlist, signature/key lookup, session binding, and error handling.
- **Gate / verify:** frontend examples are not normative; prove the deployed verifier accepts the replay or confused context.
- **Routes:** `entrypoints-auth`, `intents-auth`, `periphery-build`; `NA-AUTH-008`, `NA-OFFCHAIN-003`.

## Receipts, promises, refunds, callbacks, and yield/resume

### DOC-ASYNC-001 — Callback entrypoints authenticate the current contract

- **Source / activation:** `smart-contracts/security/cross-contract-calls/callbacks`; activate for callbacks, resolvers, and result-consuming exports.
- **Attacker / invariant:** a malicious contract can schedule a public method after its own promise; callback authority must be exact self-predecessor or an intentional external allowlist.
- **Attack trace:** attacker arranges successful/failed promise results, invokes an exposed callback with forged operation arguments, and settles value or state.
- **Search / probes:** generated ABI, `#[private]`, predecessor checks, `#[callback_result]`, `#[callback_unwrap]`, `promise_result`, and trait exports; test ordinary direct and attacker-scheduled callback calls.
- **Gate / verify:** result injection and a zero-result panic are not authentication. Prove the forged call reaches a privileged effect.
- **Routes:** `async-promises`, `entrypoints-auth`; `NA-ASYNC-003`, `NA-AUTH-002`; `INV-CALLBACK-*`.

### DOC-ASYNC-002 — Promise success bytes are not business success

- **Source / activation:** cross-contract anatomy, callbacks, FT transfer-call, and transaction execution pages.
- **Attacker / invariant:** a callee controls success bytes, malformed data, or semantic rejection; settlement occurs only after validating result count, status, decoding, and business meaning.
- **Attack trace:** `Successful(bytes)` encodes unused tokens, `false`, stale data, or malformed output, yet caller credits, unlocks, consumes a proof, or reports terminal success.
- **Search / probes:** `promise_results_count`, result index, serializers, `PromiseOrValue`, bool/amount polarity, missing terminal promise, and top-level versus receipt status.
- **Gate / verify:** fire-and-forget is safe when downstream outcome cannot affect value, authority, recovery, or liveness.
- **Routes:** `async-promises`, `token-accounting`; `NA-ASYNC-004`, `NA-ASYNC-009`; `INV-CALLBACK-*`.

### DOC-ASYNC-003 — Failed native calls return funds to the contract, not the original user

- **Source / activation:** `smart-contracts/security/cross-contract-calls/refunds`; activate when attached NEAR or transfers cross receipts.
- **Attacker / invariant:** a failing callee or deleted/unavailable receiver causes native funds to return to the calling contract; the original user's recoverable claim remains exact and operation-bound.
- **Attack trace:** failure refunds the contract balance, but callback omits user compensation, sends it to predecessor/self/wrong account, or lets another operation claim it.
- **Search / probes:** custody matrix for attached deposit and transfers, persisted original payer/beneficiary, callback compensation, retry/claim paths, and direct balance assumptions.
- **Gate / verify:** retained funds can be intentional revenue only with explicit accounting and policy. Prove a user liability is stranded or misdirected.
- **Routes:** `async-promises`, `token-accounting`; `NA-ASYNC-002`, `NA-ACCOUNT-003`; `INV-COMPENSATE-*`, `INV-CONSERVATION-*`.

### DOC-ASYNC-004 — Expected failure cleanup must not panic

- **Source / activation:** `smart-contracts/security/cross-contract-calls/callback-panics`; activate for callbacks that clear locks, restore balances, or refund.
- **Attacker / invariant:** an external failure, malformed return, or boundary input reaches the failure branch; cleanup and compensation complete without panicking or exceeding reserved gas.
- **Attack trace:** callback unwrap/assert/arithmetic/log/storage work panics before clearing pending state or returning value, permanently poisoning an operation.
- **Search / probes:** unwraps/asserts, arithmetic, deserialization, state existence, transfer creation, logs, and low-gas failure paths; inject failed/malformed results and boundary state.
- **Gate / verify:** a panic with no durable pending state or liability is not material. Prove stranded funds, reusable entitlement, or persistent liveness loss.
- **Routes:** `async-promises`, `gas-dos`, `async-state-explorer`; `NA-ASYNC-002`, `NA-ASYNC-005`, `NA-RESOURCE-005`; `INV-COMPENSATE-*`.

### DOC-ASYNC-005 — Reserve outgoing value before dispatch and expose incoming credit after success

- **Source / activation:** `smart-contracts/security/cross-contract-calls/reentrancy`; activate for withdrawals, deposits, loans, mints, and external settlement.
- **Attacker / invariant:** a user calls other public methods while a promise is pending; available, locked, and pending representations cannot spend or credit one entitlement twice.
- **Attack trace:** repeat withdrawal before callback because debit is late, or withdraw an optimistic deposit credit and also receive the external-call failure refund.
- **Search / probes:** state at dispatch, duplicate/concurrent calls, same-account/asset locks, success credit, exact failure restoration, and idempotent operation tokens.
- **Gate / verify:** checks-effects-interactions is not a syntactic rule; model the actual receipt invariant and compensation path.
- **Routes:** `async-promises`, `async-state-explorer`, `invariant-synthesis`; `NA-ASYNC-001`, `NA-ASYNC-002`; `INV-PENDING-*`, `INV-SETTLE-ONCE-*`.

### DOC-ASYNC-006 — Gas and returned promise cover the full terminal operation

- **Source / activation:** cross-contract anatomy, best practices, transaction execution, and gas pages.
- **Attacker / invariant:** user-controlled work or a callee consumes gas; every required receipt has enough gas for success and failure, and callers relying on completion observe the terminal promise.
- **Attack trace:** external action succeeds but callback starves; failure cleanup cannot run; or relayer/indexer sees only an initiating receipt and retries a still-running operation.
- **Search / probes:** static gas, unused gas weights, exact-minimum checks, `.then`/`.and`, callback complexity, terminal `Promise` return, and RPC finality/status assumptions.
- **Gate / verify:** fixed gas numbers are version-specific and intentional fire-and-forget may be safe. Measure the pinned runtime and dependent consumer behavior.
- **Routes:** `async-promises`, `gas-dos`, `periphery-build`; `NA-RESOURCE-005`, `NA-ASYNC-004`.

### DOC-YIELD-001 — Yield identifiers and resume payloads are operation-bound and terminal

- **Source / activation:** `smart-contracts/anatomy/yield-resume`; require feature/runtime activation evidence.
- **Attacker / invariant:** an external responder, concurrent requester, or timeout controls resume timing/data; each yield ID binds requester, purpose, payload schema, responder authority, expiry, and exactly one terminal transition.
- **Attack trace:** unauthorized or wrong-operation resume, shared-ID/cursor collision, malformed response, duplicate/late resume after timeout, or timeout cleanup that strands/reassigns state.
- **Search / probes:** `promise_yield_create`, `YIELD_REGISTER`, `promise_yield_resume`, stored request map, responder checks, 200-block timeout handling, deletion, retry, and concurrent requests.
- **Gate / verify:** raw yield APIs intentionally expose IDs to responders; the bug requires missing authority/context/terminal binding with material effect.
- **Routes:** `chain-signatures-yield`, `async-state-explorer`; `NA-ASYNC-008`, `NA-ASYNC-005`, `NA-STATE-004`; `INV-SETTLE-ONCE-*`.

## Storage, collections, gas, serialization, builds, and upgrades

### DOC-STORAGE-001 — Attacker-created state remains fully funded

- **Source / activation:** storage security and storage-staking pages; activate for persistent user-controlled state.
- **Attacker / invariant:** arbitrary accounts can create or enlarge keys, values, indexes, approvals, logs mirrored into state, or nested collections; every positive byte delta has a responsible payer and cannot consume contract solvency.
- **Attack trace:** many cheap registrations/strings/IDs lock the contract's NEAR until transfers/refunds or execution fail.
- **Search / probes:** measure local `storage_usage` before/after all responsible mutations at current byte cost; include worst-case IDs, auxiliary indexes, duplicates, and repeated small additions.
- **Gate / verify:** bounded protocol-funded state can be intentional. Quantify maximum exposure and liquid-balance effect.
- **Routes:** `state-storage`, `gas-dos`; `NA-RESOURCE-001`, `NA-RESOURCE-005`; `INV-STORAGE-*`.

### DOC-STORAGE-002 — Storage payer, beneficiary, liability owner, and refund recipient are explicit

- **Source / activation:** storage security, NEP-145 summaries, and FT registration pages.
- **Attacker / invariant:** caller can register another account or overpay; measured storage backing and refundable principal remain attributed and released exactly once under policy.
- **Attack trace:** beneficiary receives refund owed to payer, global usage charges an unrelated account, deletion unlocks contract balance without settling the recorded user claim, or withdraw updates a ledger without a NEAR transfer.
- **Search / probes:** predecessor versus optional `account_id`, minimum/excess, `registration_only`, already-registered branches, unregister/force, storage withdraw, deletion bytes, and refund transfer.
- **Gate / verify:** standards and product policy may intentionally separate sponsor and beneficiary. Prove deviation from the intended liability/refund policy.
- **Routes:** `state-storage`, `token-accounting`; `NA-ACCOUNT-001`, `NA-INTEGRATION-002`, `NA-ACCOUNT-003`; `INV-STORAGE-*`.

### DOC-STORAGE-003 — Persistent collection identity, metadata, and cleanup remain coherent

- **Source / activation:** state and collections anatomy plus state-cleaner guidance; pin near-sdk version and collection family.
- **Attacker / invariant:** user input grows or removes collection elements; prefixes are unique, cached mutations flush, legacy owned values are reinserted, nested raw keys are deleted, and root `STATE` stays bounded.
- **Attack trace:** prefix collision aliases assets/users, detached collection loses length metadata, mutate-without-reinsert loses authorization/accounting state, parent deletion orphans funded keys, or native maps brick every mutable call.
- **Search / probes:** prefix constructors, `near_sdk::store` versus legacy `collections`, `flush`/Drop/lifetime escapes, `get` mutation semantics, nested handles, `clear`, pagination, and native root collections.
- **Gate / verify:** collection choice alone is not a finding. Demonstrate persistent divergence, collision, uncompensated bytes, or reachable liveness failure.
- **Routes:** `state-storage`; `NA-RESOURCE-002`, `NA-RESOURCE-003`, `NA-RESOURCE-004`, `NA-STATE-001`.

### DOC-GAS-001 — Attacker-controlled work and serialized state stay below terminal gas bounds

- **Source / activation:** gas, storage, collections, serialization, events, and callback pages.
- **Attacker / invariant:** attacker controls collection size, batch length, string/bytes, logs, proof size, or retry count; every essential transition and cleanup remains executable.
- **Attack trace:** grow input/state until withdrawal, unregister, migration, callback, or cleanup exceeds gas/memory limits; repeated rejected calls drain a sponsored key/relayer.
- **Search / probes:** unbounded loops/sorts/serialization/logging, whole-state reads, fan-out promises, proof parsing, batch cardinality, pagination context, and sponsor budgets.
- **Gate / verify:** ordinary caller-paid out-of-gas is not enough. Prove shared liveness, trapped value, subsidy drain, or state that prevents bounded recovery.
- **Routes:** `gas-dos`, `state-storage`, `periphery-build`; `NA-RESOURCE-005`, `NA-RUNTIME-001` only for node-wide boundaries.

### DOC-SERIAL-001 — ABI and signed/state bytes have one canonical interpretation

- **Source / activation:** serialization, functions/types, cross-contract, token-standard, and signing pages.
- **Attacker / invariant:** caller controls JSON/Borsh/base64 bytes or signed payload fields; producer, verifier, callback, frontend, and migrated state agree on one complete typed representation.
- **Attack trace:** large integer loses precision in JSON, serializer mismatch changes callback meaning, ambiguous decoder accepts alternate authority/asset encodings, trailing data is ignored, or upgrade cannot deserialize live `STATE`.
- **Search / probes:** `U64/U128`, `Base64VecU8`, serializer attributes on both sides, optional/null/default fields, complete input consumption, typed account/chain/asset IDs, canonical hashing, and state schema versions.
- **Gate / verify:** Borsh versus JSON is a design choice. Prove two interpretations, interoperability break with material harm, or migration/liveness failure.
- **Routes:** `periphery-build`, `token-accounting`, `temporal-upgrade`; `NA-CRYPTO-001`, `NA-INTEGRATION-002`, `NA-STATE-003`.

### DOC-UPGRADE-001 — Code upgrades and migrations preserve authority and every live liability

- **Source / activation:** update, serialization, deploy, and global-contract pages.
- **Attacker / invariant:** upgrade authority or malformed new code controls deployment/migration; the effective key/contract governance is intended and old state transforms completely once.
- **Attack trace:** public/self-upgrade bypass, stale full-access key redeploys code, layout/prefix change corrupts balances or pending operations, repeatable migration, or separate deploy/migrate receipts leave unusable state.
- **Search / probes:** full-access keys plus programmatic upgrade exports, code input bounds/hash policy, `#[private]`, old/new Borsh layouts, prefixes, enum versions, pending records, rollback, and repeated migration.
- **Gate / verify:** centralized upgrade authority is a trust assumption unless it violates the stated model. Demonstrate bypass or preserved-state failure.
- **Routes:** `upgrade-keys`, `temporal-upgrade`; `NA-AUTH-006`, `NA-STATE-003`; `INV-MIGRATION-*`.

### DOC-GLOBAL-001 — Global-contract reference mode matches the intended update trust

- **Source / activation:** `smart-contracts/global-contracts`; require runtime/protocol activation and actual `use_global_*` actions.
- **Attacker / invariant:** global-contract owner or deploying factory controls referenced code; hash references stay immutable, account references inherit exactly the intended owner-update authority, and consumers can identify the active code.
- **Attack trace:** security-sensitive instances reference an updateable account when users assume immutable code, owner compromise changes every instance, factory selects an unreviewed hash/account, or migration/state compatibility is not maintained across shared updates.
- **Search / probes:** `use_global_account_id`, `use_global_hash`, owner account keys/governance, expected code hash, instance state versions, update/rollback, and event/deployed-hash monitoring.
- **Gate / verify:** account references are intentionally updateable. Report security only when actual trust claims or authority controls are violated.
- **Routes:** `upgrade-keys`, `temporal-upgrade`, `periphery-build`; `NA-AUTH-006`, `NA-STATE-003`, `NA-OFFCHAIN-004`.

### DOC-BUILD-001 — Reviewed source, release configuration, and deployed WASM agree

- **Source / activation:** production-build and deployment pages; activate when artifacts or deployed account evidence are in scope.
- **Attacker / invariant:** dependency/build/release inputs can alter code; the reviewed source and pinned toolchain reproduce the deployed code hash with security-relevant release semantics.
- **Attack trace:** overflow checks/features differ, unpinned dependency or build script changes behavior, unpublished WASM differs from reviewed source, or upgrade tooling deploys the wrong artifact.
- **Search / probes:** workspace-effective release profile, lockfile/features/build scripts, reproducible commands, Wasm normalization, deployed code query/hash, and release provenance.
- **Gate / verify:** size/style flags are quality-only unless they change semantics, limits, or artifact identity.
- **Routes:** `periphery-build`, `temporal-upgrade`; `NA-OFFCHAIN-004`, `NA-ECON-002`.

## Tokens, standards, economic design, and MEV

### DOC-FT-001 — FT receiver admits only intended token contracts and returns unused amount

- **Source / activation:** FT standard/usage and FT transfer-call security pages; activate for `ft_on_transfer`.
- **Attacker / invariant:** arbitrary FT contract and sender choose amount/message; only configured assets create credit, and returned unused amount matches actual consumption.
- **Attack trace:** fake FT predecessor mints internal credit, forged `sender_id` receives authority, or receiver returns used rather than unused amount and breaks settlement.
- **Search / probes:** predecessor allowlist/asset registry, sender versus predecessor, message decoding, zero/full/partial/malformed returns, panic, deposit credit timing, and duplicate calls.
- **Gate / verify:** permissionless multi-asset receivers are valid when token identity remains typed and valued safely.
- **Routes:** `token-accounting`, `async-promises`; `NA-INTEGRATION-001`, `NA-ECON-001`; NEP-141.

### DOC-FT-002 — FT resolver refund is private, capped, and conservation-preserving

- **Source / activation:** FT standard and transfer-call security pages; activate for token resolvers or systems consuming transfer-call outcomes.
- **Attacker / invariant:** receiver can fail, return malformed/excess unused amount, spend balance, or unregister before resolution; refund never exceeds original amount or live receiver balance and supply remains conserved.
- **Attack trace:** public resolver forges settlement, uncapped refund mints/double-credits, failure does not attempt full refund, or bridge finalizes before learning actual used amount.
- **Search / probes:** self-only resolver, original sender/receiver/amount binding, result polarity, min caps, burned/unregistered branches, supply update, and downstream recovery.
- **Gate / verify:** use exact pinned NEP behavior and target token model; do not infer rollback from receiver failure.
- **Routes:** `token-accounting`, `nep-differential`; `NA-ASYNC-009`, `NA-ASYNC-004`; NEP-141.

### DOC-NFT-001 — NFT ownership, approval, receiver, and resolver lifecycles agree

- **Source / activation:** NFT standard/usage pages and NEP-171/178 cards.
- **Attacker / invariant:** owner, approved operator, receiver, or stale marketplace controls transfer state; one live owner and approval set remain authoritative through receiver success/failure and intervening retransfer/burn.
- **Attack trace:** stale/wrong approval ID transfers, approvals survive transfer, resolver overwrites a retransfer/burn, public resolver restores forged ownership, or callback identity confuses sender and previous owner.
- **Search / probes:** exact one yocto, owner/operator authorization, approval counters and cleanup, receiver bool polarity, resolver self-only, retransfer/burn interleaving, mirrors/events, and storage refunds.
- **Gate / verify:** marketplace/indexer cache drift is not contract authority unless a consumer makes it security-critical.
- **Routes:** `token-accounting`, `nep-differential`; `NA-ASYNC-009`, `NA-STATE-001`, `NA-INTEGRATION-002`; NEP-171/178.

### DOC-DUP-001 — Caller-controlled lists cannot multiply benefits without costs

- **Source / activation:** duplicate-input security page; activate for batches of accounts, assets, token IDs, claims, recipients, or positions.
- **Attacker / invariant:** caller repeats or aliases an identifier; benefit occurrences cannot exceed the corresponding entitlement consumption or charge.
- **Attack trace:** pay/burn/reserve once, repeat the same ID in a loop, and receive multiple payouts or state transitions.
- **Search / probes:** define set/multiset semantics, normalize aliases, reject duplicates before effects, compare per-item cost and benefit, and test non-adjacent duplicates plus boundary batch sizes.
- **Gate / verify:** duplicates are safe when every occurrence independently consumes the required resource before benefit.
- **Routes:** `entrypoints-auth`, `token-accounting`; `NA-STATE-004`, `NA-ACCOUNT-002`; `INV-CONSERVATION-*`.

### DOC-MEV-001 — Public profitable inputs tolerate copying, reordering, and selective inclusion

- **Source / activation:** front-running security page, transaction flow, auctions, DEX, and vault pages.
- **Attacker / invariant:** validators/observers see arguments and producers order transactions; rewards, prices, claims, and secrets do not depend on an unprotected first valid submission.
- **Attack trace:** copy a public answer/claim, reorder fee beneficiary or price-sensitive action, sandwich predictable price impact, or replay a reveal across rounds.
- **Search / probes:** first-come rewards, public secrets, slippage/deadlines, tie rules, batch clearing, commit hash domain/account/round, reveal windows, non-reveal/cancellation, and repeated/split actions.
- **Gate / verify:** delay and higher gas are not protocol defenses; quantify ordering profit and applicable producer/observer capability.
- **Routes:** `math-economics`, `trust-gap`; `NA-ECON-003`.

### DOC-MEV-002 — Validator-influenced randomness cannot choose valuable outcomes

- **Source / activation:** randomness security page and environment/runtime pages.
- **Attacker / invariant:** block producer predicts the block seed and can choose transaction input or selectively include resolution; outcome bias stays below the value-at-risk threat model.
- **Attack trace:** producer submits a winning input after seed prediction, or withholds an unfavorable later resolution and retries/opportunistically includes a favorable one.
- **Search / probes:** random seed usage, same-receipt input, staged bet/resolve, who can force resolution, timeout/default, abort/retry economics, entropy mixing, and reward magnitude.
- **Gate / verify:** deterministic/verifiable is not unpredictable to the producer. Prove exploitable bias rather than flagging every random seed use.
- **Routes:** `math-economics`, `runtime-consensus` as supporting context; `NA-ECON-003`.

### DOC-ECON-001 — Account multiplicity does not masquerade as participant uniqueness

- **Source / activation:** Sybil security page plus DAO/social/reward primitives.
- **Attacker / invariant:** one actor controls many accounts; votes, rewards, quotas, reputation, or admission enforce the actual intended participant model at a documented attacker cost.
- **Attack trace:** fund many accounts, satisfy per-account checks, and aggregate influence/rewards beyond independent participants.
- **Search / probes:** every one-account-one-user rule, identity creation/funding cost, snapshots/windows, delegation, token weighting, fees, age/reputation farming, membership, rate limits, and residual bypasses.
- **Gate / verify:** token/fee/age defenses raise cost but do not prove personhood. Compare attacker cost with obtainable benefit and stated assumptions.
- **Routes:** `math-economics`, `trust-gap`; `NA-STATE-004`, `NA-ECON-003` where ordering combines.

### DOC-VAULT-001 — Preview, limit, conversion, and settlement paths share one vault accounting model

- **Source / activation:** tokenized-vault page and NEP-621 card; activate for shares or managed assets.
- **Attacker / invariant:** depositor/redeemer controls timing, amount, receiver, and slippage bounds; previews, maximums, state-changing conversions, external assets, fees, and total managed value agree under one rounding policy.
- **Attack trace:** donation or rounding dilutes users, zero-share deposit transfers assets, preview differs from execution, stale rate permits MEV, async loss/yield is omitted, or slippage/default receiver is misapplied.
- **Search / probes:** zero/one/max values, initial and near-empty supply, conversion direction, rounding, `min_amount_out`/`max_shares`, fee/accrual checkpoints, external balance, pending withdrawals, and partial FT refunds.
- **Gate / verify:** use the activated NEP version and explicit asset model; harmless preview drift is advisory unless it causes value loss or integration failure.
- **Routes:** `token-accounting`, `math-economics`, `invariant-synthesis`; `NA-ACCOUNT-005`, `NA-ECON-002`, `NA-ACCOUNT-004`; NEP-621.

### DOC-ORACLE-001 — External observations are authenticated, fresh, bounded, and failure-safe

- **Source / activation:** oracle, off-chain compute, yield/resume, and integration pages.
- **Attacker / invariant:** provider, responder, RPC, or market participant controls data/timing; every decision binds source, asset/unit, timestamp/round, confidence, bounds, and fallback policy.
- **Attack trace:** stale/wrong-unit price drives liquidation/mint, malformed provider response panics a terminal path, unavailable fan-out freezes state, or resume accepts an unauthorized response.
- **Search / probes:** source allowlist, decimals, timestamp/height, staleness/confidence, zero/negative/outlier data, quorum, circuit breaker, retry/timeout, and cached value updates.
- **Gate / verify:** centralization is a disclosed trust assumption unless the implementation violates it or lacks required bounds/failure behavior.
- **Routes:** `oracle-freshness`, `chain-signatures-yield`; `NA-INTEGRATION-005`, `NA-ECON-001`, `NA-ASYNC-005`.

## Intents, Chain Signatures, OmniBridge, relayers, and external settlement

### DOC-INTENT-001 — Intent and quote authorization binds every execution choice

- **Source / activation:** NEAR Intents overview and applicable external official Intents specification; activate for verifier/solver/1Click flows.
- **Attacker / invariant:** solver, relayer, observer, or partial-bundle executor controls quote and ordering; authorization binds user, assets, amounts/bounds, recipient, chain, verifier, action type, nonce, deadline, fee, and complete bundle semantics.
- **Attack trace:** replay failed sub-intents, substitute solver/callback/recipient, reuse bytes across action types/chains, execute stale quote after price/config change, or make cheap invalid solver input fail a global batch.
- **Search / probes:** canonical signed bytes, domain/version/type, nonce consumption timing, deadline, partial failure, fee beneficiary, callback URL, solver admission, slippage, and cancellation.
- **Gate / verify:** overview prose does not define a complete normative interface. Pin the target verifier/version and prove the accepted unauthorized state transition.
- **Routes:** `intents-auth`, `bridge-relayer`; `NA-AUTH-007`, `NA-AUTH-008`, `NA-ECON-003`.

### DOC-MPC-001 — Derived-key requests bind requester, path, chain, payload, and purpose

- **Source / activation:** Chain Signatures introduction and signing-transaction pages; activate for derived addresses or MPC `sign` calls.
- **Attacker / invariant:** requester/application chooses derivation path and payload; returned signature authorizes only the intended account, key tweak/path, chain/verifier, transaction bytes, and operation.
- **Attack trace:** path or account substitution derives another authority, response hash is trusted rather than recomputed, signature requested over ambiguous/incomplete bytes, or one schema's signature authorizes a different action.
- **Search / probes:** predecessor/requester binding, path namespace, master key/version, payload hash and complete chain transaction, sighash mode, domain/purpose, operation ID, response parsing, and relay destination.
- **Gate / verify:** chain-specific adapters differ. Reproduce with the exact payload/hash/signature rules of the target chain.
- **Routes:** `chain-signatures-yield`, `trust-gap`; `NA-CRYPTO-002`, `NA-CRYPTO-001`.

### DOC-MPC-002 — Threshold participants and transcript views agree before releasing shares

- **Source / activation:** Chain Signatures/MPC architecture and pinned implementation evidence; documentation counts are descriptive, not permanent constants.
- **Attacker / invariant:** malicious coordinator or bounded participant set equivocates; all honest parties authenticate participant IDs/indices, signer subset, threshold, protocol version, session, message, and tweak before releasing a share.
- **Attack trace:** split signer views reuse presignature/nonce material, peer identity maps to the wrong participant index, incompatible threshold assumptions pass different phases, or resharing admits stale members.
- **Search / probes:** peer authentication, participant mapping, quorum intersection, presignature reservation/consumption, session IDs, coordinator messages, bounds, resharing, restart, and duplicate response.
- **Gate / verify:** require cryptographic/protocol evidence; an outdated node-count statement alone is advisory.
- **Routes:** `chain-signatures-yield`; `NA-CRYPTO-002`, `NA-CRYPTO-003`, `NA-CRYPTO-004`.

### DOC-BRIDGE-001 — Each route proves the correct origin, finality, and external transition

- **Source / activation:** OmniBridge overview/how-it-works/implementation and light-client RPC pages; activate per configured chain and direction.
- **Attacker / invariant:** proof submitter, source-chain contract, message network, or relayer controls evidence; the selected backend proves finalized inclusion of the configured emitter/event/asset/recipient exactly once.
- **Attack trace:** valid proof from attacker emitter, wrong chain/domain or route backend, insufficient confirmations/reorg, malformed canonical leaf/header/work, reused event/nonce, or Wormhole/light-client assumptions are mixed across routes.
- **Search / probes:** chain-direction responsibility map, factory/locker/emitter allowlist, chain ID, proof leaf/domain, header work/finality, guardian/MPC threshold, nonce replay, expiry, pruning/reorg, and route configuration changes.
- **Gate / verify:** do not apply EVM-only or one-route assumptions universally. Pin the actual route and adversary threshold.
- **Routes:** `bridge-relayer`, `chain-signatures-yield`; `NA-INTEGRATION-003`, `NA-INTEGRATION-004`, `NA-CRYPTO-003`; `INV-SETTLE-ONCE-*`.

### DOC-BRIDGE-002 — Bridge accounting remains recoverable through destination acceptance and fees

- **Source / activation:** OmniBridge implementation, FT transfer-call, fast-transfer, and fee sections.
- **Attacker / invariant:** recipient contract, relayer, or caller controls destination acceptance, fee options, and retry timing; locked/burned/minted value, nonce state, fees, and recoverable claims conserve across every receipt and chain.
- **Attack trace:** consume proof/nonce before receiver acceptance, refund tokens without reopening operation recovery, charge caller-selected fees/deposits to a shared relayer account, front-run fee beneficiary, reimburse fast relayer before finality, or retry partial chain-to-chain routing twice.
- **Search / probes:** custody matrix per direction, FT used/refunded amount, operation-bound pending state, fee payer/beneficiary/asset, fast-liquidity reimbursement, retries, timeout/cancel, and terminal events.
- **Gate / verify:** operational delay is not a vulnerability when any user can safely resume and value remains recoverable.
- **Routes:** `bridge-relayer`, `token-accounting`, `async-state-explorer`; `NA-ASYNC-009`, `NA-ACCOUNT-002`, `NA-OFFCHAIN-002`.

### DOC-RELAYER-001 — Relayer retry and RPC status follow terminal receipt state

- **Source / activation:** meta-transaction, OmniBridge relayer, transaction/RPC status, indexer, and data-flow pages.
- **Attacker / invariant:** network/provider returns partial, stale, failed, or reordered observations; relayer persistence and idempotency produce at most one terminal action and never discard recoverable work.
- **Attack trace:** treat transaction inclusion as all-receipts success, retry after timeout while first chain continues, skip failed child receipt, lose nonce/job on restart, trust wrong network/finality, or accept a foreign malformed event.
- **Search / probes:** finality mode, receipt outcomes, network/genesis/chain ID, durable job state, nonce allocation, backoff, idempotency key, reorg handling, restart, provider disagreement, and poison-event isolation.
- **Gate / verify:** duplicate submission may be runtime-rejected; prove external cost, lost settlement, or a second accepted action.
- **Routes:** `bridge-relayer`, `periphery-build`; `NA-OFFCHAIN-001`, `NA-OFFCHAIN-002`, `NA-ASYNC-004`.

### DOC-RPC-001 — RPC and indexer observations carry explicit finality and trust

- **Source / activation:** RPC, data infrastructure, indexer, light-client, and protocol-config pages; activate for off-chain security decisions.
- **Attacker / invariant:** provider, fork, or malformed response controls observations; consumers authenticate network, choose sufficient finality, validate schema/limits, and distinguish transaction, receipt, event, and state truth.
- **Attack trace:** act on optimistic/reorged data, trust a failed receipt because transaction exists, accept wrong-network code/state/proof, crash or report success on missing fields, or rely on deprecated/partial endpoint semantics.
- **Search / probes:** endpoint/network identity, block hash/height/finality, receipt tree, proof verification, protocol version/config, provider quorum, pagination, response validation, rate limits, and reorg replay.
- **Gate / verify:** provider trust can be explicit. Escalate only when implementation contradicts it or lacks required integrity/failure handling.
- **Routes:** `bridge-relayer`, `periphery-build`; `NA-OFFCHAIN-001`, `NA-OFFCHAIN-003`.

### DOC-TEE-001 — Off-chain compute evidence binds code, platform, configuration, and result purpose

- **Source / activation:** off-chain-compute and OutLayer pages plus target attestation policy.
- **Attacker / invariant:** host, stale TCB, or malicious service controls evidence/responses; verifier binds accepted platform, TCB, code measurement, security configuration, freshness, service key, inputs, result, and protocol purpose.
- **Attack trace:** accept stale/revoked or wrong-platform attestation, altered environment/config outside measurement, replay result under another task, trust wrong service key, or crash on malformed SDK response while reporting terminal success.
- **Search / probes:** quote/collateral verifier, measurement allowlist, TCB status, nonce/freshness, config/tag binding, key provisioning, input/output hash, rollback/replay, and host privileges.
- **Gate / verify:** marketing claims are not verifier policy. Prove the target accepts evidence outside its stated trust boundary.
- **Routes:** `trust-gap`, `oracle-freshness`, `periphery-build`; `NA-CRYPTO-007`, `NA-OFFCHAIN-003`.

## Card-level completion rule

For every selected card, emit one `official-guidance-coverage.jsonl` row. The
row must end as `conformant`, `security_candidate`, `advisory`,
`quality_observation`, `not_applicable`, or `blocked`. A security row links an
ordinary candidate and exact target evidence. A non-applicable row cites the
missing feature/version evidence. Cards never bypass candidate deduplication,
adversarial verification, or human release approval.
