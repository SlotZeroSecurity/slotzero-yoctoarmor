# NEP Wallet, Authorization, and Account Attacker Checklists

Treat wallets, relayers, RPC responses, injected providers, signed payloads, callbacks, and account/key state as separate trust boundaries. Exact domain, network, signer, recipient, action, nonce, deadline, and permission binding is the default invariant.

## NEP-0366 — Meta Transactions

- **Trigger / attacker:** delegate actions, relayers, or meta-transaction construction/validation; relayer and original signer can be adversarial.
- **Invariant:** a signed delegate action authorizes exactly its receiver/actions/nonce/height/key permissions once, while relayer identity cannot inherit user authority.
- **Probe:** replay, nonce races, expiry boundary, action reordering, cross-account/network reuse, function-call-key restrictions, relayer fee substitution, nested delegation, and signer/predecessor confusion.
- **Conformance:** exact delegate serialization, signature/public key, nonce/max block height, receiver, action limits, and protocol validation.
- **Gate / verify:** execute accepted/rejected vectors and prove contract authorization uses the intended receipt principal.

## NEP-0368 — Bridge Wallets

- **Trigger / attacker:** wallet bridge discovery/connection/message transport; hostile page, bridge frame, extension, and wallet endpoint.
- **Invariant:** requests and responses bind the intended origin, wallet, account, network, session, and method without cross-dApp confusion.
- **Probe:** origin spoofing, wildcard target origin, stale session, unsolicited response, request-ID collision, account/network switch, iframe navigation, replay, and unsupported-method downgrade.
- **Conformance:** compare discovery, transport, request/response correlation, permissions, and error behavior.
- **Gate / verify:** browser-origin integration tests with hostile frames; UI incompatibility alone is conformance.

## NEP-0408 — Injected Wallet API

- **Trigger / attacker:** injected provider discovery and wallet method use; a malicious extension/page can race or impersonate providers.
- **Invariant:** the dApp selects an authenticated expected provider and binds each response to the requesting origin/session/account/network.
- **Probe:** provider clobbering, duplicate injection, method spoofing, account/network changes, stale authorization, event confusion, request replay, and unsafe fallback.
- **Conformance:** exact provider shape, methods, events, errors, and capability negotiation.
- **Gate / verify:** adversarial browser tests; do not treat object presence as wallet authenticity.

## NEP-0413 — Wallet `signMessage`

- **Trigger / attacker:** signed-message login/authorization; verifier, recipient, callback, and requesting origin may be adversarial.
- **Invariant:** signature binds the NEP-413 domain, message, recipient, nonce, callback/state, account, and a valid full-access key at the relevant block.
- **Probe:** replay, wrong recipient, nonce reuse, cross-network/dApp use, callback/state omission, key deletion/rotation, function-call key, encoding ambiguity, and stale RPC proof.
- **Conformance:** exact Borsh payload/domain prefix, signature response, nonce and recipient sizes, callback URL/state behavior.
- **Gate / verify:** official vectors plus negative field substitutions and historical key verification at one consistent block.

## NEP-0448 — Zero-Balance Accounts

- **Trigger / attacker:** account creation, access-key storage accounting, onboarding subsidies, or code assuming positive liquid balance.
- **Invariant:** account/key storage and action costs follow the activated rules; zero balance cannot bypass authorization, rent/storage, or liveness assumptions.
- **Probe:** create then add/delete keys, transfer dust, contract deployment, account deletion/refund, four-key boundary, relayed creation, and old/new protocol transition.
- **Conformance:** verify free account/key allowance and creation gas/storage charging for the target version.
- **Gate / verify:** protocol tests at activation boundaries; application findings require a concrete broken balance assumption.

## NEP-0492 — Ethereum-Address Account Restrictions

- **Trigger / attacker:** top-level account creation or tooling handling `0x`-style identifiers.
- **Invariant:** restricted address forms cannot be created through alternate paths or normalized inconsistently into another authority.
- **Probe:** case/length/hex edge cases, registrar/subaccount/implicit creation paths, Unicode/lookalike input, old receipts across activation, and wallet/RPC validation disagreement.
- **Conformance:** compare exact restricted pattern and protocol-version creation rules.
- **Gate / verify:** node/runtime tests plus client normalization differentials; a UI-only rejection mismatch is conformance unless funds can be lost.

## NEP-0518 — Web3-Compatible Wallet Support (New)

- **Trigger / attacker:** eth-implicit accounts or wallet-contract prototypes; attacker controls EVM signatures, relays, chain context, and contract initialization timing.
- **Invariant:** only the Ethereum private-key owner authorizes correctly domain-bound NEAR actions, once, on the intended network/account.
- **Probe:** ECDSA malleability/recovery edge cases, chain replay, wallet-code substitution, uninitialized account, nonce races, meta-transaction confusion, EVM/NEAR address normalization, and upgrade authority.
- **Conformance:** advisory only; compare proposal scope and do not assume activation.
- **Gate / verify:** signature vectors, negative domain tests, and end-to-end account lifecycle; never report Draft/New deviation as mandatory.

## NEP-0616 — Deterministic Account IDs

- **Trigger / attacker:** factory/global-contract deployments deriving IDs from code/init state; creator controls serialization and may seek collisions or front-run deployment.
- **Invariant:** derivation is canonical, domain-separated, collision-resistant, network/context bound as specified, and deploy/init/state verification matches the derived ID.
- **Probe:** alternate serialization, field order/default ambiguity, code hash mismatch, replay on another parent/network, pre-creation/front-run, failed initialization, refund recipient confusion, and global-contract version change.
- **Conformance:** compare exact derivation inputs/hash/encoding plus permission, storage, refund, and code-verification lifecycle.
- **Gate / verify:** golden vectors and mutation tests; replay full create/deploy/init failure paths.

## NEP-0641 — Offchain Authorizations

- **Trigger / attacker:** `w_resolve_auth`, `OffchainMessage`, recursive wallet resolution, or off-chain action approval; attacker controls nested authorizations and resolution graph.
- **Invariant:** the full authorization binds chain, signer, path, timestamp, payload, and each nested expectation; one consistent block and bounded graph determine validity.
- **Probe:** cross-chain/path/payload replay, timestamp freshness, recursion cycles/depth/width DoS, pending substitution/reordering, inconsistent block views, subpayload mismatch, malformed resolver response, and reusable-signature confusion.
- **Conformance:** exact envelope and resolver ABI, panic/invalid semantics, pending graph, and NEP-413 full-access-key branch.
- **Gate / verify:** property-test graph resolution with cycles, stale data, and field mutations; intentional reusable signatures are safe only when no different material action is authorized.
