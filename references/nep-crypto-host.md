# NEP Cryptographic Host-Function Attacker Checklists

For every entry, first prove the protocol feature is activated for the target chain/version. Distinguish host-function correctness from application-level domain separation, key validation, replay protection, and authorization.

## NEP-0364 — Signature and Hash Precompiles

- **Trigger / attacker:** contracts call runtime signature/hash precompiles for IBC, light-client, or authorization verification; attacker controls message, signature, key, and encodings.
- **Invariant:** host return semantics, curve/hash selection, input encoding, and gas charging match the verifier's security assumptions.
- **Probe:** malformed lengths, invalid points/keys, alternate encodings, wrong hash/prehash mode, zero/edge values, out-of-gas, and ignored false/error results.
- **Conformance:** compare exact imported function, memory/register ABI, algorithm, result polarity, and activation version.
- **Gate / verify:** use official vectors plus negative and malformed vectors; a safe host call does not prove the signed payload is sufficiently bound.

## NEP-0488 — BLS12-381 Host Functions

- **Trigger / attacker:** BLS signatures, aggregate verification, pairings, or zk proof verification using BLS12-381 host functions.
- **Invariant:** points are valid in the required group/subgroup, encodings and field reductions are canonical, and pairing equations bind the intended statement.
- **Probe:** infinity, non-subgroup points, malformed compressed values, empty/duplicate aggregates, message/key swapping, excessive vector sizes, and ignored host failures.
- **Conformance:** verify exact function ABI, group/field representation, gas bounds, and library/runtime activation.
- **Gate / verify:** use published positive/negative vectors and application-specific rogue-key/domain tests; timing concerns require a secret-dependent on-chain value.

## NEP-0635 — P-256 Verification Host Function (Draft)

- **Trigger / attacker:** draft `p256_verify` integration, passkeys, or an application emulation; attacker controls signature, public key, hash, and WebAuthn context.
- **Invariant:** only canonical, valid P-256 signatures over the intended digest authorize an action.
- **Probe:** high-S/low-S variants, invalid points, DER-versus-raw confusion, wrong prehashing, cross-origin/domain replay, malformed lengths, and result-polarity mistakes.
- **Conformance:** advisory only; compare the draft ABI and feature activation without treating it as mandatory.
- **Gate / verify:** curve-vector success is insufficient—also prove challenge/origin/rpId/action binding in the caller.

## NEP-0645 — ML-DSA-65 Transaction Signatures (Draft)

- **Trigger / attacker:** nearcore/access-key code implements ML-DSA-65 transactions, delegate actions, or hashed key handles.
- **Invariant:** the wire public key, stored domain-separated handle, signature scheme tag, nonce, permission, and charged verification cost bind one authorized transaction.
- **Probe:** scheme confusion, handle collisions/domain omission, malformed large keys/signatures, AddKey/DeleteKey mismatch, delegate replay, undercharged verification, and unsupported use as validator/implicit-account identity.
- **Conformance:** advisory and activation-gated; enforce the proposal's deliberately limited scope rather than extending it by assumption.
- **Gate / verify:** use FIPS vectors, serialization round trips, negative scheme-tag tests, and state/wire key reconciliation.

## NEP-0646 — FIPS 202 SHA-3 Host Functions (Draft)

- **Trigger / attacker:** `sha3_256/384/512` host calls or code migrating from legacy Keccak.
- **Invariant:** FIPS-202 SHA-3 padding/output is never confused with Keccak, and gas/register behavior cannot corrupt verification or availability.
- **Probe:** empty and boundary-length inputs, SHA3/Keccak substitution, wrong output width, overlapping registers, huge input/gas exhaustion, and ignored host errors.
- **Conformance:** advisory only; compare exact fixed-output ABI and activation. SHAKE is out of scope.
- **Gate / verify:** run NIST vectors plus explicit unequal Keccak controls; escalate only when digest confusion or charging creates material impact.
