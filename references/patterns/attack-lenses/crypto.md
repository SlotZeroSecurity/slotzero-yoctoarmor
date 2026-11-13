# Crypto attack lens

Activate only when target code exposes the stated behavior. Historical sources are examples, not target evidence.

## NA-CRYPTO-001 — Ambiguous, non-canonical, or incomplete decoding changes authority or execution

- **Kind:** security
- **Root cause:** Ambiguous, non-canonical, or incomplete decoding changes authority or execution.
- **Activation:** custom delimiter parsing is context-free, a decoder accepts trailing bytes, nested values can inject actions, external IDs have inconsistent case normalization, security-sensitive account fields remain unvalidated strings, or a compact/custom AccountId representation is not injective, canonical, length-bounded, and exactly reversible.
- **Broken invariant:** one accepted byte string or external identifier has one canonical meaning from signature/validation through execution.
- **Concrete sequence:** make validation authorize one object while execution parses another, smuggle an extra action/recipient, or split replay/identity tracking across equivalent representations.
- **Required evidence:** prove two accepted representations differ in an authorization, replay key, asset, recipient, or executed action; permissive parsing without material divergence is quality-only.
- **Exclusions:** Exclude when alternative encodings normalize to the same authorized action and replay key, or are rejected before any material effect.
- **Recovery:** Trace failure, retry, cancellation, and authorized recovery without duplicating value or authority.
- **Fix family:** canonical structured serialization, exact input consumption, typed `AccountId`/asset/domain fields, explicit normalization before hashing/comparison, and parser differential tests.

## NA-CRYPTO-002 — Threshold request, participant, transcript, or response is not cryptographically bound

- **Kind:** security
- **Root cause:** Threshold request, participant, transcript, or response is not cryptographically bound.
- **Activation:** peer IDs are accepted without unique asset-to-network binding; vector position is confused with participant index; a coordinator can choose unchecked derivation data; a response handler accepts a caller or `payload_hash` not bound to the pending request; or two operation purposes share the same transcript/signature domain.
- **Broken invariant:** every MPC/CKD operation has one authenticated session identity whose participant IDs and indices, requester, application/path, protocol version, purpose, canonical payload hash, transcript messages, and returned result all agree.
- **Concrete sequence:** substitute a participant or transcript, route a response to another pending request, control a derived key, authorize the wrong payload, or make honest parties sign inconsistent state.
- **Required evidence:** prove the missing binding is not established in a lower authenticated transport/transcript layer and changes an accepted key, signature, vote, or settlement. A display-only ID mismatch is not sufficient.
- **Exclusions:** Exclude when the lower authenticated transcript binds the same request, participant, and result fields before acceptance; a display-only mismatch is insufficient.
- **Recovery:** Reconcile authority before releasing resources or admitting a conflicting action.
- **Fix family:** derive one canonical domain-separated session/request digest; authenticate exact peer-to-participant and index mappings; recompute payload/result hashes; store immutable pending context; and verify the entire transcript/result before one-time settlement.

## NA-CRYPTO-003 — Threshold, quorum, corruption, or resharing assumptions disagree across phases

- **Kind:** security
- **Root cause:** Threshold, quorum, corruption, or resharing assumptions disagree across phases.
- **Activation:** signing threshold differs from reliable-broadcast corruption bounds; `threshold = 1`, changed membership, or changed threshold reaches an untested/invalid branch; a coordinator waits for every participant despite a threshold protocol; or `>= threshold` early responses can override a contrary honest majority.
- **Broken invariant:** DKG, broadcast, signing, key refresh, resharing, validation, and recovery use one explicit corruption model and compatible threshold/quorum rules for every old/new participant set.
- **Concrete sequence:** a minority produces an accepted result, a valid quorum cannot progress, resharing weakens proactive security, or one faulty/offline party stalls every request.
- **Required evidence:** calculate the deployed participant count, exact threshold definition, tolerated faults, and message primitive. A different numeric threshold is safe when the underlying definitions and proofs deliberately differ.
- **Exclusions:** Exclude when the protocol intentionally uses different threshold definitions and its safety and liveness proofs cover the deployed participant set.
- **Recovery:** Trace failure, retry, cancellation, and authorized recovery without duplicating value or authority.
- **Fix family:** specify phase-by-phase safety/liveness inequalities, validate them inside the primitive, preserve the original public key across resharing, count authenticated unique responses, and test every boundary and membership transition under Byzantine/offline schedules.

## NA-CRYPTO-004 — Presignature reuse across split views leaks the signing key

- **Kind:** security
- **Root cause:** Presignature reuse across split views leaks the signing key.
- **Activation:** disjoint or equivocating signer views can select the same presignature for different messages, tweaks, or participant subsets; presignature consumption is tracked only locally; or participant-count/index bounds permit overlapping threshold groups to complete inconsistent sessions.
- **Broken invariant:** nonce-bearing presignature material is consumed globally at most once and only after every participant agrees on the same protocol domain, message, key tweak/path, signer subset, participant mapping, and session.
- **Concrete sequence:** a coordinator or Byzantine subset obtains related ECDSA signature equations that reuse nonce material under different views and solves for the long-term signing key, including schedules with more than the assumed `2t + 1` participants.
- **Required evidence:** prove the same nonce-bearing material can reach two accepted signature equations. Repeated identifiers are harmless when they refer to independently generated nonces or a globally atomic store rejects the second session before any response share is released.
- **Exclusions:** Exclude when repeated IDs name fresh independent nonce material, or an atomic one-time reservation prevents any second response share.
- **Recovery:** Trace failure, retry, cancellation, and authorized recovery without duplicating value or authority.
- **Fix family:** globally reserve and one-time consume presignatures before releasing shares; include message, tweak/path, participant set and indices, threshold, protocol version, and session in authenticated agreement; enforce proven participant bounds; and test coordinator equivocation and disjoint-view schedules.

## NA-CRYPTO-005 — Secret material survives or crosses an unsafe operational boundary

- **Kind:** security
- **Root cause:** Secret material survives or crosses an unsafe operational boundary.
- **Activation:** secrets are passed on command lines, persisted in CI/container artifacts, retained after DKG/resharing, stored with excessive permissions, or left in ordinary buffers without a deliberate zeroization/threat-model decision.
- **Broken invariant:** private shares, keys, randomness, API credentials, and recovery material exist only in the minimum authorized scope and lifetime, and are never exposed through process arguments, logs, artifacts, caches, overly broad files, or stale memory.
- **Concrete sequence:** a local observer, artifact reader, later memory disclosure, or compromised runner/node recovers enough material to impersonate a service or accumulate threshold shares over time.
- **Required evidence:** identify a realistic reader and security consequence. Zeroization is not guaranteed against all compiler/runtime copies, and public configuration or already encrypted opaque values are not secret leakage by name alone.
- **Exclusions:** Exclude public settings and opaque encrypted values when no realistic reader can recover a secret or gain authority.
- **Recovery:** Trace failure, retry, cancellation, and authorized recovery without duplicating value or authority.
- **Fix family:** use scoped secret stores/FDs, restrictive permissions, non-exporting CI, redacted logs, zeroizing containers where meaningful, rotation/revocation, and tests that artifacts/process listings contain no secret.

## NA-CRYPTO-006 — Encryption nonce, context binding, or key derivation is unsafe

- **Kind:** security
- **Root cause:** Encryption nonce, context binding, or key derivation is unsafe.
- **Activation:** AES-GCM or another nonce-sensitive AEAD repeats a nonce; encrypted database values can be swapped between keys/records because AAD omits identity; a raw hash substitutes for a required KDF; or ciphertext/version/key-rotation context is ambiguous.
- **Broken invariant:** every encryption under one key uses a unique nonce, authenticates the record identity and security context, and derives independent keys with a protocol-appropriate KDF/domain.
- **Concrete sequence:** recover or forge plaintext, transplant an encrypted share/configuration into another record, or collapse independently intended keys/domains.
- **Required evidence:** prove key/nonce reuse or missing context under the actual cryptographic API. Random nonces are not automatically unsafe when collision probability, key rotation, and persistence make reuse negligible and enforced.
- **Exclusions:** Exclude random nonce schemes whose key lifetime, collision bounds, persistence, and rotation enforce the claimed uniqueness guarantee.
- **Recovery:** Trace failure, retry, cancellation, and authorized recovery without duplicating value or authority.
- **Fix family:** monotonic or collision-safe nonce allocation per key, authenticated record/type/version AAD, standard extract-and-expand KDF with explicit domain separation, and atomic nonce/key rotation metadata.

## NA-CRYPTO-007 — Attestation does not bind the claimed platform, TCB, measurement, and runtime configuration

- **Kind:** security
- **Root cause:** Attestation does not bind the claimed platform, TCB, measurement, and runtime configuration.
- **Activation:** TCB status is ignored; environment parsing/tagging changes what was measured or claimed; privileged container/runtime configuration lies outside the attested boundary; or attestation proves code but not the key/configuration used for MPC/CKD decisions.
- **Broken invariant:** an accepted attestation proves an allowed hardware/platform identity, current acceptable TCB status, exact code measurement, security-relevant configuration/tags, freshness, and intended service key for the verifier's policy.
- **Concrete sequence:** a revoked/vulnerable platform or differently configured service is accepted as trusted and receives secrets or authorizes results.
- **Required evidence:** pin the attestation format, verifier policy, collateral freshness, measured boundary, and deployment threat model. A configuration outside the claimed trust boundary is an assumption, not automatically a bypass.
- **Exclusions:** Exclude configuration outside the attested trust boundary unless the product actually claims that configuration is measured or verified.
- **Recovery:** Trace failure, retry, cancellation, and authorized recovery without duplicating value or authority.
- **Fix family:** fail closed on unsupported/revoked TCB states, canonicalize and bind configuration, verify freshness/collateral/measurements/service keys, minimize host privilege, and test negative attestations and configuration mutations.

## NA-CRYPTO-008 — Treat deletion and authority revocation separately

- **Kind:** security
- **Root cause:** A signature, key, or attestation is not bound to its intended identity, context, and lifecycle.
- **Activation:** An operation creates externally usable authority; Local rejection or deletion can occur after that authority exists
- **Broken invariant:** Local state cannot claim an operation is safely rejected while live authority can still produce a conflicting effect.
- **Concrete sequence:** Issue authority, reject or delete local tracking, then submit the surviving authority to its real executor.
- **Required evidence:** Show execution or continued signing permission after rejection and identify the fixed or attacker-controlled beneficiary.
- **Exclusions:** A surviving authorization to the rightful immutable beneficiary does not alone prove theft. Some authority is irrevocable.
- **Recovery:** Reconcile authority before releasing resources or admitting a conflicting action.
- **Fix family:** Disallow rejection after an irreversible phase, or implement effective revocation and reconcile outstanding authority.
