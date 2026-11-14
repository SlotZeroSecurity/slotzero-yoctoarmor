# Integration attack lens

Activate only when target code exposes the stated behavior. Patterns guide investigation; only target evidence establishes a finding.

## NA-INTEGRATION-001 — Receiver hook trusts the wrong token or sender context

- **Kind:** security
- **Root cause:** Receiver hook trusts the wrong token or sender context.
- **Activation:** an FT hook accepts a counterfeit predecessor, an NFT hook treats `sender_id` as `previous_owner_id` even though an approved operator can make them differ, or free-form `msg` selects an unvalidated asset, beneficiary, route, or action.
- **Broken invariant:** token/NFT hooks act only for the expected immediate predecessor and bind the exact token, amount, message, authorized caller, and asset owner required by the standard.
- **Concrete sequence:** call a hook from a counterfeit token, use an approved marketplace/operator so caller and owner identities diverge, or inject inconsistent hook data to obtain credit/release for the wrong principal.
- **Required evidence:** Show the actual receiver-hook predecessor and token account, the credited asset and principal, and a control transfer from the intended token.
- **Exclusions:** Do not report without a reachable path and material target-specific harm.
- **Recovery:** Trace failure, retry, cancellation, and authorized recovery without duplicating value or authority.
- **Fix family:** strict predecessor allowlist plus typed operation-bound message validation; for NFT transfer-call, keep authorized caller and previous owner separate. Return the full unused FT amount for unsupported assets/configuration.

## NA-INTEGRATION-002 — Standard ABI or lifecycle semantics drift breaks interoperability

- **Kind:** security
- **Root cause:** Standard ABI or lifecycle semantics drift breaks interoperability.
- **Activation:** any NEP in the pinned registry is claimed, exported, activated, implemented, or materially depended upon and its exact behavior differs. Examples include signature/serializer/numeric representation drift; optional/default or panic/`false`/`null` mismatch; wrong return polarity; missing ABI; deposit-rule conflict; lifecycle ordering drift; unsupported peer assumptions; NEP-145 beneficiary/payer/refund confusion or withdrawal without value transfer; NEP-171/178 approval-ID representation; wallet/signature domain mismatch; host-function ABI/result confusion; or node/runtime activation/state-transition disagreement.
- **Broken invariant:** every applicable, activated NEP version agrees end to end across exported ABI, argument optionality, serialization, payability/one-yocto rules, callbacks, return semantics, runtime transition, and dependent consumer behavior.
- **Concrete sequence:** Call the actual exported interface with a conforming peer and exercise optional/default arguments, numeric encodings, deposit rules, callback outcomes, and lifecycle ordering; compare each accepted or rejected branch with the pinned applicable NEP.
- **Required evidence:** Establish the target interface claim, active version/feature gate, exact ABI and branch semantics, and a reproducible interoperability or value effect. For storage operations trace both payer and beneficiary balances, not just the returned structure.
- **Exclusions:** Inactive Draft/New proposals are advisory, and intentional custom interfaces do not automatically claim a NEP. A fee-funded sponsorship policy is not theft merely because the beneficiary receives a refund; show any actual conformance conflict separately.
- **Recovery:** Trace resolver, unregister, withdrawal, refund, and retry branches through real effects; preserve approvals, balances, legacy state, and payer credits while preventing duplicate settlement.
- **Fix family:** pin the intended NEP/version, use its exact JSON representation (including bounded numeric exceptions), export and integration-test the exact ABI and branch outcomes, preserve existing registration/deposit state across every optional-argument branch, refund third-party deposit excess to the predecessor payer, and prove every storage withdrawal/unregister/refund has one matching outbound transfer or recoverable credit. Test hostile but conforming peers plus third-party registration of new and already registered accounts.

### Variants and safe controls

Test standard signatures, optional arguments, numeric representation, payability, lifecycle order, return polarity, and all failure branches against the pinned applicable interface. Include sponsored registration of new and existing accounts, legacy balances on unregister, and payout maps. A fee-funded sponsorship policy or an inactive Draft proposal is not by itself a conformance exploit.

## NA-INTEGRATION-003 — Finality, proof, or timeout races release value twice

- **Kind:** security
- **Root cause:** Finality, proof, or timeout races release value twice.
- **Activation:** proof and timeout/unlock can race, a nonce/proof is consumed too early or too late relative to terminal downstream success, source confirmations are weak, a sequence/reset is not scoped to the configured emitter, security-relevant header/event metadata is omitted from the canonical proof identity, or a callback is not idempotent.
- **Broken invariant:** one finalized canonical source event has one mutually exclusive terminal destination outcome.
- **Concrete sequence:** Race proof settlement with timeout/refund, replay a consumed event through another route or reset, or admit a noncanonical/unfinalized source event and trigger a destination effect.
- **Required evidence:** Establish the exact source verifier, finality/quorum configuration, authenticated event identity, receipt schedule, consumed marker, and actual duplicate or unauthorized value effect.
- **Exclusions:** A verified canonical source, correctly scoped one-time consumption, and mutually exclusive recoverable settlement can exclude the race. Reorg possibility or weak confirmation alone does not prove a double spend.
- **Recovery:** Reconcile every in-flight destination effect before releasing or reopening the source event; retain authenticated recovery when downstream execution fails.
- **Fix family:** Bind source finality, emitter, route, canonical event identity, and destination outcome; serialize proof and timeout settlement, and preserve idempotent recovery across receipt failure.

### Variants and safe controls

For light clients, verify cumulative work/difficulty, canonical Merkle-leaf identity, configured quorum, finality, pruning, skipped periods, and reorg handling. Test proof-versus-timeout races and reset/replay scope. Post-fee output validity, semantic authorization, and resource maturity are separately covered by NA-INTEGRATION-006, NA-INTEGRATION-007, and NA-INTEGRATION-008; do not conflate their recovery paths.

## NA-INTEGRATION-004 — Valid proof is accepted from an untrusted emitter or route

- **Kind:** security
- **Root cause:** Valid proof is accepted from an untrusted emitter or route.
- **Activation:** proof verification establishes inclusion/finality but the consumer accepts an attacker-deployed contract's otherwise valid event, trusts an emitter supplied inside the proof payload, or mutates token/address mappings before comparing the event origin with the configured per-chain factory/locker.
- **Broken invariant:** a proof authorizes state or value only when its source chain, emitting contract/factory, event signature, event identity, asset/route, and destination all match the bridge's trusted configuration.
- **Concrete sequence:** deploy a look-alike source contract, emit a structurally valid event, obtain a valid inclusion proof, and bind an arbitrary token/address route or trigger unauthorized mint/release.
- **Required evidence:** distinguish cryptographic inclusion from protocol authorization. Prove the attacker can create the source event and that no earlier verifier/configuration layer pins the exact emitter and route. A malformed or unverifiable proof does not demonstrate this pattern.
- **Exclusions:** Exclude when a trusted upstream verifier authenticates the event origin and required finality before this component accepts it.
- **Recovery:** Trace failure, retry, cancellation, and authorized recovery without duplicating value or authority.
- **Fix family:** authenticate the exact configured emitter/factory and event type for the claimed chain before any mapping or settlement mutation; bind all security-relevant header/event metadata plus destination asset/recipient/decimals, scope sequence state to the emitter/route, and consume the canonical event identity exactly once at a recoverable terminal boundary.

## NA-INTEGRATION-005 — Stale, manipulable, or unavailable input corrupts decisions

- **Kind:** security
- **Root cause:** Stale, manipulable, or unavailable input corrupts decisions.
- **Activation:** a price/reward/rate lacks freshness, decimals, source authentication, fallback, or manipulation bounds; or a confidence interval is applied in the wrong direction or without a policy bound so uncertainty itself triggers unsafe liquidation or borrowing.
- **Broken invariant:** value-sensitive actions enforce freshness, confidence, source identity, decimal normalization, and failure behavior.
- **Concrete sequence:** Make an oracle return a stale, out-of-range, or unavailable price while a borrow, liquidation, swap, or claim is pending, then trace the accepted value decision.
- **Required evidence:** Show the oracle timestamp, source/authentication, allowed age and bounds, the exact consumed price, and a control decision using valid data.
- **Exclusions:** reliance on a documented trusted bot may be an operational assumption; report only a reachable material consequence or disclose the assumption.
- **Recovery:** Trace failure, retry, cancellation, and authorized recovery without duplicating value or authority.
- **Fix family:** bind the exact source and asset, normalize units, enforce maximum age and confidence policy, use directionally conservative bounds for the specific action, and define bounded fallback/pause/recovery behavior.

## NA-INTEGRATION-006 — Validate the result after costs and transformations

- **Kind:** security
- **Root cause:** External data or an interface result is accepted without validating its authority and business meaning.
- **Activation:** An input loses value or capacity through fees or transformations; A downstream system imposes a minimum usable result
- **Broken invariant:** Every admitted operation can produce the promised usable result after all required deductions.
- **Concrete sequence:** Choose an input just above the deduction but below the destination's minimum usable output.
- **Required evidence:** Test boundaries around costs and the minimum, using the actual destination configuration; separate transport policy from hard validity.
- **Exclusions:** A documented best-effort path or a result accepted by the actual downstream system is not automatically invalid.
- **Recovery:** Trace rejection, cancellation, ownership, and retries independently of the admission defect.
- **Fix family:** Validate net output at admission and execution, bind accepted costs, and retain safe recovery on changes.

### Variants and safe controls

For an external transaction output, separate chain consensus validity from script-specific relay/minimum-output policy. Test fee-minus-one, fee, fee-plus-one, and actual downstream policy boundaries; possible direct inclusion may refute an absolute unspendability claim.

## NA-INTEGRATION-007 — Verify meaning and authorization before shared commitment

- **Kind:** security
- **Root cause:** External data or an interface result is accepted without validating its authority and business meaning.
- **Activation:** Untrusted structured data can reserve shared resources; Parsing does not establish all required semantic or authorization predicates
- **Broken invariant:** Structurally readable but semantically invalid or unauthorized input cannot irrecoverably commit shared resources.
- **Concrete sequence:** Start with valid input, alter one integrity or authorization component while retaining parseable fields, then submit it.
- **Required evidence:** Use the exact trusted verifier to reject the altered object and show that admission still commits shared state.
- **Exclusions:** Parsing and semantic verification may intentionally occur in stages if reservations are bounded and safely recoverable.
- **Recovery:** Exercise all real release, replacement, timeout, and verification paths; quantify marginal shared-resource impact.
- **Fix family:** Verify required proofs, signatures, bindings, and semantics before durable commitment, or provide safe bounded provisional allocation.

## NA-INTEGRATION-008 — Distinguish accepted state from usable resources

- **Kind:** security
- **Root cause:** External data or an interface result is accepted without validating its authority and business meaning.
- **Activation:** An upstream system accepts or records a resource; Independent rules govern when that resource may be consumed
- **Broken invariant:** Resources advertised as usable satisfy every prerequisite for actual consumption.
- **Concrete sequence:** Admit an accepted but not-yet-usable resource and attempt a dependent operation.
- **Required evidence:** Pin the real maturity, hold, finality, or readiness rule and test just before, at, and after its boundary.
- **Exclusions:** A mock acceptance response does not establish upstream validity. A single unusable item does not prove global permanent failure.
- **Recovery:** Quarantine unusable resources, wait, replace, or unwind safely; assess effects on other available inventory.
- **Fix family:** Represent accepted, provisional, and usable states separately and enforce readiness before dependency allocation.

### Variants and safe controls

Inclusion of a newly created reward output may precede its spendability. Use the actual chain counting convention and readiness boundary; a mock inclusion response establishes only local handling. Compare a mature unreserved item so an unrelated reservation does not explain the observed failure.
