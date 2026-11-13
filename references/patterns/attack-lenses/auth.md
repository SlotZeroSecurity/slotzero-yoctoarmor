# Auth attack lens

Activate only when target code exposes the stated behavior. Historical sources are examples, not target evidence.

## NA-AUTH-001 — Signer/predecessor confusion enables confused-deputy calls

- **Kind:** security
- **Root cause:** Signer/predecessor confusion enables confused-deputy calls.
- **Activation:** composable public methods authorize or pay `signer_account_id`, or self-callbacks infer the original user from predecessor.
- **Broken invariant:** authority and beneficiary derive from the intended principal at the current trust boundary.
- **Concrete sequence:** a malicious intermediary preserves the victim signer while becoming predecessor and steers the action.
- **Required evidence:** signer use can be intentional transaction-origin authentication; demonstrate a malicious intermediary path and material effect.
- **Exclusions:** Exclude intentional origin authentication when intermediary calls cannot redirect authority, value, or beneficiary.
- **Recovery:** Persist the relevant principal through deferred completion and failed refunds.
- **Fix family:** use predecessor for immediate-caller authority and persist the original actor where later receipts need it.

## NA-AUTH-002 — Exposed privileged/internal endpoint

- **Kind:** security
- **Root cause:** Exposed privileged/internal endpoint.
- **Activation:** missing/ignored role check, unprotected `#[private]` path, public test helper, user-controlled authority argument, an internal or trait implementation annotated with `#[near]`/`#[near_bindgen]` exports a helper that bypasses its guarded wrapper, initialization/ownership/admin transitions do not follow one explicit caller-and-role policy, or revocation/renunciation can remove the final principal needed for pause, upgrade, recovery, or another documented critical operation.
- **Broken invariant:** callbacks, resolvers, migration, admin helpers, and destructive methods require exact intended authority.
- **Concrete sequence:** call the generated Wasm export directly instead of the intended wrapper, forge callback/admin arguments, or assign a critical role to a valid but unusable/unintended account with no acceptance or recovery step.
- **Required evidence:** derive the actual ABI from the pinned macro/build rather than assuming every Rust method is exported. A one-step role transfer is not automatically unsafe; prove that the documented handoff requires recipient acceptance or that a mistaken assignment can materially and irrecoverably strand authority.
- **Exclusions:** Exclude non-exported helpers and intentional irreversible governance removal; an alternate export must be reachable and violate the documented role policy.
- **Recovery:** Trace failure, retry, cancellation, and authorized recovery without duplicating value or authority.
- **Fix family:** enforce exact predecessor/role in every exported path, keep internal trait implementations outside export-generating impl blocks, compare source intent with generated/built exports, remove production test endpoints, and use propose/accept or another recoverable handoff for critical roles when required by policy. If continuing administration is a documented invariant, prevent or safely replace the last required role holder; do not flag intentional immutability or governance removal without material contradiction.

## NA-AUTH-003 — One-yocto or function-call-key boundary is unsafe

- **Kind:** security
- **Root cause:** One-yocto or function-call-key boundary is unsafe.
- **Activation:** a sensitive exported method is nonpayable, omits exact `assert_one_yocto()`/equivalent validation, accepts zero or arbitrary deposit, or remains callable through a compromised third-party function-call key without the intended wallet-confirmation boundary.
- **Broken invariant:** transfers, withdrawals, permission/ownership changes, and other confirmation-sensitive user actions cannot be triggered by an unintended function-call key; the deposit-capable-key check and the actual ownership/role authorization are both enforced.
- **Concrete sequence:** a site holding an allowed function-call key invokes a transfer or permission change with the user's account as predecessor, so an ordinary ownership check passes without confirmation by a deposit-capable call path.
- **Required evidence:** missing one yocto alone is a standard/hardening issue unless the target policy requires that confirmation boundary and a function-call-key method/receiver path can cause material harm. One yocto does not replace RBAC, prove a human is present in every composed call path, repair signer/predecessor confusion, or prove that the original user approved a child call when the contract or relayer supplies that child receipt's attached yoctoNEAR.
- **Exclusions:** Exclude missing one-yocto checks when no limited function-call credential can reach a material action or the target policy does not require this confirmation boundary.
- **Recovery:** Check credential revocation and recovery of configuration without widening access.
- **Fix family:** mark the method `#[payable]`, require exactly one yoctoNEAR, retain the predecessor/owner/role check, and keep restricted-key method allowlists least-privileged.

## NA-AUTH-004 — Stale access key bypasses new governance

- **Kind:** security
- **Root cause:** Stale access key bypasses new governance.
- **Activation:** ownership changes without rotating full-access/function-call keys, keys cannot be removed, or fallback keys bypass delay/multisig.
- **Broken invariant:** documented ownership/upgrade authority equals actual account-key authority.
- **Concrete sequence:** Rotate the configured administrator or governance contract, then use an old full-access or function-call key to execute the action the new policy meant to restrict.
- **Required evidence:** Prove the old key is still live on the target account, show its permissions, and execute a policy-forbidden call after the new governance state takes effect.
- **Exclusions:** Do not report without a reachable path and material target-specific harm.
- **Recovery:** Trace failure, retry, cancellation, and authorized recovery without duplicating value or authority.
- **Fix family:** Enumerate and revoke stale account keys during governance handoff, constrain surviving function-call keys, and verify the new governance path controls every deploy and privileged action.

## NA-AUTH-005 — Initialization is public, repeatable, or binds unsafe first state

- **Kind:** security
- **Root cause:** Initialization is public, repeatable, or binds unsafe first state.
- **Activation:** initializer is exported without `#[init]`/state-existence protection, `ignore_state` is reachable, first caller selects owner, or role/config/account relationships are not validated.
- **Broken invariant:** initialization occurs exactly once under the intended deployer/governance context and establishes a validated, recoverable first state.
- **Concrete sequence:** front-run deployment, seize roles, reset state, or create an unusable contract through conflicting/invalid initial accounts and bounds.
- **Required evidence:** confirm deployment action batching and account access keys; a callable-looking method may be unreachable after atomic initialization.
- **Exclusions:** Exclude initializer races prevented by atomic deployment and initialization or by an authenticated first-state transition.
- **Recovery:** Check safe redeployment or recovery and whether any funds or permissions were exposed before repair.
- **Fix family:** atomic deploy+init, `#[init]`, `PanicOnDefault`, exact predecessor/governance checks where needed, and complete initial invariant validation.

## NA-AUTH-006 — Effective upgrade authority bypasses governance

- **Kind:** security
- **Root cause:** Effective upgrade authority bypasses governance.
- **Activation:** self-upgrade, full-access key, owner plugin, or staged code bypasses multisig/timelock.
- **Broken invariant:** every deploy-code route and access key obeys the documented governance, delay, and emergency model.
- **Concrete sequence:** Execute an upgrade through an effective full-access key, global-code owner, factory, or alternate deployment path while the advertised governance delay or vote is unsatisfied.
- **Required evidence:** Inventory every effective deployment and key path, compare with the governance requirement, and prove a bypass reaches deployed code or privileged state.
- **Exclusions:** Do not report without a reachable path and material target-specific harm.
- **Recovery:** Trace failure, retry, cancellation, and authorized recovery without duplicating value or authority.
- **Fix family:** Route every code deployment and global-code reference through the same effective governance policy; remove alternate full-access keys or include them in the approved emergency model.

## NA-AUTH-007 — Signed intent replay, recomposition, or weak domain binding

- **Kind:** security
- **Root cause:** Signed intent replay, recomposition, or weak domain binding.
- **Activation:** failed bundles leave replayable sub-intents, nonce consumption is late, a purpose/type discriminator or other domain field is absent, two accepted message schemas can encode the same signed bytes/hash for different privileged actions, or key state is unbounded.
- **Broken invariant:** authorization commits to full ordered operation context—including protocol/domain version, chain/verifier, action or function purpose, signer, recipient, assets, amounts, fees, nonce, and deadline—and is consumed exactly once before durable profitable effects.
- **Concrete sequence:** Sign an accepted intent, then replay its bytes under another action, chain, verifier, or failed bundle path to seek a second unauthorized effect.
- **Required evidence:** Show one signature or nonce authorizing two distinct material operations under the target verifier, with exact encoded bytes and domain fields.
- **Exclusions:** prove a signature valid for one accepted operation can authorize a different material operation under the deployed verifier. Cross-chain metadata reuse or another intentionally reusable signature is not a finding without an unauthorized effect that contradicts the protocol policy.
- **Recovery:** Trace failure, retry, cancellation, and authorized recovery without duplicating value or authority.
- **Fix family:** sign one canonical tagged envelope or enum whose domain/version, chain/verifier, action type, and complete payload are unambiguous before hashing; consume its nonce in the correct failure model.

## NA-AUTH-008 — Passkey/solver verification accepts attacker-controlled context

- **Kind:** security
- **Root cause:** The verifier treats unparsed or incomplete WebAuthn and quote fields as trusted authorization context, or lets one hostile quote force a shared failure.
- **Activation:** A target accepts passkey assertions, registers authenticators, or consumes solver quotes for a value-bearing action.
- **Broken invariant:** WebAuthn/curve verification and solver quotes bind every security-relevant field and cannot create a cheap global failure.
- **Concrete sequence:** Register a device with an invalid attestation or submit an assertion whose client-data type, challenge, origin, relying-party hash, or user-presence flags differ from the accepted request; then attempt the privileged action. For solver paths, submit an expired or mismatched route/amount quote and observe whether it blocks all users or settles at an unauthorized price.
- **Required evidence:** Show the actual parsed bytes, verification branch, accepted credential or quote, and resulting unauthorized action or material denial; compare with a valid control input.
- **Exclusions:** A trusted registration authority, correctly scoped credential, or rejection before any material effect may exclude the case. A missing check named in another platform's specification is not enough without this target's policy and execution path.
- **Recovery:** Revoke or expire a bad credential or quote and prove later valid requests can proceed without duplicating settlement.
- **Fix family:** Parse and validate the complete tagged challenge/response and quote envelope, bind it to the account, purpose, origin, route, amount, nonce, expiry, and accepted credential, then isolate failed requests.

## NA-AUTH-009 — Separate caller, originator, payer, and beneficiary

- **Kind:** conditional
- **Root cause:** Authorization is checked against the wrong principal, credential, or operation context.
- **Activation:** Calls can be forwarded or delegated; A later credit or authorization uses one identity in place of another
- **Broken invariant:** Authority and reimbursements use the principal intended at each trust boundary.
- **Concrete sequence:** Forward a call while preserving the original actor but changing the immediate caller or payer, then trigger a refund.
- **Required evidence:** Prove forwarding is supported and trace actual debits, credits, and authorization checks across the call chain.
- **Exclusions:** Direct-only deployments may make identities equal. Origin-based authorization can be intentional; demonstrate a policy mismatch.
- **Recovery:** Persist the relevant principal through deferred completion and failed refunds.
- **Fix family:** Bind each distinct principal explicitly and authenticate the appropriate boundary.

## NA-AUTH-010 — Check privileged methods against limited credentials

- **Kind:** conditional
- **Root cause:** Authorization is checked against the wrong principal, credential, or operation context.
- **Activation:** A credential may invoke only selected methods or low-friction actions; A privileged state change may be reachable with that credential
- **Broken invariant:** A limited credential cannot perform a privileged action outside its intended authority.
- **Concrete sequence:** Invoke the sensitive setter with the weakest actually provisioned credential that can reach it.
- **Required evidence:** Show the real credential permissions and runtime checks; identify whether an explicit-intent guard is meaningful in this environment.
- **Exclusions:** No universal tiny-payment or UI-confirmation check applies across runtimes. Owner-only reachability and absent limited credentials may exclude the case.
- **Recovery:** Check credential revocation and recovery of configuration without widening access.
- **Fix family:** Use environment-appropriate capability checks or explicit-intent enforcement for the real credential model.

## NA-AUTH-011 — Bind initialization to deployment authority

- **Kind:** conditional
- **Root cause:** Authorization is checked against the wrong principal, credential, or operation context.
- **Activation:** A newly deployed object needs one-time initialization; An untrusted actor may reach it before initialization completes
- **Broken invariant:** The first authoritative state is established only by the intended deployer or initializer.
- **Concrete sequence:** Schedule an untrusted initialization between object creation and the intended initialization.
- **Required evidence:** Inspect the actual deployment transaction or workflow and visibility boundary, not just an exposed initializer.
- **Exclusions:** Atomic creation and initialization, or authenticated initialization, can exclude the race.
- **Recovery:** Check safe redeployment or recovery and whether any funds or permissions were exposed before repair.
- **Fix family:** Initialize atomically with deployment where supported or require a bound initializer identity.

## NA-AUTH-012 — Public session credential can be reassigned across owners

- **Kind:** security
- **Root cause:** A registry treats a public credential identifier as proof of authority and lets a second account overwrite its owner, removing or invalidating the first account's live session.
- **Activation:** The target exposes session or function-call credential identifiers in events or readable storage and permits registration of an identifier already bound to another owner.
- **Broken invariant:** A live credential remains bound to its authorized owner until that owner or an approved recovery path revokes it.
- **Concrete sequence:** Observe a victim's active credential identifier, register the same identifier for an attacker account, and compare owner mappings, expiry, and the victim's ability to use the original session.
- **Required evidence:** Demonstrate the registration path, old-owner cleanup or overwrite, a working victim credential before the call, and a failed or redirected victim action afterward; distinguish a secret key from a public identifier.
- **Exclusions:** Reject if registration proves possession of the private key and cannot replace another owner's binding, or if the identifier is intentionally transferable by the current owner.
- **Recovery:** Check that the victim can revoke or regain the credential and that stale scheduled expiry cannot delete the replacement or restore the attacker's authority.
- **Fix family:** Require cryptographic possession and owner authorization for reassignment, reject live cross-owner collisions, and bind cleanup/expiry to a credential generation.
