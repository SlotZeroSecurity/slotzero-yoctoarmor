//! Safe-twin audit fixture showing the intended defenses; it is not deployable.
use near_sdk::{env, near, AccountId, NearToken, Promise, PromiseResult};
use std::collections::HashSet;

#[near(contract_state)]
pub struct Safe;

#[near]
impl Safe {
    pub fn install_worker(&mut self, worker: AccountId, allowance: NearToken) -> Promise {
        require!(!allowance.is_zero() && allowance <= NearToken::from_near(1));
        Promise::new(env::current_account_id()).add_access_key_allowance(
            env::signer_account_pk(), allowance, worker, "execute,quote".into(),
        )
    }

    #[private]
    pub fn on_withdraw(&mut self, operation_id: u64) {
        let operation = load_bound_operation(operation_id);
        match env::promise_result(0) {
            PromiseResult::Successful(_) => settle_once(operation),
            PromiseResult::Failed => credit_recoverable_claim(operation.owner, operation.amount),
        }
    }

    pub fn resume(&mut self, yield_id: Vec<u8>, response: Vec<u8>) {
        let request = load_live_yield(&yield_id);
        require!(env::predecessor_account_id() == request.responder);
        require!(env::block_height() <= request.expiry && !request.settled);
        validate_payload(&request.schema, &response);
        settle_yield_once(request, response);
    }

    #[payable]
    pub fn store_blob(&mut self, blob: Vec<u8>) {
        require!(blob.len() <= 4096);
        let before = env::storage_usage();
        persist_blob(blob);
        charge_predecessor(before, env::storage_usage());
    }

    pub fn ft_on_transfer(&mut self, _sender_id: AccountId, amount: u128, msg: String) -> u128 {
        require!(env::predecessor_account_id() == expected_ft());
        let used = consume_bounded(amount, msg);
        amount - used // NEP-141 receiver returns unused amount
    }

    #[private]
    #[init(ignore_state)]
    pub fn migrate() -> Self {
        let old: VersionedOldState = read_exact_old_borsh_state();
        migrate_all_fields(old)
    }

    pub fn execute_intent(&mut self, intent: Intent, signature: Vec<u8>) {
        require!(intent.network == env::current_account_id());
        require!(intent.deadline >= env::block_height());
        require!(!nonce_used(intent.signer.clone(), intent.nonce));
        verify_and_consume(canonical_domain_bound_bytes(&intent), signature);
    }

    pub fn unlock(&mut self, route: Route, proof: Vec<u8>) -> Promise {
        require!(route == configured_route());
        require!(verify_finalized_event(route.backend, route.chain, route.emitter, &proof));
        consume_event_once(route.event_id);
        Promise::new(route.receiver).transfer(route.amount)
    }

    pub fn reveal_random(&mut self, commitment: Vec<u8>, secret: Vec<u8>) {
        verify_round_account_commitment(commitment, secret);
        resolve_with_forced_timeout();
    }

    pub fn redeem_and_vote(&mut self, token_ids: Vec<String>) {
        require!(token_ids.len() <= 32);
        let unique: HashSet<_> = token_ids.iter().collect();
        require!(unique.len() == token_ids.len());
        for token_id in token_ids { debit_then_pay(token_id); }
        apply_documented_sybil_policy();
    }
}

// Opaque fixture helpers model reviewed dependencies and bound state.
struct Operation { owner: AccountId, amount: NearToken }
struct YieldRequest { responder: AccountId, expiry: u64, settled: bool, schema: Vec<u8> }
struct VersionedOldState;
struct Intent { network: AccountId, deadline: u64, signer: AccountId, nonce: u64 }
#[derive(PartialEq)] struct Route { backend: u8, chain: u64, emitter: Vec<u8>, event_id: Vec<u8>, receiver: AccountId, amount: NearToken }
fn load_bound_operation(_: u64) -> Operation { unimplemented!() }
fn settle_once(_: Operation) {}
fn credit_recoverable_claim(_: AccountId, _: NearToken) {}
fn load_live_yield(_: &[u8]) -> YieldRequest { unimplemented!() }
fn validate_payload(_: &[u8], _: &[u8]) {}
fn settle_yield_once(_: YieldRequest, _: Vec<u8>) {}
fn persist_blob(_: Vec<u8>) {}
fn charge_predecessor(_: u64, _: u64) {}
fn expected_ft() -> AccountId { unimplemented!() }
fn consume_bounded(_: u128, _: String) -> u128 { 0 }
fn read_exact_old_borsh_state() -> VersionedOldState { unimplemented!() }
fn migrate_all_fields(_: VersionedOldState) -> Safe { Safe }
fn nonce_used(_: AccountId, _: u64) -> bool { false }
fn canonical_domain_bound_bytes(_: &Intent) -> Vec<u8> { vec![] }
fn verify_and_consume(_: Vec<u8>, _: Vec<u8>) {}
fn configured_route() -> Route { unimplemented!() }
fn verify_finalized_event(_: u8, _: u64, _: Vec<u8>, _: &[u8]) -> bool { true }
fn consume_event_once(_: Vec<u8>) {}
fn verify_round_account_commitment(_: Vec<u8>, _: Vec<u8>) {}
fn resolve_with_forced_timeout() {}
fn debit_then_pay(_: String) {}
fn apply_documented_sybil_policy() {}
