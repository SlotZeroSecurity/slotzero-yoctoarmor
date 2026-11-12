//! Intentionally vulnerable, non-deployable audit fixture.
use near_sdk::{env, near, AccountId, Gas, NearToken, Promise, PromiseResult};
use near_sdk::store::{LookupMap, Vector};

#[near(contract_state)]
pub struct Vulnerable {
    blobs: Vector<Vec<u8>>,
    yields: LookupMap<Vec<u8>, AccountId>,
    expected_ft: AccountId,
}

#[near]
impl Vulnerable {
    pub fn install_worker(&mut self, worker: AccountId) -> Promise {
        // Empty method_names and no bounded allowance/balance lifecycle.
        Promise::new(env::current_account_id()).add_access_key_allowance(
            env::signer_account_pk(), NearToken::from_near(100), worker, "".into(),
        )
    }

    pub fn delete_funded_gas_key(&mut self) -> Promise {
        // Residual prepaid gas-key funds are not withdrawn first.
        Promise::new(env::current_account_id()).delete_key(env::signer_account_pk())
    }

    pub fn withdraw(&mut self, receiver: AccountId, amount: NearToken) -> Promise {
        Promise::new(receiver).transfer(amount).then(
            Self::ext(env::current_account_id()).with_static_gas(Gas::from_tgas(1)).on_withdraw(amount),
        )
    }

    pub fn on_withdraw(&mut self, amount: NearToken) -> Promise {
        if matches!(env::promise_result(0), PromiseResult::Failed) {
            return Promise::new(env::predecessor_account_id()).transfer(amount);
        }
        Promise::new(env::current_account_id()).transfer(NearToken::from_yoctonear(0))
    }

    pub fn resume(&mut self, yield_id: Vec<u8>, response: Vec<u8>) {
        // No requester/responder/schema/expiry/terminal-state binding.
        env::promise_yield_resume(&yield_id, &response);
    }

    pub fn store_blob(&mut self, blob: Vec<u8>) {
        self.blobs.push(blob); // no bound, storage charge, or cleanup liability
    }

    pub fn ft_on_transfer(&mut self, _sender_id: AccountId, amount: u128, _msg: String) -> u128 {
        // Does not authenticate expected_ft and returns consumed, not unused.
        amount
    }

    #[init(ignore_state)]
    pub fn migrate(json_state: String) -> Self {
        near_sdk::serde_json::from_str(&json_state).unwrap()
    }

    pub fn execute_intent(&mut self, signature: Vec<u8>, amount: u128) {
        let signed = amount.to_le_bytes(); // omits domain/verifier/recipient/nonce/deadline
        require!(verify_signature(&signature, &signed));
    }

    pub fn unlock(&mut self, proof: Vec<u8>, receiver: AccountId) -> Promise {
        require!(verify_inclusion(&proof)); // no route, emitter, chain, or finality binding
        Promise::new(receiver).transfer(NearToken::from_near(1))
    }

    pub fn claim_random(&mut self, guess: u8) {
        require!(env::random_seed_array()[0] == guess);
    }

    pub fn redeem_and_vote(&mut self, token_ids: Vec<String>) {
        debit_once();
        for token_id in token_ids { pay_and_vote_per_account(token_id); }
    }
}

fn verify_signature(_: &[u8], _: &[u8]) -> bool { true }
fn verify_inclusion(_: &[u8]) -> bool { true }
fn debit_once() {}
fn pay_and_vote_per_account(_: String) {}
