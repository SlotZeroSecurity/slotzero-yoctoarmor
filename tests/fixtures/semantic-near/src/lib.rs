use near_sdk::{env, near, AccountId, NearToken, Promise, PromiseResult};

#[near(contract_state)]
pub struct Vault {
    owner: AccountId,
    pending: std::collections::HashMap<AccountId, NearToken>,
}

#[near]
impl Vault {
    pub fn withdraw(&mut self, receiver: AccountId, amount: NearToken) -> Promise {
        let caller = env::predecessor_account_id();
        assert_eq!(caller, receiver, "caller must own withdrawal");
        self.pending.insert(receiver.clone(), amount);
        Promise::new(receiver.clone())
            .transfer(amount)
            .then(Self::ext(env::current_account_id()).on_withdraw(receiver))
    }

    #[private]
    pub fn on_withdraw(&mut self, receiver: AccountId) {
        if matches!(env::promise_result(0), PromiseResult::Successful(_)) {
            self.pending.remove(&receiver);
        }
    }

    pub fn rotate_owner(&mut self, next: AccountId) {
        assert_eq!(env::signer_account_id(), self.owner, "owner only");
        self.owner = next;
    }
}
