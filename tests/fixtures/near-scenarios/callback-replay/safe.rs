use near_sdk::{env, near, AccountId, NearToken, Promise, PromiseResult};
use std::collections::HashMap;
#[near(contract_state)]
pub struct Vault { balances: HashMap<AccountId, u128>, pending: HashMap<u64, (AccountId, u128)> }
#[near]
impl Vault {
    pub fn withdraw(&mut self, id: u64, amount: u128, recipient: AccountId) -> Promise {
        let user = env::predecessor_account_id();
        let balance = self.balances.entry(user.clone()).or_default();
        assert!(*balance >= amount && !self.pending.contains_key(&id));
        *balance -= amount; // Reserve before dispatch.
        self.pending.insert(id, (user, amount));
        Promise::new(recipient).transfer(NearToken::from_yoctonear(amount))
            .then(Self::ext(env::current_account_id()).on_withdraw(id))
    }
    #[private]
    pub fn on_withdraw(&mut self, id: u64) {
        let (user, amount) = self.pending.remove(&id).expect("unknown or settled operation");
        if !matches!(env::promise_result(0), PromiseResult::Successful(_)) {
            *self.balances.entry(user).or_default() += amount;
        }
    }
}
