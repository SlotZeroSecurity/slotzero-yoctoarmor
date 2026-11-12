use near_sdk::{env, near, AccountId, NearToken, Promise, PromiseResult};
use std::collections::HashMap;
#[near(contract_state)]
pub struct Vault { balances: HashMap<AccountId, u128>, pending: HashMap<u64, (AccountId, u128)> }
#[near]
impl Vault {
    pub fn withdraw(&mut self, id: u64, amount: u128, recipient: AccountId) -> Promise {
        let user = env::predecessor_account_id();
        assert!(self.balances.get(&user).copied().unwrap_or(0) >= amount);
        // The balance remains spendable until a later receipt. Two withdrawals can pass.
        Promise::new(recipient).transfer(NearToken::from_yoctonear(amount))
            .then(Self::ext(env::current_account_id()).on_withdraw(id, user, amount))
    }
    pub fn on_withdraw(&mut self, id: u64, user: AccountId, amount: u128) {
        // Public resolver accepts caller-supplied identity and can be replayed.
        if matches!(env::promise_result(0), PromiseResult::Successful(_)) {
            *self.balances.entry(user).or_default() -= amount;
        }
        self.pending.remove(&id);
    }
}
