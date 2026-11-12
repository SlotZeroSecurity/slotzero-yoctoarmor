use near_sdk::{env, near, AccountId, PromiseOrValue, U128};
use std::collections::HashMap;
#[near(contract_state)]
pub struct Token { balances: HashMap<AccountId, u128>, supply: u128 }
#[near]
impl Token {
    pub fn ft_on_transfer(&mut self, sender_id: AccountId, amount: U128, _msg: String) -> PromiseOrValue<U128> {
        let receiver = env::current_account_id();
        *self.balances.entry(receiver).or_default() += amount.0;
        let _ = sender_id;
        PromiseOrValue::Value(U128(0))
    }
    pub fn ft_resolve_transfer(&mut self, sender_id: AccountId, receiver_id: AccountId, unused: U128) -> U128 {
        // Ignores that receiver already moved most tokens before settlement.
        *self.balances.entry(sender_id).or_default() += unused.0;
        *self.balances.entry(receiver_id).or_default() -= unused.0;
        U128(unused.0)
    }
}
