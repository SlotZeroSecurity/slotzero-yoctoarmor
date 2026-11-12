use near_sdk::{near, AccountId, U128};
use std::collections::HashMap;
#[near(contract_state)]
pub struct Token { balances: HashMap<AccountId, u128>, supply: u128 }
#[near]
impl Token {
    #[private]
    pub fn ft_resolve_transfer(&mut self, sender_id: AccountId, receiver_id: AccountId, original: U128, unused: U128) -> U128 {
        let live = self.balances.get(&receiver_id).copied().unwrap_or(0);
        let refund = unused.0.min(original.0).min(live);
        *self.balances.entry(receiver_id).or_default() -= refund;
        *self.balances.entry(sender_id).or_default() += refund;
        U128(original.0 - refund) // Used amount, not unused amount.
    }
}
