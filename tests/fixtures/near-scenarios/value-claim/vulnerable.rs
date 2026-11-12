use near_sdk::{env, near, AccountId, U128};
use std::collections::HashMap;
#[near(contract_state)]
pub struct Vault { shares: HashMap<AccountId, u128>, total_shares: u128, tracked_assets: u128 }
#[near]
impl Vault {
    pub fn deposit(&mut self, amount: U128) -> U128 {
        let user = env::predecessor_account_id();
        // Direct donations increase actual custody but are omitted from tracked_assets.
        let minted = if self.total_shares == 0 { amount.0 } else { amount.0 * self.total_shares / self.tracked_assets };
        *self.shares.entry(user).or_default() += minted;
        self.total_shares += minted;
        self.tracked_assets += amount.0;
        U128(minted) // Zero-share deposits are accepted.
    }
}
