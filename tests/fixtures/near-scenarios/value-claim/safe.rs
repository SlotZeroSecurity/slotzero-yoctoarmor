use near_sdk::{env, near, AccountId, U128};
use std::collections::HashMap;
#[near(contract_state)]
pub struct Vault { shares: HashMap<AccountId, u128>, total_shares: u128, tracked_assets: u128 }
#[near]
impl Vault {
    pub fn deposit(&mut self, amount: U128, min_shares: U128, actual_assets_before: U128) -> U128 {
        let user = env::predecessor_account_id();
        // Reconcile direct custody and use immutable virtual seed units.
        let numerator = amount.0.checked_mul(self.total_shares + 1_000).expect("overflow");
        let minted = numerator / (actual_assets_before.0 + 1_000);
        assert!(minted > 0 && minted >= min_shares.0);
        *self.shares.entry(user).or_default() += minted;
        self.total_shares += minted;
        self.tracked_assets = actual_assets_before.0 + amount.0;
        U128(minted)
    }
}
