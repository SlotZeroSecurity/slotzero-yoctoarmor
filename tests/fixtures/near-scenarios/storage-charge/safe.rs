use near_sdk::{env, near, AccountId, NearToken};
use std::collections::HashMap;
#[near(contract_state)]
pub struct Registry { records: HashMap<AccountId, String>, credits: HashMap<AccountId, NearToken> }
#[near]
impl Registry {
    #[payable]
    pub fn register_for(&mut self, beneficiary: AccountId, note: String) {
        let payer = env::predecessor_account_id();
        let before = env::storage_usage();
        self.records.insert(beneficiary.clone(), note);
        let bytes = env::storage_usage().saturating_sub(before);
        let due = bytes as u128 * env::storage_byte_cost().as_yoctonear();
        assert!(env::attached_deposit().as_yoctonear() >= due);
        self.credits.insert(payer, NearToken::from_yoctonear(due));
        // Track beneficiary and payer separately for later deletion/refund.
    }
}
