use near_sdk::{env, near, AccountId, NearToken};
use std::collections::HashMap;
#[near(contract_state)]
pub struct Registry { records: HashMap<AccountId, String>, baseline: HashMap<AccountId, u64>, credits: HashMap<AccountId, NearToken> }
#[near]
impl Registry {
    #[payable]
    pub fn register_for(&mut self, beneficiary: AccountId, note: String) {
        let payer = env::predecessor_account_id();
        let old = self.baseline.get(&beneficiary).copied().unwrap_or(env::storage_usage());
        self.records.insert(beneficiary.clone(), note);
        let due = env::storage_usage().saturating_sub(old) as u128 * env::storage_byte_cost().as_yoctonear();
        self.baseline.insert(beneficiary, env::storage_usage());
        // Another user's writes changed global usage since old; payer is charged for them.
        assert!(env::attached_deposit().as_yoctonear() >= due);
        self.credits.insert(payer, NearToken::from_yoctonear(due));
    }
}
