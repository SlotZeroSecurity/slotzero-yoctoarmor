// Public training fixture. It is intentionally vulnerable and is not production code.
#[near]
impl Contract {
    #[payable]
    pub fn withdraw(&mut self, amount: U128) -> Promise {
        let account = env::predecessor_account_id();
        require!(self.balances.get(&account).unwrap_or(0) >= amount.0);
        ext_receiver::ext(account.clone())
            .with_attached_deposit(NearToken::from_yoctonear(amount.0))
            .withdraw()
            .then(Self::ext(env::current_account_id()).on_withdraw(account, amount))
    }

    // Missing #[private], and the reusable balance is debited only after dispatch.
    pub fn on_withdraw(&mut self, account: AccountId, amount: U128) {
        if matches!(env::promise_result(0), PromiseResult::Successful(_)) {
            let balance = self.balances.get(&account).unwrap_or(0);
            self.balances.insert(account, balance - amount.0);
        }
    }

    // The original signer survives intermediary calls and is not the direct caller.
    pub fn set_owner(&mut self, new_owner: AccountId) {
        require!(env::signer_account_id() == self.owner_id);
        self.owner_id = new_owner;
    }
}
