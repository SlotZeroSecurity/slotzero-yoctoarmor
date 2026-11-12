// Public safe twin for the async/authentication smoke fixture.
#[near]
impl Contract {
    #[payable]
    pub fn withdraw(&mut self, amount: U128) -> Promise {
        assert_one_yocto();
        let account = env::predecessor_account_id();
        let balance = self.balances.get(&account).unwrap_or(0);
        require!(balance >= amount.0);
        self.balances.insert(account.clone(), balance - amount.0);
        ext_receiver::ext(account.clone())
            .with_attached_deposit(NearToken::from_yoctonear(amount.0))
            .withdraw()
            .then(Self::ext(env::current_account_id()).on_withdraw(account, amount))
    }

    #[private]
    pub fn on_withdraw(&mut self, account: AccountId, amount: U128) {
        if !matches!(env::promise_result(0), PromiseResult::Successful(_)) {
            let balance = self.balances.get(&account).unwrap_or(0);
            self.balances.insert(account, balance + amount.0);
        }
    }

    #[payable]
    pub fn set_owner(&mut self, new_owner: AccountId) {
        assert_one_yocto();
        require!(env::predecessor_account_id() == self.owner_id);
        self.owner_id = new_owner;
    }
}
