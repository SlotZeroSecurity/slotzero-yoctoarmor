use near_sdk::near;

#[near(contract_state)]
pub struct Signals;

#[near]
impl Signals {
    pub fn ft_transfer_call(&self) {}
    pub fn storage_deposit(&self) {}
    pub fn w_resolve_auth(&self) {}
    pub fn promise_yield_create(&self) {}
    pub fn bls12_381(&self) {}
    pub fn p256_verify(&self) {}
    pub fn sha3_256(&self) {}
}

pub struct BandwidthScheduler;
pub struct FlatStorage;
pub struct ChunkValidator;
