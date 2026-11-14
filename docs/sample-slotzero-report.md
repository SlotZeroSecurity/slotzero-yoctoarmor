# 🔐 NEAR YoctoArmor v1 Security Review — fundraiser

---

## Scope

|  |  |
| --- | --- |
| **Files reviewed** | `src/lib.rs` |
| **Confidence threshold (1-100)** | 75 |
| **Passes** | 3 |
| **Revision** | `unborn-HEAD` |
| **NEAR evidence and NEP ledger** | [Technical annex](sample-technical-annex.md) |
| **Threat model** | Threat model: `THREAT_MODEL.md` · `sha256:e5714c32462cd433d450aa4b2d97b6bf707bd85df2ae6149aa5775164ef5a6a5`. Explicit trust assumptions constrain reportable findings. |
| **Review limitations** | Final rescan validation was blocked or unresolved; the stopping criterion was not established. Testing recorded in invariant-ledger.jsonl was blocked; the stopping criterion was not established. Testing recorded in nep-differential.jsonl was blocked; the stopping criterion was not established. Testing recorded in official-guidance-coverage.jsonl was blocked; the stopping criterion was not established. Asynchronous schedule testing was blocked; the stopping criterion was not established. |

---

## Findings

[92] **1. Any caller can divert accrued NEAR fees**

`Contract.set_near_fee_recipient` · Confidence: 92 · Severity: High · seen in 3/3 runs

**Description**
An ordinary caller can replace the fee recipient without authorization, causing successful fee withdrawal to send the accrued NEAR fee pool to the attacker.

**Fix**

```diff
- self.near_fee_recipient = recipient_id;
+ require!(env::predecessor_account_id() == self.beneficiary, "Only beneficiary may set fee recipient");
+ self.near_fee_recipient = recipient_id;
```

---

[85] **2. Full storage refund retains a funded record**

`Contract.on_transfer_complete` · Confidence: 85 · Severity: Medium · seen in 3/3 runs

**Description**
A donor can recover its full storage deposit while its record remains, conditionally leaving too little NEAR state stake for a later donor’s withdrawal.

**Fix**

```diff
- if let Some(mut record) = self.donors.get(&donor_id).cloned() {
- if !succeeded {
+ require!(!self.storage_withdrawals.contains(&donor_id), "Storage withdrawal pending");
+ if let Some(mut record) = self.donors.get(&donor_id).cloned() {
+ if succeeded {
+ self.donors.remove(&account_id);
+ } else {
```

---

[85] **3. Successful payout locks donor storage deposits**

`Contract.withdraw_storage` · Confidence: 85 · Severity: High · seen in 3/3 runs

**Description**
After a successful NEAR or YOLO payout, donor contribution fields remain positive, so the storage-withdrawal guard rejects the donor’s recorded NEAR deposit.

**Fix**

```diff
- record.near_amount == 0 && record.yolo_amount == 0,
+ (record.near_amount == 0 || (self.near_raised >= self.near_goal && self.near_withdrawn))
+ && (record.yolo_amount == 0 || (self.yolo_raised >= self.yolo_goal && self.yolo_withdrawn)),
```

---

[85] **4. One unclaimed refund blocks other donors’ storage**

`Contract.withdraw_storage` · Confidence: 85 · Severity: Medium · seen in 2/3 runs

**Description**
A donor can leave a tiny failed-goal refund unclaimed, keeping the global settlement gate false and blocking every other fully refunded donor’s storage deposit.

**Fix**

```diff
- require!(self.all_assets_settled(), "Settle all campaign funds first");
- let donor_id = env::predecessor_account_id();
+ let donor_id = env::predecessor_account_id();
+ let donor = self.donors.get(&donor_id).expect("Donor is not registered");
+ require!(donor.pending_refunds == 0 && donor.near_amount == 0 && donor.yolo_amount == 0, "Settle your contributions first");
```

---

Findings List

| # | Confidence | Title |
|---|---|---|
| 1 | [92] | Any caller can divert accrued NEAR fees |
| 2 | [85] | Full storage refund retains a funded record |
| 3 | [85] | Successful payout locks donor storage deposits |
| 4 | [85] | One unclaimed refund blocks other donors’ storage |

---

## Leads

_Concrete vulnerability trails whose full exploit path remains unverified. Not scored._

- **Donation splitting changes rounded fees** — `Contract.donate_near` · seen in 3/3 runs — Code smells: fee rounded before aggregation, no carried remainder — Per-receipt fee flooring changes fee ledgers when equivalent donations are split; the gas-adjusted material loss and distinct authorized fee owner remain unproved.
- **First-caller initialization depends on deployment order** — `Contract.new` · seen in 3/3 runs — Code smells: beneficiary derived from predecessor, no deployed action-order evidence — The first initializer becomes beneficiary; a takeover requires a separate reachable uninitialized interval that the supplied deployment evidence does not establish.
- **Oversized token result could confuse callback** — `Contract.on_transfer_complete` · seen in 0/3 runs — Code smells: bounded promise-result read used as success classifier, token return behavior unavailable — The 32-byte result bound might classify a successful token transfer as failed and restore accounting; the configured token’s result and a second payout path remain unproved.
- **YOLO registration deposit recovery is unverified** — `Contract.register_yolo_receiver` · seen in 3/3 runs — Code smells: full attached deposit forwarded, callback stores only registration Boolean, no payer credit path — The beneficiary funds token registration, but the fundraiser records no payer claim for a failed child deposit or NEP-145 excess returned to its account; configured-token balance effects remain untested.
