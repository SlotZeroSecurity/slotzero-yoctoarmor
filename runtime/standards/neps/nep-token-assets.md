# NEP Token and Asset Attacker Checklists

Apply exact pinned signatures, serializers, payability, return polarity, storage rules, and events. Cross-contract token behavior must remain safe after every receipt, including failure, malformed return, replay, and interleaving.

## NEP-0141 — Fungible Tokens

- **Trigger / attacker:** FT core/receiver/resolver exports or token accounting; malicious sender, receiver, approved integration, and arbitrary FT contract.
- **Invariant:** total supply and balances conserve; each transfer settles once; transfer-call unused amount is interpreted and capped correctly.
- **Probe:** zero/one/max amounts, unregistered accounts, wrong FT predecessor, receiver panic/malformed/0/full/over-amount return, sender unregister/balance change before resolver, direct resolver call, and duplicate/interleaved settlement.
- **Conformance:** exact 1 yocto on transfers, decimal-string amounts, core views, receiver `sender_id`, private resolver, return polarity, and NEP-300/297 events where claimed.
- **Gate / verify:** sandbox malicious receiver and assert state/balance conservation after every receipt. ABI-only drift without material consumer harm is conformance.

## NEP-0145 — Storage Management

- **Trigger / attacker:** registration or user-paid storage; payer, beneficiary, third party, and storage-bloat attacker can differ.
- **Invariant:** every user-induced byte is funded, credited to the correct beneficiary, withdrawable only when unlocked, and refunded to the predecessor payer as specified.
- **Probe:** omitted/provided account, new/existing registration, `registration_only` branches, below/exact/excess deposit, finite/null max, withdraw zero/max/excess, unregister force/non-force, transfer failure, and third-party victim bloat.
- **Conformance:** exact method payability, min/max/total/available semantics, beneficiary versus refund recipient, and forced burn behavior.
- **Gate / verify:** measure real storage deltas and NEAR transfers in sandbox; a custom policy is a deviation but becomes security only with reachable solvency or asset harm.

## NEP-0148 — FT Metadata

- **Trigger / attacker:** `ft_metadata` or integrations using symbol/decimals/icon/reference; malicious governance or upgrade can change representation.
- **Invariant:** metadata is valid, stable under the protocol's governance assumptions, and never used as authoritative asset identity or accounting precision without binding.
- **Probe:** invalid spec, extreme decimals, duplicate symbols, malformed data URI/reference hash, mutable metadata, bridge decimal mismatch, and stale caches.
- **Conformance:** exact view schema, spec/version, required fields, and optional reference/hash relationship.
- **Gate / verify:** metadata drift is normally conformance; escalate only when it causes material mispricing, wrong-asset routing, or signature/proof mismatch.

## NEP-0171 — Non-Fungible Tokens

- **Trigger / attacker:** NFT core/receiver/resolver or ownership mirrors; malicious owner, approved operator, receiver, and NFT contract.
- **Invariant:** exactly one owner exists across all indexes; transfer authorization is current; transfer-call resolves once without overwriting intervening ownership.
- **Probe:** zero/one yocto, unauthorized/expired approval, receiver false/true/panic/malformed, recipient retransfer/burn before resolver, direct resolver, duplicate token IDs, and coupled-index failure.
- **Conformance:** exact core signatures, owner/approval semantics, cleared approvals, receiver predecessor, private resolver, `sender_id` versus previous owner, and return polarity.
- **Gate / verify:** sandbox interleavings and assert owner/index/approval agreement after each receipt.

## NEP-0177 — NFT Metadata

- **Trigger / attacker:** contract/token metadata or marketplace/bridge consumption.
- **Invariant:** metadata cannot impersonate another asset, break bounded enumeration, or produce inconsistent content commitments.
- **Probe:** missing required fields, oversized text/media, malformed timestamps/hashes, mutable copies/supply, reference/hash mismatch, duplicate token metadata, and hostile URLs.
- **Conformance:** exact spec, contract metadata, token metadata types, and optional field relationships.
- **Gate / verify:** content and URL risks are off-chain trust unless a contract or critical service interprets them materially.

## NEP-0178 — NFT Approvals

- **Trigger / attacker:** approve/revoke/is-approved exports or marketplace callbacks; owner, operator, marketplace, and stale approval holder.
- **Invariant:** only the owner changes approvals; approval IDs are monotonic/non-reused; transfer clears approvals; storage is charged/refunded once.
- **Probe:** reapproval, stale/wrong ID, approval counter boundary, approve callback failure, revoke with no callback, transfer/resolver restoration, many approvals, and zero/exact/excess deposit.
- **Conformance:** `nft_approve` may require more than one yocto for storage; revoke methods require exact one; approval ID is the bounded standard JSON number.
- **Gate / verify:** assert live approval entry and ID at use time. Marketplace cache staleness alone needs a material execution path.

## NEP-0181 — NFT Enumeration

- **Trigger / attacker:** total/token/owner enumeration and pagination; attacker grows holdings and uses boundary indices/limits.
- **Invariant:** enumeration matches primary ownership, is bounded, deterministic, and cannot brick state-changing paths.
- **Probe:** empty sets, start beyond end, zero/huge limit, transfer/burn/mint index drift, duplicate/missing token, maximum owner holdings, and concurrent view pagination changes.
- **Conformance:** exact optional pagination arguments, return ordering/shape, and totals.
- **Gate / verify:** reconcile full enumerated sets against primary maps after state-machine sequences; expensive views alone are usually quality.

## NEP-0199 — NFT Royalties and Payouts

- **Trigger / attacker:** payout/transfer-payout exports or marketplace settlement; token owner/creator controls royalty configuration and receiver count.
- **Invariant:** payout recipients are authorized and unique as intended; sums never exceed sale balance; rounding cannot mint value or strand material dust.
- **Probe:** excessive `max_len_payout`, duplicate/aliased recipients, zero/full royalty, sum over 100%, under-total with material remainder, omitted seller, owner=royalty recipient, integer rounding, stale approvals, and transfer failure after payout computation. On the consuming marketplace, substitute a hostile but ABI-conforming NFT contract that returns an attacker-chosen payout map.
- **Conformance:** exact payout shape, maximum-length enforcement, transfer authorization, and royalty/sale-balance semantics.
- **Gate / verify:** property-test payout sum, seller proceeds, remainder policy, and recipient cardinality across boundaries. Prove the consumer validates its own accepted split rather than assuming the external NFT includes the seller; integration expectations without loss remain conformance.

## NEP-0245 — Multi-Token Standard

- **Trigger / attacker:** MT single/batch transfer, receiver, resolver, approvals, or mixed fungible/NFT IDs; attacker controls duplicate IDs and per-ID amounts.
- **Invariant:** per-token supply/balance/approval conservation holds independently and in aggregate; each batch item is charged and settled exactly once.
- **Probe:** duplicate IDs, length mismatch, zero/max amounts, mixed token classes, wrong predecessor, partial receiver returns, malformed vectors, unregister/interleaving, direct resolver, and batch gas limits.
- **Conformance:** exact core/batch ABI, per-item return semantics, one-yocto rule, receiver/resolver authority, and events.
- **Gate / verify:** property-test vector alignment and per-ID conservation with malicious receiver outcomes.

## NEP-0256 — NFT Events

- **Trigger / attacker:** NFT mint/transfer/burn event emission or consumers.
- **Invariant:** successful NFT state transitions emit canonical event data once and failed/foreign receipts cannot impersonate them.
- **Probe:** missing/duplicate event, wrong owner/authorized ID/token list, batch mismatch, event-before-panic, malformed envelope, and indexer replay.
- **Conformance:** exact NEP-297 envelope plus NFT event names/version/data.
- **Gate / verify:** reconcile successful receipt events with owner/approval state. Non-material event drift stays conformance.

## NEP-0300 — FT Events

- **Trigger / attacker:** FT mint/transfer/burn events or consumers.
- **Invariant:** canonical events match successful supply/balance changes and cannot drive value from failed or foreign receipts.
- **Probe:** wrong old/new owner, amount encoding, memo, duplicate/missing event, batch mismatch, event-before-panic, and replayed logs.
- **Conformance:** exact NEP-297 envelope plus FT event schema/version and decimal-string amounts.
- **Gate / verify:** reconcile logs with per-receipt ledger deltas; severity requires a material consumer.

## NEP-0393 — Soulbound Tokens

- **Trigger / attacker:** SBT issuer/registry, soul transfer, ban/recovery, or proof-of-personhood use; issuer, registry, account controller, and Sybil actor are distinct.
- **Invariant:** non-transferability holds except through the authorized recovery flow; registry/issuer boundaries cannot forge, duplicate, or preserve credentials on both souls.
- **Probe:** ordinary transfer/approval paths, unauthorized soul transfer, partial issuer migration, source not banned, duplicate class/token, revoke/reissue races, hostile issuer, and one-account-one-person assumptions.
- **Conformance:** compare issuer/registry APIs, ownership restrictions, transfer/banning lifecycle, and enumeration semantics.
- **Gate / verify:** cross-contract sandbox must show atomic logical migration or bounded recovery. SBT possession alone never proves unique humanity.

## NEP-0621 — Vaults

- **Trigger / attacker:** share vault previews/deposit/mint/withdraw/redeem, adapters, or managed assets; attacker can donate, front-run, manipulate rounding, and fail async asset calls.
- **Invariant:** shares and all managed assets conserve; previews and execution use compatible policy; rounding favors the vault; one pending withdrawal cannot spend twice.
- **Probe:** empty-vault bootstrap, donation/inflation, zero-share mint, direct asset transfer, max boundaries, stale/dishonest adapter, mutable asset/offset, preview drift, slippage, async failure, and position remapping.
- **Conformance:** NEP-141 share token, exact preview/max/action APIs, underlying asset identity, rounding directions, and receiver/min-share behavior.
- **Gate / verify:** stateful properties over shares, assets, adapters, donations, and failed receipts; advisory assumptions outside managed scope must be disclosed.
