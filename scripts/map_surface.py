#!/usr/bin/env python3
"""Build a deterministic NEAR audit surface manifest without changing the target."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter
from pathlib import Path


from source_inventory import SKIP_DIRS, SOURCE_SUFFIXES, discover, is_test_or_example, validate_root
from pattern_routing import select_categories, reference_paths
from review_policy import SPECIALIST_ROLES

ROLE_ORDER = [
    "entrypoints-auth",
    "async-promises",
    "state-storage",
    "token-accounting",
    "math-economics",
    "gas-dos",
    "invariant-flow",
    "periphery-build",
    "coverage-sweep",
    "numerical-gap",
    "trust-gap",
    "flow-gap",
]
CAPABILITY_ROLES = ["protocol-modeler", "pattern-matcher", "intent-reasoner"]
ACTIVE_ALWAYS = ["invariant-synthesis", "mutation-analysis"]

NEP_REGISTRY = Path(__file__).resolve().parent.parent / "references" / "nep-registry.json"
OFFICIAL_DOCS_REGISTRY = (
    Path(__file__).resolve().parent.parent / "references" / "official-docs-registry.json"
)

SIGNALS: dict[str, re.Pattern[str]] = {
    "near_sdk": re.compile(r"\bnear[_-]sdk\b|#\[near(?:_bindgen|\b)", re.I),
    "macro_trait_exports": re.compile(
        r"#\[\s*(?:near|near_bindgen)\b[^\]]*\]\s*impl\s+[^\{\n]+\s+for\s+[^\{\n]+\{",
        re.I,
    ),
    "promises": re.compile(
        r"\bPromise\b|PromiseResult|ext_contract|promise_result|callback_(?:result|unwrap)|"
        r"promise_yield|\.then\s*\(|\.and\s*\(|with_static_gas|with_unused_gas_weight",
        re.I,
    ),
    "callback_entrypoints": re.compile(
        r"#\[\s*callback_(?:result|unwrap)\s*\]|env::promise_result|env::promise_results_count|"
        r"\b(?:on|after|resolve|callback)[_A-Za-z0-9]*callback\b|\b[A-Za-z0-9_]+_callback\b",
        re.I,
    ),
    "tokens": re.compile(
        r"ft_transfer|ft_on_transfer|ft_resolve_transfer|nft_transfer|nft_on_transfer|nft_resolve_transfer|"
        r"nep[_-]?(?:141|145|171|178|199|245|297|330|366|413|621|641)",
        re.I,
    ),
    "storage": re.compile(
        r"storage_(?:usage|byte_cost|deposit|withdraw|unregister|balance|read|write|remove)|"
        r"near_sdk::(?:store|collections)|"
        r"LookupMap|LookupSet|UnorderedMap|UnorderedSet|IterableMap|IterableSet|TreeMap|Lazy(?:Option)?|"
        r"Vector::new|std::collections::(?:HashMap|HashSet|BTreeMap|BTreeSet)|"
        r"\b(?:HashMap|HashSet|BTreeMap|BTreeSet)\s*<|mem::forget|\.flush\s*\(|"
        r"BorshStorageKey|\bSTATE\b",
        re.I,
    ),
    "destructive_take": re.compile(r"\.\s*take\s*\(\s*\)", re.I),
    "queues": re.compile(r"\bVecDeque\b|\bBinaryHeap\b|\bqueue\b|\.pop_front\s*\(|\.front\s*\(", re.I),
    "upgrade": re.compile(r"migrate|upgrade|deploy_contract|ignore_state|add_full_access_key|delete_key", re.I),
    "access_keys": re.compile(r"access[_ -]?key|full[_ -]?access[_ -]?key|function[_ -]?call[_ -]?key", re.I),
    "gas_keys": re.compile(
        r"gas[_ -]?key|TransferToGasKey|WithdrawFromGasKey|GasKeyNonce|nonce_index|num_nonces|nonce[_ -]?lane",
        re.I,
    ),
    "one_yocto": re.compile(
        r"assert_one_yocto|one[_ -]?yocto|from_yoctonear\s*\(\s*1\s*\)|"
        r"attached_deposit\s*\(\s*\)\s*==\s*NearToken::from_yoctonear\s*\(\s*1\s*\)",
        re.I,
    ),
    "intents": re.compile(r"\bintent(?:s)?\b|passkey|webauthn|relayer|nonce|deadline", re.I),
    "meta_transactions": re.compile(
        r"SignedDelegateAction|DelegateAction|DelegateV2|meta[_ -]?transaction|max_block_height",
        re.I,
    ),
    "wallet_auth": re.compile(
        r"signMessage|verifySignature|wallet[_ -]?(?:auth|login)|callbackUrl|challenge[_ -]?nonce|passkey|webauthn",
        re.I,
    ),
    "bridge": re.compile(r"\bbridge\b|aurora|ethereum|evm|proof|finality|reorg|unlock|relayer", re.I),
    "chain_signatures": re.compile(r"chain[_ -]?signature|mpc|derived_public_key|payload_v2|yield_resume", re.I),
    "yield_resume": re.compile(
        r"promise_yield_create|promise_yield_resume|YIELD_REGISTER|yield[_ -]?(?:id|timeout|resume)",
        re.I,
    ),
    "global_contracts": re.compile(
        r"use_global_(?:account_id|hash)|deploy_global_contract|global[_ -]?contract",
        re.I,
    ),
    "build_artifacts": re.compile(
        r"code[_ -]?hash|reproducible[_ -]?build|wasm32-unknown-unknown|profile\.release|overflow-checks|Cargo\.lock",
        re.I,
    ),
    "native_transfers": re.compile(
        r"NearToken|attached_deposit|\.transfer\s*\(|TransferAction|Promise::new",
        re.I,
    ),
    "gas": re.compile(
        r"\bGas\b|TGas|prepaid_gas|used_gas|with_static_gas|with_unused_gas_weight|"
        r"GasWeight|gas[_ -]?(?:limit|budget|starvation|exhaust)",
        re.I,
    ),
    "offchain_rpc": re.compile(
        r"json[_ -]?rpc|light_client_proof|tx_status|receipt[_ -]?(?:id|outcome)|finality|indexer|near[_ -]?lake",
        re.I,
    ),
    "tee": re.compile(r"\bTEE\b|attestation|TDX|enclave|dstack|OutLayer|TCB", re.I),
    "runtime_consensus": re.compile(
        r"\bnearcore\b|near[_-]?vm|vm[_-]?logic|runtime[_-]?config|host[_-]?function|"
        r"promise_batch_then|create_receipt|storage_iter_range|fork[_ -]?choice|"
        r"block[_ -]?(?:producer|production|finali[sz])|validator[_ -]?(?:set|selection|stake)|"
        r"chunk[_ -]?(?:producer|validator)|epoch[_ -]?manager|doomslug|nightshade|reshard",
        re.I,
    ),
    "oracle": re.compile(r"\boracle\b|price[_ -]?feed|stale[_ -]?price|twap", re.I),
    "vault": re.compile(
        r"tokenized[_ -]?vault|total[_ -]?(?:asset|share)|convert[_ -]?to[_ -]?(?:assets|shares)|"
        r"preview[_ -]?(?:deposit|mint|withdraw|redeem)|\bvault\b",
        re.I,
    ),
    "serialization": re.compile(
        r"Borsh(?:Serialize|Deserialize)|try_from_slice|from_slice|serde_json|JSON\.parse|Base64VecU8|"
        r"(?:result_)?serializer\s*\(\s*borsh\s*\)|serializers\s*=\s*\[[^\]]*borsh|"
        r"deny_unknown_arguments|split(?:_terminator|_inclusive)?\s*\(|AccountId::try_from|"
        r"(?:account|asset|chain|token|receiver|sender)[_-]?id\s*:\s*String",
        re.I,
    ),
    "initialization": re.compile(
        r"#\[(?:near\([^\]]*)?init\b|ignore_state|state_exists|PanicOnDefault|\bconstructor\s*\(",
        re.I,
    ),
    "accrual": re.compile(
        r"\baccru(?:e|al)|reward[_ -]?(?:per|rate|index)|exchange[_ -]?rate|debt[_ -]?index|"
        r"\bbooster\b|\bcheckpoint\b|\bsnapshot\b",
        re.I,
    ),
    "numeric_precision": re.compile(
        r"\bf(?:32|64)\b|\bas\s+(?:u|i)(?:8|16|32|64|128)\b|checked_(?:add|sub|mul|div)|"
        r"saturating_(?:add|sub|mul)|U128|U64|fixed[_ -]?point",
        re.I,
    ),
    "duplicate_inputs": re.compile(
        r"\b(?:token|asset|nft|proposal|position|claim|reward|recipient|account)[_-]?ids\b|"
        r"\b(?:dedup|duplicates?|HashSet|BTreeSet)\b|"
        r"Vec\s*<\s*(?:AccountId|TokenId|AssetId|String|U64|U128)\b",
        re.I,
    ),
    "sybil": re.compile(
        r"\b(?:airdrop|referral|reputation|review|voting|vote|quota)\b|"
        r"(?:one|per)[_-]?(?:account|user)|account[_ -]?age|proof[_ -]?of[_ -]?(?:person|personhood|humanity)|"
        r"token[_ -]?weighted|eligibility[_ -]?(?:window|snapshot)|rate[_ -]?limit",
        re.I,
    ),
    "mev": re.compile(
        r"commit[_ -]?reveal|\bcommitment\b|(?:^|[^A-Za-z0-9])(?:reveal|challenge)(?:[^A-Za-z0-9]|$)|front[_ -]?run|"
        r"random_seed(?:_array)?|random[_ -]?(?:number|winner|index)|choose[_ -]?winner|"
        r"\b(?:lottery|raffle|coin[_ -]?flip)\b|first[_ -]?(?:come|valid|submitter|claim|mint)|"
        r"(?:submit|claim)[_ -]?(?:answer|solution|secret|reward)|public[_ -]?(?:secret|answer|solution)|"
        r"batch[_ -]?auction|clearing[_ -]?(?:price|rule)|private[_ -]?submission|"
        r"\bslippage\b|min[_ -]?out|\bdeadline\b",
        re.I,
    ),
}


def load_nep_registry() -> tuple[dict[str, object], dict[str, re.Pattern[str]]]:
    data = json.loads(NEP_REGISTRY.read_text(encoding="utf-8"))
    patterns: dict[str, re.Pattern[str]] = {}
    for nep_id, row in data["neps"].items():
        signals = row.get("signals", [])
        if signals:
            patterns[nep_id] = re.compile(
                "|".join(re.escape(signal) for signal in signals),
                re.IGNORECASE,
            )
    return data, patterns


def load_official_docs_registry() -> dict[str, object]:
    return json.loads(OFFICIAL_DOCS_REGISTRY.read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path, help="Repository or project root")
    parser.add_argument("files", nargs="*", type=Path, help="Optional explicit source files")
    parser.add_argument("--output", type=Path, help="Write manifest JSON here")
    args = parser.parse_args()

    try:
        root = validate_root(args.root)
        files = discover(root, args.files)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    if not files:
        parser.error("no in-scope source files found")

    nep_registry, nep_patterns = load_nep_registry()
    official_docs = load_official_docs_registry()
    counts: Counter[str] = Counter()
    nep_counts: Counter[str] = Counter()
    records: list[dict[str, object]] = []
    for path in files:
        raw = path.read_text(encoding="utf-8", errors="replace")
        file_signals = sorted(name for name, pattern in SIGNALS.items() if pattern.search(raw))
        file_neps = sorted(nep_id for nep_id, pattern in nep_patterns.items() if pattern.search(raw))
        counts.update(file_signals)
        nep_counts.update(file_neps)
        records.append(
            {
                "path": path.relative_to(root).as_posix(),
                "language": path.suffix.lower().lstrip("."),
                "lines": raw.count("\n") + (0 if raw.endswith("\n") else 1),
                "signals": file_signals,
                "nep_signals": file_neps,
            }
        )

    selected_roles = list(ROLE_ORDER)
    selected_roles.extend(SPECIALIST_ROLES)
    selected_roles.extend(ACTIVE_ALWAYS)
    if counts["promises"] or counts["callback_entrypoints"] or counts["chain_signatures"]:
        selected_roles.append("async-state-explorer")
    if counts["tokens"] or any(nep_counts[item] for item in ("0141", "0145", "0171", "0178")):
        selected_roles.append("nep-differential")
    if counts["upgrade"]:
        selected_roles.append("temporal-upgrade")

    nep_review_queue: list[dict[str, object]] = []
    for nep_id, row in nep_registry["neps"].items():
        category = nep_registry["categories"][row["category"]]
        nep_review_queue.append(
            {
                "nep_id": nep_id,
                "title": row["title"],
                "source_status": row["status"],
                "category": row["category"],
                "role_id": category["role_id"],
                "activation": row["activation"],
                "version_gate": row["version_gate"],
                "signal_hits": nep_counts[nep_id],
                "screening": (
                    "process_only" if nep_id == "0001" else
                    "legacy_if_target_uses" if nep_id == "0021" else
                    "advisory_if_implemented" if row["status"] in {"Draft", "New"} else
                    "check_applicability_and_version" if nep_counts[nep_id] else
                    "exclude_with_target_reason_unless_claimed"
                ),
            }
        )

    card_sources: dict[str, list[str]] = {}
    for page in official_docs["pages"]:
        for card_id in page["attacker_card_ids"]:
            card_sources.setdefault(card_id, []).append(page["url_path"])
    selected_cards: list[str] = []
    guidance_queue: list[dict[str, object]] = []
    guidance_counts: dict[str, int] = {}
    for card_id, metadata in official_docs["cards"].items():
        hit_count = sum(counts[signal] for signal in metadata["activation_signals"])
        guidance_counts[card_id] = hit_count
        if hit_count < 1:
            continue
        selected_cards.append(card_id)
        guidance_queue.append(
            {
                "card_id": card_id,
                "signal_hits": hit_count,
                "signals": metadata["signals"],
                "activation_signals": metadata["activation_signals"],
                "owner_role": metadata["roles"][0],
                "agent_roles": metadata["roles"],
                "canonical_pattern_ids": metadata["patterns"],
                "nep_ids": metadata["neps"],
                "invariant_families": metadata["invariants"],
                "mutation_families": metadata["mutations"],
                "source_pages": sorted(card_sources.get(card_id, [])),
            }
        )

    for item in guidance_queue:
        owner_role = str(item["owner_role"])
        if owner_role not in selected_roles:
            selected_roles.append(owner_role)

    pattern_categories = select_categories(counts)
    pattern_references = reference_paths(pattern_categories)

    docs_registry_hash = hashlib.sha256(OFFICIAL_DOCS_REGISTRY.read_bytes()).hexdigest()

    payload = {
        "schema_version": 3,
        "root": str(root),
        "files": records,
        "file_count": len(records),
        "signal_counts": dict(sorted(counts.items())),
        "selected_roles": selected_roles,
        "selected_pattern_categories": pattern_categories,
        "selected_pattern_references": pattern_references,
        "capability_roles": CAPABILITY_ROLES,
        "active_test_requirements": {
            "invariant_ledger": True,
            "mutation_analysis": True,
            "async_schedules": "async-state-explorer" in selected_roles,
            "nep_differential": "nep-differential" in selected_roles,
            "temporal_upgrade": "temporal-upgrade" in selected_roles,
        },
        "nep_source_commit": nep_registry["source"]["commit"],
        "nep_signal_counts": dict(sorted(nep_counts.items())),
        "nep_roles": [category["role_id"] for category in nep_registry["categories"].values()],
        "nep_review_queue": nep_review_queue,
        "official_docs_source_commit": official_docs["source"]["commit"],
        "official_docs_registry_hash": docs_registry_hash,
        "official_guidance_signal_counts": dict(sorted(guidance_counts.items())),
        "selected_attacker_cards": sorted(selected_cards),
        "official_guidance_review_queue": guidance_queue,
        "warnings": [] if counts["near_sdk"] else ["No near-sdk signal found; confirm NEAR scope manually."],
    }
    rendered = json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
