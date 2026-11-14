#!/usr/bin/env python3
"""Validate the pinned official NEAR documentation registry.

The checker works from a local near/docs checkout. It reconstructs Mintlify's
navigation, expands OpenAPI operations, hashes the source for every page, and
reports semantic-review changes. `--initialize` is an explicit bootstrap only;
normal validation never rewrites the registry or attacker guide.
"""

from __future__ import annotations

from reference_paths import reference_relative

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Any

from check_run_artifacts import MUTATION_FAMILIES
from map_surface import SIGNALS


ALLOWED_AUTHORITY = {
    "runtime_semantics",
    "normative_reference",
    "security_guidance",
    "integration_guidance",
    "operational",
    "tutorial",
}
ALLOWED_DEPTH = {"deep", "supporting", "classified_only"}
ALLOWED_DISPOSITIONS = {
    "actionable",
    "advisory",
    "quality_only",
    "duplicate",
    "superseded",
    "not_security_relevant",
    "blocked",
}
INVARIANT_PREFIXES = {
    "INV-CONSERVATION-*",
    "INV-PENDING-*",
    "INV-SETTLE-ONCE-*",
    "INV-COMPENSATE-*",
    "INV-SUPPLY-*",
    "INV-STORAGE-*",
    "INV-AUTH-*",
    "INV-CALLBACK-*",
    "INV-MIGRATION-*",
}

SKILL_ROOT = Path(__file__).resolve().parent.parent
CARD_GUIDE = SKILL_ROOT / reference_relative('docs_cards')
PATTERN_INDEX = SKILL_ROOT / reference_relative('attack_index')
AGENT_CATALOG = SKILL_ROOT / reference_relative('agent_catalog')
NEP_REGISTRY = SKILL_ROOT / reference_relative('nep_registry')


CARD_META: dict[str, dict[str, list[str]]] = {
    "DOC-AUTH-001": {"signals": ["near_sdk", "callback_entrypoints"], "patterns": ["NA-AUTH-001", "NA-ASYNC-003"], "roles": ["entrypoints-auth", "async-promises"], "neps": []},
    "DOC-KEY-001": {"signals": ["one_yocto", "access_keys"], "patterns": ["NA-AUTH-003"], "roles": ["entrypoints-auth"], "neps": []},
    "DOC-KEY-002": {"signals": ["access_keys", "gas_keys"], "patterns": ["NA-AUTH-004", "NA-ACCOUNT-002", "NA-STATE-004"], "roles": ["entrypoints-auth", "upgrade-keys", "periphery-build"], "neps": ["0611"]},
    "DOC-INIT-001": {"signals": ["initialization", "upgrade"], "patterns": ["NA-AUTH-005", "NA-AUTH-006"], "roles": ["entrypoints-auth", "upgrade-keys", "temporal-upgrade"], "neps": []},
    "DOC-META-001": {"signals": ["meta_transactions", "access_keys", "intents"], "patterns": ["NA-AUTH-007", "NA-OFFCHAIN-002", "NA-ACCOUNT-002"], "roles": ["entrypoints-auth", "intents-auth", "bridge-relayer"], "neps": ["0366", "0611"]},
    "DOC-WALLET-001": {"signals": ["wallet_auth", "intents"], "patterns": ["NA-AUTH-008", "NA-OFFCHAIN-003"], "roles": ["entrypoints-auth", "intents-auth", "periphery-build"], "neps": ["0413"]},
    "DOC-ASYNC-001": {"signals": ["promises", "callback_entrypoints"], "patterns": ["NA-ASYNC-003", "NA-AUTH-002"], "roles": ["async-promises", "entrypoints-auth"], "neps": []},
    "DOC-ASYNC-002": {"signals": ["promises", "serialization"], "patterns": ["NA-ASYNC-004", "NA-ASYNC-009"], "roles": ["async-promises", "token-accounting"], "neps": []},
    "DOC-ASYNC-003": {"signals": ["promises", "native_transfers"], "patterns": ["NA-ASYNC-002", "NA-ACCOUNT-003"], "roles": ["async-promises", "token-accounting"], "neps": []},
    "DOC-ASYNC-004": {"signals": ["promises", "callback_entrypoints"], "patterns": ["NA-ASYNC-002", "NA-ASYNC-005", "NA-RESOURCE-005"], "roles": ["async-promises", "gas-dos", "async-state-explorer"], "neps": []},
    "DOC-ASYNC-005": {"signals": ["promises", "tokens"], "patterns": ["NA-ASYNC-001", "NA-ASYNC-002"], "roles": ["async-promises", "async-state-explorer", "invariant-synthesis"], "neps": []},
    "DOC-ASYNC-006": {"signals": ["promises", "gas"], "patterns": ["NA-RESOURCE-005", "NA-ASYNC-004"], "roles": ["async-promises", "gas-dos", "periphery-build"], "neps": []},
    "DOC-YIELD-001": {"signals": ["promises", "chain_signatures", "yield_resume"], "patterns": ["NA-ASYNC-008", "NA-ASYNC-005", "NA-STATE-004"], "roles": ["chain-signatures-yield", "async-state-explorer"], "neps": ["0519"]},
    "DOC-STORAGE-001": {"signals": ["storage"], "patterns": ["NA-RESOURCE-001", "NA-RESOURCE-005"], "roles": ["state-storage", "gas-dos"], "neps": []},
    "DOC-STORAGE-002": {"signals": ["storage", "tokens"], "patterns": ["NA-ACCOUNT-001", "NA-INTEGRATION-002", "NA-ACCOUNT-003"], "roles": ["state-storage", "token-accounting"], "neps": ["0145"]},
    "DOC-STORAGE-003": {"signals": ["storage"], "patterns": ["NA-RESOURCE-002", "NA-RESOURCE-003", "NA-RESOURCE-004", "NA-STATE-001"], "roles": ["state-storage"], "neps": []},
    "DOC-GAS-001": {"signals": ["gas", "storage", "serialization"], "patterns": ["NA-RESOURCE-005", "NA-RUNTIME-001"], "roles": ["gas-dos", "state-storage", "periphery-build"], "neps": []},
    "DOC-SERIAL-001": {"signals": ["serialization"], "patterns": ["NA-CRYPTO-001", "NA-INTEGRATION-002", "NA-STATE-003"], "roles": ["periphery-build", "token-accounting", "temporal-upgrade"], "neps": []},
    "DOC-UPGRADE-001": {"signals": ["upgrade", "serialization"], "patterns": ["NA-AUTH-006", "NA-STATE-003"], "roles": ["upgrade-keys", "temporal-upgrade"], "neps": []},
    "DOC-GLOBAL-001": {"signals": ["global_contracts", "upgrade"], "patterns": ["NA-AUTH-006", "NA-STATE-003", "NA-OFFCHAIN-004"], "roles": ["upgrade-keys", "temporal-upgrade", "periphery-build"], "neps": ["0591"]},
    "DOC-BUILD-001": {"signals": ["upgrade", "build_artifacts"], "patterns": ["NA-OFFCHAIN-004", "NA-ECON-002"], "roles": ["periphery-build", "temporal-upgrade"], "neps": []},
    "DOC-FT-001": {"signals": ["tokens"], "patterns": ["NA-INTEGRATION-001", "NA-ECON-001"], "roles": ["token-accounting", "async-promises"], "neps": ["0141"]},
    "DOC-FT-002": {"signals": ["tokens", "callback_entrypoints"], "patterns": ["NA-ASYNC-009", "NA-ASYNC-004"], "roles": ["token-accounting", "nep-differential"], "neps": ["0141"]},
    "DOC-NFT-001": {"signals": ["tokens", "callback_entrypoints"], "patterns": ["NA-ASYNC-009", "NA-STATE-001", "NA-INTEGRATION-002"], "roles": ["token-accounting", "nep-differential"], "neps": ["0171", "0178"]},
    "DOC-DUP-001": {"signals": ["duplicate_inputs"], "patterns": ["NA-STATE-004", "NA-ACCOUNT-002"], "roles": ["entrypoints-auth", "token-accounting"], "neps": []},
    "DOC-MEV-001": {"signals": ["mev"], "patterns": ["NA-ECON-003"], "roles": ["math-economics", "trust-gap"], "neps": []},
    "DOC-MEV-002": {"signals": ["mev", "runtime_consensus"], "patterns": ["NA-ECON-003"], "roles": ["math-economics", "runtime-consensus"], "neps": []},
    "DOC-ECON-001": {"signals": ["sybil"], "patterns": ["NA-STATE-004", "NA-ECON-003"], "roles": ["math-economics", "trust-gap"], "neps": []},
    "DOC-VAULT-001": {"signals": ["vault", "tokens", "accrual", "numeric_precision"], "patterns": ["NA-ACCOUNT-005", "NA-ECON-002", "NA-ACCOUNT-004"], "roles": ["token-accounting", "math-economics", "invariant-synthesis"], "neps": ["0621"]},
    "DOC-ORACLE-001": {"signals": ["oracle", "yield_resume"], "patterns": ["NA-INTEGRATION-005", "NA-ECON-001", "NA-ASYNC-005"], "roles": ["oracle-freshness", "chain-signatures-yield"], "neps": []},
    "DOC-INTENT-001": {"signals": ["intents", "mev"], "patterns": ["NA-AUTH-007", "NA-AUTH-008", "NA-ECON-003"], "roles": ["intents-auth", "bridge-relayer"], "neps": []},
    "DOC-MPC-001": {"signals": ["chain_signatures", "serialization"], "patterns": ["NA-CRYPTO-002", "NA-CRYPTO-001"], "roles": ["chain-signatures-yield", "trust-gap"], "neps": []},
    "DOC-MPC-002": {"signals": ["chain_signatures"], "patterns": ["NA-CRYPTO-002", "NA-CRYPTO-003", "NA-CRYPTO-004"], "roles": ["chain-signatures-yield"], "neps": []},
    "DOC-BRIDGE-001": {"signals": ["bridge", "runtime_consensus"], "patterns": ["NA-INTEGRATION-003", "NA-INTEGRATION-004", "NA-CRYPTO-003"], "roles": ["bridge-relayer", "chain-signatures-yield"], "neps": []},
    "DOC-BRIDGE-002": {"signals": ["bridge", "tokens", "promises"], "patterns": ["NA-ASYNC-009", "NA-ACCOUNT-002", "NA-OFFCHAIN-002"], "roles": ["bridge-relayer", "token-accounting", "async-state-explorer"], "neps": []},
    "DOC-RELAYER-001": {"signals": ["bridge", "intents", "offchain_rpc"], "patterns": ["NA-OFFCHAIN-001", "NA-OFFCHAIN-002", "NA-ASYNC-004"], "roles": ["bridge-relayer", "periphery-build"], "neps": []},
    "DOC-RPC-001": {"signals": ["offchain_rpc", "bridge"], "patterns": ["NA-OFFCHAIN-001", "NA-OFFCHAIN-003"], "roles": ["bridge-relayer", "periphery-build"], "neps": []},
    "DOC-TEE-001": {"signals": ["tee", "oracle"], "patterns": ["NA-CRYPTO-007", "NA-OFFCHAIN-003"], "roles": ["trust-gap", "oracle-freshness", "periphery-build"], "neps": []},
}

CARD_ACTIVE_MAP: dict[str, tuple[list[str], list[str]]] = {
    "DOC-AUTH-001": (["INV-AUTH-*", "INV-CALLBACK-*"], ["identity-substitution"]),
    "DOC-KEY-001": (["INV-AUTH-*"], ["access-macro-removal", "key-capability"]),
    "DOC-KEY-002": (["INV-AUTH-*"], ["key-capability"]),
    "DOC-INIT-001": (["INV-AUTH-*", "INV-MIGRATION-*"], ["access-macro-removal", "migration-layout"]),
    "DOC-META-001": (["INV-AUTH-*", "INV-SETTLE-ONCE-*"], ["identity-substitution", "key-capability"]),
    "DOC-WALLET-001": (["INV-AUTH-*", "INV-SETTLE-ONCE-*"], ["identity-substitution"]),
    "DOC-ASYNC-001": (["INV-AUTH-*", "INV-CALLBACK-*"], ["access-macro-removal"]),
    "DOC-ASYNC-002": (["INV-CALLBACK-*", "INV-SETTLE-ONCE-*"], ["promise-result-semantics", "serializer-mismatch"]),
    "DOC-ASYNC-003": (["INV-COMPENSATE-*", "INV-CONSERVATION-*"], ["refund-principal"]),
    "DOC-ASYNC-004": (["INV-COMPENSATE-*", "INV-CALLBACK-*"], ["callback-gas", "promise-result-semantics"]),
    "DOC-ASYNC-005": (["INV-PENDING-*", "INV-SETTLE-ONCE-*"], ["late-reservation"]),
    "DOC-ASYNC-006": (["INV-CALLBACK-*"], ["callback-gas", "terminal-promise"]),
    "DOC-YIELD-001": (["INV-PENDING-*", "INV-SETTLE-ONCE-*"], ["yield-resume-binding"]),
    "DOC-STORAGE-001": (["INV-STORAGE-*", "INV-CONSERVATION-*"], ["storage-accounting"]),
    "DOC-STORAGE-002": (["INV-STORAGE-*", "INV-CONSERVATION-*"], ["storage-accounting", "refund-principal"]),
    "DOC-STORAGE-003": (["INV-STORAGE-*", "INV-MIGRATION-*"], ["storage-accounting", "migration-layout"]),
    "DOC-GAS-001": (["INV-PENDING-*", "INV-COMPENSATE-*"], ["callback-gas", "storage-accounting"]),
    "DOC-SERIAL-001": (["INV-MIGRATION-*", "INV-CALLBACK-*"], ["serializer-mismatch", "migration-layout"]),
    "DOC-UPGRADE-001": (["INV-MIGRATION-*", "INV-AUTH-*"], ["migration-layout", "deployed-code-identity"]),
    "DOC-GLOBAL-001": (["INV-MIGRATION-*", "INV-AUTH-*"], ["deployed-code-identity", "migration-layout"]),
    "DOC-BUILD-001": (["INV-MIGRATION-*"], ["deployed-code-identity", "arithmetic-rounding"]),
    "DOC-FT-001": (["INV-CONSERVATION-*", "INV-AUTH-*"], ["transfer-call-polarity", "identity-substitution"]),
    "DOC-FT-002": (["INV-CONSERVATION-*", "INV-CALLBACK-*"], ["transfer-call-polarity", "refund-cap", "promise-result-semantics"]),
    "DOC-NFT-001": (["INV-AUTH-*", "INV-SETTLE-ONCE-*"], ["access-macro-removal", "refund-cap"]),
    "DOC-DUP-001": (["INV-CONSERVATION-*", "INV-SETTLE-ONCE-*"], []),
    "DOC-MEV-001": (["INV-SETTLE-ONCE-*"], []),
    "DOC-MEV-002": (["INV-SETTLE-ONCE-*"], []),
    "DOC-ECON-001": (["INV-AUTH-*"], []),
    "DOC-VAULT-001": (["INV-CONSERVATION-*", "INV-SUPPLY-*", "INV-PENDING-*"], ["arithmetic-rounding", "late-reservation"]),
    "DOC-ORACLE-001": (["INV-PENDING-*", "INV-CALLBACK-*"], ["yield-resume-binding", "serializer-mismatch"]),
    "DOC-INTENT-001": (["INV-AUTH-*", "INV-SETTLE-ONCE-*"], ["identity-substitution", "late-reservation"]),
    "DOC-MPC-001": (["INV-AUTH-*", "INV-SETTLE-ONCE-*"], ["serializer-mismatch", "identity-substitution"]),
    "DOC-MPC-002": (["INV-AUTH-*", "INV-SETTLE-ONCE-*"], ["identity-substitution", "late-reservation"]),
    "DOC-BRIDGE-001": (["INV-AUTH-*", "INV-SETTLE-ONCE-*"], ["route-finality", "identity-substitution"]),
    "DOC-BRIDGE-002": (["INV-CONSERVATION-*", "INV-PENDING-*", "INV-SETTLE-ONCE-*"], ["route-finality", "refund-principal", "transfer-call-polarity"]),
    "DOC-RELAYER-001": (["INV-SETTLE-ONCE-*", "INV-CALLBACK-*"], ["route-finality", "terminal-promise"]),
    "DOC-RPC-001": (["INV-AUTH-*", "INV-SETTLE-ONCE-*"], ["route-finality", "serializer-mismatch"]),
    "DOC-TEE-001": (["INV-AUTH-*", "INV-SETTLE-ONCE-*"], ["serializer-mismatch", "deployed-code-identity"]),
}

CARD_ACTIVATION: dict[str, list[str]] = {
    "DOC-AUTH-001": ["near_sdk", "callback_entrypoints"],
    "DOC-KEY-001": ["one_yocto"],
    "DOC-KEY-002": ["access_keys", "gas_keys"],
    "DOC-INIT-001": ["initialization"],
    "DOC-META-001": ["meta_transactions"],
    "DOC-WALLET-001": ["wallet_auth"],
    "DOC-ASYNC-001": ["callback_entrypoints"],
    "DOC-ASYNC-002": ["promises"],
    "DOC-ASYNC-003": ["native_transfers"],
    "DOC-ASYNC-004": ["callback_entrypoints"],
    "DOC-ASYNC-005": ["promises"],
    "DOC-ASYNC-006": ["promises", "gas"],
    "DOC-YIELD-001": ["yield_resume"],
    "DOC-STORAGE-001": ["storage"],
    "DOC-STORAGE-002": ["storage"],
    "DOC-STORAGE-003": ["storage"],
    "DOC-GAS-001": ["gas"],
    "DOC-SERIAL-001": ["serialization"],
    "DOC-UPGRADE-001": ["upgrade"],
    "DOC-GLOBAL-001": ["global_contracts"],
    "DOC-BUILD-001": ["build_artifacts"],
    "DOC-FT-001": ["tokens"],
    "DOC-FT-002": ["tokens"],
    "DOC-NFT-001": ["tokens"],
    "DOC-DUP-001": ["duplicate_inputs"],
    "DOC-MEV-001": ["mev"],
    "DOC-MEV-002": ["mev"],
    "DOC-ECON-001": ["sybil"],
    "DOC-VAULT-001": ["vault", "accrual"],
    "DOC-ORACLE-001": ["oracle"],
    "DOC-INTENT-001": ["intents"],
    "DOC-MPC-001": ["chain_signatures"],
    "DOC-MPC-002": ["chain_signatures"],
    "DOC-BRIDGE-001": ["bridge"],
    "DOC-BRIDGE-002": ["bridge"],
    "DOC-RELAYER-001": ["offchain_rpc", "bridge", "meta_transactions"],
    "DOC-RPC-001": ["offchain_rpc"],
    "DOC-TEE-001": ["tee"],
}

for _card_id, (_invariants, _mutations) in CARD_ACTIVE_MAP.items():
    CARD_META[_card_id]["invariants"] = _invariants
    CARD_META[_card_id]["mutations"] = _mutations
    CARD_META[_card_id]["activation_signals"] = CARD_ACTIVATION[_card_id]


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def indexed_paths(path: Path) -> set[str]:
    text = path.read_text(encoding="utf-8")
    return {
        match.group(1).split("#", 1)[0].split("?", 1)[0]
        for match in re.finditer(r"docs\.near\.org/([^\s)]+)", text)
    }


def git_commit(root: Path) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def source_title(path: Path) -> str:
    text = path.read_text(encoding="utf-8", errors="replace")
    front = re.search(r"^title:\s*[\"']?(.+?)[\"']?\s*$", text, re.MULTILINE)
    if front:
        return front.group(1).strip()
    heading = re.search(r"^#\s+(.+?)\s*$", text, re.MULTILINE)
    return heading.group(1).strip() if heading else path.stem.replace("-", " ").title()


def walk_pages(value: Any, section: list[str], out: list[tuple[str, str]]) -> None:
    if isinstance(value, str):
        out.append((value, " / ".join(item for item in section if item.strip())))
    elif isinstance(value, list):
        for item in value:
            walk_pages(item, section, out)
    elif isinstance(value, dict) and "pages" in value:
        label = str(value.get("group", "")).strip()
        walk_pages(value["pages"], section + ([label] if label else []), out)


def openapi_operations(root: Path) -> dict[tuple[str, str], dict[str, Any]]:
    data = json.loads((root / "openapi.json").read_text(encoding="utf-8"))
    result: dict[tuple[str, str], dict[str, Any]] = {}
    for path, methods in data.get("paths", {}).items():
        for method, operation in methods.items():
            if method.lower() in {"get", "post", "put", "delete", "patch"} and isinstance(operation, dict):
                result[(method.upper(), path)] = operation
    return result


def discover_pages(root: Path) -> list[dict[str, str]]:
    config = json.loads((root / "docs.json").read_text(encoding="utf-8"))
    leaves: list[tuple[str, str]] = []
    for tab in config["navigation"]["tabs"]:
        tab_name = str(tab.get("tab", "")).strip()
        for group in tab.get("groups", []):
            label = str(group.get("group", "")).strip()
            walk_pages(group.get("pages", []), [tab_name, label], leaves)

    operations = openapi_operations(root)
    rows: list[dict[str, str]] = []
    for leaf, section in leaves:
        if re.match(r"^[A-Z]+\s+/", leaf):
            method, api_path = leaf.split(" ", 1)
            slug = f"{method.lower()}-{api_path.strip('/').lower()}"
            operation = operations[(method, api_path)]
            canonical = json.dumps(operation, sort_keys=True, separators=(",", ":")).encode()
            rows.append(
                {
                    "url_path": f"api-reference/{slug}.md",
                    "title": str(operation.get("summary") or operation.get("operationId") or leaf),
                    "section": section,
                    "source_path": "openapi.json",
                    "sha256": sha256_bytes(canonical),
                }
            )
            continue

        source = root / f"{leaf}.mdx"
        if not source.exists():
            source = root / f"{leaf}.md"
        if not source.exists():
            raise ValueError(f"navigation page has no source file: {leaf}")
        rows.append(
            {
                "url_path": f"{leaf}.md",
                "title": source_title(source),
                "section": section,
                "source_path": source.relative_to(root).as_posix(),
                "sha256": sha256_bytes(source.read_bytes()),
            }
        )

    spec = root / "openapi.json"
    rows.append(
        {
            "url_path": "openapi.json",
            "title": "openapi",
            "section": "OpenAPI Specs",
            "source_path": "openapi.json",
            "sha256": sha256_bytes(spec.read_bytes()),
        }
    )
    if len({row["url_path"] for row in rows}) != len(rows):
        raise ValueError("official docs navigation contains duplicate page paths")
    return rows


def cards_for(path: str) -> list[str]:
    p = path.removesuffix(".md")
    exact: dict[str, list[str]] = {
        "protocol/accounts-contracts/account-model": ["DOC-AUTH-001", "DOC-KEY-002"],
        "protocol/accounts-contracts/access-keys": ["DOC-KEY-001", "DOC-KEY-002"],
        "protocol/transactions/meta-tx": ["DOC-AUTH-001", "DOC-META-001", "DOC-RELAYER-001"],
        "protocol/transactions/transaction-execution": ["DOC-ASYNC-002", "DOC-ASYNC-006", "DOC-RELAYER-001"],
        "protocol/data-flow/near-data-flow": ["DOC-AUTH-001", "DOC-ASYNC-002", "DOC-RELAYER-001"],
        "protocol/data-flow/token-transfer-flow": ["DOC-ASYNC-002", "DOC-ASYNC-003", "DOC-RELAYER-001"],
        "protocol/network/token-loss": ["DOC-KEY-002", "DOC-INIT-001", "DOC-UPGRADE-001"],
        "protocol/storage/storage-staking": ["DOC-STORAGE-001", "DOC-STORAGE-002"],
        "protocol/network/runtime": ["DOC-AUTH-001", "DOC-ASYNC-002", "DOC-GAS-001"],
        "smart-contracts/anatomy/environment": ["DOC-AUTH-001", "DOC-KEY-001"],
        "smart-contracts/anatomy/actions": ["DOC-ASYNC-003", "DOC-ASYNC-006", "DOC-KEY-002"],
        "smart-contracts/anatomy/crosscontract": ["DOC-ASYNC-001", "DOC-ASYNC-002", "DOC-ASYNC-006"],
        "smart-contracts/anatomy/yield-resume": ["DOC-YIELD-001", "DOC-ASYNC-004", "DOC-ASYNC-006"],
        "smart-contracts/anatomy/storage": ["DOC-STORAGE-001", "DOC-STORAGE-003", "DOC-UPGRADE-001"],
        "smart-contracts/anatomy/collections": ["DOC-STORAGE-001", "DOC-STORAGE-003", "DOC-GAS-001"],
        "smart-contracts/anatomy/functions": ["DOC-AUTH-001", "DOC-SERIAL-001", "DOC-INIT-001"],
        "smart-contracts/anatomy/events": ["DOC-RELAYER-001", "DOC-RPC-001"],
        "smart-contracts/anatomy/serialization": ["DOC-SERIAL-001", "DOC-UPGRADE-001"],
        "smart-contracts/anatomy/reduce-size": ["DOC-BUILD-001"],
        "smart-contracts/anatomy/best-practices": ["DOC-ASYNC-006", "DOC-GAS-001", "DOC-BUILD-001"],
        "smart-contracts/global-contracts": ["DOC-GLOBAL-001", "DOC-UPGRADE-001", "DOC-BUILD-001"],
        "smart-contracts/release/deploy": ["DOC-INIT-001", "DOC-BUILD-001"],
        "smart-contracts/release/upgrade": ["DOC-UPGRADE-001", "DOC-INIT-001", "DOC-BUILD-001"],
        "smart-contracts/security/checklist": list(CARD_META),
        "smart-contracts/security/storage": ["DOC-STORAGE-001", "DOC-STORAGE-002", "DOC-STORAGE-003"],
        "smart-contracts/security/cross-contract-calls/callbacks": ["DOC-ASYNC-001", "DOC-ASYNC-002"],
        "smart-contracts/security/cross-contract-calls/refunds": ["DOC-ASYNC-003", "DOC-ASYNC-004"],
        "smart-contracts/security/cross-contract-calls/callback-panics": ["DOC-ASYNC-004", "DOC-ASYNC-006"],
        "smart-contracts/security/cross-contract-calls/callback-failures": ["DOC-ASYNC-002", "DOC-ASYNC-004", "DOC-ASYNC-006"],
        "integrations/accounts": ["DOC-KEY-002", "DOC-WALLET-001"],
        "integrations/balance-changes": ["DOC-RPC-001", "DOC-RELAYER-001"],
        "integrations/blocks-and-finality": ["DOC-RPC-001", "DOC-BRIDGE-001"],
        "integrations/create-transactions": ["DOC-RPC-001", "DOC-RELAYER-001", "DOC-KEY-002"],
        "integrations/deposits": ["DOC-RPC-001", "DOC-RELAYER-001", "DOC-ASYNC-002"],
        "integrations/errors/introduction": ["DOC-ASYNC-002", "DOC-RPC-001"],
        "integrations/exchange-integration": ["DOC-RPC-001", "DOC-RELAYER-001"],
        "integrations/fungible-tokens": ["DOC-FT-001", "DOC-FT-002", "DOC-RPC-001"],
        "integrations/nodes": ["DOC-RPC-001"],
        "integrations/on-chain-data": ["DOC-RPC-001", "DOC-RELAYER-001"],
        "integrations/staking": ["DOC-RPC-001"],
        "integrations/transaction-lifecycle": ["DOC-RPC-001", "DOC-RELAYER-001"],
        "chain-abstraction/what-is": ["DOC-INTENT-001", "DOC-MPC-001", "DOC-RELAYER-001"],
        "smart-contracts/security/cross-contract-calls/ft-transfer-call": ["DOC-FT-001", "DOC-FT-002", "DOC-ASYNC-002"],
        "smart-contracts/security/cross-contract-calls/reentrancy": ["DOC-ASYNC-005"],
        "smart-contracts/security/one_yocto": ["DOC-KEY-001", "DOC-AUTH-001"],
        "smart-contracts/security/sybil": ["DOC-ECON-001"],
        "smart-contracts/security/frontrunning": ["DOC-MEV-001"],
        "smart-contracts/security/duplicate-inputs": ["DOC-DUP-001"],
        "smart-contracts/security/random": ["DOC-MEV-002", "DOC-MEV-001"],
        "web3-apps/backend/backend": ["DOC-WALLET-001"],
        "web3-apps/tutorials/wallet-login": ["DOC-WALLET-001", "DOC-KEY-002"],
        "web3-apps/tutorials/near-auth": ["DOC-WALLET-001", "DOC-MPC-001", "DOC-MPC-002"],
        "web3-apps/tutorials/social-login": ["DOC-WALLET-001"],
        "web3-apps/tutorials/meta-transactions": ["DOC-META-001", "DOC-RELAYER-001"],
        "web3-apps/tutorials/account-validation": ["DOC-SERIAL-001", "DOC-RELAYER-001"],
        "web3-apps/tutorials/data-types": ["DOC-SERIAL-001"],
        "chain-abstraction/intents/overview": ["DOC-INTENT-001", "DOC-RELAYER-001"],
        "chain-abstraction/chain-signatures": ["DOC-MPC-001", "DOC-MPC-002"],
        "chain-abstraction/chain-signatures/implementation": ["DOC-MPC-001", "DOC-MPC-002", "DOC-RELAYER-001"],
        "chain-abstraction/omnibridge/overview": ["DOC-BRIDGE-001", "DOC-BRIDGE-002"],
        "chain-abstraction/omnibridge/how-it-works": ["DOC-BRIDGE-001", "DOC-MPC-001", "DOC-MPC-002"],
        "chain-abstraction/omnibridge/implementation": ["DOC-BRIDGE-001", "DOC-BRIDGE-002", "DOC-RELAYER-001", "DOC-MPC-002"],
        "chain-abstraction/omnibridge/roadmap": ["DOC-BRIDGE-001"],
        "primitives/ft/standard": ["DOC-FT-001", "DOC-FT-002", "DOC-STORAGE-002", "DOC-SERIAL-001"],
        "primitives/ft/ft": ["DOC-FT-001", "DOC-FT-002", "DOC-STORAGE-002"],
        "primitives/nft/standard": ["DOC-NFT-001", "DOC-STORAGE-002", "DOC-SERIAL-001"],
        "primitives/nft/nft": ["DOC-NFT-001", "DOC-STORAGE-002"],
        "primitives/tokenized-vaults": ["DOC-VAULT-001", "DOC-FT-001", "DOC-FT-002", "DOC-MEV-001"],
        "primitives/oracles": ["DOC-ORACLE-001"],
        "primitives/off-chain-compute/what-is": ["DOC-TEE-001", "DOC-ORACLE-001"],
        "primitives/off-chain-compute/outlayer": ["DOC-TEE-001", "DOC-ORACLE-001"],
        "primitives/dao": ["DOC-ECON-001", "DOC-MEV-001"],
        "primitives/dex": ["DOC-MEV-001", "DOC-ORACLE-001"],
        "data-infrastructure/indexers": ["DOC-RPC-001", "DOC-RELAYER-001"],
        "data-infrastructure/near-indexer": ["DOC-RPC-001", "DOC-RELAYER-001"],
        "api/rpc/transactions": ["DOC-RPC-001", "DOC-RELAYER-001"],
        "api/rpc/protocol": ["DOC-RPC-001"],
        "api/rpc/contracts": ["DOC-RPC-001", "DOC-KEY-002", "DOC-BUILD-001"],
    }
    if p in exact:
        return exact[p]
    if p.startswith("chain-abstraction/chain-signatures/tutorials/"):
        return ["DOC-MPC-001", "DOC-MPC-002", "DOC-RELAYER-001"]
    if p.startswith("primitives/liquid-staking/") or p.startswith("primitives/lockup/"):
        return ["DOC-VAULT-001", "DOC-ASYNC-005", "DOC-ORACLE-001"]
    if p.startswith("api-reference/"):
        if any(term in p for term in ("tx", "receipt", "light_client", "validators_ordered", "protocol_config", "view_code", "view_state", "view_access_key", "block", "changes")):
            return ["DOC-RPC-001", "DOC-RELAYER-001"]
        return []
    return []


def classify(path: str, section: str) -> tuple[str, str, str, str]:
    p = path.removesuffix(".md")
    cards = cards_for(path)
    if "/security/" in p:
        return "security_guidance", "deep", "actionable", "Official security guidance translated into attacker checks."
    if p.startswith("chain-abstraction/"):
        disposition = "advisory" if p.endswith("/roadmap") else "actionable"
        return "integration_guidance", "deep", disposition, "Cross-chain trust and settlement surface."
    if p.startswith("protocol/"):
        depth = "deep" if cards else "supporting"
        return "runtime_semantics", depth, "actionable" if cards else "not_security_relevant", "Protocol semantics support contract and cross-chain analysis."
    if p.startswith("primitives/") and cards:
        authority = "normative_reference" if any(term in p for term in ("/standard", "tokenized-vaults")) else "integration_guidance"
        return authority, "deep", "actionable", "Primitive behavior activates asset, accounting, or integration checks."
    if p.startswith("smart-contracts/") and cards:
        disposition = "quality_only" if p.endswith(("unit-test", "integration-test", "best-practices", "reduce-size")) else "actionable"
        return "integration_guidance", "deep", disposition, "Contract behavior changes security decisions when the surface is present."
    if p.startswith("web3-apps/") and cards:
        return "tutorial", "supporting", "actionable", "Example flow exposes wallet, relayer, or serialization trust boundaries."
    if p.startswith("data-infrastructure/") and cards:
        return "operational", "supporting", "actionable", "Off-chain observation semantics affect relayers and security decisions."
    if p.startswith("api/") or p.startswith("api-reference/"):
        depth = "supporting" if cards else "classified_only"
        return "operational", depth, "actionable" if cards else "not_security_relevant", "RPC semantics are loaded only for security-relevant consumers."
    if p == "openapi.json":
        return "operational", "classified_only", "not_security_relevant", "Machine API specification is represented by its routed operations."
    if "tutorial" in p or "quickstart" in p or "mastering-near" in p:
        return "tutorial", "classified_only", "not_security_relevant", "Tutorial is classified but not loaded into audit context."
    return "operational", "classified_only", "not_security_relevant", "No distinct contract or cross-chain attacker mechanism."


def initial_registry(root: Path, index_path: Path | None) -> dict[str, Any]:
    pages = discover_pages(root)
    if index_path:
        discovered = {page["url_path"] for page in pages}
        indexed = indexed_paths(index_path)
        if discovered != indexed:
            raise ValueError(
                f"checkout navigation and llms.txt differ: added={sorted(indexed - discovered)}; "
                f"missing={sorted(discovered - indexed)}"
            )
    rows: list[dict[str, Any]] = []
    for page in pages:
        authority, depth, disposition, rationale = classify(page["url_path"], page["section"])
        cards = cards_for(page["url_path"])
        meta = [CARD_META[card] for card in cards]
        stable = hashlib.sha256(page["url_path"].encode()).hexdigest()[:12].upper()
        rows.append(
            {
                "doc_id": f"DOC-PAGE-{stable}",
                **page,
                "authority": authority,
                "review_depth": depth,
                "target_tracks": sorted({track for card in cards for track in infer_tracks(card)}),
                "signals": sorted({item for row in meta for item in row["signals"]}),
                "dependencies": [],
                "nep_ids": sorted({item for row in meta for item in row["neps"]}),
                "attacker_card_ids": cards,
                "canonical_pattern_ids": sorted({item for row in meta for item in row["patterns"]}),
                "agent_roles": sorted({item for row in meta for item in row["roles"]}),
                "disposition": disposition,
                "rationale": rationale,
                "last_semantic_review": "2026-10-20",
            }
        )
    index_hash = sha256_bytes(index_path.read_bytes()) if index_path else None
    return {
        "schema_version": 1,
        "source": {
            "repository": "near/docs",
            "commit": git_commit(root),
            "index_source_path": "llms.txt",
            "index_sha256": index_hash,
            "page_count": len(rows),
            "reviewed_at": "2026-10-20",
        },
        "cards_reference": CARD_GUIDE.name,
        "cards": CARD_META,
        "pages": rows,
    }


def infer_tracks(card: str) -> list[str]:
    if card.startswith(("DOC-BRIDGE", "DOC-RELAYER", "DOC-RPC")):
        return ["bridge", "relayer", "offchain"]
    if card.startswith("DOC-MPC"):
        return ["chain-signatures", "mpc"]
    if card.startswith("DOC-INTENT"):
        return ["intents", "relayer"]
    if card.startswith(("DOC-WALLET", "DOC-META")):
        return ["wallet", "relayer"]
    if card.startswith("DOC-TEE"):
        return ["offchain", "tee"]
    return ["smart-contract"]


def headings(path: Path, expression: str) -> set[str]:
    return set(re.findall(expression, path.read_text(encoding="utf-8"), re.MULTILINE))


def validate_registry(registry: dict[str, Any], actual: list[dict[str, str]], commit: str) -> dict[str, Any]:
    errors: list[str] = []
    if registry.get("schema_version") != 1:
        errors.append("registry schema_version must be 1")
    source = registry.get("source", {})
    if source.get("commit") != commit:
        errors.append(f"source commit differs: registry={source.get('commit')} checkout={commit}")
    pages = registry.get("pages")
    if not isinstance(pages, list):
        raise ValueError("registry pages must be a list")
    card_registry = registry.get("cards")
    if not isinstance(card_registry, dict):
        errors.append("registry cards must be an object")
        card_registry = {}
    by_path: dict[str, dict[str, Any]] = {}
    ids: set[str] = set()
    for row in pages:
        if not isinstance(row, dict) or not row.get("url_path"):
            errors.append("registry has invalid page row")
            continue
        path = str(row["url_path"])
        if path in by_path:
            errors.append(f"duplicate url_path {path}")
        by_path[path] = row
        doc_id = row.get("doc_id")
        if not isinstance(doc_id, str) or doc_id in ids:
            errors.append(f"invalid or duplicate doc_id {doc_id!r}")
        ids.add(str(doc_id))
        if row.get("authority") not in ALLOWED_AUTHORITY:
            errors.append(f"{path}: invalid authority")
        if row.get("review_depth") not in ALLOWED_DEPTH:
            errors.append(f"{path}: invalid review_depth")
        if row.get("disposition") not in ALLOWED_DISPOSITIONS:
            errors.append(f"{path}: invalid disposition")
        for field in ("target_tracks", "signals", "dependencies", "nep_ids", "attacker_card_ids", "canonical_pattern_ids", "agent_roles"):
            if not isinstance(row.get(field), list):
                errors.append(f"{path}: {field} must be a list")
        if row.get("review_depth") == "deep" and not row.get("attacker_card_ids") and not row.get("rationale"):
            errors.append(f"{path}: deep page lacks cards and rationale")
        if row.get("review_depth") == "deep" and not row.get("attacker_card_ids") and row.get("disposition") == "actionable":
            errors.append(f"{path}: actionable deep page lacks an attacker card")

    actual_by_path = {row["url_path"]: row for row in actual}
    added = sorted(set(actual_by_path) - set(by_path))
    removed = sorted(set(by_path) - set(actual_by_path))
    changed: list[dict[str, str]] = []
    moved: list[dict[str, str]] = []
    for path in sorted(set(actual_by_path) & set(by_path)):
        current = actual_by_path[path]
        stored = by_path[path]
        if stored.get("sha256") != current["sha256"]:
            changed.append({"url_path": path, "old_sha256": str(stored.get("sha256")), "new_sha256": current["sha256"]})
        if stored.get("source_path") != current["source_path"]:
            moved.append({"url_path": path, "old_source_path": str(stored.get("source_path")), "new_source_path": current["source_path"]})

    known_cards = headings(CARD_GUIDE, r"^###\s+(DOC-[A-Z0-9-]+)\s+—")
    known_patterns = set(json.loads(PATTERN_INDEX.read_text(encoding="utf-8"))["cards"])
    known_roles = headings(AGENT_CATALOG, r"^###\s+`([^`]+)`")
    known_neps = set(json.loads(NEP_REGISTRY.read_text(encoding="utf-8"))["neps"])
    referenced_cards: set[str] = set()
    if set(card_registry) != known_cards:
        errors.append("registry card index differs from attacker-guide headings")
    for card, metadata in card_registry.items():
        if not isinstance(metadata, dict):
            errors.append(f"card {card}: metadata must be an object")
            continue
        for field in ("signals", "activation_signals", "patterns", "roles", "neps", "invariants", "mutations"):
            if not isinstance(metadata.get(field), list):
                errors.append(f"card {card}: {field} must be a list")
        if metadata != CARD_META.get(card):
            errors.append(f"card {card}: metadata differs from reviewed checker mapping")
        for signal in metadata.get("signals", []):
            if signal not in SIGNALS:
                errors.append(f"card {card}: unknown surface signal {signal}")
        for signal in metadata.get("activation_signals", []):
            if signal not in SIGNALS:
                errors.append(f"card {card}: unknown activation signal {signal}")
        for invariant in metadata.get("invariants", []):
            if invariant not in INVARIANT_PREFIXES:
                errors.append(f"card {card}: unknown invariant family {invariant}")
        for mutation in metadata.get("mutations", []):
            if mutation not in MUTATION_FAMILIES:
                errors.append(f"card {card}: unknown mutation family {mutation}")
    for path, row in by_path.items():
        referenced_cards.update(row.get("attacker_card_ids", []))
        for card in row.get("attacker_card_ids", []):
            if card not in known_cards:
                errors.append(f"{path}: unknown attacker card {card}")
        for pattern in row.get("canonical_pattern_ids", []):
            if pattern not in known_patterns:
                errors.append(f"{path}: unknown canonical pattern {pattern}")
        for role in row.get("agent_roles", []):
            if role not in known_roles:
                errors.append(f"{path}: unknown agent role {role}")
        for nep in row.get("nep_ids", []):
            if nep not in known_neps:
                errors.append(f"{path}: unknown NEP {nep}")
        routed = [card_registry[card] for card in row.get("attacker_card_ids", []) if card in card_registry]
        expected_page_fields = {
            "signals": sorted({item for metadata in routed for item in metadata["signals"]}),
            "canonical_pattern_ids": sorted({item for metadata in routed for item in metadata["patterns"]}),
            "agent_roles": sorted({item for metadata in routed for item in metadata["roles"]}),
            "nep_ids": sorted({item for metadata in routed for item in metadata["neps"]}),
        }
        for field, expected_values in expected_page_fields.items():
            if row.get(field) != expected_values:
                errors.append(f"{path}: {field} differs from routed card metadata")
    orphan_cards = sorted(known_cards - referenced_cards)
    if orphan_cards:
        errors.append(f"unrouted attacker cards: {orphan_cards}")
    if source.get("page_count") != len(pages):
        errors.append("source page_count differs from registry rows")

    return {
        "registry_pages": len(pages),
        "checkout_pages": len(actual),
        "cards": len(known_cards),
        "added": added,
        "removed": removed,
        "changed": changed,
        "moved": moved,
        "errors": errors,
        "semantic_review_required": bool(added or removed or changed or moved),
        "complete": not errors and not added and not removed and not changed and not moved,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("registry", type=Path)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--index", type=Path, help="Optional downloaded llms.txt for source index hashing")
    parser.add_argument("--change-report", type=Path, help="Write the semantic-review report here")
    parser.add_argument("--initialize", action="store_true", help="Explicitly create a new registry; refuses to overwrite")
    args = parser.parse_args()

    root = args.source_root.resolve()
    if not (root / "docs.json").is_file() or not (root / "openapi.json").is_file():
        parser.error("source root must be an official near/docs checkout")
    registry_path = args.registry.resolve()
    if args.initialize:
        if registry_path.exists():
            parser.error("--initialize refuses to overwrite an existing registry")
        registry = initial_registry(root, args.index.resolve() if args.index else None)
        registry_path.write_text(json.dumps(registry, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(json.dumps({"initialized": str(registry_path), "pages": len(registry["pages"])}))
        return 0

    registry = json.loads(registry_path.read_text(encoding="utf-8"))
    report = validate_registry(registry, discover_pages(root), git_commit(root))
    if args.index:
        index_hash = sha256_bytes(args.index.resolve().read_bytes())
        expected = registry.get("source", {}).get("index_sha256")
        if expected != index_hash:
            report["errors"].append("llms.txt hash differs from registry pin")
        indexed = indexed_paths(args.index.resolve())
        registered = {str(page["url_path"]) for page in registry["pages"]}
        report["index_added"] = sorted(indexed - registered)
        report["index_missing"] = sorted(registered - indexed)
        if report["index_added"] or report["index_missing"]:
            report["errors"].append("llms.txt page set differs from registry")
        report["complete"] = not report["errors"] and not report["semantic_review_required"]
    rendered = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    if args.change_report:
        args.change_report.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0 if report["complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
