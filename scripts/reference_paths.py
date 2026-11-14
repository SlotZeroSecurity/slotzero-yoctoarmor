"""Fixed package resource paths, independent of the caller's working directory.

Registries keep their existing package-relative or manifest-relative path contracts.
This module names locations only; it does not change worker access or routing.
"""
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
REFERENCE_PATHS = {
    'agent_catalog': 'runtime/workflow/agent-catalog.md',
    'lens_account': 'references/account.md',
    'lens_async': 'references/async.md',
    'lens_auth': 'references/auth.md',
    'lens_crypto': 'references/crypto.md',
    'lens_econ': 'references/econ.md',
    'lens_integration': 'references/integration.md',
    'lens_offchain': 'references/offchain.md',
    'lens_resource': 'references/resource.md',
    'lens_runtime': 'references/runtime.md',
    'lens_state': 'references/state.md',
    'attack_index': 'references/index.json',
    'audit_workflow': 'runtime/workflow/audit-workflow.md',
    'capability_model': 'runtime/workflow/capability-model.md',
    'finding_schema': 'runtime/schemas/finding-schema.md',
    'maintenance': 'docs/maintenance.md',
    'mutation_operators': 'runtime/workflow/mutation-operators.json',
    'near_security_model': 'runtime/workflow/near-security-model.md',
    'nep_contract_interfaces': 'runtime/standards/neps/nep-contract-interfaces.md',
    'nep_crypto_host': 'runtime/standards/neps/nep-crypto-host.md',
    'nep_process_legacy': 'runtime/standards/neps/nep-process-legacy.md',
    'nep_protocol_node': 'runtime/standards/neps/nep-protocol-node.md',
    'nep_registry': 'runtime/standards/neps/nep-registry.json',
    'nep_runtime_resources': 'runtime/standards/neps/nep-runtime-resources.md',
    'nep_token_assets': 'runtime/standards/neps/nep-token-assets.md',
    'nep_wallet_auth': 'runtime/standards/neps/nep-wallet-auth.md',
    'neutral_schemas': 'runtime/schemas/neutral-schemas.md',
    'docs_cards': 'runtime/standards/official-docs/review-cards.md',
    'docs_registry': 'runtime/standards/official-docs/docs-registry.json',
    'target_binding': 'references/target-binding.md',
    'technical_annex_template': 'runtime/reporting/technical-annex-template.md',
    'review_contract': 'runtime/workflow/review-contract.md',
    'runtime_adapter': 'runtime/workflow/runtime-adapter.md',
    'semantic_pipeline': 'runtime/workflow/semantic-pipeline.md',
    'slotzero_report_format': 'runtime/reporting/slotzero-report-format.md',
    'threat_model': 'runtime/workflow/threat-model.md',
    'usage_guide': 'docs/usage.md',
    'verification_reporting': 'runtime/reporting/verification-reporting.md',
    'adding_patterns': 'docs/adding-patterns.md',
}


def reference_relative(name: str) -> str:
    """Return a package-relative path for a named reference."""
    return REFERENCE_PATHS[name]


def reference_path(name: str, *, root: Path | None = None) -> Path:
    """Resolve a reference in this package or an explicitly supplied test package."""
    return (PACKAGE_ROOT if root is None else root) / reference_relative(name)


def missing_resource_paths(root: Path = PACKAGE_ROOT) -> list[str]:
    """All shipped fixed resources must exist; no compatibility symlink aliases."""
    return [relative for relative in REFERENCE_PATHS.values()
            if not (root / relative).is_file() or (root / relative).is_symlink()]
