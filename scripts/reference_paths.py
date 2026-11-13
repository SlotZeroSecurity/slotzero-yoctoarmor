"""Fixed package reference paths, independent of the caller's working directory.

Registries keep their existing package-relative or manifest-relative path contracts.
This module names locations only; it does not change worker access or routing.
"""
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
REFERENCE_PATHS = {
    'agent_catalog': 'references/workflow/agent-catalog.md',
    'lens_account': 'references/patterns/attack-lenses/account.md',
    'lens_async': 'references/patterns/attack-lenses/async.md',
    'lens_auth': 'references/patterns/attack-lenses/auth.md',
    'lens_crypto': 'references/patterns/attack-lenses/crypto.md',
    'lens_econ': 'references/patterns/attack-lenses/econ.md',
    'lens_integration': 'references/patterns/attack-lenses/integration.md',
    'lens_offchain': 'references/patterns/attack-lenses/offchain.md',
    'lens_resource': 'references/patterns/attack-lenses/resource.md',
    'lens_runtime': 'references/patterns/attack-lenses/runtime.md',
    'lens_state': 'references/patterns/attack-lenses/state.md',
    'attack_index': 'references/patterns/attack-lenses-index.json',
    'audit_workflow': 'references/workflow/audit-workflow.md',
    'capability_model': 'references/workflow/capability-model.md',
    'original_findings_index': 'references/sources/reports/original-findings-index.json',
    'finding_schema': 'references/schemas/finding-schema.md',
    'historical_id_map': 'references/maintenance/historical-id-map.json',
    'legacy_design_review': 'references/sources/reports/legacy-report-review.json',
    'maintenance': 'references/maintenance/maintenance.md',
    'mutation_operators': 'references/workflow/mutation-operators.json',
    'near_security_model': 'references/workflow/near-security-model.md',
    'nep_contract_interfaces': 'references/standards/neps/nep-contract-interfaces.md',
    'nep_crypto_host': 'references/standards/neps/nep-crypto-host.md',
    'nep_process_legacy': 'references/standards/neps/nep-process-legacy.md',
    'nep_protocol_node': 'references/standards/neps/nep-protocol-node.md',
    'nep_registry': 'references/standards/neps/nep-registry.json',
    'nep_runtime_resources': 'references/standards/neps/nep-runtime-resources.md',
    'nep_token_assets': 'references/standards/neps/nep-token-assets.md',
    'nep_wallet_auth': 'references/standards/neps/nep-wallet-auth.md',
    'neutral_schemas': 'references/schemas/neutral-schemas.md',
    'docs_cards': 'references/standards/official-docs/review-cards.md',
    'docs_registry': 'references/standards/official-docs/docs-registry.json',
    'target_binding': 'references/patterns/target-binding.md',
    'pdf_corpus_2022_2023': 'references/sources/reports/findings-2022-2023.md',
    'pdf_corpus_2024_2026': 'references/sources/reports/findings-2024-2026.md',
    'report_registry': 'references/sources/report-registry.json',
    'provenance': 'references/sources/provenance.md',
    'technical_annex_template': 'references/reporting/technical-annex-template.md',
    'review_contract': 'references/workflow/review-contract.md',
    'runtime_adapter': 'references/workflow/runtime-adapter.md',
    'issue_registry': 'references/sources/issues/omnibridge-satoshi/findings.json',
    'issue_findings': 'references/sources/issues/omnibridge-satoshi/findings.md',
    'semantic_pipeline': 'references/workflow/semantic-pipeline.md',
    'slotzero_report_format': 'references/reporting/slotzero-report-format.md',
    'issue_review': 'references/sources/issues/omnibridge-satoshi/review.json',
    'threat_model': 'references/workflow/threat-model.md',
    'usage_guide': 'references/usage-guide.md',
    'verification_reporting': 'references/reporting/verification-reporting.md',
    'catalog': 'references/README.md',
    'adding_patterns': 'references/maintenance/adding-patterns.md',
}


def reference_relative(name: str) -> str:
    """Return a package-relative path for a named reference."""
    return REFERENCE_PATHS[name]


def reference_path(name: str, *, root: Path | None = None) -> Path:
    """Resolve a reference in this package or an explicitly supplied test package."""
    return (PACKAGE_ROOT if root is None else root) / reference_relative(name)
