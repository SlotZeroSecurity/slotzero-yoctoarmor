# Adding and maintaining patterns

Use this procedure during explicit skill maintenance, not during a target audit.
Start with the [maintenance workflow](maintenance.md) and the
[target-binding protocol](../patterns/target-binding.md). Target findings and
human feedback never update the library automatically.

## Ownership and scope

- The [category cards](../patterns/attack-lenses-index.json) are authoritative for
  detailed mechanisms. Each Markdown card retains its permanent ID.
- The index owns category membership, file routing, activation summaries, and
  related-ID links. Titles and kinds must agree with the Markdown. Activation
  summaries may be shorter than the detailed activation field; review their
  semantic agreement rather than requiring identical text.
- The [source registry](../sources/report-registry.json) owns exact PDF identity
  and ingestion disposition. [Source history](../sources/provenance.md) preserves
  observations, qualifications, exclusions, and revision evidence.
- Existing categories remain unchanged. A new category requires a separate
  routing, isolation, documentation, and regression review; do not create one
  simply because a new report or project has arrived.

## 1. Record the observation

Preserve the source identity, source revision or digest where available, review
status, and evidence limits. Distinguish a reported claim or remediation from a
reproduced result. For a new PDF, register its raw bytes before extraction using
`python3 scripts/maintain.py corpus pdf register <pdf-or-directory>`.
Follow skip/resume outcomes in the maintenance workflow. Keep raw sources outside
the package. Add reviewed observations to the appropriate source ledger; a new
issue collection belongs under its own source-specific directory.

Source references in the report registry are relative to its containing
`sources/` directory, for example `reports/findings-2024-2026.md#<ledger-id>`.
Retain original report filenames and source identifiers inside historical records.

## 2. Compare mechanisms before allocating an ID

Compare root cause, invariant, attacker control, execution boundary, recovery,
terminal harm, and fix family across current cards. Similar titles alone do not
justify merging; different project names alone do not justify a new card.

- Same mechanism: extend the existing card only with a useful variant or
  qualification and retain source provenance. Do not create another ID.
- Distinct mechanism: add a card to an existing category with the appropriate
  classification. An unproven source does not become a validated target finding.
- Unsupported, disputed, inapplicable, or quality-only observation: retain that
  disposition. Do not promote it to a security pattern without supporting evidence.

## 3. Add or update the card

For a new card use the next unused `NA-<CATEGORY>-NNN` ID. Check the active index
and historical translation records; never renumber or reuse an existing or
retired ID. Append to its category's established order.

Use this structure in the category Markdown:

```text
## NA-<CATEGORY>-NNN — Specific mechanism title

- **Kind:** existing classification appropriate to the evidence
- **Root cause:** the causal defect
- **Activation:** target behavior and prerequisites
- **Broken invariant:** the property that must hold
- **Concrete sequence:** attacker-controlled actions and execution boundaries
- **Required evidence:** target facts and terminal harm needed to establish it
- **Exclusions:** safe controls and conditions that refute applicability
- **Recovery:** failure, retry, cancellation, and compensation behavior
- **Fix family:** the general repair approach
```

Keep the existing classification vocabulary; changing its meaning is separate
from adding a pattern. For a security mechanism, provide a vulnerable/safe
regression scenario where feasible. Record execution or environment limitations
when reproduction is unavailable. Historical sources never substitute for target
proof.

## 4. Update the connected records

Add the card to the category's ordered `ids` list and to the index's `cards`
object. Provide `category`, `kind`, `title`, `activation`, and `related_ids`.
Related IDs must resolve to active cards. Update source mappings and appropriate
ledger dispositions without rewriting the frozen original report index merely
to accommodate a new source.

Update NEP or official-documentation mappings only when the reviewed source
supports that relationship. Do not invent a mutation operator for every card;
new operators require their own implementation and validation. Existing-category
cards require no new controller branch or worker role.

## 5. Validate and review

Run from the package root:

```text
python3 -B scripts/maintain.py check
python3 -B scripts/near_audit.py doctor
python3 -B scripts/maintain.py corpus pdf validate
python3 -B -m unittest discover -s tests
```

Validate IDs, all nine fields, title/kind consistency, related-ID closure,
source-reference resolution, routing, and worker isolation. Review shorter
activation summaries for semantic consistency. Update current-inventory count
expectations and explanatory counts when a deliberate addition changes them;
review the migration fingerprints when intentionally changing preserved content.
The frozen baseline records the v1-to-v1_1 relocation; update affected regression
expectations only with reviewed evidence, never merely to silence a failure.

Package changes alter run hashes. Preserve the original package for existing
runs and initialize fresh runs under the updated package. Do not rewrite saved
hashes or claim benchmark equivalence from structural tests alone.
