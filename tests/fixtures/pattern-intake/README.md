# Pattern-intake evaluation cases

Give an evaluator the skill, a disposable package copy, and one input from
`inputs.json`. Withhold `expected.json`. For the repeated-input case, first apply
the stated existing-card precondition; evaluate whether any further edit is needed.

Check the resulting diff against the rubric, then run index validation and the
package tests. Distinct-mechanism classification depends on the current library;
a well-justified precise extension can be correct when it preserves the full
cause and repair. Do not reward creating more cards for its own sake.

Check that IDs remain stable, categories follow the causal defect, safe controls
survive, unsupported claims are not promoted, extraction limits are disclosed,
and no report registry or input-consumption state is written. Input and expected
files are evaluation fixtures only, never target-worker references.

These cases have not been run as independent model evaluations. Unit tests check
rubric consistency and resulting library structure, not semantic classification.
