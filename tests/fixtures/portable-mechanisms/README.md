# Portability review exercises

These eleven informed pairs use non-bridge domains to check the design of the
mechanism library. They are review prompts, not runnable target implementations.
They do not demonstrate model recall, cross-language analysis capability, or
independently reproduced vulnerabilities.

For each pair, inspect its target bindings before reading the expected reasoning.
Determine which prerequisites are established, absent, or unknown. Explain the
causal sequence using the target's state and execution model. Compare the safe
control and renaming control: renaming without changing semantics must preserve
applicability, while familiar names without required semantics must not create it.

Pay particular attention to the atomic-transaction and intentional-policy cases.
They should stop inappropriate transfer of receipt or bridge assumptions.
Static regression tests check the fixtures' integrity and routing contracts;
independent agent answers and adjudication are required for an actual evaluation.
