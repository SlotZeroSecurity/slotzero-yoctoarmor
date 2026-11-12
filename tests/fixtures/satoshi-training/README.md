# Informed Satoshi training exercises

These paired scenarios teach evidence collection and rejection of false positives.
They are synthetic descriptions, not executed bridge contracts, reproduced
exploits, held-out benchmarks, or measured model recall. Never put this directory
or its expected answers in target audit packets.

For each pair in `cases.json`, first reason from the `candidate` and `safe_control`
descriptions. Identify receipt ordering, authority, committed versus rolled-back
effects, and all terminal or recovery paths. Then compare with `expected`.
The safe control must actually implement the stated safeguards; a name such as
“paused” or “validated” is not evidence that they exist.

The regression tests validate corpus accounting, reference integrity, hash
sensitivity, and packet routing. They do not score an agent's answers to these
exercises. A later evaluation must record actual model output, independent
adjudication, source revision, and runtime/token telemetry before claiming gains.
