# Run journal and Codex worker adapter

Current runs use manifest schema 6 and state schema 4. `run-events/` is the
authoritative, hash-linked, append-only run journal. `run-state.json` is a
replaceable projection. Read-only `status` replays the journal without writing;
`resume` repairs a missing or stale projection under the run lock. An invalid,
missing, reordered, or edited event blocks the run. Older runs remain read-only.

The controller does not spawn Codex workers. The orchestrator uses its existing
worker tools, then records only host-observed facts through the same CLI:

```text
python3 <skill>/scripts/near_audit.py packet <run-dir> '<packet-id>'
python3 <skill>/scripts/near_audit.py worker <run-dir> start '<packet-id>' --worker-id '<observed-id>'
python3 <skill>/scripts/near_audit.py worker <run-dir> finish '<packet-id>' --worker-id '<observed-id>' \
  --wall-seconds <observed-seconds> --input-tokens <observed-count>
python3 <skill>/scripts/near_audit.py status <run-dir>
```

`packet` returns only the selected role's prompt sections, reference paths,
owned official cards, permitted/forbidden inputs, and assigned outputs. Bind any
remaining target-specific placeholders before dispatch. L0/L2 receive the
neutral surface and neutral schemas only; no attacker card body or corpus prompt
is included. Packet text is a dispatch aid, not filesystem isolation.

Use `worker ... fail --reason ...` for a host failure. `worker ... cancel`
records a request; only `--termination-evidence <observed-host-result>` records
confirmed cancellation. Claim `--isolation host_enforced` only with
`--isolation-evidence <observed-host-result>`; the default is `prompt_only`.
Never turn a prompt restriction, worktree, or unknown host capability into an
enforced-isolation claim. Unknown usage remains null. When runtime capacity is
unknown, the adapter admits one active worker at a time.

`finish` checks that every assigned file exists, is contained in the run, is at
most 16 MiB, and parses as JSON or JSONL where applicable. It retains oversized
files in place and reports their paths without ingesting them. This is a local
artifact bound; the Codex host must separately bound streamed tool output and
provide actual worker cancellation and sandboxing. A submitted worker is only
syntax checked; the existing phase gate still validates complete schemas and
coverage. A failed or cancelled recorded worker blocks phase advancement until
its successful retry. The packet's one-retry limit remains in force.

For a change claiming better output, use three paired, configuration-equivalent
before/after benchmark summaries on the same target manifest and scorer:

```text
python3 <skill>/scripts/check_harness_upgrade.py \
  --baseline <old-1.json> <old-2.json> <old-3.json> \
  --candidate <new-1.json> <new-2.json> <new-3.json>
```

The gate requires adjudicated quality to hold, at least one measured quality
gain, and median wall-time and input-token overhead at or below 20%. Public
smoke fixtures are regressions, not qualification evidence. If representative
targets or actual usage exports are unavailable, leave the release-gain claim
unverified rather than synthesizing measurements.
