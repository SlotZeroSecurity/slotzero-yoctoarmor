<div align="center">

# NEAR YoctoArmor v1

**A Slot Zero Security framework for finding vulnerabilities in NEAR contracts.**

<p>
  <a href="https://slotzerosecurity.com/"><img src="https://img.shields.io/badge/Website-006DFF?style=for-the-badge&labelColor=0a0a0a" alt="Website"></a>
  <a href="https://x.com/Slot_Zero_Sec"><img src="https://img.shields.io/badge/Twitter-006DFF?style=for-the-badge&labelColor=0a0a0a" alt="Twitter"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-006DFF?style=for-the-badge&labelColor=0a0a0a" alt="MIT License"></a>
</p>

[Install](#install) · [Run](#run-a-review) · [Threat model](#threat-model) · [How it works](#how-it-works) · [Specialists](#meet-the-specialists) · [Reports](#what-you-receive) · [Usage guide](docs/usage.md)

</div>

<a id="install"></a>

## 📦 Install

Open [Codex](https://learn.chatgpt.com/docs/build-skills) or [Claude Code](https://code.claude.com/docs/en/skills/) and paste:

```text
Install NEAR YoctoArmor v1 locally as a personal skill for this AI tool.
Clone branch v1 from https://github.com/SlotZeroSecurity/slotzero-nearshield.git
Install the complete package as near-yoctoarmor-v1 in this tool's supported
skills directory. Preserve any existing installation outside skill-discovery
directories and avoid duplicate copies.
Show the installed path and how to invoke the skill.
```

<a id="run-a-review"></a>

## 🚀 Run a review

<a id="threat-model"></a>

### 🧭 First, the threat model

Put `THREAT_MODEL.md` in your project's root. Explain what needs protecting, what an attacker can do, who is trusted, and which rules must hold.
Use the [threat-model skill](https://github.com/openai/codex-security/tree/main/plugins/codex-security/skills/threat-model) to generate it, then review it yourself. See the [example and instructions](docs/usage.md#threat-model).
The audit stops if it is missing unless you explicitly choose to continue without it.

Then paste into Codex:

```text
$near-yoctoarmor-v1 Audit /absolute/path/to/near-project with --loop 1.
Read THREAT_MODEL.md first and keep audit files outside the project.
```

`--loop 1` runs one discovery pass with all required review checks. The host needs tools for independent agents.
For more passes, selected files, and troubleshooting, open the [usage guide](docs/usage.md).

<a id="how-it-works"></a>

## 🔎 How it works

| Level | What it means |
| --- | --- |
| **L0 — Understand** | Map what the contract should do, who uses it, and where funds move. |
| **L1 — Recognize** | Check relevant known bug patterns against the actual code. |
| **L2 — Reason** | Find gaps between intended and actual behavior without reading the pattern library. |
| **L3 — Challenge** | Combine specialist searches, testing, independent verification, and a check for missed paths. |
| **L4 — Measure** | Measure performance on separate, independently reviewed benchmarks. Requires recorded qualification evidence. |

<a id="meet-the-specialists"></a>

## 🧑‍🔬 Meet the specialists

The framework combines **12 core discovery roles** with **96 attack patterns across 10 categories**.

### 12 core discovery roles

| Role | What it reviews |
| --- | --- |
| **`entrypoints-auth`** | Checks public methods, permissions, access keys, and initialization for unauthorized access. |
| **`async-promises`** | Traces promises and callbacks for failures, replay, ordering problems, and incorrect refunds. |
| **`state-storage`** | Examines persistent state, storage costs, collection behavior, and cleanup. |
| **`token-accounting`** | Reconciles token balances, supply, transfers, approvals, fees, and refunds. |
| **`math-economics`** | Tests arithmetic, rounding, pricing, rewards, and economic incentives for abuse. |
| **`gas-dos`** | Looks for attacker-controlled workloads that exhaust gas or block essential operations. |
| **`invariant-flow`** | Checks that related state and value flows remain consistent throughout each lifecycle. |
| **`periphery-build`** | Reviews interfaces, serialization, dependencies, build settings, and surrounding integrations. |
| **`coverage-sweep`** | Independently reviews the full scope for overlooked methods, branches, and promise paths. |
| **`numerical-gap`** | Investigates interactions between arithmetic, storage costs, and asynchronous state. |
| **`trust-gap`** | Finds authority mismatches across identities, access keys, external contracts, and callbacks. |
| **`flow-gap`** | Traces value movement, failure recovery, lifecycle transitions, and migrations for missing steps. |

Explore the [full agent catalog](runtime/workflow/agent-catalog.md). Agents run within the host's available capacity.

### 10 attack-pattern categories

| Category | Patterns | What it covers |
| --- | ---: | --- |
| **[Authorization](references/auth.md)** | 12 | Covers caller identity confusion, exposed privileged methods, access-key boundaries, and replay. |
| **[Async execution](references/async.md)** | 17 | Covers split-receipt double spending, stale callbacks, failed compensation, and pending-operation recovery. |
| **[Accounting](references/account.md)** | 7 | Covers liabilities, reserves, storage charges, reward accrual, claim recovery, and vault-share dilution. |
| **[State](references/state.md)** | 16 | Covers inconsistent records, unsafe migrations, missing lifecycle transitions, and conflicting configuration. |
| **[Economics](references/econ.md)** | 4 | Covers asset and unit confusion, arithmetic errors, ordering manipulation, and incorrect compensation. |
| **[Resources](references/resource.md)** | 10 | Covers unpaid storage, collection collisions, unbounded work, sponsorship, and refund attribution. |
| **[Integration](references/integration.md)** | 8 | Covers receiver identity, interface mismatches, bridge proof and finality races, and unreliable external inputs. |
| **[Cryptography](references/crypto.md)** | 8 | Covers ambiguous encoding, threshold-signing assumptions, nonce reuse, secret handling, and attestation binding. |
| **[Runtime](references/runtime.md)** | 2 | Covers unmetered host execution and failures in consensus agreement or liveness. |
| **[Offchain](references/offchain.md)** | 12 | Covers indexer trust, relayer retries, unsafe inputs, build integrity, testing, monitoring, and recovery documentation. |

<a id="what-you-receive"></a>

## 📄 What you receive

Every completed audit automatically delivers two downloadable files:

- **`slotzero-report.md`** — findings, confidence, suggested fixes, and unverified leads.
- **`technical-annex.md`** — affected code, attack paths, tests, coverage, and limitations.

## 📑 Sample reports

- [Sample security report](docs/sample-slotzero-report.md)
- [Sample technical annex](docs/sample-technical-annex.md)
