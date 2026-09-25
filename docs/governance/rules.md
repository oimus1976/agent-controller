# Standing rules for workers

These rules apply to every worker in this repository, whatever the provider. Each rule states what to do and links to the record that owns it. When a rule here and its owning Issue or ADR disagree, the owning record wins and this file should be corrected.

The house baseline this project follows is [`oimus1976/ai-dev-starter`](https://github.com/oimus1976/ai-dev-starter) (`BASELINE.md`). This repository predates full adoption of that baseline. Project-specific ADRs and Issues take precedence where they are stricter.

## 1. Evidence authority

- Treat agent, provider, and chat statements as claims until an authoritative source confirms them. That includes "done", "tests pass", "pushed", "reviewed", and "Ready".
- Authority is per fact. GitHub owns refs, PR state, heads, and diffs. GitHub Actions owns CI results. The canonical inspector owns review state (rule 4).
- Do not manufacture missing evidence from prose.
- Owners: [#1](https://github.com/oimus1976/agent-controller/issues/1), [ADR #12](https://github.com/oimus1976/agent-controller/issues/12), `ai-dev-starter` BASELINE §2–3.

## 2. Human-final authority

- Ready, merge, release, deploy, visibility changes, credential or secret administration, destructive cleanup, and other LEVEL 3 effects are performed by the human.
- Workers prepare the exact action, verify its preconditions, surface one concise decision, and re-read authoritative state afterwards.
- Owner: [ADR #90](https://github.com/oimus1976/agent-controller/issues/90).

## 3. Independent implementation and review

Implementation and review must remain independent.

- The implementing session or agent must not be the sole reviewer of its own work.
- Independent review must bind to an exact commit/head and start from a fresh review context.
- Review findings may be remediated by the original implementer or another implementation agent, but remediation is not self-validating.
- After remediation changes the exact head, a fresh reviewer must review the new head. The agent or session that performed the remediation must not be the sole evidence that the fix is correct.
- For security-sensitive trust-boundary, credential, permission, destructive-effect, or fail-closed changes, add cross-model or cross-agent review when practical.
- Self-review, tests, linting, and remediation-thread confirmation are supplemental evidence, not substitutes for independent review.
- Record the review in the PR using [`review-record.md`](review-record.md), including the independence level L0–L3 (BASELINE §9). Self-review is L0.
- Owner: [ADR #199](https://github.com/oimus1976/agent-controller/issues/199). The bullets above are the operational projection originally staged on branch `adr-199-review-independence`.

## 4. Canonical review evidence

- A review state (clean, finding, pending, absent) may be claimed only from the complete multi-surface evidence of the canonical inspector path, `inspect-pr`. That evidence covers formal reviews, top-level PR comments, inline threads, and reactions, all bound to the current head.
- A read of one raw GitHub surface is advisory. Absence on one surface is not absence of a review.
- Owner: [#194](https://github.com/oimus1976/agent-controller/issues/194).

## 5. Provider results pending human application

- A provider task can complete while the GitHub branch is still unchanged. For example, Codex needs `View Task → Update branch`.
- Treat that state as "complete, pending human apply". Do not reimplement the change, and do not infer failure from an unchanged head.
- After the human applies it, re-read the exact head from GitHub.
- Owner: [#200](https://github.com/oimus1976/agent-controller/issues/200).

## 6. Workstream isolation and scope

- New work gets its own Issue (workstream). Do not widen an active PR with unrelated work.
- Repository proximity, recency, adjacent numbers, branch-name similarity, and provider prose do not make an artifact part of your workstream. Unknown or unbound targets fail closed.
- Owner: [#120](https://github.com/oimus1976/agent-controller/issues/120), [`docs/workstream-isolation.md`](../workstream-isolation.md).

## 7. Capacity policy (replaces the fixed WIP cap)

- There is no fixed limit on concurrent Draft PRs.
- Before opening new implementation work, check the open PRs and the known remaining capacity of the providers the work will consume.
- When a provider is near its usage limit, prefer finishing or reviewing open work, or waiting, over starting new work that needs that provider.
- Do not treat unknown capacity as available, and never start paid usage without explicit human authorization.
- Owners: owner decision of 2026-09-25 recorded in [#256](https://github.com/oimus1976/agent-controller/issues/256); capacity semantics in [#168](https://github.com/oimus1976/agent-controller/issues/168) and [#55](https://github.com/oimus1976/agent-controller/issues/55).

## 8. Live, owner-machine, and operator-facing effects

- Any live or owner-machine effect needs a separate explicit human authorization for the exact plan. Examples include runner registration, workflow dispatch, archive apply, account or ACL changes, and target execution.
- Consumed, failed, or uncertain authority is never reused or retried automatically. Merging a code fix does not authorize a live retry.
- Operator-facing commands must pass the deterministic operator-step gate before they are presented as executable.
- Owners: [#216](https://github.com/oimus1976/agent-controller/issues/216), [#195](https://github.com/oimus1976/agent-controller/issues/195).

## 9. Exact-head evidence and invalidation

- CI and review evidence apply only to the exact head they observed.
- A new head invalidates the prior evidence that the change affects. Rerun what the change invalidates, and do not carry old-head evidence forward.
- Owner: `ai-dev-starter` BASELINE §8.

## 10. Reuse-first and specification-driven work

- Before writing custom integration code, prefer official APIs/CLIs/SDKs, then established OSS, then thin wrappers ([ADR #12](https://github.com/oimus1976/agent-controller/issues/12)).
- Specification drives the work, and layered evidence establishes conformance ([ADR #179](https://github.com/oimus1976/agent-controller/issues/179)).
- Write stable acceptance items and verify each against evidence.

## 11. Public-repository evidence hygiene

- This repository is public. Never publish credentials, tokens, or private keys.
- In new durable evidence, use normalized placeholders (`<HOST>`, `<RUNNER>`, `<NONCE>`, `<WORKSPACE>`, …) for machine-specific identifiers unless the exact value is material.
- Owner: [`docs/PUBLIC_REPOSITORY_READINESS.md`](../PUBLIC_REPOSITORY_READINESS.md).

## 12. Post-merge local closeout

- After a human merge, confirm the merge on GitHub and run [`post-merge-closeout.md`](post-merge-closeout.md).
- Keep remote topic branches unless a human decides otherwise ([`docs/post-merge-cleanup-candidates.md`](../post-merge-cleanup-candidates.md)).

## 13. Handoff and status index

- At every meaningful handoff, post a checkpoint on the workstream Issue using [`checkpoint-template.md`](checkpoint-template.md).
- When the set of workstreams, the main line, or a standing policy changes, update [`PROJECT_STATUS.md`](../../PROJECT_STATUS.md) in the same PR.
- Record meaningful semantic changes in [`CHANGELOG.md`](../../CHANGELOG.md), following its recording policy.
- Owner: [#256](https://github.com/oimus1976/agent-controller/issues/256).
