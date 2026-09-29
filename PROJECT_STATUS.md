# Project Status (index)

> **This file is an index, not an authority.** Do not infer PR, head, CI, review, or authorization state from it. Before acting, re-read those facts from GitHub and CI. For each workstream, the authority is its Issue: read the latest checkpoint comment there.

- **as_of:** 2026-09-25, reconciled against `main` at `e6494caa14dac09ba9f87d9d2a9dfe6ee04e6969`. This is an advisory freshness hint only.
- **Entry point for workers:** [`AGENTS.md`](AGENTS.md). **Rules:** [`docs/governance/rules.md`](docs/governance/rules.md).

## Goal

Agent Controller is a provider-neutral control plane. It lets heterogeneous, untrusted AI workers (Codex, Claude, Antigravity, Jules, …) do bounded work, and it verifies that work objectively from GitHub evidence. It keeps the work moving and brings the human only the decisions that need human authority.

Shorthand: *automate the work, not the final authority* ([ADR #12](https://github.com/oimus1976/agent-controller/issues/12), [ADR #90](https://github.com/oimus1976/agent-controller/issues/90)).

## Main line

- **[#216](https://github.com/oimus1976/agent-controller/issues/216)** — the first human-authorized live Windows one-job private-CI pilot.
  - Parents: [#207](https://github.com/oimus1976/agent-controller/issues/207) and [#195](https://github.com/oimus1976/agent-controller/issues/195).
  - Its operational log, authorizations, and probe results are the comments on #216. Read the newest checkpoint or comment there.
  - Live effects need a separate human authorization for the exact plan ([rules §8](docs/governance/rules.md)).

## Active workstreams

This table lists pointers only. Status comes from each authority Issue's latest checkpoint and from GitHub.

| Workstream | Authority Issue | Related Issues / PRs | Checkpoints |
|---|---|---|---|
| Private-CI live pilot (main line) | [#216](https://github.com/oimus1976/agent-controller/issues/216) | [#229](https://github.com/oimus1976/agent-controller/issues/229), [#243](https://github.com/oimus1976/agent-controller/issues/243) | comments on #216 |
| Test-suite audit follow-up | [#246](https://github.com/oimus1976/agent-controller/issues/246) | [#254](https://github.com/oimus1976/agent-controller/issues/254) / PR [#255](https://github.com/oimus1976/agent-controller/pull/255) | comments on #246 |
| Worker entry point and handoff | [#256](https://github.com/oimus1976/agent-controller/issues/256) | PR [#257](https://github.com/oimus1976/agent-controller/pull/257) | comments on #256 |

## Standing decisions

- ADRs: [#12](https://github.com/oimus1976/agent-controller/issues/12) provider-neutral / reuse-first; [#90](https://github.com/oimus1976/agent-controller/issues/90) human-final; [#179](https://github.com/oimus1976/agent-controller/issues/179) specification-driven; [#199](https://github.com/oimus1976/agent-controller/issues/199) independent review.
- Capacity policy: there is no fixed WIP cap; check provider capacity before starting new work ([rules §7](docs/governance/rules.md)).
- House baseline: [`oimus1976/ai-dev-starter`](https://github.com/oimus1976/ai-dev-starter) `BASELINE.md`.

## Backlog (open, not active)

These Issues are open but not being worked on. Their order is an owner decision. The last recorded queue is in a [#55 comment](https://github.com/oimus1976/agent-controller/issues/55) dated 2026-09-04 and may be stale. Before selecting one, confirm it with the owner.

- Enforcement: [#194](https://github.com/oimus1976/agent-controller/issues/194) canonical review evidence, [#200](https://github.com/oimus1976/agent-controller/issues/200) Codex task apply states.
- Orchestration: [#215](https://github.com/oimus1976/agent-controller/issues/215) review-remediation loop, [#173](https://github.com/oimus1976/agent-controller/issues/173) verified-head / single-writer, [#178](https://github.com/oimus1976/agent-controller/issues/178) canonical TaskSpec.
- Efficiency / capacity: [#55](https://github.com/oimus1976/agent-controller/issues/55) (umbrella), [#174](https://github.com/oimus1976/agent-controller/issues/174), [#176](https://github.com/oimus1976/agent-controller/issues/176), [#177](https://github.com/oimus1976/agent-controller/issues/177), [#182](https://github.com/oimus1976/agent-controller/issues/182).
- Providers: [#159](https://github.com/oimus1976/agent-controller/issues/159), [#170](https://github.com/oimus1976/agent-controller/issues/170) Jules; [#183](https://github.com/oimus1976/agent-controller/issues/183) Antigravity review-only adapter.
- Policy consumption: [#180](https://github.com/oimus1976/agent-controller/issues/180) ai-dev-starter branch-cleanup policy.

## Where to look

- Semantic history: [`CHANGELOG.md`](CHANGELOG.md).
- Design and runbooks: [`docs/`](docs/), including [`verification-policy.md`](docs/verification-policy.md), [`threat-model.md`](docs/threat-model.md), and [`workstream-isolation.md`](docs/workstream-isolation.md).
- Validation: `python -m unittest discover -s tests` (Python 3.12). CI runs `.github/workflows/tests.yml` on pull requests.
