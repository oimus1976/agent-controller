# Agent Instructions

This file is the entry point for every worker — Codex, Claude Code, Antigravity, Jules, and chat assistants. It is deliberately short: it tells you what to read and which rules you must never break. Rule text and rationale live in [`docs/governance/`](docs/governance/README.md).

Do not add `CLAUDE.md` or `GEMINI.md`. By default, a project `CLAUDE.md` or `CLAUDE.local.md` stops Claude Code from reading this file, and Antigravity already reads this file itself. If a Claude-specific file ever becomes unavoidable, it may contain only the import `@AGENTS.md`, written relative to its own directory. Do not add provider-only rule files either (`.claude/AGENTS.md`, `.claude/rules/`, `.agents/AGENTS.md`, `.agents/rules/`, `.agent/rules/`): they load alongside this file for one provider only.

## Start here

Before changing tracked state, read in this order:

1. [`PROJECT_STATUS.md`](PROJECT_STATUS.md). It is an index of where authority lives, not a statement of current state.
2. The workstream Issue you are bound to and its latest checkpoint comment. If you cannot name the Issue, stop and ask. Do not pick work because it is recent, adjacent, or in the same repository.
3. [`docs/governance/rules.md`](docs/governance/rules.md), and the ADRs linked there that apply to your task.

Then re-read every mutable fact you will rely on from GitHub or CI: PR state, exact head SHA, CI result, review evidence, and authorization. Chat history, checkpoints, and summaries — including this repository's own status files — are pointers, not proof.

## Non-negotiables

Each rule links to the record that owns it.

- **Evidence authority.** Agent, provider, and chat statements are claims until verified. GitHub refs, exact SHAs, diffs, CI, and canonical review evidence are authoritative ([#1](https://github.com/oimus1976/agent-controller/issues/1), [ADR #12](https://github.com/oimus1976/agent-controller/issues/12)).
- **Human-final.** Ready, merge, and every LEVEL 3 effect are human actions. Prepare and verify them; never perform or infer them ([ADR #90](https://github.com/oimus1976/agent-controller/issues/90)).
- **Independent review.** The implementing worker is not the sole reviewer of its own work. Self-review is L0 and never counts as independent review. Review binds to an exact head, and every remediation needs a fresh-head rereview ([ADR #199](https://github.com/oimus1976/agent-controller/issues/199)).
- **No duplicate implementation.** While a completed Codex task still offers its `View Task → Update branch` handoff, do not reimplement it. Fall back only after that apply is shown to be absent or failed ([#200](https://github.com/oimus1976/agent-controller/issues/200)).
- **Live and owner-machine effects** need a separate explicit human authorization for the exact plan. Consumed authority is never reused ([#216](https://github.com/oimus1976/agent-controller/issues/216), [#195](https://github.com/oimus1976/agent-controller/issues/195)).
- **Scope.** New work gets its own Issue or workstream. Do not widen an active PR. Repository proximity is not task authority ([#120](https://github.com/oimus1976/agent-controller/issues/120)).

## Handoff

At the end of a session, at a stop for a human decision, or when handing work to another worker:

1. Post a checkpoint on the workstream Issue using [`docs/governance/checkpoint-template.md`](docs/governance/checkpoint-template.md).
2. If the set of workstreams, the main line, or a standing policy changed, update [`PROJECT_STATUS.md`](PROJECT_STATUS.md) in the same PR.
3. After a human merge, run the post-merge local closeout in [`docs/governance/post-merge-closeout.md`](docs/governance/post-merge-closeout.md).

## Starting from a chat assistant

Chat surfaces do not load this file automatically. Begin a new chat with:

> Read AGENTS.md in oimus1976/agent-controller before doing anything.
