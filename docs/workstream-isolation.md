# Workstream isolation — MVP boundary

Issue #120 introduces a small provider-neutral workstream identity layer after a real same-repository coordination failure between the independent #116/#117 Jules-integration line and the #118/#119 post-merge-closeout rollout line.

## Invariant

Repository proximity is not task authority.

The following facts do not establish that an artifact is the continuation of the current workstream:

- same repository;
- adjacent Issue or PR number;
- most recently updated/open PR;
- global attention-queue priority;
- matching provider;
- provider prose;
- branch-name similarity;
- temporal proximity.

A lane-aware action must have a Controller-owned `WorkstreamBinding` that explicitly binds its task and target artifacts, or an explicit relationship to another workstream. Unknown/unbound targets fail closed instead of being guessed into the active lane.

## Reused mechanisms

This slice does not replace existing provider identity binding. `TaskBinding -> ProviderOperationRef -> observation/artifact` remains the vertical provider/evidence chain.

Workstream identity is orthogonal:

- `WorkstreamBinding` binds Controller tasks, GitHub Issues, PRs, and branch refs to one independent line of work;
- provider operation membership is derived through the existing `controller_task_id`;
- `multi_watch` may observe multiple lanes concurrently while preserving Controller-owned `workstream_id`;
- `AttentionItem` carries lane identity and lane-scoped selection must be used for continuation decisions;
- global attention ordering remains the existing presentation order and grants no continuation authority;
- the lane-aware `ENSURE_DRAFT` execution boundary checks exact workstream PR membership before any GitHub re-read or mutation;
- the lane-aware reconciler checks exact workstream PR ownership before entering the historical watcher/planner/executor composition, so a wrong-lane target is rejected before any legacy reconciliation work begins.

## Compatibility boundary

Historical single-target/unbound observation, reconciliation, and `execute_action` entry points remain for compatibility in this MVP. They do not gain workstream authority merely because the new contract exists.

New concurrent/lane-aware orchestration must:

1. use explicit workstream IDs for all targets in a multi-target lane-aware watch;
2. select follow-up attention by workstream, not by the first/highest-priority item in the global queue;
3. use `reconcile_workstream_pr_once` for mutation-capable PR reconciliation so target ownership is proven before the legacy composition is entered;
4. use the explicit lane-aware execution boundary when invoking execution directly;
5. never fall back silently to an unbound legacy mutation when a lane binding is missing or mismatched.

A later migration may make workstream binding mandatory for all mutation-capable Controller paths after routine use proves the contract and compatibility impact.

## Repository-wide events

A `main` change can invalidate evidence in another lane and require that lane to re-observe/review. It does not transfer ownership of the other lane or make that lane the current workstream's next task.

## Explicitly deferred

This MVP does not add:

- scheduling or lane priority policy;
- persistent workstream registry/database;
- provider routing;
- Jules plan approval or `sendMessage` remediation;
- branch update/rebase automation;
- distributed locking across Controller instances;
- project-management UI;
- Ready/merge/release/deploy authority.

Ready and merge remain human-final under ADR #90.
