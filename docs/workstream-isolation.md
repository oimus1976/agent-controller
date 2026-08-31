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
- an active workstream set is validated before lane-aware concurrent work: duplicate workstream IDs, overlapping task/Issue/PR/branch ownership, and dependencies on unknown lanes fail closed;
- `run_workstream_attention_watch` validates the complete binding set and every configured repo/PR-to-lane membership before the first watcher call, then reuses existing `multi_watch`;
- `AttentionItem` carries lane identity and lane-scoped selection must be used for continuation decisions;
- global attention ordering remains the existing presentation order and grants no continuation authority;
- the lane-aware `ENSURE_DRAFT` execution boundary checks exact workstream PR membership before any GitHub re-read or mutation;
- `reconcile_active_workstream_pr_once` validates the complete active binding set and selects the named lane before entering the single-lane reconciler; wrong/overlapping lane ownership is rejected before legacy reconciliation begins.

## Compatibility boundary

Historical single-target/unbound observation, reconciliation, and `execute_action` entry points remain for compatibility in this MVP. They do not gain workstream authority merely because the new contract exists.

New concurrent/lane-aware orchestration must:

1. validate the complete active binding set before observation or mutation;
2. use `run_workstream_attention_watch` so configured `workstream_id` labels are checked against explicit PR ownership before observation;
3. select follow-up attention by workstream, not by the first/highest-priority item in the global queue;
4. use `reconcile_active_workstream_pr_once` for mutation-capable reconciliation in a concurrent context;
5. use the explicit lane-aware execution boundary when invoking execution directly from an already validated single-lane context;
6. never fall back silently to an unbound legacy mutation when a lane binding is missing, conflicting, or mismatched.

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
