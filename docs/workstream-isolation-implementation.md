# Issue #120 implementation notes

This Draft implementation reuses existing Agent Controller seams rather than adding a scheduler or orchestration database.

Implemented boundaries:

- immutable `WorkstreamBinding` and deterministic membership validators;
- `multi_watch` can enter lane mode with explicit Controller-owned `workstream_id` on every target;
- provider/watch output cannot override the configured workstream identity;
- `AttentionItem` preserves `workstream_id` and exposes lane-scoped selection;
- global attention ordering is presentation only and does not establish continuation authority;
- `execute_workstream_action` requires an explicit workstream binding and validates the exact PR target before any GitHub re-read or mutation;
- provider operation membership is checked through existing `controller_task_id` without changing `TaskBinding`.

The historical unbound entry points remain for compatibility in this MVP. New concurrent lane-aware orchestration must use the explicit lane-aware paths and must not silently fall back to legacy unbound mutation.

The deterministic incident regression models #116/#117 and #118/#119 in the same repository and proves that the globally higher-priority #119 human action is not selected as the continuation of the #117 lane, and that a #119 mutation attempted with the #117 workstream is blocked before GitHub or mutator calls.

Deferred: persistence, lane scheduling/priority, provider routing, plan approval, remediation messaging, branch update/rebase automation, distributed locking, Ready/merge/release/deploy authority.
