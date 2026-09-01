# Published Controller Draft PR -> existing GitHub inspection boundary

Issue #133 adds only a thin composition layer after successful Draft publication.

The publication result is not treated as sufficient evidence by itself. Before inspection, the Controller validates the exact task/workstream/branch binding and independently re-reads the exact PR number. The PR must still be open, Draft, unmerged, in the exact repository, on the exact Controller-owned publication branch/head, and targeted at the branch derived from `TaskBinding.expected_start_ref`.

The composition then calls the existing `inspector.inspect_pr()` path. Scope evaluation, exact-head pull-request Actions status, Codex review evidence, unresolved review threads, and the resulting classification remain owned by the existing inspector; this slice does not duplicate or reinterpret those rules.

After inspection, the Controller checks that inspection evidence still reports the exact published head/base/open-Draft state and re-reads the PR once more. Drift or malformed/uncertain evidence never becomes PASS.

A PASS from this composition means only that the exact published Draft PR was safely connected to the existing inspection evidence. The returned inspector classification may still be `NEEDS_REVIEW`, `REVIEW_READY`, or another existing classification. This composition never marks Ready, merges, auto-merges, releases, deploys, approves a provider plan, or sends provider messages.

After this slice, the remaining limited-production gate is one bounded live Jules E2E smoke through dispatch, human plan gate, completion, ChangeSet read, guarded Draft publication, and this GitHub inspection path, followed by freezing the operator runbook. Human Ready/merge remain final under ADR #90.
