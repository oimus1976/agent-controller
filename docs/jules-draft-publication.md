# Jules ChangeSet -> Controller-owned Draft PR boundary

Issue #131 adds one guarded LEVEL 0–2 publication path from exactly one completed Jules session to a Controller-owned implementation branch and Draft PR.

A provider ChangeSet remains untrusted input. Before any provider/GitHub publication work, `DRAFT_PR_CREATE` must be explicitly allowed by the `TaskBinding` and must not be forbidden. Task/operation/workstream identity is exact, and the destination branch must be explicitly owned by that workstream.

Publication then requires all of the following before the first write: terminal success on the exact provider operation, exactly one complete ChangeSet candidate, a recomputed SHA-256 matching the recorded patch digest, candidate `baseCommitId` equal to `TaskBinding.expected_start_sha`, fresh GitHub equality for the exact `expected_start_ref`, a destination branch in the `controller/` namespace that is absent and non-default, conservative text-patch parsing, and `ObjectiveScope` satisfaction for every source and destination path.

The supported MVP patch surface is intentionally narrow: regular UTF-8 text unified diffs over ordinary `100644` blobs only. Existing source files are checked from the exact base Git tree before their contents are used. Binary patches, executable/other file modes, mode changes, symlink mode, no-newline markers, traversal/absolute paths, malformed headers or hunk counts, duplicate path blocks, truncated Git trees, and unsupported metadata fail closed. Patch contents are data; they are never executed as shell or code.

GitHub publication uses a narrow Git Data composition: build one new tree/commit from the exact base, create the explicit `controller/` implementation branch, then create a Draft PR. The PR base is derived from the exact `TaskBinding.expected_start_ref`; repository default-branch proximity cannot silently retarget it. The path exposes no Ready, merge, auto-merge, release, deploy, provider plan approval, or sendMessage action.

Write responses are not treated as proof. After publication the Controller independently re-reads the branch head and the exact base ref, compares exact-base..head changed paths, re-checks scope, re-reads the PR state/head/base, and requires exactly one open Draft PR for the branch. Base drift after publication, partial publication, an uncertain read, or any mismatched postcondition is reported as `UNCERTAIN` rather than `PASS`.

This slice intentionally blocks when the destination branch or open PR already exists. Idempotent replay support may be added only with an exact publication receipt/identity design; silently reusing, overwriting, or duplicating an existing target is not permitted.

Reuse-first choices for this slice are the existing binding/workstream validators, `RepositoryWriteGuard`, `JulesChangeSetReadClient`, `ObjectiveScope` semantics, and GitHub's native Git Data/Draft pull-request APIs. Custom code is limited to the safety gap around provider patch parsing/application, freshness/effect/scope gates, and objective publication postconditions.

After this slice, limited-production work remains: compose the published Draft PR into existing objective GitHub verification/CI/review evidence, then perform one bounded live Jules E2E smoke and freeze the operator runbook. Ready and merge remain human-final under ADR #90.
