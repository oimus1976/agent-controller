# Jules ChangeSet -> Controller-owned Draft PR boundary

Issue #131 adds one guarded LEVEL 0–2 publication path from exactly one completed Jules session to a Controller-owned implementation branch and Draft PR.

A provider ChangeSet remains untrusted input. Publication requires all of the following before the first write: exact TaskBinding/ProviderOperationRef/workstream membership, terminal success on the exact operation, exactly one complete ChangeSet candidate, candidate base equal to TaskBinding.expected_start_sha, fresh GitHub base equality, explicit non-default destination branch, conservative text-patch parsing, and ObjectiveScope satisfaction for every source and destination path.

The supported MVP patch surface is intentionally narrow: regular UTF-8 text unified diffs only. Binary patches, mode changes, symlink mode, no-newline markers, traversal/absolute paths, malformed headers/hunks, duplicate path blocks, and unsupported metadata fail closed. Patch contents are data; they are never executed as shell or code.

GitHub publication uses a narrow Git Data composition: build a new tree/commit from the exact base, create the explicit implementation branch, then create a Draft PR. The path exposes no Ready, merge, auto-merge, release, deploy, provider plan approval, or sendMessage action.

Write responses are not treated as proof. After publication the Controller independently re-reads the branch head, compares base..head changed paths, re-checks scope, re-reads the PR state/head/base, and requires exactly one open Draft PR for the branch. Any uncertain or mismatched postcondition is reported as UNCERTAIN rather than PASS.

This slice intentionally blocks when the destination branch or open PR already exists. Idempotent replay support may be added only with an exact publication receipt/identity design; silently reusing or overwriting an existing target is not permitted.

After this slice, limited-production work remains: compose the published Draft PR into existing objective GitHub verification/CI/review evidence, then perform one bounded live Jules E2E smoke and freeze the operator runbook. Ready and merge remain human-final under ADR #90.
