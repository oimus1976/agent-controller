# Jules ChangeSet artifact read boundary

Issue #129 adds a read-only bridge from one exactly bound Jules session to the code patch evidence exposed by the official Jules Activities API.

## Authority boundary

A Jules `ChangeSet.gitPatch` is **provider-reported evidence**, not a GitHub artifact and not Controller verification success.

For a complete patch candidate the Controller records:

- the exact bound Jules provider operation id;
- activity id and full activity resource name;
- optional activity creation time and whether the activity reports `sessionCompleted`;
- Jules source resource name;
- nonempty `unidiffPatch`;
- nonempty provider-reported `baseCommitId`;
- optional `suggestedCommitMessage`;
- observation timestamp;
- SHA-256 of the patch text for stable evidence identity.

No branch, commit, pull request, Ready state, merge, release, or deployment is created by this slice.

## Exact-session rule

The session whose activities are read comes only from the supplied, already-bound `ProviderOperationRef`. Session recency, title, repository proximity, provider prose, or a global queue must never select a replacement session.

Activity resource names are checked against that exact session before a ChangeSet is accepted.

## Source and pagination rules

The task repository is resolved through the existing Jules source resolver. A ChangeSet source must match that resolved source exactly.

Activities pagination is bounded, rejects malformed or whitespace-padded page tokens, detects token cycles, and stops before exceeding the configured page limit.

Non-ChangeSet artifacts are ignored. User/system-originated ChangeSets are not promoted as agent output.

## Incomplete ChangeSet snapshots

The official Jules API examples show agent activities containing schema-valid intermediate `ChangeSet.gitPatch` snapshots where `unidiffPatch` is empty or fields such as `baseCommitId` are omitted while the session is progressing. Those are not publication candidates, but their existence is not by itself a malformed session.

Accordingly:

- absent/empty patch or base commit -> ignore that incomplete snapshot;
- wrong field type, malformed `changeSet`/`gitPatch`, cross-session activity identity, or source mismatch -> fail closed;
- all complete candidates are returned; this slice does **not** guess which candidate is final or select one by recency.

The later publication slice must define an explicit Controller-owned candidate-selection/finality rule before any write.

## What is deliberately not verified yet

`baseCommitId` remains a provider claim in this slice. The next publication slice must independently re-read GitHub and require the selected patch base to equal the Controller-owned `TaskBinding.expected_start_sha` before any patch application or repository write.

Likewise, a patch hash only identifies the bytes that were observed. It does not prove that the patch is safe, in scope, applicable, final, or present in GitHub.

## Next boundary

The next slice may publish one explicitly selected, exact validated ChangeSet to a Controller-owned implementation branch and create a Draft PR. That write path must have exact-base, scope, workstream, candidate-finality, and repository-write guards and must not gain Ready/merge authority.
