# Live Jules E2E smoke runbook

This runbook is the operator procedure for Issue #139. It proves the real Jules/GitHub composition once before limited practical deployment.

## Preconditions

Use a trusted local checkout of `oimus1976/agent-controller`. Before running the smoke, switch that checkout to `main`, fast-forward it to the accepted GitHub `main`, and leave the working tree clean. The runner independently re-reads and freezes GitHub `main`, then refuses live dispatch unless the local repository root, current branch, local HEAD, and clean-tree state match that accepted main exactly.

Required environment variables:

- `JULES_API_KEY` — official Jules API key;
- `GITHUB_TOKEN` — token with the repository read/write permissions needed by the existing guarded Draft-PR publication backend.

The smoke target is fixed in code:

- repository: `oimus1976/agent-controller`;
- base: `main`;
- only allowed live change: `docs/live-jules-e2e-smoke-result.md`;
- publication branch namespace: `controller/live-jules-e2e-smoke-*`;
- Jules uses `requirePlanApproval=true` and `AUTOMATION_MODE_UNSPECIFIED`.

If the smoke document already exists, the runner blocks before session creation. Do not delete it merely to repeat the smoke.

## Start exactly once

On the owner machine, from the repository root after `git switch main` and `git pull --ff-only`:

```powershell
python .\scripts\run_jules_e2e_smoke.py
```

The one-shot evidence marker is the fixed file `.jules_e2e_smoke_state.json` in the repository root. There is no command-line override for its location. If that file already exists, the runner refuses to dispatch another live session. Inspect the existing state, Jules session, and GitHub state instead of deleting the marker and retrying blindly.

Before dispatch the runner:

1. validates the Jules credential without printing it;
2. performs GitHub preflight reads and freezes the exact current `main` SHA;
3. verifies the dedicated smoke document does not already exist;
4. requires the local command to be running from the repository root on clean `main` at exactly that frozen GitHub SHA;
5. constructs one TaskBinding and one WorkstreamBinding;
6. creates the fixed one-shot local state marker;
7. only then may create one Jules session.

## Human Jules plan gate

The runner follows the exact returned session until it reaches the provider-neutral human plan gate. Before asking for operator input, it writes the bound Jules session ID and provider URL (when available) into the fixed state file, so an interruption at the gate still leaves a recoverable exact-session identity.

It then prints `HUMAN PLAN ACTION REQUIRED` plus that same bound Jules session identity/URL.

Open that exact session in Jules UI. Inspect the plan. The expected plan is limited to creating `docs/live-jules-e2e-smoke-result.md` and changing nothing else.

Approve the plan in Jules UI only if it has that narrow scope. Reject or leave it unapproved if the plan proposes any other file, code, workflow, configuration, branch, or PR action.

After acting in Jules UI, return to the terminal and press Enter.

**Enter is not approval.** It is only a pacing signal. Agent Controller then calls `resume_plan_gate_flow()` with the exact frozen checkpoint and re-reads the same provider operation. There is no `approved=True`, provider plan-approval API call, replacement session, or redispatch path.

If Jules still reports a plan gate, the runner stops `BLOCKED`; it does not loop on human action or create another session.

## Provider completion and ChangeSet publication

After the same Jules session reaches terminal success, the runner uses the existing ChangeSet reader and publication path. Publication proceeds only when all existing fail-closed guards pass, including:

- exact task/operation/workstream binding;
- exactly one complete final ChangeSet candidate;
- ChangeSet comes from the exact session and a `sessionCompleted` activity;
- provider-reported base commit equals the frozen starting SHA;
- fresh GitHub base still equals that SHA;
- patch digest is recomputed;
- patch parses as the supported text-only unified diff;
- every changed path is within the dedicated smoke document scope;
- destination is a fresh Controller-owned non-default branch;
- the created PR is Draft and exact branch/base/head postconditions re-read cleanly.

Jules itself must not create a branch or PR because `AUTOMATION_MODE_UNSPECIFIED` is unchanged.

A partial GitHub write or uncertain external failure never becomes PASS. Do not rerun the smoke automatically after such a result; inspect the exact branch/PR/provider state first.

## Live GitHub inspection

After publication, the runner immediately calls the existing `inspect_published_draft_pr_live()` composition. The first inspection may legitimately show CI as pending or review not yet present. A successful read/identity/scope check is distinct from later `REVIEW_READY` status.

The normal Controller/GitHub flow then handles the published Draft PR:

1. wait for deterministic Actions on the exact published head;
2. use the existing exact-head Codex review-request path when its policy allows and CI is PASS;
3. remediate only through the existing bounded remediation path if needed;
4. when exact-head CI/review evidence is clean, surface the human Ready gate;
5. Ready and merge remain human actions under ADR #90.

## Evidence to record on Issue #139

Record no secrets. Record only:

- frozen starting SHA;
- Jules session ID and provider URL if non-sensitive;
- TaskBinding/workstream IDs;
- exact ChangeSet activity ID and patch SHA-256;
- Controller publication branch and commit SHA;
- Draft PR number;
- first live inspection status/classification/CI/scope status;
- confirmation that Jules created no PR/branch and Agent Controller performed no Ready/merge/plan-approval action;
- later exact-head CI and Codex review result.

The runner's local state JSON contains the machine-readable subset and intentionally remains after the run.

## Fail-closed outcomes

Stop and investigate rather than retry when any of these occur: local checkout mismatch/dirty state, plan gate not reached, plan still waiting after operator action, terminal failure, provider read timeout/uncertainty, ChangeSet zero/multiple candidates, base drift, scope violation, patch mismatch, destination collision, partial publication, PR postcondition mismatch, or inspection uncertainty.

A leftover `controller/...` branch or Draft PR after an uncertain publication is evidence to inspect, not disposable residue. Likewise, the fixed state marker is evidence; do not delete or relocate it merely to obtain another dispatch.

## Closeout and cleanup

If the smoke Draft PR is eventually merged, use the existing post-merge local closeout verifier for any local checkout that participated. The post-merge cleanup-candidate contract may surface the remote topic branch or local worktree as `SAFE_TO_CONSIDER`; it never deletes either automatically.

## Limited-production declaration

The Jules path is eligible for limited practical deployment only after this one live smoke has demonstrated:

- one exact session from frozen GitHub start state;
- human-only provider plan decision;
- same-operation resume;
- terminal success with one exact completed ChangeSet;
- guarded Controller-owned Draft PR publication;
- objective GitHub scope/identity inspection;
- exact-head deterministic CI and clean review evidence through the normal flow;
- no automated Ready/merge/release/deploy or Jules plan approval;
- no unresolved provider/API semantic mismatch.
