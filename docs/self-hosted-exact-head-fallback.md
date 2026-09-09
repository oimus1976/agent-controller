# Self-hosted exact-head CI fallback

Related: Issue #187

## Purpose

Provide a bounded zero-paid verification path while GitHub-hosted Actions minutes are unavailable, without relabeling self-hosted or local evidence as GitHub-hosted CI.

The canonical `.github/workflows/tests.yml` remains unchanged. This fallback is a separate, manually dispatched trust domain.

## Evidence classes

- `GITHUB_HOSTED_CI_PASS`: canonical GitHub-hosted workflow evidence.
- `SELF_HOSTED_EXACT_HEAD_PASS`: manually dispatched GitHub Actions execution on a repository-scoped self-hosted runner after exact current PR head validation.
- `LOCAL_EXACT_HEAD_PASS`: operator-run local execution outside GitHub Actions.

No class automatically promotes to another class. Ready / merge remain human-final under ADR #90.

## Initial Windows pilot

The first bounded pilot uses one Windows x64 self-hosted runner and runs:

1. the full deterministic unittest suite;
2. the real Windows junction containment regression.

This gives GitHub-bound exact-head execution evidence on Windows, but does not claim OS-equivalence with the canonical Ubuntu job. A later Linux self-hosted pilot may reproduce the Ubuntu job if needed.

## Runner trust requirements

Before registration, the runner host/account must satisfy all of the following:

- repository-scoped registration for `oimus1976/agent-controller` only;
- dedicated standard-user runner identity;
- no owner/admin browser session, password vault, SSH private key, cloud/provider API key, unrelated repository token, or other valuable credential reachable by the runner account;
- dedicated/disposable machine or VM preferred; persistent runner is disabled/offline outside the pilot window;
- Python 3.12 installed and available to the runner account;
- custom label `agent-controller-ci` in addition to `self-hosted`, `Windows`, and `X64`;
- do not execute fork PRs, arbitrary branch names, issue attachments, or unpublished agent worktrees;
- operator confirms the target is an open same-repository PR and supplies its exact current 40-hex head SHA.

A persistent self-hosted runner executes repository code with the local privileges of the runner account. The workflow gates reduce target-selection risk; they do not make arbitrary repository code safe. Disposable runner state remains the preferred long-term design.

## Workflow safety properties

`.github/workflows/self-hosted-exact-head.yml` is intentionally separate from `tests.yml` and has these properties:

- `workflow_dispatch` only;
- required `pr_number` and `target_sha` inputs;
- runner labels `[self-hosted, Windows, X64, agent-controller-ci]`;
- repository permission `contents: read` only;
- before target checkout, GitHub API preflight proves:
  - input shapes are valid;
  - PR is open;
  - PR head repository is exactly `oimus1976/agent-controller`;
  - PR current head SHA exactly equals `target_sha`;
- target checkout is by immutable SHA with `persist-credentials: false` and `clean: true`;
- HEAD and clean working tree are checked before tests;
- Python major/minor must be exactly 3.12;
- full unittest suite and Windows junction regression must both pass;
- HEAD and clean tree are checked after tests;
- a final GitHub API read requires the PR to still be open, same-repository, and still at the same SHA;
- only after every gate passes does the workflow emit `SELF_HOSTED_EXACT_HEAD_PASS`.

The GitHub token is scoped to the preflight/final verification steps. It is not intentionally exported to target test steps. Checkout does not persist credentials in the repository configuration.

## Pilot operation

1. Keep the runner offline/unregistered until the workflow has been independently reviewed.
2. Register the runner repository-scoped using GitHub's short-lived registration token.
3. Add the custom `agent-controller-ci` label.
4. Confirm the runner account and Python 3.12 runtime.
5. Bring the runner online only for the bounded pilot.
6. From the trusted fallback workflow, manually dispatch with the exact PR number and exact current head SHA.
7. Preserve the GitHub run/job identity and exact SHA as evidence.
8. Take the runner offline after the pilot. For a persistent host, inspect/reset runner state before future use.

## Failure semantics

Any malformed input, GitHub API error, fork/head-repository mismatch, PR state mismatch, head drift, Python version mismatch, test failure, or dirty/head-changed postcondition fails the job. Do not infer PASS from partial steps.

A capacity-blocked GitHub-hosted job remains distinct from self-hosted PASS and from code failure.
