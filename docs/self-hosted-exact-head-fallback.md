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
- dedicated/disposable machine or VM preferred;
- Python 3.12 installed and available to the runner account;
- register for exactly one job with `--ephemeral`;
- suppress the default routable labels with `--no-default-labels`;
- assign one fresh high-entropy custom label `ac-ci-<16 hex>` for that pilot only;
- do not execute fork PRs, arbitrary branch names, issue attachments, or unpublished agent worktrees;
- operator confirms the target is an open same-repository PR and supplies its exact current 40-hex head SHA.

GitHub recommends ephemeral self-hosted runners for autoscaling/use-once scenarios and notes that an ephemeral runner is automatically de-registered after one job. The one-time label reduces the chance that an unrelated queued workflow can claim the runner when it comes online. It is not a substitute for host isolation.

A self-hosted runner still executes repository code with the local privileges of the runner account. Disposable runner state remains the preferred long-term design; after the one job, wipe or discard the pilot workspace/VM where practical.

## Workflow safety properties

`.github/workflows/self-hosted-exact-head.yml` is intentionally separate from `tests.yml` and has these properties:

- `workflow_dispatch` only;
- required `pr_number`, `target_sha`, and `runner_nonce` inputs;
- `runs-on` resolves only to `ac-ci-${runner_nonce}` rather than any GitHub-hosted label or generic `self-hosted` label;
- `runner_nonce` must be exactly 16 hexadecimal characters;
- repository permissions are `contents: read` and `pull-requests: read` only;
- the first step requires the workflow itself to have been dispatched from `refs/heads/main`;
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

## Workflow-ref bootstrap boundary

`workflow_dispatch` is useful only after this workflow is present on trusted `main`. The fallback cannot serve as its own pre-merge CI substitute.

After merge, dispatch this workflow explicitly from `main`. The in-workflow `github.ref` check catches accidental non-main dispatch when the trusted workflow definition is used, but a topic branch can theoretically modify its own copy of a workflow. Therefore operator selection of `main` remains part of the trust boundary; the recommended invocation should explicitly specify `--ref main` rather than relying on a UI default.

## Pilot operation

1. Keep the runner unregistered until this workflow has been independently reviewed and human-merged to `main`.
2. Generate a fresh random 16-hex nonce and derive label `ac-ci-<nonce>`.
3. Register the runner repository-scoped using GitHub's short-lived registration token with `--ephemeral --no-default-labels --labels ac-ci-<nonce>`.
4. Confirm the runner account and Python 3.12 runtime.
5. Dispatch the trusted workflow explicitly from `main`, supplying the exact PR number, exact current head SHA, and the same nonce.
6. Preserve the GitHub run/job identity and exact SHA as evidence.
7. The runner should de-register after the single job. Wipe/discard its workspace or VM before reuse where practical.

## Failure semantics

Any malformed input, GitHub API error, fork/head-repository mismatch, PR state mismatch, head drift, Python version mismatch, test failure, dirty/head-changed postcondition, or final PR drift fails the job. Do not infer PASS from partial steps.

A capacity-blocked GitHub-hosted job remains distinct from self-hosted PASS and from code failure.
