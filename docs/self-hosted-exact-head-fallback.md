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

## Host-specific decision for the first pilot

The available Agent Controller host is already a dedicated mini PC, not a general-purpose personal workstation:

- HP ProDesk 400 G4 DM;
- Intel Core i5-8500T, 6 cores / 6 logical processors;
- approximately 16 GB RAM;
- 256 GB SSD with approximately 198 GB free at characterization time;
- Windows reports that a hypervisor is already detected.

Given this hardware, the first bounded design does **not** require a Windows guest VM. Running the Windows CI path directly on this dedicated host under a CI-only standard user gives a better resource/complexity trade-off than keeping an additional Windows VM resident on a 16 GB machine.

This is a host-specific risk acceptance, not a claim that a Windows account boundary is equivalent to a disposable VM. The standard-user boundary reduces blast radius; it is not a sandbox.

## Windows first-pilot execution model

Use the dedicated Agent Controller mini PC as the Windows CI host, with these role boundaries:

- `c-admin`: host administration/setup only; never the runner identity;
- `agy-agent`: existing Antigravity characterization account; never the CI runner identity;
- `ac-runner`: dedicated standard-user account for self-hosted CI only.

The `ac-runner` profile must not contain owner/admin browser sessions, password-vault state, SSH private keys, provider/cloud API keys, Antigravity/Codex/Jules state, unrelated repository credentials, or other valuable material.

The Windows runner is repository-scoped, one-job ephemeral, and routed only through a fresh one-time label. After each pilot job, the runner workspace/profile state is treated as potentially contaminated until cleanup/recreation is completed. `--ephemeral` de-registers the runner after one job; it does not reset the host filesystem.

## Linux coverage decision

The canonical hosted workflow also has an Ubuntu/Python 3.12 full-suite job. A Windows PASS must not be promoted to Ubuntu-equivalent evidence.

If GitHub-hosted capacity remains unavailable long enough to justify Linux fallback coverage, add a separate Linux execution environment on the same mini PC rather than a second Windows VM.

Preferred Linux shape:

- Ubuntu Hyper-V VM rather than WSL2 when the goal is to approximate the canonical Ubuntu runner semantics;
- 2 vCPU;
- 3 GB RAM initially, with 4 GB as the upper pilot target if tests require it;
- 30-40 GB dynamically expanding virtual disk;
- no unrelated credentials or shared host secrets;
- one-job ephemeral GitHub runner registration inside the VM;
- VM powered off when not needed;
- if practical, revert to a known-clean checkpoint or recreate the VM before later untrusted target execution.

These limits preserve host headroom on a 16 GB machine while being ample for the current Python unittest workload. Do not run the Windows and Linux self-hosted CI jobs concurrently on this host during the first pilot.

## Runner trust requirements

Before registration, the Windows runner host/account must satisfy all of the following:

- repository-scoped registration for `oimus1976/agent-controller` only;
- dedicated standard-user runner identity (`ac-runner` for the first pilot);
- no valuable credentials reachable by the runner account;
- Python 3.12 installed and available to the runner account;
- register for exactly one job with `--ephemeral`;
- suppress default routable labels with `--no-default-labels`;
- assign one fresh high-entropy custom label `ac-ci-<16 hex>` for that pilot only;
- do not execute fork PRs, arbitrary branch names, issue attachments, or unpublished agent worktrees;
- operator confirms the target is an open same-repository PR and supplies its exact current 40-hex head SHA;
- runner workspace is not reused blindly after a job; cleanup/recreation is required before subsequent untrusted execution.

The one-time label reduces the chance that an unrelated queued workflow can claim the runner when it comes online. It is not a substitute for host isolation.

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
2. Create/verify the dedicated `ac-runner` standard-user account on the Agent Controller mini PC.
3. Install only the runtime prerequisites needed by the runner account (Git, Python 3.12, Actions runner files).
4. Generate a fresh random 16-hex nonce and derive label `ac-ci-<nonce>`.
5. Register the runner repository-scoped using GitHub's short-lived registration token with `--ephemeral --no-default-labels --labels ac-ci-<nonce>`.
6. Dispatch the trusted workflow explicitly from `main`, supplying the exact PR number, exact current head SHA, and the same nonce.
7. Preserve the GitHub run/job identity and exact SHA as evidence.
8. After the one job, confirm de-registration, remove/reset runner workspace state, and treat the account as contaminated until cleanup is complete.
9. Add Linux VM fallback only if hosted Ubuntu capacity remains unavailable and Ubuntu-equivalent evidence becomes necessary.

## Failure semantics

Any malformed input, GitHub API error, fork/head-repository mismatch, PR state mismatch, head drift, Python version mismatch, test failure, dirty/head-changed postcondition, or final PR drift fails the job. Do not infer PASS from partial steps.

A capacity-blocked GitHub-hosted job remains distinct from self-hosted PASS and from code failure.

## Residual risk acceptance

The first Windows pilot intentionally accepts more residual host-persistence risk than a disposable Windows VM in exchange for substantially lower resource and operational cost on the available 16 GB dedicated host. This acceptance is bounded by:

- dedicated physical host;
- dedicated standard-user runner account;
- no valuable credentials;
- manual same-repository exact-head dispatch only;
- one-job ephemeral registration;
- one-time routing label;
- explicit post-job cleanup;
- human-final Ready/merge boundary.

If the project later begins executing less-trusted repositories, fork code, automated dispatches, secrets-bearing jobs, or materially higher-risk workloads, this bare-metal exception must be revisited and a disposable Windows VM/image should become the default.