# Self-hosted exact-head CI fallback

Related: Issue #187

## Purpose

Provide a bounded zero-paid verification path while GitHub-hosted Actions minutes are unavailable, without relabeling self-hosted or local evidence as GitHub-hosted CI.

The canonical `.github/workflows/tests.yml` remains unchanged. This fallback is a separate, manually dispatched trust domain.

## Evidence classes

- `GITHUB_HOSTED_CI_PASS`: canonical GitHub-hosted workflow evidence.
- `SELF_HOSTED_EXACT_HEAD_PASS`: manually dispatched GitHub Actions execution on the bounded self-hosted fallback after exact current PR head validation.
- `LOCAL_EXACT_HEAD_PASS`: operator-run local execution outside GitHub Actions.

No class automatically promotes to another class. Ready / merge remain human-final under ADR #90.

## Host-specific decision

The available Agent Controller host is a dedicated HP ProDesk 400 G4 DM with Intel Core i5-8500T (6C/6T), approximately 16 GB RAM, 256 GB SSD, and approximately 198 GB free at characterization time.

The first Windows fallback remains bare metal on this dedicated host. A resident Windows guest VM is not required for the first pilot. This is a resource/complexity trade-off, not a claim that Windows accounts are a sandbox.

Codex review of PR #189 identified two stronger boundaries that the initial account-only design did not meet:

1. target-controlled tests must not execute in the same Windows identity/profile that performs trusted post-test verification and PASS emission;
2. deleting only a reused user profile does not eliminate persistence outside that profile.

The Windows design therefore uses a **persistent trusted control identity plus a disposable target identity/SID for each pilot**.

## Windows identity model

- `c-admin`: host administration and target-account provisioning/cleanup only; never executes PR target code.
- `agy-agent`: existing Antigravity characterization account; outside the CI trust domain.
- `ac-runner`: persistent local standard-user **control** identity. The GitHub Actions runner and all trusted pre/post gates execute here. PR target Python does not.
- `act-<16hex>`: one disposable local standard-user **target** account derived from the one-time runner nonce. It exists for one pilot only and is deleted after the job. A later pilot receives a new account name/SID.

`ac-runner` and `act-<nonce>` must have distinct local SIDs and neither may be a member of local Administrators. The workflow compares the running token SID to the SID resolved for local `ac-runner`; a same-named domain account is not accepted. The workflow also inspects explicit local Administrators membership instead of relying only on an elevated-token check.

## Control/target separation

The runner itself remains under `ac-runner`. The trusted workflow:

1. validates `main`, Windows/X64, local control SID, target SID, local Administrators membership, clean target state, one-time credential ACL, open same-repository PR, and exact current PR head, then as the final trusted pre-check before checkout rejects any existing reparse point in `GITHUB_WORKSPACE` or its lexical ancestors;
2. checks out the exact immutable target SHA under `ac-runner` with checkout credentials not persisted;
3. validates HEAD/cleanliness using fixed machine-wide Git and Python paths;
4. protects checkout ACLs from inheritance, preserves full control for `ac-runner`, SYSTEM, and local Administrators, explicitly denies the disposable target SID write-class rights (including rights obtained through group membership), and grants that SID read/execute-only access;
5. launches the full unittest suite and Windows junction regression through `Start-Process -Credential ... -UseNewEnvironment -LoadUserProfile` under `act-<nonce>`;
6. uses `-NoProfile` for both trusted and target PowerShell execution;
7. verifies the target process did not inherit `GITHUB_*` or `GH_TOKEN` environment state and cannot open the runner command files (`GITHUB_STEP_SUMMARY`, `GITHUB_ENV`, `GITHUB_PATH`) or write to the `ac-runner` profile;
8. removes the one-time target credential file **before** PR target code starts;
9. after tests, under `ac-runner`, repeatedly identifies and terminates target-SID processes within a fixed deadline, requires a fresh query to prove zero remain, rejects scheduled-task persistence, rejects premature PASS-marker emission, recursively removes the target grant and denies all residual target checkout access, and rechecks exact HEAD/cleanliness;
10. performs a fresh GitHub API read of the PR head;
11. only then writes `SELF_HOSTED_EXACT_HEAD_PASS`.

This keeps PR-controlled test execution out of the profile, command files, credentials, and environment used by the trusted post-test gates. The target still executes arbitrary same-repository PR code with the rights of its own standard-user SID; the host-kernel residual risk remains accepted only for this bounded manual pilot.

## Trusted machine-wide runtime

The first pilot requires these trusted read/execute runtime paths outside either user profile:

- `C:\Program Files\Python312\python.exe` and Python 3.12.x;
- `C:\Program Files\Git\cmd\git.exe`.

The target account receives read/execute-only access to the repository checkout. Inheritance is disabled throughout the checkout, trusted SYSTEM/Administrators/`ac-runner` access is preserved, and an explicit target-SID deny for write-class rights prevents broad group grants from restoring write access. Before any target test command, real target-credential file-open probes against a workspace file and `.git/config` must both fail specifically with access denied. Python runs with `-B` so target execution does not require writing `__pycache__` into the checkout.

Immediately before `actions/checkout(clean: true)`, trusted preflight walks the lexical `GITHUB_WORKSPACE` path upward and rejects every existing reparse-point component so checkout cannot first mutate a redirected destination. After checkout, hardening inventories every object, including hidden `.git` children, again rejects reparse points (including workspace ancestors), and writes a complete explicit protected DACL to each child before its parent. Only SYSTEM, local Administrators, or `ac-runner` may own checkout objects. Every DACL grants those three SIDs FullControl, grants the target ReadAndExecute, and denies target Write, Delete, DeleteSubdirectoriesAndFiles, ChangePermissions, and TakeOwnership. Each write is read back, then every object is checked again after all parent changes. Cleanup authority therefore exists before target launch and does not depend on successful postconditions. Native command exit codes alone are not ACL evidence.

## One-time target credential boundary

`c-admin` provisions the fresh `act-<nonce>` standard-user account before runner registration and writes its random one-time local password to:

`C:\ProgramData\AgentController\ci-secrets\<nonce>.txt`

The credential is low-value and local to the disposable target identity, but it is still treated as secret material:

- ACL inheritance is disabled;
- SYSTEM or local Administrators must own it; those are the only allowed SIDs besides the exact `ac-runner` SID;
- provision the exact `ac-runner` SID with **Read, Delete, Synchronize** on this file only. Read alone is insufficient. No Write, replacement, ChangePermissions, or TakeOwnership authority is allowed; do not grant directory write/delete-child rights to compensate for missing file Delete;
- Everyone, Authenticated Users, BUILTIN Users, the target SID, and all other SIDs must not be granted access;
- preflight requires the complete Read and Delete masks and rejects excess control rights, inherited/propagating ACEs, and deny ACEs rather than inferring effective access from partial Read bits;
- `ac-runner` reads the password into a `PSCredential` and deletes the file with plain `Remove-Item` before target code starts;
- if the file remains or its ACL cannot be proven, the job fails closed.

Issue #201 real-Windows characterization reproduced the pilot authority boundary with a fresh standard-user control SID: the parent directory had no delete-child authority and the credential file granted only Read, Delete, and Synchronize. Under that exact boundary, `Remove-Item -Force` failed with access denied while plain `Remove-Item` and `[IO.File]::Delete()` both removed the file. Protected-sibling delete/write/replace, parent-file creation, and target-SID read probes all remained blocked. The workflow therefore intentionally uses plain `Remove-Item`; do not reintroduce `-Force` or broaden the shared credential directory's write/delete-child authority to compensate.

No GitHub PAT, SSH key, provider credential, browser session, Antigravity/Codex/Jules state, or owner credential is placed in either target state or the one-time credential file.

## Disposable SID / cross-run reset contract

A profile reset is no longer the claimed reuse boundary. The **target SID itself is disposable**.

Before each pilot:

1. no previous `act-*` account may remain;
2. create exactly one fresh `act-<nonce>` local standard user with a new random password;
3. confirm no Windows profile exists yet for that SID;
4. confirm that SID is not in local Administrators and owns no scheduled task;
5. create the protected one-time credential file;
6. only then register the `ac-runner` GitHub runner and dispatch the trusted workflow from `main`.

After each pilot, from `c-admin`:

1. confirm the one-job GitHub runner deregistered;
2. terminate/log off the disposable target identity if necessary;
3. remove any scheduled task or other explicitly identified state owned by the target SID;
4. delete the `act-<nonce>` local account and its Windows profile;
5. remove the per-pilot result directory and any remaining credential artifact;
6. verify that no `act-*` account/profile for the completed pilot remains;
7. if cleanup is incomplete or uncertain, block the next untrusted self-hosted pilot.

Recreating the same username is not used as a cleanup strategy. A later pilot uses a fresh nonce and therefore a fresh local account name/SID. Stale persistence bound to an old SID cannot be accepted as clean evidence and must be removed during administrator cleanup.

## Runner routing and repository boundary

The GitHub runner remains:

- repository-scoped to `oimus1976/agent-controller`;
- registered for exactly one job with `--ephemeral`;
- registered with `--no-default-labels`;
- assigned one fresh high-entropy `ac-ci-<16hex>` label;
- selected only by `runs-on: ac-ci-${runner_nonce}`;
- dispatched manually from the trusted `main` workflow definition;
- limited to open same-repository PRs and an operator-supplied exact current 40-hex SHA.

`--ephemeral` limits GitHub job reuse; it does not reset Windows state. The disposable target SID and administrator cleanup provide the cross-run target boundary.

## Workflow safety properties

`.github/workflows/self-hosted-exact-head.yml` intentionally remains separate from canonical `tests.yml` and requires:

- `workflow_dispatch` only;
- `contents: read` and `pull-requests: read` permissions only;
- pinned `actions/checkout` by full commit SHA;
- `persist-credentials: false` and `clean: true`;
- all trusted PowerShell steps use `-NoProfile`;
- exact local `ac-runner` SID and explicit non-admin membership checks;
- exactly one fresh `act-<nonce>` account, no existing profile, and no pre-existing scheduled task for its SID;
- `GITHUB_WORKSPACE` and every existing lexical ancestor are rejected if any is a reparse point before `actions/checkout(clean: true)` can mutate the workspace;
- target test process executes with alternate credentials and `-UseNewEnvironment`;
- target environment cannot inherit GitHub command/token variables;
- target cannot write GitHub command files or the control profile;
- target checkout access is read/execute-only and is revoked after tests;
- target-credential write probes against a workspace file and `.git/config` both prove access denied before tests;
- full unittest suite and Windows junction regression both pass;
- fresh target-SID process queries prove quiescence before repository, API, and PASS-capable postconditions;
- target-created scheduled-task persistence blocks PASS;
- exact HEAD and clean tree are checked before and after target execution;
- final PR state/repository/head are freshly revalidated;
- PASS evidence is emitted only by the trusted control identity after every preceding gate passes.

Regression tests also reject unnamed workflow steps and bind each expected step name to its security-critical body predicates. Merely preserving marker strings is not sufficient.

## Bootstrap boundary

The fallback cannot validate its own new workflow before that workflow exists on trusted `main`. PR #189 therefore still needs exact-head local regression, independent/adversarial review, and human Ready/merge before any runner is registered.

After merge, dispatch explicitly from `main`; do not rely on a UI default branch selection.

## Linux coverage

A Windows self-hosted PASS does not replace canonical Ubuntu/Python 3.12 evidence. If hosted capacity remains unavailable long enough to justify Linux fallback evidence, add a separate Ubuntu Hyper-V VM on the same mini PC:

- 2 vCPU;
- 3 GB RAM initially, up to 4 GB if required;
- 30-40 GB dynamically expanding disk;
- one-job ephemeral runner inside the VM;
- powered off when unused;
- known-clean checkpoint/recreate before later untrusted execution where practical;
- no concurrent Windows/Linux self-hosted pilot jobs on this 16 GB host.

WSL2 may remain useful for development but is not the preferred evidence path when approximating canonical Ubuntu runner semantics.

## Failure semantics

Malformed inputs, non-main dispatch, wrong runner OS/arch, control/target SID mismatch, direct/local Administrators membership, stale target account/profile/task state, unsafe credential ACL, GitHub API uncertainty, fork/head mismatch, head drift, trusted-runtime mismatch, writable checkout ACLs, target command-file write access, inherited GitHub environment, target test failure, unquiesced target-SID processes, target-created task persistence, dirty/head-changed postcondition, premature PASS marker, final PR drift, or uncertain cross-run cleanup all fail closed.

A capacity-blocked GitHub-hosted job remains distinct from self-hosted PASS and from code failure.

Issue #197 repairs credential delete authority and child ACL cleanup authority. A fresh nonce/SID/ephemeral-runner pilot is still required before reuse or `SELF_HOSTED_EXACT_HEAD_PASS`. It does not fix the separate #196 failure-path revocation concern: the trusted postcondition step remains success-only, and administrator cleanup is still required after failed execution.

## Human gate and escalation

The bare-metal choice retains more host risk than a disposable Windows VM. Human acceptance is limited to the dedicated mini PC, manually selected same-repository PR heads, no valuable runner/target credentials, disposable target SIDs, and human-final Ready/merge.

If the project later executes fork/other-repository code, automated dispatch, secrets-bearing target jobs, or materially higher-risk workloads, the bare-metal exception must be revisited and a disposable Windows VM/image should become the default.
