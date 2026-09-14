# Public repository readiness

Issue: #196

Status: **BLOCKED — publication retirement change requires validation and merge**

This document is the repository-local publication contract for changing `oimus1976/agent-controller` from private to public. It records completed audit evidence, remaining blockers, and the human-final publication sequence. It does not itself authorize a visibility change.

## Bound repository state

The current public-readiness branch was created from `main` at:

`98d4bb9d9c8396c89c3be7b235a04dd4348e3a03`

The completed history/surface audit below is bound to that baseline and the then-current GitHub repository surfaces. Re-run freshness checks if `main`, publication-reachable refs, retained artifacts, or Actions history materially changes before the visibility gate. GitHub remains the source of truth for repository state.

## Publication invariants

Public publication is allowed only after all required checks are satisfied and the human explicitly authorizes the visibility change.

Required invariants:

1. no known secret, credential, private key, or sensitive unpublished data is exposed by current tree, publication-reachable history, GitHub metadata, retained Actions logs/artifacts, Releases, or other repository surfaces;
2. third-party redistribution and repository licensing are explicit;
3. public GitHub Actions do not expose a trusted self-hosted runner to untrusted public/fork code;
4. normal hosted CI uses least privilege and does not persist checkout credentials unnecessarily;
5. `main` is protected immediately after publication using GitHub-side rules available to the public repository;
6. provider output, CI, review evidence, and human-final authority remain separate;
7. post-public verification proves the expected hosted workflows actually run on GitHub-hosted runners.

## Human publication decisions already recorded

On 2026-09-13 the human explicitly accepted publication of:

- already-recorded historical commit email metadata;
- already-recorded non-secret infrastructure diagnostic metadata such as host identifiers, local SIDs/account identifiers, runner identifiers, nonces, and local paths.

These accepted items do not require history rewrite, Issue/PR scrubbing, Actions-run deletion, or destructive cleanup solely for their removal.

This acceptance does **not** extend to secrets, credentials, private keys, or unrelated personal data if discovered.

## Forward evidence anonymization rule

New durable/public-facing evidence should avoid unnecessary real infrastructure identifiers.

Prefer:

- `<HOST>` for a machine name;
- `<CONTROL_SID>` and `<TARGET_SID>` for local identity values;
- `<RUNNER>` for a runner name;
- `<NONCE>` when the exact nonce is not material;
- `<EVIDENCE_ROOT>`, `<WORKSPACE>`, and `<CREDENTIAL_ROOT>` for local machine paths.

Keep repository-verification facts concrete when they are material to auditability, including exact commit SHA, PR/Issue/run IDs, workflow name, test result, and failure boundary.

If an exact machine-specific value is required to reproduce a security-sensitive failure, prefer retaining it in local/private operator evidence while publishing only the minimum normalized fact necessary.

## Completed audit evidence

### Current tree screening — COMPLETE

Bounded current-tree screening found no tracked `.env`, `.pem`, `.pfx`, or `.key` path and no obvious GitHub token/private-key marker in default-branch code search.

### Full publication-reachable history scan — COMPLETE

Authenticated mirror verification against bound `main` `98d4bb9d9c8396c89c3be7b235a04dd4348e3a03` completed with:

- mirror refresh exit: `0`;
- `git fsck --full --strict` exit: `0`;
- refs inventoried: `157`;
- PR refs inventoried: `76`;
- commits inventoried: `707`;
- merge commits inventoried: `6`;
- scanner: Gitleaks `8.30.1`;
- findings: `5`, all rule `generic-api-key`.

All five findings were individually reviewed and classified `FALSE_POSITIVE_PUBLIC_KEY`. They are Ed25519 **public verification fixture keys** used by the signed-approval PoC path; the associated implementation and tests explicitly use public-key verification and do not store the fixture private signing keys.

Final secret disposition for the bound history:

- unresolved secret findings: `0`;
- history rewrite required: **no**.

### Author and committer identity inventory — COMPLETE

All `707` publication-reachable commits were covered on both author and committer sides. The observed identity groups were limited to the expected repository owner identity, GitHub platform identity, and Jules bot identity.

The historical owner Gmail identity is covered by the explicit human publication decision above. No unexpected third-party identity was found.

### Historical filename/path/blob audit — COMPLETE

Historical path inventory found:

- unique historical paths: `245`;
- secret-like paths: `0`;
- machine/infrastructure-identifier paths: `0`;
- binary/archive/database-style paths: `0`.

The largest historical blob was under 50 KB. The largest mapped objects were ordinary source/test text (`tests/test_reconciler.py`) and `CHANGELOG.md` revisions. No path-based history rewrite blocker was found.

### GitHub Issues / PR metadata — REVIEWED

Bounded searches of Issue/PR bodies and comments found no obvious actual `ghp_`, `github_pat_`, or private-key marker. References to environment-variable names or explicitly unset credentials are not credential values.

Historical non-secret host diagnostics remain visible and are covered by the explicit human acceptance above.

### Retained Actions artifacts — COMPLETE FOR CURRENT INVENTORY

A fresh repository-wide artifact inventory found exactly `8` retained artifacts:

- `7` named `cloudflare-reviewed-deploy-candidate`;
- `1` named `package-lock.json`.

All eight retained artifacts were inspected. Known retained artifacts included:

- artifact `9584489035`, digest `sha256:09b236ddd303eaaa5306a896cc534f9de5fbdf011780a1cb72e7a790636aca3f`;
- artifact `9568053846`, package-lock digest `sha256:2183ac70c238c2d489b6d2530fa237bf7fe819086f123051d14314c4b42f2f72`.

The additional six review artifacts were compared by ZIP structure, per-file hashes, and changed-file content. Common files matched the already-audited candidate where expected; changed manifest/evidence/deploy files did not expose a credential/private-key blocker. Later deploy code referenced environment-provided public-key values rather than embedding private material.

Current retained-artifact disposition:

`RETAINED_ACTIONS_ARTIFACT_SURFACE_REVIEWED`

### Actions logs — COMPLETE FOR CURRENT INVENTORY

A complete Actions run inventory found:

- total workflow runs: `479`;
- workflow files: `5`;
- inventory retrieval: `479 / 479`.

Available log bodies were machine-scanned for private-key markers and common token/key/secret forms, including GitHub token prefixes, AWS access-key IDs, Slack token forms, OpenAI key forms, and named secret assignments.

Results:

- log bodies retrieved and scanned: `430`;
- candidate runs: `0`;
- candidate match groups: `0`.

The remaining `49` runs returned no log body. Their job metadata showed `98` hosted jobs total:

- `49` `unittest` jobs;
- `49` `windows-junction` jobs.

All `98` classified `NOT_EXECUTED_BEFORE_RUNNER`: no runner assignment and no workflow-step execution, so no job log body was generated.

The two self-hosted `workflow_dispatch` runs were separately reviewed in full:

- run `34694491500`;
- run `34734397983`.

Observed GitHub token/checkout auth remained masked as `***`; one-time disposable-target password content was not emitted. Real runner/machine/SID/nonce/path metadata is non-secret historical infrastructure evidence covered by the explicit human publication decision.

Both self-hosted runs failed at the one-time credential deletion boundary before target-process execution. The later run demonstrated the known `Remove-Item -Force` deletion failure tracked by #201; this is an implementation/lifecycle blocker, not a secret-exposure finding.

Current Actions-log disposition:

`ACTIONS_LOG_SURFACE_REVIEWED`

### Repository-local audit record / changelog — COMPLETE IN DRAFT

`CHANGELOG.md` now contains the Issue #196 / Draft PR #203 public-readiness and safety-boundary record, including completed history/surface audit evidence, forward anonymization policy, human-final authority, the self-hosted publication blocker, and the private hosted-CI limitation.

## Repository change in PR #203

### Hosted Actions checkout hardening — IMPLEMENTED IN DRAFT

`.github/workflows/tests.yml` uses `contents: read` and `persist-credentials: false` on both hosted `actions/checkout` steps.

A deterministic regression verifies checkout step boundaries and rejects any hosted checkout that persists credentials.

The most recent hosted exact-head observation before this document synchronization was:

- PR head: `52655052f22df82bd61524efca969786238c20f9`;
- run: `34745681520`;
- `unittest`: failure before runner/step execution, `steps=null`;
- `windows-junction`: failure before runner/step execution, `steps=null`.

This remains classified:

`HOSTED_CI_NOT_EXECUTED / PRIVATE_CAPACITY_BLOCKED`

It is not an implementation-test failure and it is not a CI PASS. Documentation-only synchronization after that observation does not change this private-plan limitation.

Post-public closeout must prove the canonical hosted jobs actually receive GitHub-hosted runners and execute.

## Remaining blockers before human visibility gate

### 1. License — COMPLETE

MIT is present at the repository root and remains the selected publication license.

### 2. Self-hosted exact-head fallback — RETIRED IN PUBLICATION CANDIDATE

The private-era bare-metal self-hosted workflow has been removed from the publication candidate. Its implementation-specific active-workflow regressions are replaced by a publication regression that fails if an active workflow again targets `self-hosted` or the private `ac-ci-*` runner label family.

The historical design and repair evidence remain in Git history and in the retired runbook. Reintroduction is a new security-sensitive decision and is not part of publication closeout.

### 3. Exact-head validation and independent review — REQUIRED BEFORE MERGE

This retirement change must pass:

- focused publication-surface regression;
- full deterministic suite;
- Windows junction regression;
- exact HEAD / clean tree / remote-head binding;
- independent exact-head adversarial review.

Ready and merge remain human-final.

### 4. Fresh publication inventory — REQUIRED AFTER MERGE

After this retirement change merges, refresh the publication-reachable tree/history/surface inventory against the new exact `main`. Prior completed scans remain evidence, but material repository changes since the earlier baseline require freshness confirmation before the visibility gate.

### 5. Public `main` protection and hosted CI — REQUIRED IMMEDIATELY AFTER VISIBILITY CHANGE

After the human changes visibility to public:

- configure/read back `main` protection;
- block force push and deletion;
- require pull requests and review-thread resolution where supported;
- require canonical hosted CI checks;
- prove the GitHub-hosted jobs actually receive runners and execute.

Do not record `PUBLISHED_VERIFIED` before those post-public checks pass.

## Public fork / Actions trust review

Hosted `pull_request` workflows must remain read-only and must not grant public fork code repository-write or secret authority.

Do not use `pull_request_target` to execute untrusted PR code with elevated repository context.

Any self-hosted workflow retained in a public repository requires a separate explicit proof that untrusted contributors cannot trigger execution on the trusted machine. The safer default for publication is to disable/retire the fallback unless there is a continuing operational need and its repaired trust boundary has been independently verified.

## Human-final publication sequence

The safe sequence is:

1. complete the remaining self-hosted lifecycle and exact-head validation gates;
2. merge only reviewed public-readiness changes through the normal human Ready/merge gate;
3. refresh exact `main`, publication-reachable history, retained artifacts, and Actions inventory immediately before visibility change if repository state materially changed;
4. record `READY_FOR_HUMAN_VISIBILITY_GATE` only when every pre-public blocker is closed;
5. human explicitly changes repository visibility from private to public;
6. immediately configure and read back `main` protection/ruleset;
7. trigger/observe canonical GitHub-hosted CI and prove jobs actually start on hosted runners;
8. verify repository metadata, README, license, Issues/PR visibility, Actions permissions, and self-hosted posture from the public side;
9. record post-public closeout evidence in Issue #196; only then classify `PUBLISHED_VERIFIED`.

Ready, merge, visibility change, history rewrite, and destructive cleanup remain human-final unless separately and explicitly delegated.

## Current classification

`BLOCKED_PENDING_RETIREMENT_VALIDATION_AND_MERGE`

The security/content/license audit remains complete for its recorded surfaces. The active publication blocker is now the bounded retirement change itself, followed by the fresh publication inventory. PR #193 is a separate Draft implementation workstream and is not a visibility prerequisite.

After the retirement merge and fresh inventory, Issue #196 may advance to `READY_FOR_HUMAN_VISIBILITY_GATE` only from refreshed evidence.