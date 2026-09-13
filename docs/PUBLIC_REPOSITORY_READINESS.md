# Public repository readiness

Issue: #196

Status: **BLOCKED — audit/remediation in progress**

This document is the repository-local publication contract for changing `oimus1976/agent-controller` from private to public. It records what has been checked, what remains unresolved, and the human-final publication sequence. It does not itself authorize a visibility change.

## Bound repository state

The current implementation branch for this audit was created from `main` at:

`98d4bb9d9c8396c89c3be7b235a04dd4348e3a03`

All publication evidence must be refreshed if `main` changes before the visibility gate. GitHub remains the source of truth for repository state.

## Publication invariants

Public publication is allowed only after all required checks are satisfied and the human explicitly authorizes the visibility change.

Required invariants:

1. no known secret, credential, private key, or sensitive unpublished data is exposed by current tree, reachable history, GitHub metadata, retained Actions logs/artifacts, Releases, or other repository surfaces;
2. third-party redistribution and repository licensing are explicit;
3. public GitHub Actions do not expose a trusted self-hosted runner to untrusted public/fork code;
4. normal hosted CI uses least privilege and does not persist checkout credentials unnecessarily;
5. `main` is protected immediately after publication using GitHub-side rules available to the public repository;
6. provider output, CI, review evidence, and human-final authority remain separate;
7. post-public verification proves the expected hosted workflows actually run on GitHub-hosted runners.

## Audit snapshot

### Current tree

Bounded current-tree screening found no tracked `.env`, `.pem`, `.pfx`, or `.key` path and no obvious GitHub token/private-key marker in default-branch code search.

This is useful evidence but is not a substitute for the required full-history secret scan.

### Historical identity and infrastructure metadata

Human publication decision on 2026-09-13:

- already-recorded historical commit email metadata is accepted for this repository;
- already-recorded non-secret infrastructure diagnostic metadata is accepted for this repository;
- those accepted items do not require history rewrite, Issue/PR scrubbing, or Actions-run deletion solely for their removal;
- this acceptance does **not** extend to secrets, credentials, private keys, or unrelated personal data if later discovered.

### Forward evidence anonymization rule

New durable/public-facing evidence should avoid unnecessary real infrastructure identifiers.

Prefer:

- `<HOST>` for a machine name;
- `<CONTROL_SID>` and `<TARGET_SID>` for local identity values;
- `<RUNNER>` for a runner name;
- `<NONCE>` when the exact nonce is not material;
- `<EVIDENCE_ROOT>`, `<WORKSPACE>`, and `<CREDENTIAL_ROOT>` for local machine paths.

Keep repository-verification facts concrete when they are material to auditability, including exact commit SHA, PR/Issue/run IDs, workflow name, test result, and failure boundary.

If an exact machine-specific value is required to reproduce a security-sensitive failure, prefer retaining it in local/private operator evidence while publishing only the minimum normalized fact necessary.

### GitHub Issues / PR metadata

Bounded searches of Issue/PR bodies and comments found no obvious `ghp_`, `github_pat_`, or private-key marker. References to environment-variable names or explicitly unset credentials are not credential values.

Historical non-secret host diagnostics remain visible and are covered by the explicit human acceptance above.

### Actions logs and artifacts

At the audit snapshot the repository had 477 Actions runs. The audit therefore uses risk-tiered inspection rather than claiming that every line of every historical log was manually reviewed.

Representative higher-risk surfaces inspected include:

- the trusted self-hosted exact-head pilot path, including run `34734397983`;
- historical artifact-producing Cloudflare review workflows;
- historical hosted Cloudflare PoC test workflows.

Observed GitHub/checkout tokens were masked in the inspected logs. No actual credential value was found in those representative logs.

Retained artifacts already inspected include:

- artifact `9584489035`, digest `sha256:09b236ddd303eaaa5306a896cc534f9de5fbdf011780a1cb72e7a790636aca3f`;
- artifact `9568053846`, package-lock digest `sha256:2183ac70c238c2d489b6d2530fa237bf7fe819086f123051d14314c4b42f2f72`.

Bounded content review found no obvious credential material in those artifacts. This evidence does not replace the remaining retained-surface inventory requirement.

### Short-lived historical commits

Selected reverted/short-lived commits that introduced dependency/design material were inspected directly. No secret material was found in those inspected changes. This sampling does not replace the full-history scan.

## Required work still blocking publication

### 1. Full-history secret scan — REQUIRED

Run an authenticated full clone against the publication candidate and perform a full-history secret scan, including unreachable/reachable historical filenames and blobs as appropriate for the chosen scanner.

Minimum evidence to retain:

- exact audited `main` SHA;
- scanner/tool version;
- command/config used;
- result summary;
- disposition of every finding.

Do not classify publication ready from API sampling alone.

### 2. Author/committer metadata inventory — REQUIRED

Confirm the complete publication-reachable author/committer identity set. The already-known historical email metadata is explicitly accepted, but unexpected third-party or sensitive identity data still requires disposition.

### 3. Retained GitHub surface inventory — REQUIRED

Complete the risk-tiered inventory of retained Actions logs/artifacts and other publication-visible GitHub surfaces. Representative sampling may prioritize likely secret-bearing workflows, but the final record must explain the coverage model and any residual uncertainty.

### 4. License — REQUIRED

No open-source license has been selected for this repository. Do not inherit the license choice from another repository automatically.

Before publication:

- human selects the license;
- add the corresponding root `LICENSE` file;
- ensure README/project metadata is consistent with that license.

### 5. Hosted Actions checkout hardening — IN THIS CHANGE

`.github/workflows/tests.yml` must keep `contents: read` and set `persist-credentials: false` on every `actions/checkout` step. A deterministic regression test protects this contract.

### 6. Self-hosted exact-head fallback — BLOCKER

A public repository must not expose an unsafe bare-metal self-hosted execution path.

The current fallback has active remediation work tracked separately, including #201 and #202. Public-readiness also retains the stronger #196 requirement that failure/cancellation semantics must not leave trusted cleanup or access revocation dependent on an earlier step succeeding.

Before publication, choose and verify one path:

- **retire/disable** the self-hosted fallback for the public repository; or
- **remediate and re-verify** it so public/fork code cannot obtain a route to the trusted host and trusted cleanup/revocation is fail-safe across success, failure, and cancellation.

Do not weaken this requirement merely because GitHub-hosted Actions become available after publication.

### 7. Public `main` protection — REQUIRED IMMEDIATELY AFTER VISIBILITY CHANGE

On the current GitHub Free private repository, repository rulesets are unavailable. After the human changes visibility to public, configure and read back a GitHub-side rule for `main` before treating publication as complete.

The intended baseline is:

- block deletion and force push;
- require pull requests to `main`;
- require resolution of review threads where supported;
- require the canonical hosted CI checks;
- no automation bypass that would silently widen merge authority.

Exact rule names/check identifiers must be read from the public repository state at that time, not guessed in advance.

## Public fork / Actions trust review

Hosted `pull_request` workflows must remain read-only and must not grant public fork code repository-write or secret authority.

Do not use `pull_request_target` to execute untrusted PR code with elevated repository context.

Any self-hosted workflow retained in a public repository requires a separate explicit proof that untrusted contributors cannot trigger execution on the trusted machine. The safer default for publication is to disable/retire the fallback unless there is a continuing operational need and its repaired trust boundary has been independently verified.

## Human-final publication sequence

The safe sequence is:

1. merge only reviewed public-readiness changes through the normal human Ready/merge gate;
2. refresh exact `main` and complete full-history/retained-surface/license/self-hosted gates against that state;
3. record `READY_FOR_HUMAN_VISIBILITY_GATE` only when every blocker above is closed;
4. human explicitly changes repository visibility from private to public;
5. immediately configure and read back `main` protection/ruleset;
6. trigger/observe canonical GitHub-hosted CI and prove jobs actually start on hosted runners rather than failing before assignment because of private-plan quota;
7. verify repository metadata, README, license, Issues/PR visibility, Actions permissions, and self-hosted posture from the public side;
8. record post-public closeout evidence in Issue #196; only then classify `PUBLISHED_VERIFIED`.

Ready, merge, visibility change, history rewrite, and destructive cleanup remain human-final unless separately and explicitly delegated.

## Current classification

`BLOCKED`

Current blockers include at least:

- full-history secret scan;
- complete publication-reachable identity/surface inventory;
- license selection;
- self-hosted fallback retire/disable-or-remediate decision and verification;
- post-public `main` protection, which cannot be completed until after the human visibility change.

This document should be updated from fresh GitHub evidence before any later readiness classification.
