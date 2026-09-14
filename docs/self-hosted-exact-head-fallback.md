# Self-hosted exact-head fallback — retired for public publication

Status: **RETIRED**

This document preserves the private-era design history of the Windows self-hosted exact-head fallback. The active GitHub Actions workflow was retired from the publication candidate under Issue #196 after Issues #197, #201, and #202 established and repaired its bounded private-runner behavior.

The retirement decision is a forward runtime-surface decision, not a history rewrite. Historical Issues, pull requests, commits, validation evidence, and the former workflow remain available through Git history.

## Publication posture

The public repository uses GitHub-hosted CI as the canonical routine test path.

The publication candidate must not contain an active GitHub Actions job that targets:

- the `self-hosted` runner class; or
- the private `ac-ci-*` runner label family.

`tests/test_publication_no_self_hosted_workflow.py` enforces this boundary deterministically.

## Why the fallback was retired

The fallback existed to work around private-repository hosted Actions capacity while preserving exact-head verification on a trusted Windows machine. Once the repository becomes public, GitHub-hosted Actions removes that primary operational motivation.

Keeping a bare-metal self-hosted execution path in a public repository would retain an additional trust boundary, cleanup lifecycle, dispatch surface, and future workflow-regression risk. Publication therefore chooses the smaller surface: retire the fallback and verify hosted CI after the visibility change.

## Historical safety work

The private-era implementation was hardened through the Issue #197 / #201 / #202 sequence, including:

- same-repository exact-head binding;
- separate trusted control and disposable target identities;
- bounded checkout ACLs;
- one-time credential deletion before target execution;
- target environment isolation checks;
- reparse/junction pre-checks;
- fail-closed target/process/postcondition checks.

Those results remain useful security research and regression history, but they no longer define an active public workflow.

## Reintroduction rule

Reintroducing any self-hosted GitHub Actions execution path is a new security-sensitive design decision. It must not happen by restoring the old workflow mechanically.

A future proposal must independently justify the operational need, define the public-fork trust boundary, receive focused adversarial review, add fresh deterministic regression coverage, and preserve human-final authority under ADR #90.

## Publication closeout

After the retirement change is merged:

1. refresh Issue #196 publication inventory against exact `main`;
2. before the visibility gate, read back GitHub Actions runtime state and prove:
   - repository self-hosted runner registrations accessible to this repository are empty;
   - no queued or in-progress workflow run can still target the retired self-hosted path;
   - any residual queued/in-progress retired-path run is cancelled and then re-read as absent before proceeding;
3. record the exact pre-visibility read-back evidence in Issue #196;
4. reach the human visibility gate only if the refreshed publication inventory and the self-hosted decommission read-back are both clear;
5. after publication, establish/read back `main` protection;
6. prove canonical GitHub-hosted CI actually receives hosted runners and executes;
7. record `PUBLISHED_VERIFIED` only after those checks pass.

Deleting the workflow file is not sufficient evidence of runtime decommissioning. The
visibility gate remains blocked until the runner/run read-back above is complete.