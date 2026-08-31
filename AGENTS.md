# Agent Instructions

This repository predates full `ai-dev-starter` adoption. Existing repository docs, ADRs, Issues, PRs, and code remain authoritative for project-specific behavior and governance. This file adds only the cross-project post-merge local closeout rule.

## Post-merge local closeout

GitHub merge completion and local checkout readiness are separate facts.

When a tracked PR used a local checkout/worktree:

1. independently confirm the intended PR was merged on GitHub;
2. run `python scripts/verify_local_closeout.py` in the local checkout;
3. do not report the task locally closed out, and do not start the next tracked implementation in that checkout, until the verifier passes.

The verifier may fetch the canonical remote branch to establish freshness. It must not reset, stash, discard files, delete branches/worktrees, or perform other destructive cleanup merely to make the gate pass. If it fails, preserve intentional local work and report the unresolved local state.

This rule does not change existing Ready, merge, release, deployment, or other authority decisions in this repository.

Upstream baseline source: `oimus1976/ai-dev-starter@2ffc50384fca55938a47bec363e184396f7ca1d3`.
