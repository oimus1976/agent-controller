# Agent Instructions

This repository predates full `ai-dev-starter` adoption. Existing repository docs, ADRs, Issues, PRs, and code remain authoritative for project-specific behavior and governance. This file adds only selected cross-project operational rules that agents must apply directly while working in this repository.

## Independent implementation and review

Implementation and review must remain independent.

- The implementing session/agent must not be the sole reviewer of its own work.
- Independent review must bind to an exact commit/head and start from a fresh review context.
- Review findings may be remediated by the original implementer or another implementation agent, but remediation is not self-validating.
- After remediation changes the exact head, require a fresh reviewer to review the new head; the agent/session that performed the remediation must not be the sole evidence that the fix is correct.
- For security-sensitive trust-boundary, credential, permission, destructive-effect, or fail-closed changes, add cross-model or cross-agent review when practical.
- Self-review, tests, linting, and remediation-thread confirmation are supplemental evidence, not substitutes for independent review.
- Ready and merge remain human-final under ADR #90.

Canonical rationale and scope: ADR #199, `ADR: Independent implementation and fresh-head review after remediation`.

## Post-merge local closeout

GitHub merge completion, task-worktree residue, and canonical next-work readiness are separate facts.

When a tracked PR used a local checkout/worktree, independently confirm the intended PR was merged on GitHub before claiming local closeout.

### Same/canonical checkout

If the PR checkout itself is the canonical checkout for the next task, run:

`python scripts/verify_local_closeout.py`

Require the canonical branch to be clean, free of in-progress Git operations, freshly fetched, and exactly synchronized to `origin/main` unless the project defines another canonical remote/branch.

### Separate linked topic worktree

If the PR used a linked topic worktree while canonical `main` remains checked out elsewhere:

1. independently read the merged PR's full head SHA from GitHub;
2. from the topic worktree run `python scripts/verify_local_closeout.py --expected-pr-head <FULL_PR_HEAD_SHA>`;
3. require the topic worktree to be clean, free of in-progress Git operations, and still at that confirmed PR head;
4. require the separate canonical worktree to be clean and exactly synchronized to fresh `origin/main`.

A successful linked-topic closeout means the task worktree has no unaccounted local residue and the canonical worktree is the next-work entry point. It does not require switching the topic worktree to `main` or deleting the topic branch/worktree.

The verifier may fetch the canonical remote branch to establish freshness. It must not reset, stash, discard files, delete branches/worktrees, or perform other destructive cleanup merely to make the gate pass. If it fails, preserve intentional local work and report the unresolved local state.

This rule does not change existing Ready, merge, release, deployment, or other authority decisions in this repository.

Upstream baseline source: `oimus1976/ai-dev-starter@e4482fb25e501171255eab26258cf10619fce51d`.
