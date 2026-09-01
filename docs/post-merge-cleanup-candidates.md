# Post-merge cleanup candidates

Issue #135 extends the existing non-destructive local closeout rule with advisory cleanup candidacy only.

Remote topic-branch candidacy is derived from authoritative GitHub facts: the exact tracked PR must be merged, its head branch and full head SHA must be intact, the branch must not be canonical/default, the current remote branch must still equal that merged PR head, no open PR may use it, and no supplied active workstream may own it. An already absent branch is reported separately rather than treated as work to perform.

Local linked-worktree candidacy is a separate fact. GitHub evidence alone can never make a local worktree safe to remove. The Controller accepts only the explicit PASS contract emitted by `scripts/verify_local_closeout.py --expected-pr-head <FULL_PR_HEAD_SHA>` in topic-worktree mode, including clean task worktree, exact PR-head match, ready canonical worktree, and completed canonical-branch freshness fetch. Active workstream ownership still blocks candidacy.

`SAFE_TO_CONSIDER` is advisory evidence, not deletion authority. This surface has no branch deletion, worktree removal, reset, stash, force-update, Ready, merge, release, or deploy action. Any future destructive cleanup requires a separately scoped, human-authorized decision after operational evidence shows it is worth adding.

This cleanup lane is independent from the Jules limited-production lane. Same repository and temporal proximity do not create shared workstream authority.
