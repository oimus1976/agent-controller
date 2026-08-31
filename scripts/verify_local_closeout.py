#!/usr/bin/env python3
"""Verify that a local checkout is safely closed out after a merged PR.

The verifier is non-destructive with respect to branches and working-tree
content. It refreshes the canonical remote-tracking branch explicitly, then
checks whether the active checkout is ready for the next work item.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import subprocess
import sys


def git(*args: str, cwd: Path, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=check,
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify post-merge local closeout without reset/stash/delete cleanup."
    )
    parser.add_argument("--repo", default=".", help="Local repository/worktree path.")
    parser.add_argument("--branch", default="main", help="Canonical local branch.")
    parser.add_argument("--remote", default="origin", help="Canonical Git remote.")
    args = parser.parse_args()

    repo = Path(args.repo).resolve()
    failures: list[str] = []

    probe = git("rev-parse", "--show-toplevel", cwd=repo, check=False)
    if probe.returncode != 0:
        print("LOCAL CLOSEOUT: FAIL")
        print("- not a Git worktree/repository")
        return 1

    remote_ref = f"refs/remotes/{args.remote}/{args.branch}"
    fetch_refspec = f"+refs/heads/{args.branch}:{remote_ref}"
    fetched = git("fetch", args.remote, fetch_refspec, cwd=repo, check=False)
    if fetched.returncode != 0:
        # Do not echo fetch output here: unusual remote URLs/errors can contain
        # sensitive connection material. The operator can run Git directly when
        # troubleshooting the remote.
        failures.append(
            f"could not refresh {args.remote}/{args.branch}; remote freshness is unverified"
        )

    branch = git("branch", "--show-current", cwd=repo, check=False).stdout.strip()
    if branch != args.branch:
        failures.append(
            f"current branch is {branch or '<detached HEAD>'!r}; expected {args.branch!r}"
        )

    status = git("status", "--porcelain=v1", "--untracked-files=all", cwd=repo, check=False)
    if status.returncode != 0:
        failures.append("could not read working-tree status")
    elif status.stdout.strip():
        failures.append("working tree is not clean")

    in_progress_markers = [
        "MERGE_HEAD",
        "CHERRY_PICK_HEAD",
        "REVERT_HEAD",
        "BISECT_LOG",
    ]
    git_dir = git("rev-parse", "--git-dir", cwd=repo, check=False).stdout.strip()
    if git_dir:
        git_dir_path = Path(git_dir)
        if not git_dir_path.is_absolute():
            git_dir_path = repo / git_dir_path
        for marker in in_progress_markers:
            if (git_dir_path / marker).exists():
                failures.append(f"Git operation still in progress: {marker}")
        for marker in ("rebase-apply", "rebase-merge"):
            if (git_dir_path / marker).exists():
                failures.append(f"Git operation still in progress: {marker}")

    remote_sha = git("rev-parse", "--verify", remote_ref, cwd=repo, check=False)
    if remote_sha.returncode != 0:
        failures.append(f"remote-tracking ref is unavailable: {args.remote}/{args.branch}")
    else:
        head_sha = git("rev-parse", "HEAD", cwd=repo, check=False).stdout.strip()
        expected_sha = remote_sha.stdout.strip()
        if head_sha != expected_sha:
            failures.append(
                f"HEAD {head_sha[:12]} does not match {args.remote}/{args.branch} {expected_sha[:12]}"
            )

    if failures:
        print("LOCAL CLOSEOUT: FAIL")
        for failure in failures:
            print(f"- {failure}")
        print("NEXT STEPS:")
        print("1. Preserve or commit any intentional local changes before cleanup.")
        print(f"2. Switch to {args.branch}: git switch {args.branch}")
        print(f"3. Fast-forward only: git pull --ff-only {args.remote} {args.branch}")
        print("4. Re-run this verifier. Do not use reset/stash/delete merely to make the gate pass.")
        return 1

    head_sha = git("rev-parse", "HEAD", cwd=repo).stdout.strip()
    print("LOCAL CLOSEOUT: PASS")
    print(f"branch={args.branch}")
    print(f"head={head_sha}")
    print(f"remote={args.remote}/{args.branch}")
    print("working_tree=clean")
    print("freshness=canonical-branch-fetch-completed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
