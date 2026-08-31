#!/usr/bin/env python3
"""Verify local post-merge closeout without destructive cleanup.

The verifier refreshes the canonical remote branch, checks the worktree used
for the tracked PR, and verifies the canonical checkout that is safe to use as
the next-work entry point. A linked topic worktree may remain on its topic
branch when canonical main is checked out in another worktree.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import subprocess
import sys


FULL_GITHUB_SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")


def git(*args: str, cwd: Path, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=check,
    )


def git_dir_for(worktree: Path) -> Path | None:
    result = git("rev-parse", "--git-dir", cwd=worktree, check=False)
    if result.returncode != 0:
        return None
    path = Path(result.stdout.strip())
    if not path.is_absolute():
        path = worktree / path
    return path.resolve()


def check_worktree_state(worktree: Path, label: str, failures: list[str]) -> None:
    if not worktree.is_dir():
        failures.append(f"{label} worktree path is unavailable")
        return

    status = git(
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
        cwd=worktree,
        check=False,
    )
    if status.returncode != 0:
        failures.append(f"could not read {label} working-tree status")
    elif status.stdout.strip():
        failures.append(f"{label} working tree is not clean")

    git_dir = git_dir_for(worktree)
    if git_dir is None:
        failures.append(f"could not resolve {label} Git directory")
        return

    for marker in ("MERGE_HEAD", "CHERRY_PICK_HEAD", "REVERT_HEAD", "BISECT_LOG"):
        if (git_dir / marker).exists():
            failures.append(f"{label} Git operation still in progress: {marker}")
    for marker in ("rebase-apply", "rebase-merge"):
        if (git_dir / marker).exists():
            failures.append(f"{label} Git operation still in progress: {marker}")


def list_worktrees(repo: Path) -> list[dict[str, str]]:
    result = git("worktree", "list", "--porcelain", cwd=repo, check=False)
    if result.returncode != 0:
        return []

    entries: list[dict[str, str]] = []
    current: dict[str, str] = {}
    for raw_line in result.stdout.splitlines():
        if not raw_line:
            if current:
                entries.append(current)
                current = {}
            continue
        key, separator, value = raw_line.partition(" ")
        current[key] = value if separator else ""
    if current:
        entries.append(current)
    return entries


def canonical_worktree(repo: Path, branch: str) -> Path | None:
    branch_ref = f"refs/heads/{branch}"
    matches = [
        entry["worktree"]
        for entry in list_worktrees(repo)
        if entry.get("branch") == branch_ref and entry.get("worktree")
    ]
    if len(matches) != 1:
        return None
    candidate = Path(matches[0]).resolve()
    if not candidate.is_dir():
        return None
    return candidate


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify post-merge local closeout without reset/stash/delete cleanup."
    )
    parser.add_argument("--repo", default=".", help="Tracked PR worktree/repository path.")
    parser.add_argument("--branch", default="main", help="Canonical local branch.")
    parser.add_argument("--remote", default="origin", help="Canonical Git remote.")
    parser.add_argument(
        "--expected-pr-head",
        help=(
            "Full 40-character PR head SHA from an independent GitHub merge read. "
            "Required when running from a non-canonical topic worktree."
        ),
    )
    args = parser.parse_args()

    requested = Path(args.repo).resolve()
    if not requested.is_dir():
        print("LOCAL CLOSEOUT: FAIL")
        print("- requested repository/worktree path is unavailable")
        return 1

    probe = git("rev-parse", "--show-toplevel", cwd=requested, check=False)
    if probe.returncode != 0:
        print("LOCAL CLOSEOUT: FAIL")
        print("- not a Git worktree/repository")
        return 1

    task_worktree = Path(probe.stdout.strip()).resolve()
    failures: list[str] = []

    remote_ref = f"refs/remotes/{args.remote}/{args.branch}"
    fetch_refspec = f"+refs/heads/{args.branch}:{remote_ref}"
    fetched = git("fetch", args.remote, fetch_refspec, cwd=task_worktree, check=False)
    freshness_ok = fetched.returncode == 0
    if not freshness_ok:
        # Do not echo fetch output: unusual remote URLs/errors can contain
        # sensitive connection material.
        failures.append(
            f"could not refresh {args.remote}/{args.branch}; remote freshness is unverified"
        )

    check_worktree_state(task_worktree, "task", failures)

    task_branch = git(
        "branch", "--show-current", cwd=task_worktree, check=False
    ).stdout.strip()
    task_head = git("rev-parse", "HEAD", cwd=task_worktree, check=False).stdout.strip()

    canonical = task_worktree if task_branch == args.branch else None
    topic_mode = canonical is None

    if topic_mode:
        expected_pr_head = (args.expected_pr_head or "").strip()
        if not expected_pr_head:
            failures.append(
                "topic worktree closeout requires --expected-pr-head from the independently confirmed merged PR"
            )
        elif not FULL_GITHUB_SHA_RE.fullmatch(expected_pr_head):
            failures.append("--expected-pr-head must be a full 40-character hexadecimal GitHub commit SHA")
        elif task_head.lower() != expected_pr_head.lower():
            failures.append(
                f"task HEAD {task_head[:12]} does not match expected PR head "
                f"{expected_pr_head[:12]}"
            )

        canonical = canonical_worktree(task_worktree, args.branch)
        if canonical is None:
            failures.append(
                f"canonical branch {args.branch!r} is not checked out in exactly one available worktree"
            )
        else:
            check_worktree_state(canonical, "canonical", failures)
            canonical_branch = git(
                "branch", "--show-current", cwd=canonical, check=False
            ).stdout.strip()
            if canonical_branch != args.branch:
                failures.append(
                    f"canonical worktree branch is {canonical_branch or '<detached HEAD>'!r}; "
                    f"expected {args.branch!r}"
                )

    remote_sha = ""
    canonical_head = ""
    if freshness_ok:
        remote_result = git(
            "rev-parse", "--verify", remote_ref, cwd=task_worktree, check=False
        )
        if remote_result.returncode != 0:
            failures.append(
                f"remote-tracking ref is unavailable: {args.remote}/{args.branch}"
            )
        elif canonical is not None:
            remote_sha = remote_result.stdout.strip()
            canonical_head = git(
                "rev-parse", "HEAD", cwd=canonical, check=False
            ).stdout.strip()
            if canonical_head != remote_sha:
                failures.append(
                    f"canonical HEAD {canonical_head[:12]} does not match "
                    f"{args.remote}/{args.branch} {remote_sha[:12]}"
                )

    if failures:
        print("LOCAL CLOSEOUT: FAIL")
        for failure in failures:
            print(f"- {failure}")
        print("NEXT STEPS:")
        print("1. Preserve or commit any intentional local changes before cleanup.")
        if topic_mode:
            print(
                "2. Resolve every task-worktree finding first; do not switch away from "
                "the topic worktree to bypass the confirmed PR-head check."
            )
            if canonical is None:
                print(
                    f"3. Check out {args.branch} in a separate canonical worktree, then "
                    f"fast-forward it only from {args.remote}/{args.branch}."
                )
            else:
                print(
                    f"3. Repair/synchronize the existing {args.branch} worktree; "
                    f"fast-forward only: git pull --ff-only {args.remote} {args.branch}"
                )
            print(
                "4. Re-run this verifier from the topic worktree with the full "
                "--expected-pr-head confirmed from GitHub."
            )
        else:
            print(f"2. Switch to {args.branch}: git switch {args.branch}")
            print(
                f"3. Fast-forward only: git pull --ff-only {args.remote} {args.branch}"
            )
            print("4. Re-run this verifier.")
        print("Do not use reset/stash/delete merely to make the gate pass.")
        return 1

    print("LOCAL CLOSEOUT: PASS")
    print(f"task_worktree_role={'topic' if topic_mode else 'canonical'}")
    if topic_mode:
        print("task_worktree=clean")
        print(f"task_head={task_head}")
        print("expected_pr_head=matched")
    print("canonical_worktree=ready")
    print(f"branch={args.branch}")
    print(f"head={canonical_head or task_head}")
    print(f"remote={args.remote}/{args.branch}")
    print("freshness=canonical-branch-fetch-completed")
    print("next_task_checkout=canonical-worktree")
    return 0


if __name__ == "__main__":
    sys.exit(main())
