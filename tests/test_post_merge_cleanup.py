import inspect
import unittest

from agent_controller.post_merge_cleanup import (
    assess_local_worktree_cleanup_candidate,
    assess_remote_branch_cleanup_candidate,
    parse_local_closeout_evidence,
)
from agent_controller.workstream import WorkstreamBinding


REPO = "oimus1976/agent-controller"
HEAD = "a" * 40
BRANCH = "topic/merged"


def lane(*, branch=BRANCH, workstream_id="lane-a"):
    return WorkstreamBinding(
        workstream_id=workstream_id,
        repo=REPO,
        root_work_item_ref="issue-x",
        task_ids=(f"task-{workstream_id}",),
        branch_refs=(branch,),
    )


def merged_pr(*, merged=True, state="closed", branch=BRANCH, head=HEAD, repo=REPO, number=77):
    return {
        "number": number,
        "merged": merged,
        "state": state,
        "head": {"ref": branch, "sha": head, "repo": {"full_name": repo}},
    }


class RemoteHarness:
    def __init__(self):
        self.pr = merged_pr()
        self.branch_sha = HEAD
        self.open_prs = []
        self.default_branch = "main"
        self.reads = {"pr": 0, "branch": 0, "open_prs": 0, "default": 0}

    def read_pr(self, repo, pr):
        self.reads["pr"] += 1
        return self.pr

    def read_branch(self, repo, branch):
        self.reads["branch"] += 1
        return self.branch_sha

    def list_open_prs(self, repo, branch):
        self.reads["open_prs"] += 1
        return self.open_prs

    def read_default(self, repo):
        self.reads["default"] += 1
        return self.default_branch


def assess(h=None, active=()):
    h = h or RemoteHarness()
    result = assess_remote_branch_cleanup_candidate(
        repo=REPO,
        pr_number=77,
        active_workstreams=active,
        read_pr=h.read_pr,
        read_branch_sha=h.read_branch,
        list_open_prs_for_head=h.list_open_prs,
        read_default_branch=h.read_default,
    )
    return result, h


PASS_OUTPUT = f"""LOCAL CLOSEOUT: PASS
task_worktree_role=topic
task_worktree=clean
task_head={HEAD}
expected_pr_head=matched
canonical_worktree=ready
branch=main
head={'b' * 40}
remote=origin/main
freshness=canonical-branch-fetch-completed
next_task_checkout=canonical-worktree
"""


class PostMergeCleanupTests(unittest.TestCase):
    def test_exact_merged_unowned_branch_is_candidate(self):
        result, h = assess()
        self.assertEqual(result.status, "SAFE_TO_CONSIDER")
        self.assertEqual(result.branch, BRANCH)
        self.assertEqual(result.merged_pr_head, HEAD)
        self.assertEqual(h.reads, {"pr": 1, "branch": 1, "open_prs": 1, "default": 1})

    def test_unmerged_pr_is_not_safe_before_branch_reads(self):
        h = RemoteHarness()
        h.pr = merged_pr(merged=False, state="open")
        result, h = assess(h)
        self.assertEqual((result.status, result.reason), ("NOT_SAFE", "PR_NOT_MERGED"))
        self.assertEqual(h.reads["branch"], 0)

    def test_default_branch_is_never_candidate(self):
        h = RemoteHarness()
        h.pr = merged_pr(branch="main")
        result, _ = assess(h)
        self.assertEqual((result.status, result.reason), ("NOT_SAFE", "CANONICAL_BRANCH"))

    def test_branch_drift_is_not_safe(self):
        h = RemoteHarness()
        h.branch_sha = "c" * 40
        result, _ = assess(h)
        self.assertEqual((result.status, result.reason), ("NOT_SAFE", "REMOTE_BRANCH_DRIFTED"))

    def test_open_pr_using_branch_blocks(self):
        h = RemoteHarness()
        h.open_prs = [{"number": 88, "state": "open"}]
        result, _ = assess(h)
        self.assertEqual((result.status, result.reason), ("NOT_SAFE", "OPEN_PR_USES_BRANCH"))

    def test_active_workstream_ownership_blocks_before_branch_read(self):
        result, h = assess(active=(lane(),))
        self.assertEqual((result.status, result.reason), ("NOT_SAFE", "ACTIVE_WORKSTREAM_OWNS_BRANCH"))
        self.assertEqual(h.reads["branch"], 0)

    def test_already_absent_is_distinct(self):
        h = RemoteHarness()
        h.branch_sha = None
        result, _ = assess(h)
        self.assertEqual((result.status, result.reason), ("ALREADY_ABSENT", "REMOTE_BRANCH_ABSENT"))

    def test_malformed_github_evidence_is_uncertain(self):
        h = RemoteHarness()
        h.pr = {"number": 77, "merged": True, "state": "closed", "head": {}}
        result, _ = assess(h)
        self.assertEqual(result.status, "UNCERTAIN")

        h = RemoteHarness()
        h.open_prs = ["bad"]
        result, _ = assess(h)
        self.assertEqual(result.status, "UNCERTAIN")

    def test_local_closeout_pass_is_required_for_local_candidate(self):
        result = assess_local_worktree_cleanup_candidate(
            repo=REPO,
            pr_number=77,
            topic_branch=BRANCH,
            merged_pr_head=HEAD,
            active_workstreams=(),
            closeout_output=PASS_OUTPUT,
            closeout_returncode=0,
        )
        self.assertEqual((result.status, result.reason), ("SAFE_TO_CONSIDER", "LOCAL_CLOSEOUT_VERIFIED"))

        failed = assess_local_worktree_cleanup_candidate(
            repo=REPO,
            pr_number=77,
            topic_branch=BRANCH,
            merged_pr_head=HEAD,
            active_workstreams=(),
            closeout_output="LOCAL CLOSEOUT: FAIL\n- dirty",
            closeout_returncode=1,
        )
        self.assertEqual((failed.status, failed.reason), ("NOT_SAFE", "LOCAL_CLOSEOUT_FAILED"))

    def test_local_wrong_head_or_incomplete_pass_is_not_safe(self):
        wrong = PASS_OUTPUT.replace(f"task_head={HEAD}", f"task_head={'c' * 40}")
        evidence = parse_local_closeout_evidence(output=wrong, returncode=0, expected_pr_head=HEAD)
        self.assertFalse(evidence.valid)
        self.assertEqual(evidence.reason, "LOCAL_CLOSEOUT_HEAD_MISMATCH")

        incomplete = PASS_OUTPUT.replace("canonical_worktree=ready\n", "")
        evidence = parse_local_closeout_evidence(output=incomplete, returncode=0, expected_pr_head=HEAD)
        self.assertFalse(evidence.valid)
        self.assertEqual(evidence.reason, "LOCAL_CLOSEOUT_PASS_EVIDENCE_INCOMPLETE")

    def test_local_active_workstream_ownership_blocks(self):
        result = assess_local_worktree_cleanup_candidate(
            repo=REPO,
            pr_number=77,
            topic_branch=BRANCH,
            merged_pr_head=HEAD,
            active_workstreams=(lane(),),
            closeout_output=PASS_OUTPUT,
            closeout_returncode=0,
        )
        self.assertEqual((result.status, result.reason), ("NOT_SAFE", "ACTIVE_WORKSTREAM_OWNS_BRANCH"))

    def test_github_only_remote_candidate_does_not_fabricate_local_safety(self):
        remote, _ = assess()
        self.assertEqual(remote.status, "SAFE_TO_CONSIDER")
        local = assess_local_worktree_cleanup_candidate(
            repo=REPO,
            pr_number=77,
            topic_branch=BRANCH,
            merged_pr_head=HEAD,
            active_workstreams=(),
            closeout_output="",
            closeout_returncode=1,
        )
        self.assertEqual(local.status, "NOT_SAFE")

    def test_public_surfaces_have_no_destructive_action_parameters(self):
        for fn in (assess_remote_branch_cleanup_candidate, assess_local_worktree_cleanup_candidate):
            params = inspect.signature(fn).parameters
            for forbidden in ("delete", "remove", "reset", "stash", "force", "prune"):
                self.assertNotIn(forbidden, params)


if __name__ == "__main__":
    unittest.main()
