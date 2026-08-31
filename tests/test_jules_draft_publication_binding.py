import hashlib
import unittest

from agent_controller.jules_changesets import JulesChangeSetEvidence
from agent_controller.jules_draft_publication import publish_jules_changeset_to_draft_pr
from agent_controller.provider_contract import AgentObservation, AwaitingInput, ControllerState, ObjectiveScope, ProviderOperationRef, TaskBinding, TerminalClaim
from agent_controller.workstream import WorkstreamBinding

BASE = "1" * 40
COMMIT = "2" * 40
PATCH = "diff --git a/app.txt b/app.txt\n--- a/app.txt\n+++ b/app.txt\n@@ -1 +1 @@\n-old\n+new\n"


def make_task(ref="refs/heads/release"):
    return TaskBinding("task-a", "op-a", "jules", "o/r", ref, BASE, ObjectiveScope(allowed_paths=("app.txt",)), "IMPLEMENT", ("SESSION_CREATE", "DRAFT_PR_CREATE"), ("READY", "MERGE"), "policy", "2026-09-01T00:00:00Z")


def make_operation():
    return ProviderOperationRef("jules", "session-a", None, "task-a", "op-a")


def make_lane(branch):
    return WorkstreamBinding("lane-a", "o/r", "issue-131", task_ids=("task-a",), branch_refs=(branch,))


def make_observation():
    return AgentObservation("jules", "session-a", "2026-09-01T00:01:00Z", None, {"state": "COMPLETED"}, ControllerState.ARTIFACT_READY, AwaitingInput.NONE, TerminalClaim.SUCCESS)


def make_evidence():
    return JulesChangeSetEvidence("jules", "session-a", "act-1", "sessions/session-a/activities/act-1", None, True, "sources/github/o/r", PATCH, BASE, "Implement", "2026-09-01T00:01:00Z", hashlib.sha256(PATCH.encode()).hexdigest())


class Reader:
    def list_change_sets(self, **kwargs):
        return (make_evidence(),)


class GitHub:
    def __init__(self):
        self.branch = None
        self.pr = None
        self.created_changes = None

    def get_default_branch(self, repo): return "main"
    def get_ref_sha(self, repo, ref):
        clean = ref.removeprefix("refs/heads/")
        if clean == "release": return BASE
        if clean == "controller/task-a": return self.branch
        return None
    def get_file_text(self, repo, commit_sha, path): return "old\n"
    def create_commit_from_text_changes(self, **kwargs):
        self.created_changes = kwargs["changes"]
        return COMMIT
    def create_branch(self, repo, branch, sha): self.branch = sha
    def list_open_prs_for_branch(self, repo, branch): return () if self.pr is None else ({"number": 7},)
    def create_draft_pr(self, **kwargs):
        self.pr = {"number": 7, "state": "open", "draft": True, "merged": False, "head": {"ref": kwargs["head"], "sha": self.branch}, "base": {"ref": kwargs["base"]}}
        return {"number": 7}
    def get_pr(self, repo, pr_number): return self.pr
    def compare_files(self, repo, base_sha, head_sha): return ({"filename": "app.txt"},)


class PublicationBindingTests(unittest.TestCase):
    def test_pr_base_is_exact_expected_start_branch_not_repository_default(self):
        github = GitHub()
        result = publish_jules_changeset_to_draft_pr(
            task=make_task(), operation=make_operation(), workstream=make_lane("controller/task-a"), destination_branch="controller/task-a",
            observe=lambda _: make_observation(), change_reader=Reader(), github=github, pr_title="x", pr_body="y",
        )
        self.assertEqual(result.status, "PASS")
        self.assertEqual(github.pr["base"]["ref"], "release")

    def test_non_controller_namespace_blocks_before_provider_observation(self):
        calls = []
        result = publish_jules_changeset_to_draft_pr(
            task=make_task(), operation=make_operation(), workstream=make_lane("feature/task-a"), destination_branch="feature/task-a",
            observe=lambda _: calls.append(True) or make_observation(), change_reader=Reader(), github=GitHub(), pr_title="x", pr_body="y",
        )
        self.assertEqual(result.status, "BLOCKED")
        self.assertEqual(result.reason, "CONTROLLER_BRANCH_NAMESPACE_REQUIRED")
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
