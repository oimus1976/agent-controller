import hashlib
import unittest

from agent_controller.jules_changesets import JulesChangeSetEvidence
from agent_controller.jules_draft_publication import publish_jules_changeset_to_draft_pr
from agent_controller.provider_contract import (
    AgentObservation,
    AwaitingInput,
    ControllerState,
    ObjectiveScope,
    ProviderOperationRef,
    TaskBinding,
    TerminalClaim,
)
from agent_controller.workstream import WorkstreamBinding


BASE = "1" * 40
COMMIT = "2" * 40
BRANCH = "controller/task-a"
PATCH = """diff --git a/app.txt b/app.txt
--- a/app.txt
+++ b/app.txt
@@ -1 +1 @@
-old
+new
"""


def task(scope=None):
    return TaskBinding(
        controller_task_id="task-a",
        operation_id="op-a",
        provider="jules",
        repo="oimus1976/agent-controller",
        expected_start_ref="refs/heads/main",
        expected_start_sha=BASE,
        objective_scope=scope or ObjectiveScope(allowed_paths=("app.txt",)),
        requested_capability="IMPLEMENT",
        allowed_effects=("SESSION_CREATE", "DRAFT_PR_CREATE"),
        forbidden_effects=("READY", "MERGE"),
        approval_policy_id="policy",
        created_at="2026-09-01T00:00:00Z",
    )


def operation(task_id="task-a", op_id="op-a"):
    return ProviderOperationRef(
        provider="jules",
        provider_operation_id="session-a",
        provider_url=None,
        controller_task_id=task_id,
        operation_id=op_id,
    )


def lane(branch=BRANCH, task_id="task-a"):
    return WorkstreamBinding(
        workstream_id="lane-a",
        repo="oimus1976/agent-controller",
        root_work_item_ref="issue-131",
        task_ids=(task_id,),
        branch_refs=(branch,),
    )


def observation(success=True, session="session-a"):
    return AgentObservation(
        provider="jules",
        provider_operation_id=session,
        observed_at="2026-09-01T00:01:00Z",
        provider_updated_at=None,
        provider_raw_state={"state": "COMPLETED" if success else "IN_PROGRESS"},
        mapped_state=ControllerState.ARTIFACT_READY if success else ControllerState.EXECUTING,
        awaiting_input=AwaitingInput.NONE,
        terminal_claim=TerminalClaim.SUCCESS if success else TerminalClaim.NONE,
    )


def evidence(patch=PATCH, base=BASE, activity="act-1"):
    return JulesChangeSetEvidence(
        provider="jules",
        provider_operation_id="session-a",
        activity_id=activity,
        activity_name=f"sessions/session-a/activities/{activity}",
        activity_create_time="2026-09-01T00:00:30Z",
        session_completed=True,
        source="sources/github/oimus1976/agent-controller",
        unidiff_patch=patch,
        base_commit_id=base,
        suggested_commit_message="Implement task-a",
        observed_at="2026-09-01T00:01:00Z",
        patch_sha256=hashlib.sha256(patch.encode()).hexdigest(),
    )


class Reader:
    def __init__(self, items):
        self.items = tuple(items)
        self.calls = 0

    def list_change_sets(self, **kwargs):
        self.calls += 1
        return self.items


class FakeGitHub:
    def __init__(self):
        self.default_branch = "main"
        self.base_reads = 0
        self.base_sequence = [BASE, BASE, BASE]
        self.branch_sha = None
        self.open_prs = []
        self.files = {"app.txt": "old\n", "src/old.txt": "old\n"}
        self.created_changes = None
        self.pr = None
        self.writes = []
        self.compare_override = None
        self.post_branch_override = None

    def get_default_branch(self, repo):
        return self.default_branch

    def get_ref_sha(self, repo, ref):
        clean = ref.replace("refs/heads/", "")
        if clean == "main":
            value = self.base_sequence[min(self.base_reads, len(self.base_sequence) - 1)]
            self.base_reads += 1
            return value
        if clean == BRANCH:
            if self.post_branch_override is not None and self.writes:
                return self.post_branch_override
            return self.branch_sha
        return None

    def get_file_text(self, repo, commit_sha, path):
        return self.files.get(path)

    def create_commit_from_text_changes(self, **kwargs):
        self.writes.append("commit")
        self.created_changes = kwargs["changes"]
        return COMMIT

    def create_branch(self, repo, branch, sha):
        self.writes.append("branch")
        self.branch_sha = sha

    def list_open_prs_for_branch(self, repo, branch):
        return tuple(self.open_prs)

    def create_draft_pr(self, **kwargs):
        self.writes.append("pr")
        self.pr = {
            "number": 77,
            "state": "open",
            "draft": True,
            "merged": False,
            "head": {"ref": kwargs["head"], "sha": self.branch_sha},
            "base": {"ref": kwargs["base"]},
        }
        self.open_prs = [{"number": 77}]
        return {"number": 77, "draft": True}

    def get_pr(self, repo, pr_number):
        return dict(self.pr)

    def compare_files(self, repo, base_sha, head_sha):
        if self.compare_override is not None:
            return self.compare_override
        changes = self.created_changes or ()
        result = []
        for item in changes:
            if item.new_path is None:
                result.append({"filename": item.old_path, "status": "removed"})
            elif item.old_path is not None and item.old_path != item.new_path:
                result.append({"filename": item.new_path, "previous_filename": item.old_path, "status": "renamed"})
            else:
                result.append({"filename": item.new_path, "status": "modified"})
        return result


def publish(github=None, reader=None, obs=None, t=None, op=None, ws=None, branch=BRANCH):
    github = github or FakeGitHub()
    reader = reader or Reader([evidence()])
    result = publish_jules_changeset_to_draft_pr(
        task=t or task(),
        operation=op or operation(),
        workstream=ws or lane(branch=branch),
        destination_branch=branch,
        observe=(lambda _: obs or observation()),
        change_reader=reader,
        github=github,
        pr_title="Task A",
        pr_body="Controller-owned Draft publication",
    )
    return result, github, reader


class JulesDraftPublicationTests(unittest.TestCase):
    def test_completed_single_candidate_publishes_draft_pr(self):
        result, github, _ = publish()
        self.assertEqual(result.status, "PASS")
        self.assertEqual(result.pr_number, 77)
        self.assertEqual(result.commit_sha, COMMIT)
        self.assertEqual(github.writes, ["commit", "branch", "pr"])
        self.assertTrue(github.pr["draft"])
        self.assertEqual(github.created_changes[0].new_text, "new\n")

    def test_zero_or_multiple_candidates_block_before_writes(self):
        for items in ([], [evidence(), evidence(activity="act-2")]):
            github = FakeGitHub()
            result, _, _ = publish(github=github, reader=Reader(items))
            self.assertEqual(result.status, "BLOCKED")
            self.assertEqual(result.reason, "CHANGESET_FINALITY_AMBIGUOUS")
            self.assertEqual(github.writes, [])

    def test_nonterminal_and_wrong_observation_identity_block(self):
        for obs, reason in (
            (observation(False), "JULES_SESSION_NOT_COMPLETED_SUCCESSFULLY"),
            (observation(True, "session-b"), "OBSERVATION_OPERATION_MISMATCH"),
        ):
            github = FakeGitHub()
            result, _, _ = publish(github=github, obs=obs)
            self.assertEqual(result.status, "BLOCKED")
            self.assertEqual(result.reason, reason)
            self.assertEqual(github.writes, [])

    def test_candidate_base_mismatch_and_base_drift_block(self):
        github = FakeGitHub()
        result, _, _ = publish(github=github, reader=Reader([evidence(base="3" * 40)]))
        self.assertEqual(result.reason, "CHANGESET_BASE_MISMATCH")
        self.assertEqual(github.writes, [])

        github = FakeGitHub()
        github.base_sequence = [BASE, "4" * 40]
        result, _, _ = publish(github=github)
        self.assertEqual(result.reason, "EXPECTED_BASE_DRIFT_BEFORE_WRITE")
        self.assertEqual(github.writes, [])

    def test_malformed_binary_traversal_and_scope_violation_block(self):
        bad_patches = (
            "diff --git a/a b/a\nGIT binary patch\n--- a/a\n+++ b/a\n@@ -0,0 +1 @@\n+x\n",
            "diff --git a/../x b/../x\n--- a/../x\n+++ b/../x\n@@ -0,0 +1 @@\n+x\n",
            "diff --git a/other.txt b/other.txt\n--- a/other.txt\n+++ b/other.txt\n@@ -0,0 +1 @@\n+x\n",
        )
        for patch in bad_patches:
            github = FakeGitHub()
            result, _, _ = publish(github=github, reader=Reader([evidence(patch=patch)]))
            self.assertEqual(result.status, "BLOCKED")
            self.assertEqual(github.writes, [])

    def test_rename_source_and_destination_are_both_scoped(self):
        patch = """diff --git a/src/old.txt b/app.txt
similarity index 50%
rename from src/old.txt
rename to app.txt
--- a/src/old.txt
+++ b/app.txt
@@ -1 +1 @@
-old
+new
"""
        narrow = task(ObjectiveScope(allowed_paths=("app.txt",)))
        github = FakeGitHub()
        result, _, _ = publish(github=github, reader=Reader([evidence(patch=patch)]), t=narrow)
        self.assertEqual(result.reason, "PATCH_SCOPE_VIOLATION")
        self.assertEqual(github.writes, [])

    def test_wrong_workstream_or_operation_binding_blocks_before_writes(self):
        github = FakeGitHub()
        result, _, _ = publish(github=github, op=operation(task_id="other"))
        self.assertEqual(result.status, "BLOCKED")
        self.assertEqual(github.writes, [])

        github = FakeGitHub()
        result, _, _ = publish(github=github, ws=lane(task_id="other"))
        self.assertEqual(result.status, "BLOCKED")
        self.assertEqual(github.writes, [])

    def test_default_branch_alias_and_branch_collision_block(self):
        github = FakeGitHub()
        result, _, _ = publish(github=github, branch="main", ws=lane(branch="main"))
        self.assertEqual(result.reason, "DEFAULT_BRANCH_WRITE_FORBIDDEN")
        self.assertEqual(github.writes, [])

        github = FakeGitHub()
        github.branch_sha = "5" * 40
        result, _, _ = publish(github=github)
        self.assertEqual(result.reason, "PUBLICATION_TARGET_ALREADY_EXISTS")
        self.assertEqual(github.writes, [])

    def test_postcondition_head_scope_and_draft_mismatch_are_uncertain(self):
        github = FakeGitHub()
        github.post_branch_override = "9" * 40
        result, _, _ = publish(github=github)
        self.assertEqual(result.status, "UNCERTAIN")
        self.assertEqual(result.reason, "BRANCH_POSTCONDITION_FAILED")

        github = FakeGitHub()
        github.compare_override = [{"filename": "other.txt", "status": "modified"}]
        result, _, _ = publish(github=github)
        self.assertEqual(result.reason, "PUBLISHED_SCOPE_POSTCONDITION_FAILED")

        github = FakeGitHub()
        original = github.create_draft_pr
        def not_draft(**kwargs):
            payload = original(**kwargs)
            github.pr["draft"] = False
            return payload
        github.create_draft_pr = not_draft
        result, _, _ = publish(github=github)
        self.assertEqual(result.reason, "PR_STATE_POSTCONDITION_FAILED")

    def test_publication_surface_has_no_ready_or_merge_argument(self):
        import inspect
        params = inspect.signature(publish_jules_changeset_to_draft_pr).parameters
        for forbidden in ("ready", "merge", "auto_merge", "approve_plan", "send_message"):
            self.assertNotIn(forbidden, params)


if __name__ == "__main__":
    unittest.main()
