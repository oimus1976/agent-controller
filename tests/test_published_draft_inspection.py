import inspect
import unittest
from unittest import mock

from agent_controller.jules_draft_publication import DraftPublicationResult
from agent_controller.provider_contract import ObjectiveScope, TaskBinding
from agent_controller.published_draft_inspection import inspect_published_draft_pr, inspect_published_draft_pr_live
from agent_controller.workstream import WorkstreamBinding


HEAD = "a" * 40
BRANCH = "controller/task-a"
REPO = "oimus1976/agent-controller"


def task():
    return TaskBinding(
        controller_task_id="task-a",
        operation_id="op-a",
        provider="jules",
        repo=REPO,
        expected_start_ref="refs/heads/main",
        expected_start_sha="b" * 40,
        objective_scope=ObjectiveScope(allowed_paths=("agent_controller/**", "tests/**")),
        requested_capability="IMPLEMENT",
        allowed_effects=("DRAFT_PR_CREATE",),
        forbidden_effects=("READY", "MERGE"),
        approval_policy_id="policy",
        created_at="2026-09-01T00:00:00Z",
    )


def lane(branch=BRANCH, task_id="task-a"):
    return WorkstreamBinding(
        workstream_id="lane-a",
        repo=REPO,
        root_work_item_ref="issue-133",
        task_ids=(task_id,),
        branch_refs=(branch,),
    )


def publication(status="PASS", branch=BRANCH, head=HEAD, pr=77):
    return DraftPublicationResult(status=status, branch=branch, commit_sha=head, pr_number=pr)


def pr_snapshot(*, head=HEAD, branch=BRANCH, base="main", draft=True, state="open", merged=False, repo=REPO, number=77):
    return {
        "number": number,
        "state": state,
        "draft": draft,
        "merged": merged,
        "head": {"ref": branch, "sha": head, "repo": {"full_name": repo}},
        "base": {"ref": base},
    }


class Harness:
    def __init__(self):
        self.reads = 0
        self.inspections = 0
        self.before = pr_snapshot()
        self.after = pr_snapshot()
        self.evidence = {
            "head_sha": HEAD,
            "base_branch": "main",
            "draft": True,
            "merged": False,
            "state": "open",
            "classification": "NEEDS_REVIEW",
            "actions_ci_status": "PENDING",
            "scope_status": "SATISFIED",
        }
        self.inspect_args = None

    def read_pr(self, repo, pr_number):
        self.reads += 1
        return dict(self.before if self.reads == 1 else self.after)

    def inspect(self, owner, repo, pr_number, scope_policy):
        self.inspections += 1
        self.inspect_args = (owner, repo, pr_number, scope_policy)
        return dict(self.evidence)


def run(pub=None, t=None, ws=None, harness=None):
    h = harness or Harness()
    result = inspect_published_draft_pr(
        publication=pub or publication(),
        task=t or task(),
        workstream=ws or lane(),
        read_pr=h.read_pr,
        inspector=h.inspect,
    )
    return result, h


class PublishedDraftInspectionTests(unittest.TestCase):
    def test_exact_publication_reuses_existing_inspector(self):
        result, h = run()
        self.assertEqual(result.status, "PASS")
        self.assertEqual(result.classification, "NEEDS_REVIEW")
        self.assertEqual(result.actions_ci_status, "PENDING")
        self.assertEqual(result.scope_status, "SATISFIED")
        self.assertEqual(h.reads, 2)
        self.assertEqual(h.inspections, 1)
        self.assertEqual(h.inspect_args[:3], ("oimus1976", "agent-controller", 77))
        self.assertEqual(h.inspect_args[3]["allowed_paths"], ["agent_controller/**", "tests/**"])

    def test_nonpass_and_malformed_publication_block_before_reads(self):
        cases = (
            publication(status="BLOCKED"),
            publication(pr=0),
            publication(branch="feature/x"),
            publication(head="bad"),
        )
        for pub in cases:
            result, h = run(pub=pub)
            self.assertEqual(result.status, "BLOCKED")
            self.assertEqual(h.reads, 0)
            self.assertEqual(h.inspections, 0)

    def test_wrong_workstream_blocks_before_reads(self):
        result, h = run(ws=lane(task_id="other"))
        self.assertEqual(result.status, "BLOCKED")
        self.assertEqual(h.reads, 0)
        self.assertEqual(h.inspections, 0)

        result, h = run(ws=lane(branch="controller/other"))
        self.assertEqual(result.status, "BLOCKED")
        self.assertEqual(h.reads, 0)
        self.assertEqual(h.inspections, 0)

    def test_pr_identity_state_repo_and_base_mismatch_block_before_inspector(self):
        snapshots = (
            pr_snapshot(head="c" * 40),
            pr_snapshot(branch="controller/other"),
            pr_snapshot(base="develop"),
            pr_snapshot(draft=False),
            pr_snapshot(state="closed"),
            pr_snapshot(merged=True),
            pr_snapshot(repo="other/repo"),
            pr_snapshot(number=78),
        )
        for snapshot in snapshots:
            h = Harness()
            h.before = snapshot
            result, h = run(harness=h)
            self.assertEqual(result.status, "BLOCKED")
            self.assertEqual(h.inspections, 0)

    def test_inspector_identity_or_state_drift_is_uncertain(self):
        for key, value in (
            ("head_sha", "c" * 40),
            ("base_branch", "develop"),
            ("draft", False),
            ("state", "closed"),
            ("merged", True),
        ):
            h = Harness()
            h.evidence[key] = value
            result, _ = run(harness=h)
            self.assertEqual(result.status, "UNCERTAIN")
            self.assertEqual(h.reads, 1)

    def test_post_inspection_pr_drift_is_uncertain(self):
        h = Harness()
        h.after = pr_snapshot(head="c" * 40)
        result, h = run(harness=h)
        self.assertEqual(result.status, "UNCERTAIN")
        self.assertEqual(result.reason, "PR_DRIFT_AFTER_INSPECTION")
        self.assertEqual(h.inspections, 1)

    def test_existing_inspector_statuses_are_preserved_not_reclassified(self):
        for classification, ci in (
            ("NEEDS_REVIEW", "PENDING"),
            ("NEEDS_REVIEW", "FAIL"),
            ("REVIEW_READY", "PASS"),
        ):
            h = Harness()
            h.evidence["classification"] = classification
            h.evidence["actions_ci_status"] = ci
            result, _ = run(harness=h)
            self.assertEqual(result.status, "PASS")
            self.assertEqual(result.classification, classification)
            self.assertEqual(result.actions_ci_status, ci)

    def test_malformed_inspector_evidence_fails_closed(self):
        h = Harness()
        h.evidence.pop("classification")
        result, _ = run(harness=h)
        self.assertEqual(result.status, "UNCERTAIN")

    def test_live_wrapper_delegates_to_existing_inspector_only(self):
        evidence = {
            "head_sha": HEAD,
            "base_branch": "main",
            "draft": True,
            "merged": False,
            "state": "open",
            "classification": "NEEDS_REVIEW",
            "actions_ci_status": "PENDING",
            "scope_status": "SATISFIED",
        }
        with mock.patch("agent_controller.inspector.get_pr_details", side_effect=[pr_snapshot(), pr_snapshot()]) as read_mock, mock.patch(
            "agent_controller.inspector.inspect_pr", return_value=evidence
        ) as inspect_mock:
            result = inspect_published_draft_pr_live(publication=publication(), task=task(), workstream=lane())
        self.assertEqual(result.status, "PASS")
        self.assertEqual(read_mock.call_count, 2)
        inspect_mock.assert_called_once_with(
            "oimus1976",
            "agent-controller",
            77,
            {"allowed_paths": ["agent_controller/**", "tests/**"], "denied_paths": []},
        )

    def test_surfaces_have_no_ready_or_merge_argument(self):
        for function in (inspect_published_draft_pr, inspect_published_draft_pr_live):
            params = inspect.signature(function).parameters
            for forbidden in ("ready", "merge", "auto_merge", "approve_plan", "send_message"):
                self.assertNotIn(forbidden, params)


if __name__ == "__main__":
    unittest.main()
