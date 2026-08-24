import unittest

from agent_controller.artifact_verifier import verify_github_artifact
from agent_controller.provider_contract import (
    ArtifactEvidence,
    ObjectiveScope,
    ProviderOperationRef,
    TaskBinding,
    VerificationResult,
)


class FakeGitHub:
    def __init__(self, *, state="open", merged=False, number=15, head_ref="refs/heads/work", head_sha="new-sha"):
        self.state = state
        self.merged = merged
        self.number = number
        self.head_ref = head_ref
        self.head_sha = head_sha
        self.pr_calls = []
        self.compare_calls = []
        self.ref_calls = []

    def get_ref_sha(self, repo, ref):
        self.ref_calls.append((repo, ref))
        return self.head_sha

    def get_pull_request(self, repo, pr_number):
        self.pr_calls.append((repo, pr_number))
        return {
            "number": self.number,
            "state": self.state,
            "merged": self.merged,
            "head_ref": self.head_ref,
            "head_sha": self.head_sha,
        }

    def compare_commits(self, repo, base_sha, head_sha):
        self.compare_calls.append((repo, base_sha, head_sha))
        return {
            "merge_base_sha": "start-sha",
            "files": [{"filename": "agent_controller/example.py", "changes": 1}],
        }


def task(provider="jules"):
    return TaskBinding(
        controller_task_id="task-1",
        operation_id="op-1",
        provider=provider,
        repo="oimus1976/agent-controller",
        expected_start_ref="refs/heads/main",
        expected_start_sha="start-sha",
        objective_scope=ObjectiveScope(allowed_paths=("agent_controller/**",)),
        requested_capability="IMPLEMENT",
        allowed_effects=("CREATE_COMMIT", "CREATE_PR"),
        forbidden_effects=("MERGE",),
        approval_policy_id="policy-1",
        created_at="2026-08-24T01:00:00Z",
    )


def operation(provider="jules"):
    return ProviderOperationRef(
        provider=provider,
        provider_operation_id=f"{provider}-op",
        provider_url=None,
        controller_task_id="task-1",
        operation_id="op-1",
    )


def evidence(provider="jules", *, artifact_id="15", ref="refs/heads/work", sha="new-sha"):
    return ArtifactEvidence(
        provider=provider,
        provider_operation_id=f"{provider}-op",
        artifact_kind="pull_request",
        provider_artifact_id=artifact_id,
        provider_reported_ref=ref,
        provider_reported_sha=sha,
        content_hash=None,
        observed_at="2026-08-24T01:05:00Z",
        freshness_basis="provider_report",
    )


class TestPullRequestArtifactVerifier(unittest.TestCase):
    def test_open_pr_identity_head_ancestry_and_scope_can_pass_for_both_providers(self):
        for provider in ("jules", "codex"):
            github = FakeGitHub()
            result = verify_github_artifact(
                task=task(provider),
                operation=operation(provider),
                evidence=evidence(provider),
                github=github,
            )
            self.assertEqual(result.verification_result, VerificationResult.PASS)
            self.assertTrue(result.independently_verified)
            self.assertEqual(result.verified_sha, "new-sha")
            self.assertEqual(github.pr_calls, [("oimus1976/agent-controller", 15)])
            self.assertEqual(github.ref_calls, [])
            self.assertEqual(len(github.compare_calls), 1)

    def test_closed_or_merged_pr_fails(self):
        for github in (FakeGitHub(state="closed"), FakeGitHub(merged=True)):
            result = verify_github_artifact(
                task=task(), operation=operation(), evidence=evidence(), github=github
            )
            self.assertEqual(result.verification_result, VerificationResult.FAIL)
            self.assertFalse(result.independently_verified)
            self.assertEqual(github.compare_calls, [])

    def test_pr_number_ref_or_sha_mismatch_fails(self):
        cases = (
            FakeGitHub(number=16),
            FakeGitHub(head_ref="refs/heads/other"),
            FakeGitHub(head_sha="different-sha"),
        )
        for github in cases:
            result = verify_github_artifact(
                task=task(), operation=operation(), evidence=evidence(), github=github
            )
            self.assertEqual(result.verification_result, VerificationResult.FAIL)
            self.assertFalse(result.independently_verified)

    def test_missing_or_invalid_pr_identity_blocks_without_pr_read(self):
        for artifact_id in (None, "", "not-a-number", "0"):
            github = FakeGitHub()
            result = verify_github_artifact(
                task=task(),
                operation=operation(),
                evidence=evidence(artifact_id=artifact_id),
                github=github,
            )
            self.assertEqual(result.verification_result, VerificationResult.BLOCKED)
            self.assertEqual(github.pr_calls, [])

    def test_client_without_pr_read_capability_blocks(self):
        class CodeOnlyGitHub:
            def get_ref_sha(self, repo, ref):
                return "new-sha"

            def compare_commits(self, repo, base_sha, head_sha):
                return {"merge_base_sha": base_sha, "files": []}

        result = verify_github_artifact(
            task=task(),
            operation=operation(),
            evidence=evidence(),
            github=CodeOnlyGitHub(),
        )
        self.assertEqual(result.verification_result, VerificationResult.BLOCKED)


if __name__ == "__main__":
    unittest.main()
