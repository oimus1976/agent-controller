import unittest

from agent_controller.artifact_verifier import verify_github_artifact
from agent_controller.provider_contract import (
    ArtifactEvidence,
    ObjectiveScope,
    ProviderOperationRef,
    TaskBinding,
    VerificationResult,
)


class NoReadGitHub:
    def __init__(self):
        self.ref_calls = 0
        self.compare_calls = 0

    def get_ref_sha(self, repo, ref):
        self.ref_calls += 1
        return "new-sha"

    def compare_commits(self, repo, base_sha, head_sha):
        self.compare_calls += 1
        return {"merge_base_sha": base_sha, "files": []}


class TestArtifactVerifierScope(unittest.TestCase):
    def test_unspecified_scope_blocks_before_github_read(self):
        task = TaskBinding(
            controller_task_id="task-1",
            operation_id="op-1",
            provider="jules",
            repo="oimus1976/agent-controller",
            expected_start_ref="refs/heads/main",
            expected_start_sha="start-sha",
            objective_scope=ObjectiveScope(),
            requested_capability="IMPLEMENT",
            allowed_effects=("CREATE_COMMIT",),
            forbidden_effects=("MERGE",),
            approval_policy_id="policy-1",
            created_at="2026-08-24T01:00:00Z",
        )
        operation = ProviderOperationRef(
            provider="jules",
            provider_operation_id="provider-op-1",
            provider_url=None,
            controller_task_id="task-1",
            operation_id="op-1",
        )
        evidence = ArtifactEvidence(
            provider="jules",
            provider_operation_id="provider-op-1",
            artifact_kind="commit",
            provider_artifact_id="artifact-1",
            provider_reported_ref="refs/heads/work",
            provider_reported_sha="new-sha",
            content_hash=None,
            observed_at="2026-08-24T01:01:00Z",
            freshness_basis="provider_report",
        )
        github = NoReadGitHub()

        result = verify_github_artifact(
            task=task,
            operation=operation,
            evidence=evidence,
            github=github,
        )

        self.assertEqual(result.verification_result, VerificationResult.BLOCKED)
        self.assertFalse(result.independently_verified)
        self.assertEqual(github.ref_calls, 0)
        self.assertEqual(github.compare_calls, 0)


if __name__ == "__main__":
    unittest.main()
