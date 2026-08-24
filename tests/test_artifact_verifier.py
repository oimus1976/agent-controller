import unittest

from agent_controller.artifact_verifier import (
    GitHubArtifactReadClient,
    verify_github_artifact,
)
from agent_controller.provider_contract import (
    ArtifactEvidence,
    ObjectiveScope,
    ProviderOperationRef,
    TaskBinding,
    VerificationResult,
    VerificationSource,
)


class FakeGitHub:
    def __init__(self, *, ref_sha="new-sha", merge_base_sha="start-sha", files=None):
        self.ref_sha = ref_sha
        self.merge_base_sha = merge_base_sha
        self.files = files if files is not None else [
            {"filename": "agent_controller/example.py", "changes": 1}
        ]
        self.ref_calls = []
        self.compare_calls = []
        self.raise_ref = False
        self.raise_compare = False

    def get_ref_sha(self, repo, ref):
        self.ref_calls.append((repo, ref))
        if self.raise_ref:
            raise RuntimeError("ref unavailable")
        return self.ref_sha

    def compare_commits(self, repo, base_sha, head_sha):
        self.compare_calls.append((repo, base_sha, head_sha))
        if self.raise_compare:
            raise RuntimeError("compare unavailable")
        return {
            "merge_base_sha": self.merge_base_sha,
            "files": self.files,
        }


class ReadOnlyShape:
    def get_ref_sha(self, repo, ref):
        return "sha"

    def compare_commits(self, repo, base_sha, head_sha):
        return {"merge_base_sha": base_sha, "files": []}


def make_task(provider="jules"):
    return TaskBinding(
        controller_task_id="task-1",
        operation_id="op-1",
        provider=provider,
        repo="oimus1976/agent-controller",
        expected_start_ref="refs/heads/main",
        expected_start_sha="start-sha",
        objective_scope=ObjectiveScope(
            allowed_paths=("agent_controller/**", "tests/**"),
            denied_paths=("secrets/**",),
        ),
        requested_capability="IMPLEMENT",
        allowed_effects=("CREATE_COMMIT",),
        forbidden_effects=("MERGE",),
        approval_policy_id="policy-1",
        created_at="2026-08-24T01:00:00Z",
    )


def make_operation(provider="jules", provider_operation_id="provider-op-1"):
    return ProviderOperationRef(
        provider=provider,
        provider_operation_id=provider_operation_id,
        provider_url=None,
        controller_task_id="task-1",
        operation_id="op-1",
    )


def make_evidence(provider="jules", *, ref="refs/heads/work", sha="new-sha", provider_operation_id="provider-op-1"):
    return ArtifactEvidence(
        provider=provider,
        provider_operation_id=provider_operation_id,
        artifact_kind="commit",
        provider_artifact_id="artifact-1",
        provider_reported_ref=ref,
        provider_reported_sha=sha,
        content_hash=None,
        observed_at="2026-08-24T01:30:00Z",
        freshness_basis="provider_report",
    )


def verify(provider="jules", *, task=None, operation=None, evidence=None, github=None):
    return verify_github_artifact(
        task=task or make_task(provider),
        operation=operation or make_operation(provider),
        evidence=evidence or make_evidence(provider),
        github=github or FakeGitHub(),
    )


class TestArtifactVerifier(unittest.TestCase):
    def test_read_client_protocol_is_read_only_shape(self):
        self.assertIsInstance(ReadOnlyShape(), GitHubArtifactReadClient)
        source_names = set(dir(GitHubArtifactReadClient))
        for forbidden in ("merge", "update_ref", "create_file", "delete_file", "deploy"):
            self.assertNotIn(forbidden, source_names)

    def test_successful_verification_promotes_only_after_github_facts_pass(self):
        result = verify()
        self.assertTrue(result.independently_verified)
        self.assertEqual(result.verification_source, VerificationSource.GITHUB)
        self.assertEqual(result.verification_result, VerificationResult.PASS)
        self.assertEqual(result.verified_repo, "oimus1976/agent-controller")
        self.assertEqual(result.verified_ref, "refs/heads/work")
        self.assertEqual(result.verified_sha, "new-sha")

    def test_provider_name_does_not_change_verification_rules(self):
        jules = verify("jules")
        codex = verify("codex")
        self.assertEqual(jules.verification_result, codex.verification_result)
        self.assertEqual(jules.verified_sha, codex.verified_sha)

    def test_provider_reported_sha_mismatch_fails(self):
        result = verify(evidence=make_evidence(sha="claimed-sha"))
        self.assertFalse(result.independently_verified)
        self.assertEqual(result.verification_result, VerificationResult.FAIL)

    def test_unchanged_start_sha_fails_freshness(self):
        result = verify(
            evidence=make_evidence(sha="start-sha"),
            github=FakeGitHub(ref_sha="start-sha"),
        )
        self.assertEqual(result.verification_result, VerificationResult.FAIL)

    def test_wrong_ancestry_fails(self):
        result = verify(github=FakeGitHub(merge_base_sha="other-base"))
        self.assertEqual(result.verification_result, VerificationResult.FAIL)

    def test_scope_violation_fails_for_both_providers(self):
        files = [{"filename": "secrets/private.txt", "changes": 1}]
        for provider in ("jules", "codex"):
            result = verify(provider, github=FakeGitHub(files=files))
            self.assertEqual(result.verification_result, VerificationResult.FAIL)
            self.assertFalse(result.independently_verified)

    def test_missing_required_binding_is_blocked_without_github_read(self):
        task = make_task()
        task = TaskBinding(
            controller_task_id=task.controller_task_id,
            operation_id=task.operation_id,
            provider=task.provider,
            repo=None,
            expected_start_ref=task.expected_start_ref,
            expected_start_sha=task.expected_start_sha,
            objective_scope=task.objective_scope,
            requested_capability=task.requested_capability,
            allowed_effects=task.allowed_effects,
            forbidden_effects=task.forbidden_effects,
            approval_policy_id=task.approval_policy_id,
            created_at=task.created_at,
        )
        github = FakeGitHub()
        result = verify(task=task, github=github)
        self.assertEqual(result.verification_result, VerificationResult.BLOCKED)
        self.assertEqual(github.ref_calls, [])

    def test_missing_provider_ref_is_blocked(self):
        result = verify(evidence=make_evidence(ref=None))
        self.assertEqual(result.verification_result, VerificationResult.BLOCKED)

    def test_ref_read_uncertainty_is_not_failure_or_pass(self):
        github = FakeGitHub()
        github.raise_ref = True
        result = verify(github=github)
        self.assertEqual(result.verification_result, VerificationResult.UNCERTAIN)
        self.assertFalse(result.independently_verified)

    def test_compare_uncertainty_is_not_failure_or_pass(self):
        github = FakeGitHub()
        github.raise_compare = True
        result = verify(github=github)
        self.assertEqual(result.verification_result, VerificationResult.UNCERTAIN)
        self.assertFalse(result.independently_verified)

    def test_binding_mismatch_blocks_before_github_read(self):
        github = FakeGitHub()
        result = verify(
            operation=make_operation("jules", provider_operation_id="provider-op-1"),
            evidence=make_evidence("jules", provider_operation_id="other-provider-op"),
            github=github,
        )
        self.assertEqual(result.verification_result, VerificationResult.BLOCKED)
        self.assertFalse(result.independently_verified)
        self.assertEqual(github.ref_calls, [])
        self.assertEqual(github.compare_calls, [])

    def test_cross_provider_artifact_blocks_before_github_read(self):
        github = FakeGitHub()
        result = verify(
            task=make_task("jules"),
            operation=make_operation("jules"),
            evidence=make_evidence("codex"),
            github=github,
        )
        self.assertEqual(result.verification_result, VerificationResult.BLOCKED)
        self.assertEqual(github.ref_calls, [])


if __name__ == "__main__":
    unittest.main()
