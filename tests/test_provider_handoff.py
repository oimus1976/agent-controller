import unittest

from agent_controller.provider_adapters import (
    CodexObservationAdapter,
    JulesObservationAdapter,
)
from agent_controller.provider_artifacts import (
    CodexArtifactAdapter,
    JulesArtifactAdapter,
)
from agent_controller.provider_contract import (
    ControllerState,
    ObjectiveScope,
    ProviderOperationRef,
    TaskBinding,
    VerificationResult,
)
from agent_controller.provider_handoff import run_verified_handoff


class FakeObservationClient:
    def __init__(self, payload):
        self.payload = payload
        self.calls = 0

    def get_operation_raw(self, operation):
        self.calls += 1
        return self.payload


class FakeArtifactClient:
    def __init__(self, payloads):
        self.payloads = payloads
        self.calls = 0

    def list_artifacts_raw(self, operation):
        self.calls += 1
        return list(self.payloads)


class FakeGitHub:
    def __init__(self):
        self.ref_calls = []
        self.compare_calls = []

    def get_ref_sha(self, repo, ref):
        self.ref_calls.append((repo, ref))
        return "new-sha"

    def compare_commits(self, repo, base_sha, head_sha):
        self.compare_calls.append((repo, base_sha, head_sha))
        return {
            "merge_base_sha": "start-sha",
            "files": [{"filename": "agent_controller/example.py", "changes": 1}],
        }


def task(provider):
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


def operation(provider):
    return ProviderOperationRef(
        provider=provider,
        provider_operation_id=f"{provider}-provider-op",
        provider_url=None,
        controller_task_id="task-1",
        operation_id="op-1",
    )


class TestProviderHandoff(unittest.TestCase):
    def _run(self, provider):
        if provider == "jules":
            observation_client = FakeObservationClient(
                {"status": "COMPLETED", "updated_at": "2026-08-24T01:10:00Z"}
            )
            observer = JulesObservationAdapter(
                observation_client, lambda: "2026-08-24T01:11:00Z"
            )
            artifact_client = FakeArtifactClient([
                {
                    "kind": "commit",
                    "id": "artifact-1",
                    "ref": "refs/heads/work",
                    "sha": "new-sha",
                }
            ])
            collector = JulesArtifactAdapter(
                artifact_client, lambda: "2026-08-24T01:12:00Z"
            )
        else:
            observation_client = FakeObservationClient(
                {
                    "status": "done",
                    "result": "success",
                    "updated_at": "2026-08-24T01:10:00Z",
                }
            )
            observer = CodexObservationAdapter(
                observation_client, lambda: "2026-08-24T01:11:00Z"
            )
            artifact_client = FakeArtifactClient([
                {
                    "kind": "commit",
                    "id": "artifact-1",
                    "ref": "refs/heads/work",
                    "sha": "new-sha",
                }
            ])
            collector = CodexArtifactAdapter(
                artifact_client, lambda: "2026-08-24T01:12:00Z"
            )

        github = FakeGitHub()
        result = run_verified_handoff(
            task=task(provider),
            operation=operation(provider),
            observer=observer,
            artifact_collector=collector,
            github=github,
        )
        return result, observation_client, artifact_client, github

    def test_jules_and_codex_reach_verified_artifact_through_same_flow(self):
        normalized = []
        for provider in ("jules", "codex"):
            result, observation_client, artifact_client, github = self._run(provider)

            self.assertTrue(result.binding.valid)
            self.assertEqual(result.observation.mapped_state, ControllerState.ARTIFACT_READY)
            self.assertEqual(len(result.artifacts), 1)
            artifact = result.artifacts[0]
            self.assertTrue(artifact.independently_verified)
            self.assertEqual(artifact.verification_result, VerificationResult.PASS)
            self.assertEqual(artifact.verified_sha, "new-sha")
            self.assertEqual(observation_client.calls, 1)
            self.assertEqual(artifact_client.calls, 1)
            self.assertEqual(len(github.ref_calls), 1)
            self.assertEqual(len(github.compare_calls), 1)
            normalized.append(
                (
                    result.observation.mapped_state,
                    artifact.verification_result,
                    artifact.verified_sha,
                )
            )

        self.assertEqual(normalized[0], normalized[1])

    def test_operation_binding_failure_stops_before_provider_or_github_reads(self):
        observation_client = FakeObservationClient({"status": "COMPLETED"})
        artifact_client = FakeArtifactClient([])
        observer = JulesObservationAdapter(
            observation_client, lambda: "2026-08-24T01:11:00Z"
        )
        collector = JulesArtifactAdapter(
            artifact_client, lambda: "2026-08-24T01:12:00Z"
        )
        github = FakeGitHub()
        bad_operation = ProviderOperationRef(
            provider="jules",
            provider_operation_id="jules-provider-op",
            provider_url=None,
            controller_task_id="other-task",
            operation_id="op-1",
        )

        result = run_verified_handoff(
            task=task("jules"),
            operation=bad_operation,
            observer=observer,
            artifact_collector=collector,
            github=github,
        )

        self.assertFalse(result.binding.valid)
        self.assertEqual(result.binding.reason, "CONTROLLER_TASK_ID_MISMATCH")
        self.assertIsNone(result.observation)
        self.assertEqual(result.artifacts, ())
        self.assertEqual(observation_client.calls, 0)
        self.assertEqual(artifact_client.calls, 0)
        self.assertEqual(github.ref_calls, [])

    def test_artifact_binding_failure_stops_before_github_verification(self):
        observation_client = FakeObservationClient(
            {"status": "COMPLETED", "updated_at": "2026-08-24T01:10:00Z"}
        )
        observer = JulesObservationAdapter(
            observation_client, lambda: "2026-08-24T01:11:00Z"
        )

        class WrongArtifactCollector:
            def collect_artifacts(self, op):
                from agent_controller.provider_contract import ArtifactEvidence
                return [
                    ArtifactEvidence(
                        provider="codex",
                        provider_operation_id=op.provider_operation_id,
                        artifact_kind="commit",
                        provider_artifact_id="bad",
                        provider_reported_ref="refs/heads/work",
                        provider_reported_sha="new-sha",
                        content_hash=None,
                        observed_at="2026-08-24T01:12:00Z",
                        freshness_basis="provider_report",
                    )
                ]

        github = FakeGitHub()
        result = run_verified_handoff(
            task=task("jules"),
            operation=operation("jules"),
            observer=observer,
            artifact_collector=WrongArtifactCollector(),
            github=github,
        )

        self.assertFalse(result.binding.valid)
        self.assertEqual(result.binding.reason, "ARTIFACT_PROVIDER_MISMATCH")
        self.assertEqual(github.ref_calls, [])
        self.assertEqual(github.compare_calls, [])


if __name__ == "__main__":
    unittest.main()
