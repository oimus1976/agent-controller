import unittest

from agent_controller.metered_handoff import run_metered_verified_handoff
from agent_controller.provider_adapters import JulesObservationAdapter
from agent_controller.provider_artifacts import JulesArtifactAdapter
from agent_controller.provider_contract import ObjectiveScope, ProviderOperationRef, TaskBinding, VerificationResult
from agent_controller.resource_usage import ResourceUsageSource


class FakeObservationClient:
    def __init__(self, payload):
        self.payload = payload

    def get_operation_raw(self, operation):
        return self.payload


class FakeArtifactClient:
    def __init__(self, payloads):
        self.payloads = payloads

    def list_artifacts_raw(self, operation):
        return list(self.payloads)


class FakeGitHub:
    def get_ref_sha(self, repo, ref):
        return "new-sha"

    def compare_commits(self, repo, base_sha, head_sha):
        return {
            "merge_base_sha": "start-sha",
            "files": [{"filename": "agent_controller/example.py", "changes": 1}],
        }


def task():
    return TaskBinding(
        controller_task_id="task-1",
        operation_id="op-1",
        provider="jules",
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
        created_at="2026-08-26T00:00:00Z",
    )


def operation(*, controller_task_id="task-1"):
    return ProviderOperationRef(
        provider="jules",
        provider_operation_id="jules-op-1",
        provider_url=None,
        controller_task_id=controller_task_id,
        operation_id="op-1",
    )


def observer(payload=None):
    return JulesObservationAdapter(
        FakeObservationClient(payload or {"status": "COMPLETED", "updated_at": "2026-08-26T00:01:00Z"}),
        lambda: "2026-08-26T00:02:00Z",
    )


def collector(payloads=None):
    return JulesArtifactAdapter(
        FakeArtifactClient(
            payloads
            or [
                {
                    "kind": "commit",
                    "id": "artifact-1",
                    "ref": "refs/heads/work",
                    "sha": "new-sha",
                }
            ]
        ),
        lambda: "2026-08-26T00:03:00Z",
    )


class MeteredVerifiedHandoffTests(unittest.TestCase):
    def test_success_counts_controller_owned_read_boundaries(self):
        result = run_metered_verified_handoff(
            task=task(),
            operation=operation(),
            observer=observer(),
            artifact_collector=collector(),
            github=FakeGitHub(),
            controller_run_id="run-1",
        )

        self.assertEqual(VerificationResult.PASS, result.handoff.verification_result)
        usage = result.resource_usage
        self.assertIs(ResourceUsageSource.CONTROLLER_MEASURED, usage.source)
        self.assertEqual("task-1", usage.controller_task_id)
        self.assertEqual("op-1", usage.operation_id)
        self.assertEqual("mvp-v1", usage.operation_version)
        self.assertEqual("jules", usage.provider)
        self.assertEqual("run-1", usage.controller_run_id)
        self.assertEqual(4, usage.tool_call_count)
        self.assertEqual(0, usage.retry_count)
        self.assertEqual(0, usage.files_read_count)
        self.assertEqual(0, usage.bytes_read)
        self.assertIsNone(usage.uncached_input_tokens)
        self.assertIsNone(usage.output_tokens)
        self.assertIsNone(usage.allowance_units)

    def test_binding_failure_measures_zero_external_reads(self):
        result = run_metered_verified_handoff(
            task=task(),
            operation=operation(controller_task_id="wrong-task"),
            observer=observer(),
            artifact_collector=collector(),
            github=FakeGitHub(),
            controller_run_id="run-2",
        )

        self.assertEqual(VerificationResult.BLOCKED, result.handoff.verification_result)
        self.assertEqual(0, result.resource_usage.tool_call_count)

    def test_non_artifact_ready_stops_after_observation_read(self):
        result = run_metered_verified_handoff(
            task=task(),
            operation=operation(),
            observer=observer({"status": "WORKING"}),
            artifact_collector=collector(),
            github=FakeGitHub(),
            controller_run_id="run-3",
        )

        self.assertEqual(VerificationResult.BLOCKED, result.handoff.verification_result)
        self.assertEqual(1, result.resource_usage.tool_call_count)

    def test_empty_artifact_set_stops_after_observation_and_collection(self):
        result = run_metered_verified_handoff(
            task=task(),
            operation=operation(),
            observer=observer(),
            artifact_collector=collector([]),
            github=FakeGitHub(),
            controller_run_id="run-4",
        )

        self.assertEqual(VerificationResult.BLOCKED, result.handoff.verification_result)
        self.assertEqual(2, result.resource_usage.tool_call_count)


if __name__ == "__main__":
    unittest.main()
