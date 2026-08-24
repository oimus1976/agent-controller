import inspect
import unittest

from agent_controller.provider_artifacts import (
    CodexArtifactAdapter,
    JulesArtifactAdapter,
    ProviderArtifactReadClient,
    map_codex_artifact,
    map_jules_artifact,
)
from agent_controller.provider_contract import (
    ProviderOperationRef,
    VerificationResult,
    VerificationSource,
)


class FixtureArtifactClient:
    def __init__(self, artifacts):
        self.artifacts = artifacts
        self.calls = 0

    def list_artifacts_raw(self, operation):
        self.calls += 1
        return list(self.artifacts)


class MissingArtifactReadClient:
    pass


def operation(provider):
    return ProviderOperationRef(
        provider=provider,
        provider_operation_id=f"{provider}-operation-1",
        provider_url=None,
        controller_task_id="controller-task-1",
        operation_id="operation-1",
    )


class TestProviderArtifactBoundaries(unittest.TestCase):
    def test_artifact_read_client_is_single_read_method_protocol(self):
        client = FixtureArtifactClient([])
        self.assertIsInstance(client, ProviderArtifactReadClient)
        self.assertNotIsInstance(MissingArtifactReadClient(), ProviderArtifactReadClient)

        source = inspect.getsource(ProviderArtifactReadClient)
        self.assertIn("def list_artifacts_raw", source)
        for forbidden in (
            "def dispatch",
            "def approve",
            "def send",
            "def retry",
            "def cancel",
            "def merge",
            "def deploy",
            "def create",
            "def update",
            "def delete",
        ):
            self.assertNotIn(forbidden, source)

    def test_jules_reported_artifact_is_unverified(self):
        artifact = map_jules_artifact(
            provider_operation_id="jules-operation-1",
            raw_artifact={
                "kind": "commit",
                "id": "artifact-1",
                "ref": "refs/heads/work",
                "sha": "provider-claimed-sha",
                "content_hash": "sha256:provider-report",
                "freshness_basis": "provider_updated_at",
            },
            observed_at="2026-08-24T02:00:00Z",
        )

        self.assertEqual(artifact.provider, "jules")
        self.assertEqual(artifact.provider_reported_sha, "provider-claimed-sha")
        self.assertFalse(artifact.independently_verified)
        self.assertEqual(artifact.verification_source, VerificationSource.NONE)
        self.assertEqual(artifact.verification_result, VerificationResult.NOT_RUN)
        self.assertIsNone(artifact.verified_repo)
        self.assertIsNone(artifact.verified_ref)
        self.assertIsNone(artifact.verified_sha)

    def test_codex_reported_artifact_is_unverified(self):
        artifact = map_codex_artifact(
            provider_operation_id="codex-operation-1",
            raw_artifact={
                "kind": "review",
                "id": "review-1",
                "ref": "refs/pull/10/head",
                "sha": "provider-claimed-review-sha",
            },
            observed_at="2026-08-24T02:00:00Z",
        )

        self.assertEqual(artifact.provider, "codex")
        self.assertEqual(artifact.artifact_kind, "review")
        self.assertFalse(artifact.independently_verified)
        self.assertEqual(artifact.verification_source, VerificationSource.NONE)
        self.assertEqual(artifact.verification_result, VerificationResult.NOT_RUN)

    def test_unparseable_artifact_fails_closed_to_unknown_unverified_evidence(self):
        artifact = map_jules_artifact(
            provider_operation_id="jules-operation-1",
            raw_artifact="not-a-mapping",
            observed_at="2026-08-24T02:00:00Z",
        )

        self.assertEqual(artifact.artifact_kind, "unknown")
        self.assertEqual(artifact.freshness_basis, "provider_report_unparseable")
        self.assertFalse(artifact.independently_verified)
        self.assertEqual(artifact.verification_result, VerificationResult.NOT_RUN)

    def test_jules_adapter_reads_then_maps_all_artifacts(self):
        client = FixtureArtifactClient(
            [
                {"kind": "commit", "id": "a1", "sha": "sha-1"},
                {"kind": "pr", "id": "a2", "ref": "refs/pull/1/head"},
            ]
        )
        adapter = JulesArtifactAdapter(
            client=client,
            observed_at=lambda: "2026-08-24T02:05:00Z",
        )

        artifacts = adapter.collect_artifacts(operation("jules"))

        self.assertEqual(client.calls, 1)
        self.assertEqual(len(artifacts), 2)
        self.assertTrue(all(item.provider == "jules" for item in artifacts))
        self.assertTrue(all(not item.independently_verified for item in artifacts))

    def test_codex_adapter_supports_review_only_artifact_without_code_publication(self):
        client = FixtureArtifactClient(
            [{"kind": "review", "id": "review-only", "sha": "reviewed-sha"}]
        )
        adapter = CodexArtifactAdapter(
            client=client,
            observed_at=lambda: "2026-08-24T02:05:00Z",
        )

        artifacts = adapter.collect_artifacts(operation("codex"))

        self.assertEqual(len(artifacts), 1)
        self.assertEqual(artifacts[0].artifact_kind, "review")
        self.assertFalse(artifacts[0].independently_verified)

    def test_provider_mismatch_is_rejected_before_artifact_client_read(self):
        jules_client = FixtureArtifactClient([])
        codex_client = FixtureArtifactClient([])
        jules = JulesArtifactAdapter(
            client=jules_client,
            observed_at=lambda: "2026-08-24T02:05:00Z",
        )
        codex = CodexArtifactAdapter(
            client=codex_client,
            observed_at=lambda: "2026-08-24T02:05:00Z",
        )

        with self.assertRaises(ValueError):
            jules.collect_artifacts(operation("codex"))
        with self.assertRaises(ValueError):
            codex.collect_artifacts(operation("jules"))

        self.assertEqual(jules_client.calls, 0)
        self.assertEqual(codex_client.calls, 0)

    def test_artifact_adapters_expose_no_provider_mutation_surface(self):
        for adapter_type in (JulesArtifactAdapter, CodexArtifactAdapter):
            source = inspect.getsource(adapter_type)
            self.assertIn("collect_artifacts", source)
            for forbidden in (
                "def dispatch",
                "def approve",
                "def send",
                "def retry",
                "def cancel",
                "def merge",
                "def deploy",
            ):
                self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
