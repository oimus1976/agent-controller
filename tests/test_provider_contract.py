import dataclasses
import inspect
import unittest

from agent_controller.provider_contract import (
    AgentAdapter,
    AgentObservation,
    ArtifactEvidence,
    AwaitingInput,
    ControllerState,
    ObjectiveScope,
    ProviderOperationRef,
    TaskBinding,
    TerminalClaim,
    VerificationResult,
    VerificationSource,
    PublicationClassification,
    PublicationStateEvidence,
)


class ThreeMethodAdapter:
    """Deliberately implements only the mandatory provider-neutral surface."""

    def dispatch(self, task):
        return ProviderOperationRef(
            provider=task.provider,
            provider_operation_id="provider-op-1",
            provider_url=None,
            controller_task_id=task.controller_task_id,
            operation_id=task.operation_id,
        )

    def observe(self, operation):
        return AgentObservation(
            provider=operation.provider,
            provider_operation_id=operation.provider_operation_id,
            observed_at="2026-08-24T00:00:00Z",
            provider_updated_at=None,
            provider_raw_state={"opaque": "provider-state"},
            mapped_state=ControllerState.EXECUTING,
        )

    def collect_artifacts(self, operation):
        return []


class MissingArtifactCollectorAdapter:
    def dispatch(self, task):
        raise NotImplementedError

    def observe(self, operation):
        raise NotImplementedError


class TestProviderContract(unittest.TestCase):
    def make_task(self):
        return TaskBinding(
            controller_task_id="task-1",
            operation_id="operation-1",
            provider="example-provider",
            repo="owner/repo",
            expected_start_ref="refs/heads/main",
            expected_start_sha="abc123",
            objective_scope=ObjectiveScope(
                allowed_paths=("agent_controller/**",),
                denied_paths=("secrets/**",),
            ),
            requested_capability="IMPLEMENT",
            allowed_effects=("CREATE_BRANCH", "CREATE_COMMIT"),
            forbidden_effects=("MERGE",),
            approval_policy_id="policy-1",
            created_at="2026-08-24T00:00:00Z",
        )

    def test_three_methods_are_sufficient_for_runtime_protocol(self):
        adapter = ThreeMethodAdapter()
        self.assertIsInstance(adapter, AgentAdapter)
        self.assertFalse(hasattr(adapter, "capabilities"))

    def test_missing_required_method_does_not_satisfy_protocol(self):
        self.assertNotIsInstance(MissingArtifactCollectorAdapter(), AgentAdapter)

    def test_contract_models_are_frozen(self):
        task = self.make_task()
        operation = ThreeMethodAdapter().dispatch(task)
        observation = ThreeMethodAdapter().observe(operation)
        artifact = ArtifactEvidence(
            provider="example-provider",
            provider_operation_id="provider-op-1",
            artifact_kind="commit",
            provider_artifact_id="artifact-1",
            provider_reported_ref="refs/heads/work",
            provider_reported_sha="def456",
            content_hash=None,
            observed_at="2026-08-24T00:01:00Z",
            freshness_basis="provider_updated_at",
        )

        for value in (task, operation, observation, artifact):
            with self.assertRaises(dataclasses.FrozenInstanceError):
                value.provider = "mutated-provider"

    def test_observation_serialization_keeps_raw_state_opaque(self):
        raw_state = {
            "state": "provider-specific-running-state",
            "nested": {"approval": "provider-specific-value"},
        }
        observation = AgentObservation(
            provider="example-provider",
            provider_operation_id="provider-op-1",
            observed_at="2026-08-24T00:00:00Z",
            provider_updated_at="2026-08-24T00:00:01Z",
            provider_raw_state=raw_state,
            mapped_state=ControllerState.PLAN_REVIEW_REQUIRED,
            awaiting_input=AwaitingInput.PLAN_APPROVAL,
            terminal_claim=TerminalClaim.NONE,
        )

        serialized = observation.to_dict()
        self.assertEqual(serialized["provider_raw_state"], raw_state)
        self.assertEqual(serialized["mapped_state"], "PLAN_REVIEW_REQUIRED")
        self.assertEqual(serialized["awaiting_input"], "PLAN_APPROVAL")
        self.assertEqual(serialized["terminal_claim"], "NONE")

    def test_artifact_defaults_do_not_treat_provider_claim_as_verification(self):
        artifact = ArtifactEvidence(
            provider="example-provider",
            provider_operation_id="provider-op-1",
            artifact_kind="commit",
            provider_artifact_id="artifact-1",
            provider_reported_ref="refs/heads/work",
            provider_reported_sha="def456",
            content_hash="sha256:example",
            observed_at="2026-08-24T00:01:00Z",
            freshness_basis="provider_updated_at",
        )

        self.assertFalse(artifact.independently_verified)
        self.assertEqual(artifact.verification_source, VerificationSource.NONE)
        self.assertEqual(artifact.verification_result, VerificationResult.NOT_RUN)
        self.assertIsNone(artifact.verified_repo)
        self.assertIsNone(artifact.verified_ref)
        self.assertIsNone(artifact.verified_sha)

    def test_verified_evidence_serialization_separates_reported_and_verified_sha(self):
        artifact = ArtifactEvidence(
            provider="example-provider",
            provider_operation_id="provider-op-1",
            artifact_kind="commit",
            provider_artifact_id="artifact-1",
            provider_reported_ref="refs/heads/work",
            provider_reported_sha="provider-claim",
            content_hash="sha256:example",
            observed_at="2026-08-24T00:01:00Z",
            freshness_basis="github-readback",
            independently_verified=True,
            verification_source=VerificationSource.GITHUB,
            verified_repo="owner/repo",
            verified_ref="refs/heads/work",
            verified_sha="objective-readback",
            verification_result=VerificationResult.PASS,
        )

        serialized = artifact.to_dict()
        self.assertEqual(serialized["provider_reported_sha"], "provider-claim")
        self.assertEqual(serialized["verified_sha"], "objective-readback")
        self.assertEqual(serialized["verification_source"], "GITHUB")
        self.assertEqual(serialized["verification_result"], "PASS")

    def test_controller_state_vocabulary_is_provider_neutral(self):
        forbidden_provider_terms = ("jules", "codex", "manus")
        state_values = " ".join(state.value.lower() for state in ControllerState)
        for term in forbidden_provider_terms:
            self.assertNotIn(term, state_values)

    def test_protocol_source_does_not_grow_provider_lifecycle_surface(self):
        source = inspect.getsource(AgentAdapter)
        self.assertIn("def dispatch", source)
        self.assertIn("def observe", source)
        self.assertIn("def collect_artifacts", source)
        self.assertNotIn("def approve", source)
        self.assertNotIn("def cancel", source)
        self.assertNotIn("def retry", source)
        self.assertNotIn("def capabilities", source)

    def test_publication_evidence_bound_branch_advanced(self):
        evidence = PublicationStateEvidence(
            provider="example-provider",
            operation_id="op-1",
            repo="owner/repo",
            bound_branch="refs/heads/main",
            authoritative_baseline_bound_sha="a" * 40,
            authoritative_current_bound_sha="b" * 40,
            provider_reported_completion=False,
        )
        self.assertEqual(evidence.classify(), PublicationClassification.BOUND_BRANCH_ADVANCED)

    def test_publication_evidence_new_provider_branch_exposed(self):
        evidence = PublicationStateEvidence(
            provider="example-provider",
            operation_id="op-1",
            repo="owner/repo",
            bound_branch="refs/heads/main",
            authoritative_baseline_bound_sha="a" * 40,
            authoritative_current_bound_sha="a" * 40,
            provider_reported_completion=False,
            provider_reported_branch="refs/heads/provider-work",
            independently_observed_provider_sha="b" * 40,
        )
        self.assertEqual(evidence.classify(), PublicationClassification.NEW_PROVIDER_BRANCH_EXPOSED)

    def test_publication_evidence_workspace_complete_publication_unknown(self):
        evidence = PublicationStateEvidence(
            provider="example-provider",
            operation_id="op-1",
            repo="owner/repo",
            bound_branch="refs/heads/main",
            authoritative_baseline_bound_sha="a" * 40,
            authoritative_current_bound_sha="a" * 40,
            provider_reported_completion=True,
        )
        self.assertEqual(evidence.classify(), PublicationClassification.WORKSPACE_COMPLETE_PUBLICATION_UNKNOWN)

    def test_publication_evidence_ambiguous_invalid_baseline_sha(self):
        evidence = PublicationStateEvidence(
            provider="example-provider",
            operation_id="op-1",
            repo="owner/repo",
            bound_branch="refs/heads/main",
            authoritative_baseline_bound_sha="invalid",
            authoritative_current_bound_sha="a" * 40,
        )
        self.assertEqual(evidence.classify(), PublicationClassification.PUBLICATION_AMBIGUOUS)

    def test_publication_evidence_ambiguous_invalid_current_sha(self):
        evidence = PublicationStateEvidence(
            provider="example-provider",
            operation_id="op-1",
            repo="owner/repo",
            bound_branch="refs/heads/main",
            authoritative_baseline_bound_sha="a" * 40,
            authoritative_current_bound_sha="invalid",
        )
        self.assertEqual(evidence.classify(), PublicationClassification.PUBLICATION_AMBIGUOUS)
        
    def test_publication_evidence_ambiguous_invalid_observed_sha(self):
        evidence = PublicationStateEvidence(
            provider="example-provider",
            operation_id="op-1",
            repo="owner/repo",
            bound_branch="refs/heads/main",
            authoritative_baseline_bound_sha="a" * 40,
            authoritative_current_bound_sha="a" * 40,
            independently_observed_provider_sha="invalid",
        )
        self.assertEqual(evidence.classify(), PublicationClassification.PUBLICATION_AMBIGUOUS)

    def test_publication_evidence_ambiguous_provider_branch_equals_bound_branch(self):
        evidence = PublicationStateEvidence(
            provider="example-provider",
            operation_id="op-1",
            repo="owner/repo",
            bound_branch="refs/heads/main",
            authoritative_baseline_bound_sha="a" * 40,
            authoritative_current_bound_sha="a" * 40,
            provider_reported_branch="refs/heads/main",
            independently_observed_provider_sha="b" * 40,
        )
        self.assertEqual(evidence.classify(), PublicationClassification.PUBLICATION_AMBIGUOUS)

    def test_publication_evidence_conflicting_bound_and_provider_branch_is_ambiguous(self):
        evidence = PublicationStateEvidence(
            provider="example-provider",
            operation_id="op-1",
            repo="owner/repo",
            bound_branch="refs/heads/main",
            authoritative_baseline_bound_sha="a" * 40,
            authoritative_current_bound_sha="b" * 40,
            provider_reported_branch="refs/heads/provider-work",
            independently_observed_provider_sha="c" * 40,
        )
        self.assertEqual(
            evidence.classify(),
            PublicationClassification.PUBLICATION_AMBIGUOUS,
        )

    def test_publication_evidence_observed_sha_without_provider_branch_is_ambiguous(self):
        evidence = PublicationStateEvidence(
            provider="example-provider",
            operation_id="op-1",
            repo="owner/repo",
            bound_branch="refs/heads/main",
            authoritative_baseline_bound_sha="a" * 40,
            authoritative_current_bound_sha="a" * 40,
            independently_observed_provider_sha="b" * 40,
        )
        self.assertEqual(
            evidence.classify(),
            PublicationClassification.PUBLICATION_AMBIGUOUS,
        )

    def test_publication_evidence_malformed_identity_fields_are_ambiguous(self):
        base = dict(
            provider="example-provider",
            operation_id="op-1",
            repo="owner/repo",
            bound_branch="refs/heads/main",
            authoritative_baseline_bound_sha="a" * 40,
            authoritative_current_bound_sha="b" * 40,
        )
        for field in ("provider", "operation_id", "repo", "bound_branch"):
            for malformed in ("", "   ", None, 123):
                with self.subTest(field=field, malformed=malformed):
                    kwargs = dict(base)
                    kwargs[field] = malformed
                    evidence = PublicationStateEvidence(**kwargs)
                    self.assertEqual(
                        evidence.classify(),
                        PublicationClassification.PUBLICATION_AMBIGUOUS,
                    )

    def test_publication_evidence_non_bool_completion_is_ambiguous(self):
        evidence = PublicationStateEvidence(
            provider="example-provider",
            operation_id="op-1",
            repo="owner/repo",
            bound_branch="refs/heads/main",
            authoritative_baseline_bound_sha="a" * 40,
            authoritative_current_bound_sha="a" * 40,
            provider_reported_completion="complete",
        )
        self.assertEqual(
            evidence.classify(),
            PublicationClassification.PUBLICATION_AMBIGUOUS,
        )

    def test_publication_evidence_malformed_provider_branch_is_ambiguous(self):
        for malformed in ("", "   ", 123):
            with self.subTest(malformed=malformed):
                evidence = PublicationStateEvidence(
                    provider="example-provider",
                    operation_id="op-1",
                    repo="owner/repo",
                    bound_branch="refs/heads/main",
                    authoritative_baseline_bound_sha="a" * 40,
                    authoritative_current_bound_sha="a" * 40,
                    provider_reported_completion=True,
                    provider_reported_branch=malformed,
                )
                self.assertEqual(
                    evidence.classify(),
                    PublicationClassification.PUBLICATION_AMBIGUOUS,
                )

    def test_publication_evidence_ambiguous_no_completion_no_advancement(self):
        evidence = PublicationStateEvidence(
            provider="example-provider",
            operation_id="op-1",
            repo="owner/repo",
            bound_branch="refs/heads/main",
            authoritative_baseline_bound_sha="a" * 40,
            authoritative_current_bound_sha="a" * 40,
            provider_reported_completion=False,
        )
        self.assertEqual(evidence.classify(), PublicationClassification.PUBLICATION_AMBIGUOUS)

    def test_publication_evidence_immutable(self):
        evidence = PublicationStateEvidence(
            provider="example-provider",
            operation_id="op-1",
            repo="owner/repo",
            bound_branch="refs/heads/main",
            authoritative_baseline_bound_sha="a" * 40,
            authoritative_current_bound_sha="b" * 40,
        )
        with self.assertRaises(dataclasses.FrozenInstanceError):
            evidence.provider = "new-provider"

    def test_publication_evidence_to_dict(self):
        evidence = PublicationStateEvidence(
            provider="example-provider",
            operation_id="op-1",
            repo="owner/repo",
            bound_branch="refs/heads/main",
            authoritative_baseline_bound_sha="a" * 40,
            authoritative_current_bound_sha="b" * 40,
            provider_reported_completion=True,
            provider_reported_branch="refs/heads/provider-work",
            independently_observed_provider_sha="c" * 40,
        )
        d = evidence.to_dict()
        self.assertEqual(d["provider"], "example-provider")
        self.assertEqual(d["operation_id"], "op-1")
        self.assertEqual(d["repo"], "owner/repo")
        self.assertEqual(d["bound_branch"], "refs/heads/main")
        self.assertEqual(d["authoritative_baseline_bound_sha"], "a" * 40)
        self.assertEqual(d["authoritative_current_bound_sha"], "b" * 40)
        self.assertTrue(d["provider_reported_completion"])
        self.assertEqual(d["provider_reported_branch"], "refs/heads/provider-work")
        self.assertEqual(d["independently_observed_provider_sha"], "c" * 40)


if __name__ == "__main__":
    unittest.main()
