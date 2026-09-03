import unittest
from unittest.mock import Mock

from agent_controller.provider_contract import PublicationClassification, PublicationStateEvidence
from agent_controller.publication_observation import (
    PublicationObservationError,
    observe_publication_state,
)


class PublicationObservationTests(unittest.TestCase):
    def setUp(self):
        self.mock_client = Mock()
        self.default_kwargs = {
            "provider": "p1",
            "operation_id": "op1",
            "repo": "owner/repo",
            "bound_branch": "feature-1",
            "authoritative_baseline_bound_sha": "a" * 40,
            "provider_reported_completion": False,
            "provider_reported_branch": None,
            "target_client": self.mock_client,
        }

    def test_unchanged_completed_returns_workspace_complete(self):
        self.mock_client.get_ref_sha.return_value = "a" * 40
        kwargs = self.default_kwargs.copy()
        kwargs["provider_reported_completion"] = True

        evidence = observe_publication_state(**kwargs)

        self.assertIsNotNone(evidence)
        self.assertEqual(evidence.classify(), PublicationClassification.WORKSPACE_COMPLETE_PUBLICATION_UNKNOWN)
        self.mock_client.get_ref_sha.assert_called_once_with("owner/repo", "feature-1")

    def test_bound_advanced_returns_bound_branch_advanced(self):
        self.mock_client.get_ref_sha.return_value = "b" * 40

        evidence = observe_publication_state(**self.default_kwargs)

        self.assertIsNotNone(evidence)
        self.assertEqual(evidence.classify(), PublicationClassification.BOUND_BRANCH_ADVANCED)
        self.mock_client.get_ref_sha.assert_called_once_with("owner/repo", "feature-1")

    def test_distinct_branch_observed_returns_new_provider_branch_exposed(self):
        def mock_get_ref_sha(repo, branch):
            if branch == "feature-1":
                return "a" * 40
            if branch == "new-branch":
                return "c" * 40
            return None

        self.mock_client.get_ref_sha.side_effect = mock_get_ref_sha
        kwargs = self.default_kwargs.copy()
        kwargs["provider_reported_branch"] = "new-branch"

        evidence = observe_publication_state(**kwargs)

        self.assertIsNotNone(evidence)
        self.assertEqual(evidence.classify(), PublicationClassification.NEW_PROVIDER_BRANCH_EXPOSED)
        self.assertEqual(self.mock_client.get_ref_sha.call_count, 2)

    def test_conflicting_evidence_returns_ambiguous(self):
        def mock_get_ref_sha(repo, branch):
            if branch == "feature-1":
                return "b" * 40  # Bound advanced
            if branch == "new-branch":
                return "c" * 40  # Distinct branch observed
            return None

        self.mock_client.get_ref_sha.side_effect = mock_get_ref_sha
        kwargs = self.default_kwargs.copy()
        kwargs["provider_reported_branch"] = "new-branch"

        evidence = observe_publication_state(**kwargs)

        self.assertIsNotNone(evidence)
        self.assertEqual(evidence.classify(), PublicationClassification.PUBLICATION_AMBIGUOUS)

    def test_definite_absence_does_not_count_as_publication(self):
        def mock_get_ref_sha(repo, branch):
            if branch == "feature-1":
                return "a" * 40
            if branch == "new-branch":
                return None  # Definite absence
            return "z" * 40

        self.mock_client.get_ref_sha.side_effect = mock_get_ref_sha
        kwargs = self.default_kwargs.copy()
        kwargs["provider_reported_branch"] = "new-branch"
        kwargs["provider_reported_completion"] = True

        evidence = observe_publication_state(**kwargs)

        self.assertIsNotNone(evidence)
        self.assertEqual(evidence.classify(), PublicationClassification.WORKSPACE_COMPLETE_PUBLICATION_UNKNOWN)
        self.assertIsNone(evidence.independently_observed_provider_sha)

    def test_definite_absence_without_completion_is_ambiguous(self):
        def mock_get_ref_sha(repo, branch):
            if branch == "feature-1":
                return "a" * 40
            if branch == "new-branch":
                return None
            raise AssertionError(f"unexpected branch lookup: {branch}")

        self.mock_client.get_ref_sha.side_effect = mock_get_ref_sha
        kwargs = self.default_kwargs.copy()
        kwargs["provider_reported_branch"] = "new-branch"

        evidence = observe_publication_state(**kwargs)

        self.assertEqual(
            evidence.classify(),
            PublicationClassification.PUBLICATION_AMBIGUOUS,
        )
        self.mock_client.get_ref_sha.assert_any_call("owner/repo", "new-branch")

    def test_malformed_provider_branch_sha_is_ambiguous(self):
        def mock_get_ref_sha(repo, branch):
            if branch == "feature-1":
                return "a" * 40
            if branch == "new-branch":
                return "not-a-valid-sha"
            raise AssertionError(f"unexpected branch lookup: {branch}")

        self.mock_client.get_ref_sha.side_effect = mock_get_ref_sha
        kwargs = self.default_kwargs.copy()
        kwargs["provider_reported_branch"] = "new-branch"

        evidence = observe_publication_state(**kwargs)

        self.assertEqual(
            evidence.classify(),
            PublicationClassification.PUBLICATION_AMBIGUOUS,
        )

    def test_bound_branch_transport_failure_is_fail_closed(self):
        self.mock_client.get_ref_sha.side_effect = Exception("Network error")

        with self.assertRaises(PublicationObservationError) as ctx:
            observe_publication_state(**self.default_kwargs)

        self.assertEqual(
            ctx.exception.classification,
            PublicationClassification.PUBLICATION_AMBIGUOUS,
        )

    def test_provider_branch_transport_failure_is_fail_closed(self):
        def mock_get_ref_sha(repo, branch):
            if branch == "feature-1":
                return "a" * 40
            if branch == "new-branch":
                raise Exception("Network error")
            return None

        self.mock_client.get_ref_sha.side_effect = mock_get_ref_sha
        kwargs = self.default_kwargs.copy()
        kwargs["provider_reported_branch"] = "new-branch"

        with self.assertRaises(PublicationObservationError) as ctx:
            observe_publication_state(**kwargs)

        self.assertEqual(
            ctx.exception.classification,
            PublicationClassification.PUBLICATION_AMBIGUOUS,
        )

    def test_same_branch_behavior_does_not_trigger_second_lookup(self):
        self.mock_client.get_ref_sha.return_value = "a" * 40
        kwargs = self.default_kwargs.copy()
        kwargs["provider_reported_branch"] = "feature-1"
        kwargs["provider_reported_completion"] = True

        evidence = observe_publication_state(**kwargs)

        self.assertIsNotNone(evidence)
        self.assertEqual(evidence.classify(), PublicationClassification.WORKSPACE_COMPLETE_PUBLICATION_UNKNOWN)
        self.mock_client.get_ref_sha.assert_called_once_with("owner/repo", "feature-1")

    def test_malformed_authoritative_sha_fails_closed(self):
        self.mock_client.get_ref_sha.return_value = "invalid-sha"
        kwargs = self.default_kwargs.copy()

        evidence = observe_publication_state(**kwargs)

        self.assertIsNotNone(evidence)
        self.assertEqual(evidence.classify(), PublicationClassification.PUBLICATION_AMBIGUOUS)

    def test_bound_branch_missing_fails_closed(self):
        self.mock_client.get_ref_sha.return_value = None

        with self.assertRaises(PublicationObservationError) as ctx:
            observe_publication_state(**self.default_kwargs)

        self.assertEqual(
            ctx.exception.classification,
            PublicationClassification.PUBLICATION_AMBIGUOUS,
        )

if __name__ == "__main__":
    unittest.main()
