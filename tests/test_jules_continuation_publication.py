import unittest
from unittest.mock import Mock

from agent_controller.provider_contract import PublicationClassification
from agent_controller.publication_observation import TargetReadClient
from agent_controller.jules_continuation_publication import (
    observe_jules_continuation_publication,
    JulesContinuationResult,
)


class TestJulesContinuationPublication(unittest.TestCase):
    def setUp(self):
        self.mock_client = Mock(spec=TargetReadClient)
        self.default_kwargs = {
            "provider": "jules",
            "operation_id": "op-123",
            "repo": "owner/repo",
            "bound_branch": "feature-1",
            "authoritative_baseline_bound_sha": "a" * 40,
            "provider_reported_completion": False,
            "provider_reported_branch": None,
            "target_client": self.mock_client,
        }

    def test_workspace_complete_publication_unknown(self):
        self.mock_client.get_ref_sha.return_value = "a" * 40
        kwargs = self.default_kwargs.copy()
        kwargs["provider_reported_completion"] = True

        result = observe_jules_continuation_publication(**kwargs)

        self.assertEqual(
            result.classification,
            PublicationClassification.WORKSPACE_COMPLETE_PUBLICATION_UNKNOWN,
        )
        self.assertIn("attention required", result.guidance)
        self.assertIn("workspace completion may be known", result.guidance)
        self.assertIn("GitHub publication is not established", result.guidance)
        self.assertIn("no mutation/retry recommendation", result.guidance)

    def test_bound_branch_advanced(self):
        self.mock_client.get_ref_sha.return_value = "b" * 40

        result = observe_jules_continuation_publication(**self.default_kwargs)

        self.assertEqual(
            result.classification, PublicationClassification.BOUND_BRANCH_ADVANCED
        )
        self.assertEqual(result.baseline_bound_sha, "a" * 40)
        self.assertEqual(result.current_bound_sha, "b" * 40)
        self.assertIn("attention required", result.guidance)
        self.assertIn("new untrusted evidence", result.guidance)
        self.assertIn("objective scope, exact-head CI, and independent review from scratch", result.guidance)

    def test_new_provider_branch_exposed(self):
        def mock_get_ref_sha(repo, branch):
            if branch == "feature-1":
                return "a" * 40
            if branch == "new-feature":
                return "c" * 40
            return None

        self.mock_client.get_ref_sha.side_effect = mock_get_ref_sha
        kwargs = self.default_kwargs.copy()
        kwargs["provider_reported_branch"] = "new-feature"

        result = observe_jules_continuation_publication(**kwargs)

        self.assertEqual(
            result.classification, PublicationClassification.NEW_PROVIDER_BRANCH_EXPOSED
        )
        self.assertEqual(result.provider_reported_branch, "new-feature")
        self.assertEqual(result.independently_observed_provider_sha, "c" * 40)
        self.assertIn("attention required", result.guidance)
        self.assertIn("not the Controller-bound PR branch", result.guidance)
        self.assertIn("no branch/PR mutation", result.guidance)

    def test_publication_ambiguous_conflicting_evidence(self):
        def mock_get_ref_sha(repo, branch):
            if branch == "feature-1":
                return "b" * 40
            if branch == "new-feature":
                return "c" * 40
            return None

        self.mock_client.get_ref_sha.side_effect = mock_get_ref_sha
        kwargs = self.default_kwargs.copy()
        kwargs["provider_reported_branch"] = "new-feature"

        result = observe_jules_continuation_publication(**kwargs)

        self.assertEqual(
            result.classification, PublicationClassification.PUBLICATION_AMBIGUOUS
        )
        self.assertIn("attention required", result.guidance)
        self.assertIn("no publication or retry recommendation", result.guidance)
        self.assertEqual(result.baseline_bound_sha, "a" * 40)
        self.assertEqual(result.current_bound_sha, "b" * 40)
        self.assertEqual(result.provider_reported_branch, "new-feature")
        self.assertEqual(result.independently_observed_provider_sha, "c" * 40)

    def test_definite_provider_branch_absence(self):
        def mock_get_ref_sha(repo, branch):
            if branch == "feature-1":
                return "a" * 40
            if branch == "new-feature":
                return None
            return None

        self.mock_client.get_ref_sha.side_effect = mock_get_ref_sha
        kwargs = self.default_kwargs.copy()
        kwargs["provider_reported_branch"] = "new-feature"
        kwargs["provider_reported_completion"] = True

        result = observe_jules_continuation_publication(**kwargs)

        self.assertEqual(
            result.classification,
            PublicationClassification.WORKSPACE_COMPLETE_PUBLICATION_UNKNOWN,
        )

    def test_read_failure_returns_ambiguous(self):
        self.mock_client.get_ref_sha.side_effect = Exception("Read failed")

        result = observe_jules_continuation_publication(**self.default_kwargs)

        self.assertEqual(
            result.classification, PublicationClassification.PUBLICATION_AMBIGUOUS
        )
        self.assertIn("attention required", result.guidance)
        self.assertIn("no publication or retry recommendation", result.guidance)

    def test_malformed_provider_branch_returns_ambiguous(self):
        kwargs = self.default_kwargs.copy()
        kwargs["provider_reported_branch"] = 123  # Not a string

        result = observe_jules_continuation_publication(**kwargs)

        self.assertEqual(
            result.classification, PublicationClassification.PUBLICATION_AMBIGUOUS
        )
        self.assertIn("attention required", result.guidance)
        self.assertIn("no publication or retry recommendation", result.guidance)


if __name__ == "__main__":
    unittest.main()
