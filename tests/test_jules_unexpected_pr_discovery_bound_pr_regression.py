import unittest

from agent_controller.jules_unexpected_pr_discovery import (
    JulesPRDiscoveryClassification,
    PullRequestFact,
    discover_unexpected_jules_pr,
)


class _Client:
    def __init__(self, fact):
        self.fact = fact
        self.get_calls = []
        self.search_calls = []
        self.ancestry_calls = []

    def get_pull_request(self, repo, pr_number):
        self.get_calls.append((repo, pr_number))
        return self.fact

    def find_pull_requests_by_head(self, repo, head_ref):
        self.search_calls.append((repo, head_ref))
        return ()

    def is_ancestor(self, repo, ancestor_sha, descendant_sha):
        self.ancestry_calls.append((repo, ancestor_sha, descendant_sha))
        return True


class BoundPRTerminalOutputRegressionTests(unittest.TestCase):
    def test_terminal_output_for_bound_pr_is_not_classified_as_unexpected_provider_pr(self):
        fact = PullRequestFact(
            repo="owner/repo",
            number=42,
            base_ref="main",
            head_ref="controller/task-1",
            head_sha="a" * 40,
            draft=True,
            open=True,
            merged=False,
        )
        client = _Client(fact)

        result = discover_unexpected_jules_pr(
            provider="jules",
            repo="owner/repo",
            bound_branch="controller/task-1",
            authoritative_baseline_bound_sha="a" * 40,
            authoritative_current_bound_sha="a" * 40,
            expected_base_ref="main",
            expected_start_sha="a" * 40,
            provider_reported_completion=True,
            provider_reported_branch=None,
            provider_reported_pull_request_url="https://github.com/owner/repo/pull/42",
            client=client,
        )

        self.assertEqual(
            result.classification,
            JulesPRDiscoveryClassification.PUBLICATION_AMBIGUOUS,
        )
        self.assertIn("Controller-bound branch", result.guidance)
        self.assertEqual(client.get_calls, [("owner/repo", 42)])
        self.assertEqual(client.search_calls, [])
        self.assertEqual(client.ancestry_calls, [])


if __name__ == "__main__":
    unittest.main()
