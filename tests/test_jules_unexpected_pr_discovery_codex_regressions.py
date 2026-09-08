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


def _fact():
    return PullRequestFact(
        repo="owner/repo",
        number=42,
        base_ref="main",
        head_ref="jules/provider-output",
        head_sha="b" * 40,
        draft=True,
        open=True,
        merged=False,
        head_repo="owner/repo",
    )


def _discover(client, **overrides):
    values = dict(
        provider="jules",
        repo="owner/repo",
        bound_branch="controller/task-1",
        authoritative_baseline_bound_sha="a" * 40,
        authoritative_current_bound_sha="a" * 40,
        expected_base_ref="main",
        expected_start_sha="a" * 40,
        provider_reported_completion=True,
        provider_reported_branch="jules/provider-output",
        provider_reported_pull_request_url="https://github.com/owner/repo/pull/42",
        client=client,
    )
    values.update(overrides)
    return discover_unexpected_jules_pr(**values)


class CodexRegressionTests(unittest.TestCase):
    def test_malformed_provider_branch_with_terminal_pr_fails_closed(self):
        client = _Client(_fact())
        result = _discover(client, provider_reported_branch=123)

        self.assertEqual(
            result.classification,
            JulesPRDiscoveryClassification.PUBLICATION_AMBIGUOUS,
        )
        self.assertIn("malformed provider branch evidence", result.guidance)
        self.assertEqual(client.get_calls, [])
        self.assertEqual(client.ancestry_calls, [])

    def test_bound_branch_advance_and_distinct_terminal_pr_is_ambiguous(self):
        client = _Client(_fact())
        result = _discover(
            client,
            authoritative_current_bound_sha="c" * 40,
        )

        self.assertEqual(
            result.classification,
            JulesPRDiscoveryClassification.PUBLICATION_AMBIGUOUS,
        )
        self.assertIn("simultaneous publication effects", result.guidance)
        self.assertEqual(client.get_calls, [("owner/repo", 42)])
        self.assertEqual(
            client.ancestry_calls,
            [("owner/repo", "a" * 40, "b" * 40)],
        )


if __name__ == "__main__":
    unittest.main()
