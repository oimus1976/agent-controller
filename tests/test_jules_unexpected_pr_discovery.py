import unittest

from agent_controller.jules_unexpected_pr_discovery import (
    JulesPRDiscoveryClassification,
    PullRequestFact,
    discover_unexpected_jules_pr,
)


class FakeDiscoveryClient:
    def __init__(self, *, prs=(), ancestry=True, fail_search=False, fail_ancestry=False, fail_get=False):
        self.prs = tuple(prs)
        self.ancestry = ancestry
        self.fail_search = fail_search
        self.fail_ancestry = fail_ancestry
        self.fail_get = fail_get
        self.get_calls = []
        self.search_calls = []
        self.ancestry_calls = []

    def get_pull_request(self, repo, pr_number):
        self.get_calls.append((repo, pr_number))
        if self.fail_get:
            raise RuntimeError("get failed")
        matches = [pr for pr in self.prs if pr.number == pr_number]
        if len(matches) != 1:
            raise RuntimeError("PR not found")
        return matches[0]

    def find_pull_requests_by_head(self, repo, head_ref):
        self.search_calls.append((repo, head_ref))
        if self.fail_search:
            raise RuntimeError("search failed")
        return self.prs

    def is_ancestor(self, repo, ancestor_sha, descendant_sha):
        self.ancestry_calls.append((repo, ancestor_sha, descendant_sha))
        if self.fail_ancestry:
            raise RuntimeError("ancestry failed")
        return self.ancestry


class TestUnexpectedJulesPRDiscovery(unittest.TestCase):
    def setUp(self):
        self.base = dict(
            provider="jules",
            repo="owner/repo",
            bound_branch="controller/task-1",
            authoritative_baseline_bound_sha="a" * 40,
            authoritative_current_bound_sha="a" * 40,
            expected_base_ref="main",
            expected_start_sha="a" * 40,
            provider_reported_completion=True,
            provider_reported_branch="jules/provider-output",
            provider_reported_pull_request_url=None,
        )

    def fact(self, **overrides):
        values = dict(
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
        values.update(overrides)
        return PullRequestFact(**values)

    def run_discovery(self, client, **overrides):
        values = self.base.copy()
        values.update(overrides)
        return discover_unexpected_jules_pr(client=client, **values)

    def test_terminal_pull_request_output_is_preferred_over_branch_search(self):
        fact = self.fact(number=42)
        client = FakeDiscoveryClient(prs=[fact])
        result = self.run_discovery(
            client,
            provider_reported_pull_request_url="https://github.com/owner/repo/pull/42",
        )
        self.assertEqual(
            result.classification,
            JulesPRDiscoveryClassification.UNEXPECTED_PROVIDER_PR_EXPOSED,
        )
        self.assertEqual(result.pull_request, fact)
        self.assertIn("Session.outputs.pullRequest", result.guidance)
        self.assertEqual(client.get_calls, [("owner/repo", 42)])
        self.assertEqual(client.search_calls, [])

    def test_terminal_pull_request_output_malformed_or_cross_repo_fails_closed_without_fallback(self):
        for url in (
            "http://github.com/owner/repo/pull/42",
            "https://example.com/owner/repo/pull/42",
            "https://github.com/other/repo/pull/42",
            "https://github.com/owner/repo/issues/42",
            "https://github.com/owner/repo/pull/42?x=1",
        ):
            with self.subTest(url=url):
                client = FakeDiscoveryClient(prs=[self.fact()])
                result = self.run_discovery(client, provider_reported_pull_request_url=url)
                self.assertEqual(
                    result.classification,
                    JulesPRDiscoveryClassification.PUBLICATION_AMBIGUOUS,
                )
                self.assertEqual(client.get_calls, [])
                self.assertEqual(client.search_calls, [])

    def test_terminal_pull_request_output_github_read_failure_fails_closed_without_branch_guess(self):
        client = FakeDiscoveryClient(prs=[self.fact()], fail_get=True)
        result = self.run_discovery(
            client,
            provider_reported_pull_request_url="https://github.com/owner/repo/pull/42",
        )
        self.assertEqual(
            result.classification,
            JulesPRDiscoveryClassification.PUBLICATION_AMBIGUOUS,
        )
        self.assertEqual(client.search_calls, [])

    def test_terminal_pull_request_and_branch_disagreement_fails_closed(self):
        fact = self.fact(head_ref="different/provider-output")
        client = FakeDiscoveryClient(prs=[fact])
        result = self.run_discovery(
            client,
            provider_reported_pull_request_url="https://github.com/owner/repo/pull/42",
        )
        self.assertEqual(
            result.classification,
            JulesPRDiscoveryClassification.PUBLICATION_AMBIGUOUS,
        )
        self.assertIn("disagrees", result.guidance)
        self.assertEqual(client.search_calls, [])

    def test_completed_unchanged_bound_pr_without_distinct_pr_is_unknown_not_empty(self):
        result = self.run_discovery(FakeDiscoveryClient())
        self.assertEqual(
            result.classification,
            JulesPRDiscoveryClassification.WORKSPACE_COMPLETE_PUBLICATION_UNKNOWN,
        )
        self.assertIn("not evidence of empty work", result.guidance)
        self.assertIsNone(result.pull_request)

    def test_provider_completion_without_exact_branch_never_implies_github_ready(self):
        client = FakeDiscoveryClient()
        result = self.run_discovery(client, provider_reported_branch=None)
        self.assertEqual(
            result.classification,
            JulesPRDiscoveryClassification.WORKSPACE_COMPLETE_PUBLICATION_UNKNOWN,
        )
        self.assertIn("publication identity", result.guidance)
        self.assertEqual(client.search_calls, [])

    def test_exact_distinct_branch_with_one_pr_is_exposed_as_fallback(self):
        fact = self.fact()
        client = FakeDiscoveryClient(prs=[fact])
        result = self.run_discovery(client)
        self.assertEqual(
            result.classification,
            JulesPRDiscoveryClassification.UNEXPECTED_PROVIDER_PR_EXPOSED,
        )
        self.assertEqual(result.pull_request, fact)
        self.assertIn("bounded provider-branch fallback", result.guidance)
        self.assertIn("observed Draft PR", result.guidance)
        self.assertIn("new untrusted evidence", result.guidance)
        self.assertEqual(client.search_calls, [("owner/repo", "jules/provider-output")])
        self.assertEqual(
            client.ancestry_calls,
            [("owner/repo", "a" * 40, "b" * 40)],
        )

    def test_same_branch_name_on_foreign_head_repo_fails_closed(self):
        fact = self.fact(head_repo="other/fork")
        client = FakeDiscoveryClient(prs=[fact])
        result = self.run_discovery(client)
        self.assertEqual(
            result.classification,
            JulesPRDiscoveryClassification.PUBLICATION_AMBIGUOUS,
        )
        self.assertIn("foreign head-repository", result.guidance)
        self.assertEqual(client.ancestry_calls, [])

    def test_non_draft_provider_pr_is_observed_effect_not_authorized_ready(self):
        fact = self.fact(draft=False)
        result = self.run_discovery(FakeDiscoveryClient(prs=[fact]))
        self.assertEqual(
            result.classification,
            JulesPRDiscoveryClassification.UNEXPECTED_PROVIDER_PR_EXPOSED,
        )
        self.assertIn("not Controller-authorized Ready", result.guidance)

    def test_multiple_exact_prs_are_ambiguous(self):
        result = self.run_discovery(
            FakeDiscoveryClient(prs=[self.fact(number=42), self.fact(number=43)])
        )
        self.assertEqual(
            result.classification,
            JulesPRDiscoveryClassification.PUBLICATION_AMBIGUOUS,
        )
        self.assertIn("multiple exact provider-branch PR candidates", result.guidance)

    def test_title_or_recency_like_unrelated_candidate_is_not_identity(self):
        unrelated = self.fact(head_ref="similar-looking-branch")
        result = self.run_discovery(FakeDiscoveryClient(prs=[unrelated]))
        self.assertEqual(
            result.classification,
            JulesPRDiscoveryClassification.WORKSPACE_COMPLETE_PUBLICATION_UNKNOWN,
        )
        self.assertIsNone(result.pull_request)

    def test_wrong_repo_fails_closed(self):
        result = self.run_discovery(FakeDiscoveryClient(prs=[self.fact(repo="other/repo")]))
        self.assertEqual(
            result.classification,
            JulesPRDiscoveryClassification.PUBLICATION_AMBIGUOUS,
        )
        self.assertIn("cross-repository", result.guidance)

    def test_wrong_base_fails_closed(self):
        result = self.run_discovery(FakeDiscoveryClient(prs=[self.fact(base_ref="release")]))
        self.assertEqual(
            result.classification,
            JulesPRDiscoveryClassification.PUBLICATION_AMBIGUOUS,
        )
        self.assertIn("unexpected PR base", result.guidance)

    def test_unproven_start_ancestry_fails_closed(self):
        result = self.run_discovery(
            FakeDiscoveryClient(prs=[self.fact()], ancestry=False)
        )
        self.assertEqual(
            result.classification,
            JulesPRDiscoveryClassification.PUBLICATION_AMBIGUOUS,
        )
        self.assertIn("not proven to descend", result.guidance)

    def test_search_failure_fails_closed(self):
        result = self.run_discovery(FakeDiscoveryClient(fail_search=True))
        self.assertEqual(
            result.classification,
            JulesPRDiscoveryClassification.PUBLICATION_AMBIGUOUS,
        )
        self.assertIn("discovery failed", result.guidance)

    def test_ancestry_failure_fails_closed(self):
        result = self.run_discovery(
            FakeDiscoveryClient(prs=[self.fact()], fail_ancestry=True)
        )
        self.assertEqual(
            result.classification,
            JulesPRDiscoveryClassification.PUBLICATION_AMBIGUOUS,
        )
        self.assertIn("ancestry verification failed", result.guidance)

    def test_bound_branch_advance_preempts_distinct_pr_discovery(self):
        client = FakeDiscoveryClient(prs=[self.fact()])
        result = self.run_discovery(
            client,
            authoritative_current_bound_sha="c" * 40,
        )
        self.assertEqual(
            result.classification,
            JulesPRDiscoveryClassification.BOUND_BRANCH_ADVANCED,
        )
        self.assertEqual(client.get_calls, [])
        self.assertEqual(client.search_calls, [])
        self.assertIn("restart scope/CI/review", result.guidance)

    def test_same_provider_and_bound_branch_is_ambiguous(self):
        client = FakeDiscoveryClient()
        result = self.run_discovery(
            client,
            provider_reported_branch="refs/heads/controller/task-1",
        )
        self.assertEqual(
            result.classification,
            JulesPRDiscoveryClassification.PUBLICATION_AMBIGUOUS,
        )
        self.assertEqual(client.search_calls, [])

    def test_non_jules_provider_fails_closed_before_read(self):
        client = FakeDiscoveryClient(prs=[self.fact()])
        result = self.run_discovery(client, provider="codex")
        self.assertEqual(
            result.classification,
            JulesPRDiscoveryClassification.PUBLICATION_AMBIGUOUS,
        )
        self.assertEqual(client.get_calls, [])
        self.assertEqual(client.search_calls, [])


if __name__ == "__main__":
    unittest.main()
