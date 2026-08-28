import json
import os
import tempfile
import unittest

from agent_controller.review_request import ACTION, plan_codex_review_request


HEAD = "a" * 40


class ReviewRequestConcurrencyBoundaryTests(unittest.TestCase):
    def test_same_snapshot_can_yield_two_executable_plans_without_atomic_github_claim(self):
        """Document the intentional MVP limit: planning is not a distributed lock.

        Two Controller instances that both inspect the same GitHub snapshot before
        either POSTs cannot atomically claim the right to request review. Both can
        therefore plan EXECUTABLE. The exact-head marker deduplicates later/replayed
        runs after one request becomes visible, but this slice does not claim global
        exactly-once semantics for a truly simultaneous race.
        """

        fd, policy_path = tempfile.mkstemp()
        try:
            with os.fdopen(fd, "w") as handle:
                json.dump({"allowed_actions": [ACTION]}, handle)

            inspection = {
                "head_sha": HEAD,
                "draft": True,
                "merged": False,
                "state": "open",
                "files": [{"filename": "agent_controller/example.py", "changes": 1}],
                "actions_ci_status": "PASS",
                "graphql_error": False,
                "issue_comments": [],
                "reviews": [],
                "review_threads_graphql": [],
            }
            scope = {
                "allowed_paths": ["agent_controller/*"],
                "denied_paths": [],
                "allow_docs_only": True,
            }

            first = plan_codex_review_request(
                owner="oimus1976",
                repo="agent-controller",
                pr_number=109,
                policy_path=policy_path,
                scope_policy=scope,
                inspection=inspection,
            )
            second = plan_codex_review_request(
                owner="oimus1976",
                repo="agent-controller",
                pr_number=109,
                policy_path=policy_path,
                scope_policy=scope,
                inspection=inspection,
            )

            self.assertEqual("EXECUTABLE", first["decision"])
            self.assertEqual("EXECUTABLE", second["decision"])
            self.assertEqual(first["head_sha"], second["head_sha"])
        finally:
            if os.path.exists(policy_path):
                os.remove(policy_path)


if __name__ == "__main__":
    unittest.main()
