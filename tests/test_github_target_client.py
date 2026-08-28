import unittest
from unittest.mock import patch

from agent_controller.github_target_client import GitHubRestTargetReadClient


class GitHubRestTargetReadClientTests(unittest.TestCase):
    def test_resolves_explicit_branch_ref_to_commit_sha(self):
        client = GitHubRestTargetReadClient()
        with patch(
            "agent_controller.github_target_client._github_api_request",
            return_value={"object": {"type": "commit", "sha": "b" * 40}},
        ) as request:
            sha = client.get_ref_sha("oimus1976/example", "feature/task-1")

        self.assertEqual("b" * 40, sha)
        self.assertIn("/git/ref/heads/feature/task-1", request.call_args.args[0])

    def test_rejects_non_branch_refs_before_network_read(self):
        client = GitHubRestTargetReadClient()
        with patch("agent_controller.github_target_client._github_api_request") as request:
            with self.assertRaises(ValueError):
                client.get_ref_sha("oimus1976/example", "refs/tags/v1")
        request.assert_not_called()

    def test_compare_maps_only_required_objective_facts(self):
        client = GitHubRestTargetReadClient()
        payload = {
            "merge_base_commit": {"sha": "a" * 40},
            "files": [{"filename": "src/app.py", "changes": 2}],
            "commits": [{"sha": "provider-irrelevant"}],
        }
        with patch(
            "agent_controller.github_target_client._github_api_request",
            return_value=payload,
        ):
            result = client.compare_commits("oimus1976/example", "a" * 40, "b" * 40)

        self.assertEqual(
            {
                "merge_base_sha": "a" * 40,
                "files": [{"filename": "src/app.py", "changes": 2}],
            },
            result,
        )

    def test_potentially_truncated_300_file_compare_fails_closed(self):
        client = GitHubRestTargetReadClient()
        payload = {
            "merge_base_commit": {"sha": "a" * 40},
            "files": [
                {"filename": f"src/{index}.py", "changes": 1}
                for index in range(300)
            ],
        }
        with patch(
            "agent_controller.github_target_client._github_api_request",
            return_value=payload,
        ):
            with self.assertRaises(RuntimeError):
                client.compare_commits("oimus1976/example", "a" * 40, "b" * 40)


if __name__ == "__main__":
    unittest.main()
