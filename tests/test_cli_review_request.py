import io
import json
import sys
import unittest
from contextlib import redirect_stdout
from unittest.mock import Mock, patch

from agent_controller import cli


class CliReviewRequestTests(unittest.TestCase):
    def test_routes_scope_policy_policy_file_and_apply(self):
        plan = {
            "repo": "oimus1976/example",
            "pr": 12,
            "requested_action": "REQUEST_CODEX_REVIEW",
            "decision": "EXECUTABLE",
            "reason": "READY_TO_REQUEST_CODEX_REVIEW",
            "head_sha": "a" * 40,
        }
        result = {
            "final_outcome": "SUCCESS",
            "failure_reason": None,
        }
        stdout = io.StringIO()

        with patch.object(
            sys,
            "argv",
            [
                "agent-controller",
                "request-codex-review",
                "--repo",
                "oimus1976/example",
                "--pr",
                "12",
                "--allowed-paths",
                "src/*",
                "tests/*",
                "--denied-paths",
                "secrets/*",
                "--allow-docs-only",
                "--policy",
                "policy.json",
                "--apply",
            ],
        ), patch.object(
            cli, "plan_codex_review_request", return_value=plan
        ) as planner, patch.object(
            cli, "execute_codex_review_request", return_value=result
        ) as executor, redirect_stdout(stdout):
            cli.main()

        planner.assert_called_once_with(
            owner="oimus1976",
            repo="example",
            pr_number=12,
            policy_path="policy.json",
            scope_policy={
                "allowed_paths": ["src/*", "tests/*"],
                "denied_paths": ["secrets/*"],
                "allow_docs_only": True,
            },
        )
        executor.assert_called_once_with(
            plan=plan,
            owner="oimus1976",
            repo="example",
            pr_number=12,
            policy_path="policy.json",
            apply=True,
        )
        output = stdout.getvalue()
        self.assertIn('"decision": "EXECUTABLE"', output)
        self.assertIn('"final_outcome": "SUCCESS"', output)

    def test_without_apply_forwards_false(self):
        plan = {"decision": "EXECUTABLE"}
        result = {"final_outcome": "DRY_RUN", "failure_reason": "APPLY_FLAG_NOT_SET"}

        with patch.object(
            sys,
            "argv",
            [
                "agent-controller",
                "request-codex-review",
                "--repo",
                "oimus1976/example",
                "--pr",
                "12",
                "--policy",
                "policy.json",
                "--allowed-paths",
                "src/*",
            ],
        ), patch.object(
            cli, "plan_codex_review_request", return_value=plan
        ), patch.object(
            cli, "execute_codex_review_request", return_value=result
        ) as executor, redirect_stdout(io.StringIO()):
            cli.main()

        self.assertFalse(executor.call_args.kwargs["apply"])

    def test_blocked_execution_exits_nonzero(self):
        plan = {"decision": "BLOCKED", "reason": "EXACT_HEAD_CI_NOT_PASS"}
        result = {"final_outcome": "BLOCKED", "failure_reason": "EXACT_HEAD_CI_NOT_PASS"}

        with patch.object(
            sys,
            "argv",
            [
                "agent-controller",
                "request-codex-review",
                "--repo",
                "oimus1976/example",
                "--pr",
                "12",
                "--policy",
                "policy.json",
                "--allowed-paths",
                "src/*",
            ],
        ), patch.object(
            cli, "plan_codex_review_request", return_value=plan
        ), patch.object(
            cli, "execute_codex_review_request", return_value=result
        ), redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit) as raised:
                cli.main()

        self.assertEqual(1, raised.exception.code)


if __name__ == "__main__":
    unittest.main()
