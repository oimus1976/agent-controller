import io
import sys
import unittest
from unittest.mock import patch

from agent_controller import cli


class RemediationCliRoutingTests(unittest.TestCase):
    @patch("agent_controller.cli.execute_codex_remediation_request")
    @patch("agent_controller.cli.plan_codex_remediation_request")
    def test_cli_routes_to_dedicated_remediation_path_and_forwards_apply(
        self, plan_request, execute_request
    ):
        plan_request.return_value = {
            "repo": "oimus1976/agent-controller",
            "pr": 112,
            "requested_action": "REQUEST_CODEX_REMEDIATION",
            "decision": "EXECUTABLE",
        }
        execute_request.return_value = {
            "final_outcome": "DRY_RUN",
            "mutation_attempted": False,
        }

        argv = [
            "agent-controller",
            "request-codex-remediation",
            "--repo",
            "oimus1976/agent-controller",
            "--pr",
            "112",
            "--policy",
            "policy.json",
            "--allowed-paths",
            "agent_controller/**",
            "tests/**",
        ]
        with patch.object(sys, "argv", argv), patch("sys.stdout", new=io.StringIO()):
            cli.main()

        plan_request.assert_called_once_with(
            owner="oimus1976",
            repo="agent-controller",
            pr_number=112,
            policy_path="policy.json",
            scope_policy={
                "allowed_paths": ["agent_controller/**", "tests/**"],
                "denied_paths": None,
                "allow_docs_only": False,
            },
        )
        execute_request.assert_called_once()
        self.assertFalse(execute_request.call_args.kwargs["apply"])

    @patch("agent_controller.cli.execute_codex_remediation_request")
    @patch("agent_controller.cli.plan_codex_remediation_request")
    def test_cli_requires_explicit_apply_for_write(self, plan_request, execute_request):
        plan_request.return_value = {
            "repo": "oimus1976/agent-controller",
            "pr": 112,
            "requested_action": "REQUEST_CODEX_REMEDIATION",
            "decision": "EXECUTABLE",
        }
        execute_request.return_value = {
            "final_outcome": "PASS",
            "mutation_attempted": True,
        }

        argv = [
            "agent-controller",
            "request-codex-remediation",
            "--repo",
            "oimus1976/agent-controller",
            "--pr",
            "112",
            "--policy",
            "policy.json",
            "--allowed-paths",
            "agent_controller/**",
            "--apply",
        ]
        with patch.object(sys, "argv", argv), patch("sys.stdout", new=io.StringIO()):
            cli.main()

        self.assertTrue(execute_request.call_args.kwargs["apply"])


if __name__ == "__main__":
    unittest.main()
