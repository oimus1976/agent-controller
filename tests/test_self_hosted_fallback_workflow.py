from pathlib import Path
import re
import unittest


REPO_ROOT = Path(__file__).resolve(strict=True).parents[1]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "self-hosted-exact-head.yml"


class SelfHostedFallbackWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = WORKFLOW.read_text(encoding="utf-8")
        cls.step_names = re.findall(r"(?m)^      - name: (.+)$", cls.text)

    def test_manual_only_trigger_and_separate_workflow(self):
        self.assertIn("  workflow_dispatch:\n", self.text)
        self.assertNotRegex(self.text, r"(?m)^  (push|pull_request|schedule|repository_dispatch):")

    def test_runner_selection_is_one_time_custom_label_not_generic_or_hosted(self):
        self.assertIn("runs-on: ac-ci-${{ inputs.runner_nonce }}", self.text)
        self.assertNotIn("runs-on: [self-hosted", self.text)
        self.assertNotIn("windows-latest", self.text)
        self.assertNotIn("ubuntu-latest", self.text)
        self.assertIn("^[0-9a-fA-F]{16}$", self.text)

    def test_permissions_and_checkout_are_read_only_shaped(self):
        self.assertIn("permissions:\n  contents: read\n  pull-requests: read\n", self.text)
        self.assertNotRegex(self.text, r"(?m)^\s+[a-z-]+: write$")
        self.assertIn("persist-credentials: false", self.text)
        self.assertIn("clean: true", self.text)
        self.assertRegex(self.text, r"uses: actions/checkout@[0-9a-f]{40}")

    def test_preflight_binds_main_host_identity_same_repo_and_exact_head(self):
        required = (
            "refs/heads/main",
            "runner OS must be Windows",
            "runner architecture must be X64",
            "runner identity must be dedicated ac-runner standard user",
            "runner identity must not be an administrator",
            "runner profile contains forbidden credential/provider state",
            "fork or foreign head repository is not allowed",
            "target_sha is not the current PR head",
        )
        for marker in required:
            self.assertIn(marker, self.text)

    def test_security_critical_step_order_fails_closed(self):
        expected = [
            "Preflight trusted runner and exact current same-repository PR head",
            "Checkout exact target SHA",
            "Verify exact clean checkout and Python 3.12",
            "Run full deterministic suite",
            "Run real Windows junction containment regression",
            "Verify checkout unchanged after tests",
            "Revalidate current PR head after tests",
            "Record self-hosted evidence class",
        ]
        self.assertEqual(self.step_names, expected)

    def test_postconditions_recheck_head_cleanliness_and_pr_head(self):
        required = (
            "HEAD changed during tests",
            "working tree changed during tests",
            "PR head changed during self-hosted verification",
            "SELF_HOSTED_EXACT_HEAD_PASS",
            "evidence is not GITHUB_HOSTED_CI_PASS",
        )
        for marker in required:
            self.assertIn(marker, self.text)

    def test_exact_test_commands_are_preserved(self):
        self.assertIn("python -m unittest discover -s tests -v", self.text)
        self.assertIn(
            'python -m unittest discover -s tests -p "test_antigravity_windows_junction.py" -v',
            self.text,
        )


if __name__ == "__main__":
    unittest.main()
