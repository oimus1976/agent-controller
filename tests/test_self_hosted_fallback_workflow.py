from pathlib import Path
import re
import unittest


REPO_ROOT = Path(__file__).resolve(strict=True).parents[1]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "self-hosted-exact-head.yml"


class SelfHostedFallbackWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = WORKFLOW.read_text(encoding="utf-8")
        cls.step_headers = re.findall(r"(?m)^      - ([A-Za-z0-9_-]+):(?:\s*(.*))?$", cls.text)
        cls.step_blocks = {}
        matches = list(re.finditer(r"(?m)^      - name: (.+)$", cls.text))
        for index, match in enumerate(matches):
            end = matches[index + 1].start() if index + 1 < len(matches) else len(cls.text)
            cls.step_blocks[match.group(1)] = cls.text[match.start():end]

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
        checkout = self.step_blocks["Checkout exact target SHA"]
        self.assertIn("persist-credentials: false", checkout)
        self.assertIn("clean: true", checkout)
        self.assertRegex(checkout, r"uses: actions/checkout@[0-9a-f]{40}")

    def test_every_step_is_named_and_exact_step_set_is_preserved(self):
        # At the steps indentation level, an unnamed `uses`, `run`, or `shell`
        # step must not be able to appear before validation unnoticed.
        self.assertTrue(self.step_headers)
        self.assertTrue(all(key == "name" for key, _ in self.step_headers), self.step_headers)
        expected = [
            "Preflight trusted control and disposable target identities",
            "Checkout exact target SHA",
            "Verify exact clean checkout and grant target read-only access",
            "Run target tests under disposable SID",
            "Verify trusted postconditions and revoke target access",
            "Revalidate current PR head after tests",
            "Record self-hosted evidence class",
        ]
        self.assertEqual([value for _, value in self.step_headers], expected)
        self.assertEqual(set(self.step_blocks), set(expected))

    def test_preflight_binds_local_control_sid_disposable_target_and_exact_head(self):
        preflight = self.step_blocks["Preflight trusted control and disposable target identities"]
        required = (
            "refs/heads/main",
            "runner OS must be Windows",
            "runner architecture must be X64",
            "Get-LocalUser -Name 'ac-runner'",
            "runner identity SID must equal local ac-runner SID",
            "local ac-runner account must not be a member of local Administrators",
            'targetName = "act-$($env:INPUT_RUNNER_NONCE.ToLowerInvariant())"',
            "exactly one current disposable act-* target account may exist before a pilot",
            "disposable target SID already has a Windows profile",
            "disposable target SID already owns scheduled-task state",
            "one-time credential ACL must disable inheritance",
            "one-time credential file grants access to forbidden SID",
            "fork or foreign head repository is not allowed",
            "target_sha is not the current PR head",
        )
        for marker in required:
            self.assertIn(marker, preflight)

    def test_trusted_shells_disable_profiles(self):
        run_steps = [name for name in self.step_blocks if name != "Checkout exact target SHA"]
        for name in run_steps:
            with self.subTest(step=name):
                self.assertIn(
                    'shell: powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "& \'{0}\'"',
                    self.step_blocks[name],
                )

    def test_target_execution_is_different_sid_with_isolated_environment(self):
        target = self.step_blocks["Run target tests under disposable SID"]
        required = (
            "Start-Process",
            "-Credential $credential",
            "-LoadUserProfile -UseNewEnvironment",
            "-NoProfile",
            "GITHUB_*",
            "GH_TOKEN",
            "GITHUB_STEP_SUMMARY",
            "GITHUB_ENV",
            "GITHUB_PATH",
            "one-time credential file was not removed before target execution",
            "python.exe'",
            "-B -m unittest discover -s tests -v",
            "-B -m unittest discover -s tests -p 'test_antigravity_windows_junction.py' -v",
        )
        for marker in required:
            self.assertIn(marker, target)
        self.assertNotIn("GH_TOKEN:", target)
        self.assertNotIn(">> $env:GITHUB_STEP_SUMMARY", target)

    def test_checkout_access_is_read_only_and_revoked_after_tests(self):
        pre_test = self.step_blocks["Verify exact clean checkout and grant target read-only access"]
        post_test = self.step_blocks["Verify trusted postconditions and revoke target access"]
        self.assertIn('(OI)(CI)(RX)', pre_test)
        self.assertIn('/grant:r', pre_test)
        self.assertIn('/remove:g', post_test)
        self.assertIn("HEAD changed during tests", post_test)
        self.assertIn("working tree changed during tests", post_test)
        self.assertIn("target tests created scheduled-task persistence", post_test)
        self.assertIn("PASS evidence marker existed before trusted final evidence step", post_test)

    def test_trusted_postconditions_and_api_revalidation_precede_pass_emission(self):
        names = [value for _, value in self.step_headers]
        post_index = names.index("Verify trusted postconditions and revoke target access")
        api_index = names.index("Revalidate current PR head after tests")
        pass_index = names.index("Record self-hosted evidence class")
        self.assertLess(post_index, api_index)
        self.assertLess(api_index, pass_index)

        final_api = self.step_blocks["Revalidate current PR head after tests"]
        self.assertIn("PR head changed during self-hosted verification", final_api)
        self.assertIn("GH_TOKEN: ${{ github.token }}", final_api)

        evidence = self.step_blocks["Record self-hosted evidence class"]
        self.assertIn(">> $env:GITHUB_STEP_SUMMARY", evidence)
        self.assertIn("SELF_HOSTED_EXACT_HEAD_PASS", evidence)
        self.assertIn("evidence is not GITHUB_HOSTED_CI_PASS", evidence)
        self.assertIn("Ready / merge remain human-final", evidence)

    def test_target_test_commands_appear_only_in_disposable_target_step(self):
        full = "unittest discover -s tests -v"
        junction = "unittest discover -s tests -p 'test_antigravity_windows_junction.py' -v"
        for name, block in self.step_blocks.items():
            if name == "Run target tests under disposable SID":
                self.assertIn(full, block)
                self.assertIn(junction, block)
            else:
                self.assertNotIn(full, block)
                self.assertNotIn(junction, block)


if __name__ == "__main__":
    unittest.main()
