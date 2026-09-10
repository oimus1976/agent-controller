from pathlib import Path
import re
import shutil
import subprocess
import sys
import unittest


REPO_ROOT = Path(__file__).resolve(strict=True).parents[1]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "self-hosted-exact-head.yml"
EXPECTED_STEPS = [
    "Preflight trusted control and disposable target identities",
    "Checkout exact target SHA",
    "Verify exact clean checkout and grant target read-only access",
    "Run target tests under disposable SID",
    "Verify trusted postconditions and revoke target access",
    "Revalidate current PR head after tests",
    "Record self-hosted evidence class",
]
TRUSTED_SHELL = 'shell: powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "& \'{0}\'"'


def parse_strict_workflow_structure(text: str) -> dict[str, str]:
    """Parse only the intentionally tiny workflow shape and reject structural drift.

    This is deliberately stricter than a general YAML parser: any extra job, unnamed
    list entry, conditional step/job, or alternate executable surface fails closed.
    """
    lines = text.splitlines()
    try:
        jobs_index = lines.index("jobs:")
        steps_index = lines.index("    steps:")
    except ValueError as exc:
        raise ValueError("required workflow structure is missing") from exc

    job_names = []
    for line in lines[jobs_index + 1 :]:
        match = re.fullmatch(r"  ([A-Za-z0-9_-]+):", line)
        if match:
            job_names.append(match.group(1))
    if job_names != ["windows-exact-head"]:
        raise ValueError(f"unexpected job set: {job_names!r}")

    job_level_keys = []
    for line in lines[jobs_index + 1 : steps_index + 1]:
        match = re.fullmatch(r"    ([A-Za-z0-9_-]+):(?:\s*(.*))?", line)
        if match:
            job_level_keys.append(match.group(1))
    if job_level_keys != ["runs-on", "timeout-minutes", "steps"]:
        raise ValueError(f"unexpected job-level keys: {job_level_keys!r}")

    if re.search(r"(?m)^\s+(?:if|continue-on-error):", text):
        raise ValueError("workflow conditions/continue-on-error are not allowed")
    if re.search(r'''(?m)^\s+["'](?:if|continue-on-error)["']\s*:''', text):
        raise ValueError("quoted workflow conditions/continue-on-error are not allowed")

    step_starts = []
    for index, line in enumerate(lines[steps_index + 1 :], start=steps_index + 1):
        if line.startswith("      -"):
            match = re.fullmatch(r"      - name: (.+)", line)
            if not match:
                raise ValueError(f"unnamed or alternate step entry at line {index + 1}")
            step_starts.append((index, match.group(1)))

    if [name for _, name in step_starts] != EXPECTED_STEPS:
        raise ValueError("security-critical step set/order changed")

    blocks: dict[str, str] = {}
    for position, (start, name) in enumerate(step_starts):
        end = step_starts[position + 1][0] if position + 1 < len(step_starts) else len(lines)
        block = "\n".join(lines[start:end]) + "\n"
        blocks[name] = block

        executable_keys = re.findall(r"(?m)^        (uses|shell|run):", block)
        if name == "Checkout exact target SHA":
            if executable_keys != ["uses"]:
                raise ValueError("checkout executable shape changed")
        else:
            if executable_keys != ["shell", "run"]:
                raise ValueError(f"trusted run-step executable shape changed: {name}")
            if TRUSTED_SHELL not in block:
                raise ValueError(f"trusted shell changed: {name}")

    return blocks


def extract_run_blocks(text: str) -> list[str]:
    lines = text.splitlines()
    blocks = []
    index = 0
    while index < len(lines):
        if lines[index] != "        run: |":
            index += 1
            continue
        index += 1
        body = []
        while index < len(lines):
            line = lines[index]
            if line and not line.startswith("          "):
                break
            body.append(line[10:] if line.startswith("          ") else "")
            index += 1
        blocks.append("\n".join(body) + "\n")
    return blocks


class SelfHostedFallbackWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = WORKFLOW.read_text(encoding="utf-8")
        cls.step_blocks = parse_strict_workflow_structure(cls.text)

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

    def test_exact_job_and_step_structure_is_preserved(self):
        self.assertEqual(list(self.step_blocks), EXPECTED_STEPS)

    def test_structure_parser_rejects_dash_only_unnamed_step(self):
        mutated = self.text.replace(
            "    steps:\n",
            "    steps:\n      -\n        run: echo unsafe-before-preflight\n",
            1,
        )
        with self.assertRaises(ValueError):
            parse_strict_workflow_structure(mutated)

    def test_structure_parser_rejects_skipped_gate(self):
        needle = f"      - name: {EXPECTED_STEPS[0]}\n"
        mutated = self.text.replace(needle, needle + "        if: false\n", 1)
        with self.assertRaises(ValueError):
            parse_strict_workflow_structure(mutated)

    def test_structure_parser_rejects_quoted_skipped_gate(self):
        needle = f"      - name: {EXPECTED_STEPS[0]}\n"
        for quoted_key in ('"if"', "'if'"):
            with self.subTest(quoted_key=quoted_key):
                mutated = self.text.replace(needle, needle + f"        {quoted_key}: false\n", 1)
                with self.assertRaises(ValueError):
                    parse_strict_workflow_structure(mutated)

    def test_structure_parser_rejects_extra_reusable_workflow_job(self):
        mutated = self.text + "\n  shadow-job:\n    uses: owner/repo/.github/workflows/unsafe.yml@main\n"
        with self.assertRaises(ValueError):
            parse_strict_workflow_structure(mutated)

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
        for name, block in self.step_blocks.items():
            if name == "Checkout exact target SHA":
                continue
            with self.subTest(step=name):
                self.assertIn(TRUSTED_SHELL, block)

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

    def test_acl_sid_interpolation_is_braced_before_colon_suffix(self):
        relevant = "\n".join(
            self.step_blocks[name]
            for name in (
                "Verify exact clean checkout and grant target read-only access",
                "Run target tests under disposable SID",
                "Verify trusted postconditions and revoke target access",
            )
        )
        self.assertIn('"*${targetSid}:(OI)(CI)(RX)"', relevant)
        self.assertIn('"*${controlSid}:(OI)(CI)(F)"', relevant)
        self.assertIn('"*${targetSid}:(OI)(CI)(M)"', relevant)
        self.assertIn('"*${targetSid}"', relevant)
        self.assertNotRegex(relevant, r'"\*\$(?:targetSid|controlSid):')

    @unittest.skipUnless(sys.platform == "win32", "Windows PowerShell parser regression")
    def test_every_embedded_powershell_run_block_parses_on_windows(self):
        powershell = shutil.which("powershell.exe") or shutil.which("powershell")
        if powershell is None:
            self.skipTest("Windows PowerShell is unavailable")
        blocks = extract_run_blocks(self.text)
        self.assertEqual(len(blocks), len(EXPECTED_STEPS) - 1)
        parser = "[void][ScriptBlock]::Create([Console]::In.ReadToEnd())"
        for index, block in enumerate(blocks):
            with self.subTest(run_block=index):
                completed = subprocess.run(
                    [powershell, "-NoProfile", "-NonInteractive", "-Command", parser],
                    input=block,
                    text=True,
                    capture_output=True,
                    timeout=10,
                    check=False,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)

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
        names = list(self.step_blocks)
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
