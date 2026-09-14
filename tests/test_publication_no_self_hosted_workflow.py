from pathlib import Path
import re
import unittest


REPO_ROOT = Path(__file__).resolve(strict=True).parents[1]
WORKFLOW_DIR = REPO_ROOT / ".github" / "workflows"
RETIRED = WORKFLOW_DIR / "self-hosted-exact-head.yml"


class PublicationNoSelfHostedWorkflowTests(unittest.TestCase):
    def test_private_self_hosted_fallback_is_retired(self):
        self.assertFalse(
            RETIRED.exists(),
            "private-era self-hosted exact-head workflow must stay retired for publication",
        )

    def _runner_values(self, text):
        values = []
        for line_number, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            match = re.match(r"""^["']?runs-on["']?\s*:\s*(.+?)\s*$""", stripped, re.IGNORECASE)
            if match:
                values.append((line_number, match.group(1)))
        return values

    def test_all_active_workflow_runners_are_known_github_hosted_labels(self):
        allowed = {"ubuntu-latest", "windows-latest"}
        offenders = []
        for workflow in sorted(WORKFLOW_DIR.glob("*.y*ml")):
            text = workflow.read_text(encoding="utf-8")
            for line_number, value in self._runner_values(text):
                normalized = value.strip().strip("\"'")
                if normalized not in allowed:
                    offenders.append(
                        f"{workflow.relative_to(REPO_ROOT)}:{line_number}:{value}"
                    )
        self.assertEqual(
            offenders,
            [],
            "publication workflows must use only explicitly allowed GitHub-hosted runners",
        )

    def test_runner_allowlist_rejects_indirection_and_self_hosted_labels(self):
        allowed = {"ubuntu-latest", "windows-latest"}
        for candidate in (
            "${{ vars.RUNNER }}",
            "self-hosted",
            "[self-hosted, windows, x64]",
            "ac-ci-deadbeefdeadbeef",
        ):
            with self.subTest(candidate=candidate):
                values = self._runner_values(f"jobs:\n  probe:\n    runs-on: {candidate}\n")
                self.assertEqual(len(values), 1)
                normalized = values[0][1].strip().strip("\"'")
                self.assertNotIn(normalized, allowed)

    def test_hosted_tests_workflow_keeps_read_only_checkout_contract(self):
        path = WORKFLOW_DIR / "tests.yml"
        text = path.read_text(encoding="utf-8")
        self.assertIn("permissions:\n  contents: read\n", text)
        self.assertNotRegex(text, r"(?m)^\s+[a-z-]+:\s*write\s*$")
        self.assertGreaterEqual(text.count("persist-credentials: false"), 2)


if __name__ == "__main__":
    unittest.main()