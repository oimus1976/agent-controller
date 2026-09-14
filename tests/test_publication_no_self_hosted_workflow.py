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

    def test_no_active_workflow_targets_self_hosted_runner(self):
        offenders = []
        for workflow in sorted(WORKFLOW_DIR.glob("*.y*ml")):
            text = workflow.read_text(encoding="utf-8")
            for line_number, line in enumerate(text.splitlines(), start=1):
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                lower = stripped.lower()
                if re.match(r"""^["']?runs-on["']?\s*:""", lower):
                    if "self-hosted" in lower or "ac-ci-" in lower:
                        offenders.append(
                            f"{workflow.relative_to(REPO_ROOT)}:{line_number}:{stripped}"
                        )
        self.assertEqual(offenders, [], "active self-hosted runner surface reintroduced")

    def test_hosted_tests_workflow_keeps_read_only_checkout_contract(self):
        path = WORKFLOW_DIR / "tests.yml"
        text = path.read_text(encoding="utf-8")
        self.assertIn("permissions:\n  contents: read\n", text)
        self.assertNotRegex(text, r"(?m)^\s+[a-z-]+:\s*write\s*$")
        self.assertGreaterEqual(text.count("persist-credentials: false"), 2)


if __name__ == "__main__":
    unittest.main()