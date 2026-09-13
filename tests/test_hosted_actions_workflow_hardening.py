from pathlib import Path
import unittest


WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "tests.yml"
CHECKOUT = "uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262"


class HostedActionsWorkflowHardeningTests(unittest.TestCase):
    def test_every_hosted_checkout_disables_credential_persistence(self):
        lines = WORKFLOW.read_text(encoding="utf-8").splitlines()
        checkout_lines = [index for index, line in enumerate(lines) if CHECKOUT in line]

        self.assertEqual(len(checkout_lines), 2)
        for index in checkout_lines:
            block = "\n".join(lines[index : index + 5])
            self.assertIn("with:", block)
            self.assertIn("persist-credentials: false", block)


if __name__ == "__main__":
    unittest.main()
