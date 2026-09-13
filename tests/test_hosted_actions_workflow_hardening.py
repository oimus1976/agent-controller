from pathlib import Path
import unittest


WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "tests.yml"
CHECKOUT = "uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262"


def checkout_step_blocks(lines):
    blocks = []
    for index, line in enumerate(lines):
        if CHECKOUT not in line:
            continue

        start = index
        while start >= 0 and not lines[start].startswith("      - "):
            start -= 1
        if start < 0:
            raise AssertionError("checkout action is not inside a workflow step")

        end = start + 1
        while end < len(lines) and not lines[end].startswith("      - "):
            end += 1
        blocks.append("\n".join(lines[start:end]))
    return blocks


class HostedActionsWorkflowHardeningTests(unittest.TestCase):
    def test_every_hosted_checkout_disables_credential_persistence(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        lines = text.splitlines()
        blocks = checkout_step_blocks(lines)

        self.assertIn("permissions:\n  contents: read", text)
        self.assertNotIn("persist-credentials: true", text)
        self.assertEqual(len(blocks), 2)
        for block in blocks:
            self.assertIn(CHECKOUT, block)
            self.assertIn("        with:\n          persist-credentials: false", block)


if __name__ == "__main__":
    unittest.main()
