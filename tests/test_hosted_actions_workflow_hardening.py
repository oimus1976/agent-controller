from pathlib import Path
import unittest


WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "tests.yml"
CHECKOUT_PREFIX = "actions/checkout@"
PINNED_CHECKOUT = "actions/checkout@11d5960a326750d5838078e36cf38b85af677262"


def uses_value(line):
    stripped = line.strip()
    if stripped.startswith("- "):
        stripped = stripped[2:].lstrip()
    if not stripped.startswith("uses:"):
        return None

    value = stripped[len("uses:") :].strip()
    if not value:
        return None

    if value[0] in ("'", '"'):
        quote = value[0]
        closing = value.find(quote, 1)
        if closing < 0:
            return value
        return value[1:closing]

    return value.split(" #", 1)[0].strip()


def is_checkout_action(action):
    return action is not None and action.lower().startswith(CHECKOUT_PREFIX)


def checkout_step_blocks(lines):
    blocks = []
    for index, line in enumerate(lines):
        action = uses_value(line)
        if not is_checkout_action(action):
            continue

        start = index
        while start >= 0 and not lines[start].startswith("      - "):
            start -= 1
        if start < 0:
            raise AssertionError("checkout action is not inside a workflow step")

        end = start + 1
        while end < len(lines) and not lines[end].startswith("      - "):
            end += 1
        blocks.append((action, "\n".join(lines[start:end])))
    return blocks


def literal_checkout_lines(lines):
    matches = []
    for line in lines:
        non_comment = line.split("#", 1)[0]
        if CHECKOUT_PREFIX in non_comment.lower():
            matches.append(line)
    return matches


def complete_checkout_step_blocks(lines):
    blocks = checkout_step_blocks(lines)
    literal_lines = literal_checkout_lines(lines)
    if len(blocks) != len(literal_lines):
        raise AssertionError(
            "checkout discovery is incomplete; unsupported YAML indirection "
            "or spelling must fail closed"
        )
    return blocks


def assert_workflow_permissions_are_read_only(lines):
    declarations = [
        line for line in lines
        if line.lstrip().startswith("permissions:")
    ]
    if declarations != ["permissions:"]:
        raise AssertionError(
            "hosted workflow must use exactly one workflow-level "
            "permissions declaration"
        )


class HostedActionsWorkflowHardeningTests(unittest.TestCase):
    def test_checkout_discovery_is_not_tied_to_current_pin_or_yaml_spelling(self):
        examples = (
            (
                "named step, unquoted",
                [
                    "    steps:",
                    "      - name: Example checkout",
                    "        uses: actions/checkout@v4",
                    "      - run: echo done",
                ],
            ),
            (
                "named step, single quoted",
                [
                    "    steps:",
                    "      - name: Example checkout",
                    "        uses: 'actions/checkout@v4'",
                    "      - run: echo done",
                ],
            ),
            (
                "named step, double quoted",
                [
                    "    steps:",
                    "      - name: Example checkout",
                    '        uses: "actions/checkout@v4"',
                    "      - run: echo done",
                ],
            ),
            (
                "list item, unquoted",
                [
                    "    steps:",
                    "      - uses: actions/checkout@v4",
                    "      - run: echo done",
                ],
            ),
            (
                "list item, single quoted",
                [
                    "    steps:",
                    "      - uses: 'actions/checkout@v4'",
                    "      - run: echo done",
                ],
            ),
            (
                "list item, double quoted",
                [
                    "    steps:",
                    '      - uses: "actions/checkout@v4"',
                    "      - run: echo done",
                ],
            ),
        )

        for label, lines in examples:
            with self.subTest(label=label):
                blocks = complete_checkout_step_blocks(lines)

                self.assertEqual(len(blocks), 1)
                action, block = blocks[0]
                self.assertEqual(action, "actions/checkout@v4")
                self.assertIn("checkout@v4", block)

    def test_checkout_discovery_matches_repository_case_insensitively(self):
        lines = [
            "    steps:",
            "      - name: Example checkout",
            "        uses: Actions/Checkout@v4",
            "      - run: echo done",
        ]

        blocks = complete_checkout_step_blocks(lines)

        self.assertEqual(len(blocks), 1)
        action, block = blocks[0]
        self.assertEqual(action.lower(), "actions/checkout@v4")
        self.assertIn("Actions/Checkout@v4", block)

    def test_indirect_checkout_action_via_yaml_alias_fails_closed(self):
        lines = [
            "checkout_action: &checkout_action actions/checkout@v4",
            "jobs:",
            "  unittest:",
            "    steps:",
            "      - uses: *checkout_action",
            "      - run: echo done",
        ]

        with self.assertRaisesRegex(
            AssertionError,
            "checkout discovery is incomplete",
        ):
            complete_checkout_step_blocks(lines)

    def test_job_level_permissions_are_rejected(self):
        lines = [
            "permissions:",
            "  contents: read",
            "jobs:",
            "  unittest:",
            "    permissions: write-all",
            "    steps:",
            "      - run: echo done",
        ]

        with self.assertRaisesRegex(
            AssertionError,
            "exactly one workflow-level permissions declaration",
        ):
            assert_workflow_permissions_are_read_only(lines)

    def test_every_hosted_checkout_is_pinned_and_disables_credential_persistence(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        lines = text.splitlines()
        blocks = complete_checkout_step_blocks(lines)

        assert_workflow_permissions_are_read_only(lines)
        self.assertIn("permissions:\n  contents: read", text)
        self.assertNotIn("persist-credentials: true", text)
        self.assertGreaterEqual(len(blocks), 1)
        for action, block in blocks:
            self.assertEqual(action.lower(), PINNED_CHECKOUT)
            self.assertIn("        with:\n          persist-credentials: false", block)


if __name__ == "__main__":
    unittest.main()
