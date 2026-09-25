"""Contract for the worker-neutral entry point (Issue #256).

These checks keep the entry documents usable by every worker:

- `AGENTS.md` stays a small bootloader that carries the non-negotiables.
- `PROJECT_STATUS.md` stays an index, not an authority.
- Every relative link in the entry documents resolves.
- No provider-specific instruction file shadows `AGENTS.md`.
"""

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
AGENTS = ROOT / "AGENTS.md"
STATUS = ROOT / "PROJECT_STATUS.md"
GOVERNANCE = ROOT / "docs" / "governance"

# Codex caps combined instruction files at 32 KiB by default. The entry file
# must stay far below that so it is always loaded in full and actually read.
AGENTS_SIZE_BUDGET_BYTES = 8 * 1024

LINK = re.compile(r"\]\(([^)\s]+)\)")


def _text(path):
    return path.read_bytes().decode("utf-8")


def _normalized(text):
    return " ".join(text.split()).lower()


class WorkerEntryContractTests(unittest.TestCase):
    def test_agents_md_is_a_small_bootloader(self):
        size = AGENTS.stat().st_size
        self.assertLessEqual(size, AGENTS_SIZE_BUDGET_BYTES, f"AGENTS.md is {size} bytes")
        text = _text(AGENTS)
        for heading in ("## Start here", "## Non-negotiables", "## Handoff"):
            with self.subTest(heading=heading):
                self.assertIn(heading, text)

    def test_agents_md_carries_the_non_negotiables(self):
        text = _normalized(_text(AGENTS))
        required = {
            "evidence authority": "claims until verified",
            "human-final authority": "ready, merge, and every level 3 effect are human actions",
            "independent review": "is not the sole reviewer of its own work",
            "self-review is not independent": "self-review is l0",
            "no duplicate implementation": "do not reimplement",
            "live-effect authorization": "separate explicit human authorization",
            "status file is not authority": "not a statement of current state",
        }
        for label, phrase in required.items():
            with self.subTest(rule=label):
                self.assertIn(phrase, text)

    def test_project_status_declares_itself_an_index(self):
        text = _text(STATUS)
        normalized = _normalized(text)
        self.assertIn("this file is an index, not an authority.", normalized)
        self.assertIn("re-read those facts from github and ci", normalized)
        self.assertRegex(text, r"\*\*as_of:\*\* \d{4}-\d{2}-\d{2}")
        for heading in ("## Main line", "## Active workstreams", "## Standing decisions"):
            with self.subTest(heading=heading):
                self.assertIn(heading, text)

    def test_project_status_does_not_carry_state_columns(self):
        # Workstream rows are pointers; state belongs to the authority Issue.
        text = _text(STATUS)
        table = text.split("## Active workstreams", 1)[1].split("\n## ", 1)[0]
        header = next(line for line in table.splitlines() if line.startswith("|"))
        for forbidden in ("status", "state", "ci", "review"):
            with self.subTest(column=forbidden):
                self.assertNotIn(forbidden, [cell.strip().lower() for cell in header.split("|")])

    def test_every_governance_rule_names_its_owner(self):
        text = _text(GOVERNANCE / "rules.md")
        sections = re.split(r"\n## ", text)[1:]
        self.assertGreaterEqual(len(sections), 13)
        for section in sections:
            title = section.splitlines()[0]
            with self.subTest(rule=title):
                self.assertTrue(
                    re.search(r"#\d+|BASELINE|\.md\)", section),
                    f"rule without an owning record: {title}",
                )

    def test_relative_links_in_entry_documents_resolve(self):
        documents = [AGENTS, STATUS, *sorted(GOVERNANCE.glob("*.md"))]
        for document in documents:
            for target in LINK.findall(_text(document)):
                if re.match(r"[a-z]+://", target) or target.startswith("#"):
                    continue
                path = (document.parent / target.split("#", 1)[0]).resolve()
                with self.subTest(document=document.name, link=target):
                    self.assertTrue(path.exists(), f"{document.name}: broken link {target}")

    def test_no_provider_file_shadows_agents_md(self):
        # A CLAUDE.md makes Claude Code skip AGENTS.md; only an import shim is allowed.
        for name in ("CLAUDE.md", "CLAUDE.local.md", ".claude/CLAUDE.md", "GEMINI.md"):
            path = ROOT / name
            if not path.exists():
                continue
            with self.subTest(file=name):
                lines = [line.strip() for line in _text(path).splitlines() if line.strip()]
                self.assertEqual(lines, ["@AGENTS.md"], f"{name} must be an import-only shim")


if __name__ == "__main__":
    unittest.main()
