"""Contract for the worker-neutral entry point (Issue #256).

These checks keep the entry documents usable by every worker:

- `AGENTS.md` stays a small bootloader that carries the non-negotiables.
- `PROJECT_STATUS.md` stays an index, not an authority.
- Every governance rule names its owning record.
- Every relative link in the entry documents resolves.
- No provider-specific instruction file shadows `AGENTS.md`.

The checks read the operative Markdown structure. Text inside fenced code
blocks or HTML comments does not count, and each required statement must sit
in the section and list where a worker will act on it. Each checker is also
run against small fixtures, so a checker that stops seeing a violation fails.
"""

import os
import re
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
AGENTS = ROOT / "AGENTS.md"
STATUS = ROOT / "PROJECT_STATUS.md"
GOVERNANCE = ROOT / "docs" / "governance"

# Codex caps combined instruction files at 32 KiB by default. The entry file
# must stay far below that so it is always loaded in full and actually read.
AGENTS_SIZE_BUDGET_BYTES = 8 * 1024

AGENTS_REQUIRED_SECTIONS = ("Start here", "Non-negotiables", "Handoff")

# Required statements, keyed by the section whose list items must carry them.
AGENTS_REQUIRED_STATEMENTS = {
    "Start here": {
        "status file is not authority": "not a statement of current state",
    },
    "Non-negotiables": {
        "evidence authority": "claims until verified",
        "human-final authority": "ready, merge, and every level 3 effect are human actions",
        "independent review": "is not the sole reviewer of its own work",
        "self-review is not independent": "self-review is l0",
        "no duplicate implementation": "do not reimplement",
        "live-effect authorization": "separate explicit human authorization",
    },
}

STATUS_REQUIRED_SECTIONS = ("Main line", "Active workstreams", "Standing decisions")
STATUS_FORBIDDEN_COLUMNS = ("status", "state", "ci", "review")

RULES_MINIMUM_SECTIONS = 13

# Files that make a provider read something other than AGENTS.md. Claude Code
# skips AGENTS.md when a CLAUDE.md is present, and Codex prefers
# AGENTS.override.md over AGENTS.md in the same directory.
SHIM_ONLY_FILES = frozenset({"CLAUDE.md", "CLAUDE.local.md", "GEMINI.md"})
FORBIDDEN_FILES = frozenset({"AGENTS.override.md"})
SKIPPED_DIRS = frozenset({".git", "node_modules", ".venv", "venv", "__pycache__"})

INLINE_LINK = re.compile(r"\]\(\s*<?([^)\s>]+)>?(?:\s+\"[^\"]*\")?\s*\)")
REFERENCE_USE = re.compile(r"\[([^\]]+)\]\[([^\]]*)\]")
REFERENCE_DEFINITION = re.compile(r"^ {0,3}\[([^\]]+)\]:\s*<?([^\s>]+)>?")
FENCE = re.compile(r"^ {0,3}(`{3,}|~{3,})")
LIST_ITEM = re.compile(r"^\s*(?:[-*+]|\d+[.)])\s+")
ISSUE_LINK = re.compile(r"\]\(https://github\.com/oimus1976/agent-controller/issues/\d+\)")
RELATIVE_MD_LINK = re.compile(r"\]\((?![a-z]+://)[^)\s]+\.md(?:#[^)\s]*)?\)")
OWNER_ITEM = re.compile(r"^\s*-\s+Owners?:\s")


def _text(path):
    return path.read_bytes().decode("utf-8")


def _normalized(text):
    return " ".join(text.split()).lower()


def operative_lines(text):
    """Return the lines that render as document content.

    HTML comments and fenced code blocks are dropped, because a statement
    there is not an instruction a worker will follow.
    """
    text = re.sub(r"<!--.*?-->", "", text, flags=re.S)
    lines = []
    fence = None
    for line in text.splitlines():
        match = FENCE.match(line)
        if match:
            marker = match.group(1)
            if fence is None:
                fence = marker
                continue
            if marker[0] == fence[0] and len(marker) >= len(fence):
                fence = None
                continue
        if fence is None:
            lines.append(line)
    return lines


def split_sections(lines):
    """Split operative lines into a preamble and level-2 sections."""
    preamble = []
    sections = {}
    current = preamble
    for line in lines:
        match = re.match(r"^## (.+?)\s*#*\s*$", line)
        if match:
            current = sections.setdefault(match.group(1).strip(), [])
            continue
        current.append(line)
    return preamble, sections


def list_items(lines):
    """Return each list item with its indented continuation lines, normalized."""
    items = []
    current = None
    for line in lines:
        if LIST_ITEM.match(line):
            current = [line]
            items.append(current)
        elif current is not None and line.strip() and line.startswith((" ", "\t")):
            current.append(line.strip())
        else:
            current = None
    return [_normalized(" ".join(item)) for item in items]


def agents_violations(text):
    violations = []
    _, sections = split_sections(operative_lines(text))
    for heading in AGENTS_REQUIRED_SECTIONS:
        if heading not in sections:
            violations.append(f"missing section: {heading}")
    for heading, statements in AGENTS_REQUIRED_STATEMENTS.items():
        items = list_items(sections.get(heading, []))
        for label, phrase in statements.items():
            if not any(phrase in item for item in items):
                violations.append(f"{heading}: no list item states {label!r} ({phrase!r})")
    return violations


def status_violations(text):
    violations = []
    preamble, sections = split_sections(operative_lines(text))
    head = _normalized("\n".join(preamble))
    if "this file is an index, not an authority." not in head:
        violations.append("preamble does not declare the file an index")
    if "re-read those facts from github and ci" not in head:
        violations.append("preamble does not direct readers to GitHub and CI")
    if not re.search(r"\*\*as_of:\*\* \d{4}-\d{2}-\d{2}", "\n".join(preamble)):
        violations.append("preamble has no as_of date")
    for heading in STATUS_REQUIRED_SECTIONS:
        if heading not in sections:
            violations.append(f"missing section: {heading}")
    table = [line for line in sections.get("Active workstreams", []) if line.lstrip().startswith("|")]
    if not table:
        violations.append("Active workstreams has no table")
    else:
        columns = [cell.strip().lower() for cell in table[0].strip().strip("|").split("|")]
        for forbidden in STATUS_FORBIDDEN_COLUMNS:
            if forbidden in columns:
                violations.append(f"Active workstreams carries a {forbidden!r} column")
    return violations


def rules_violations(text):
    violations = []
    _, sections = split_sections(operative_lines(text))
    if len(sections) < RULES_MINIMUM_SECTIONS:
        violations.append(f"only {len(sections)} rule sections")
    for title, lines in sections.items():
        owners = [line for line in lines if OWNER_ITEM.match(line)]
        if not owners:
            violations.append(f"{title}: no Owner line")
            continue
        if not any(
            ISSUE_LINK.search(line) or RELATIVE_MD_LINK.search(line) or re.search(r"BASELINE §\d", line)
            for line in owners
        ):
            violations.append(f"{title}: Owner line links no owning record")
    return violations


def link_violations(document, text):
    """Return unresolved relative links, inline or reference-style."""
    lines = operative_lines(text)
    body = "\n".join(lines)
    definitions = {}
    for line in lines:
        match = REFERENCE_DEFINITION.match(line)
        if match:
            definitions[match.group(1).strip().lower()] = match.group(2)
    targets = list(INLINE_LINK.findall(body))
    violations = []
    for label_text, label in REFERENCE_USE.findall(body):
        key = (label or label_text).strip().lower()
        if key not in definitions:
            violations.append(f"undefined link reference [{key}]")
    targets.extend(definitions.values())
    for target in targets:
        if re.match(r"[a-z][a-z0-9+.-]*:", target, flags=re.I) or target.startswith("#"):
            continue
        path = (document.parent / target.split("#", 1)[0]).resolve()
        if not path.exists():
            violations.append(f"broken link {target}")
    return violations


def shadow_violations(root):
    """Return provider instruction files that would shadow root AGENTS.md."""
    agents = root / "AGENTS.md"
    violations = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIPPED_DIRS)
        for name in sorted(filenames):
            path = Path(dirpath) / name
            relative = path.relative_to(root).as_posix()
            if name in FORBIDDEN_FILES:
                violations.append(f"{relative} must not exist")
            elif name in SHIM_ONLY_FILES:
                expected = "@" + os.path.relpath(agents, path.parent).replace(os.sep, "/")
                lines = [line.strip() for line in _text(path).splitlines() if line.strip()]
                if lines != [expected]:
                    violations.append(f"{relative} must contain only {expected}")
    return violations


class WorkerEntryContractTests(unittest.TestCase):
    def test_agents_md_is_a_small_bootloader(self):
        size = AGENTS.stat().st_size
        self.assertLessEqual(size, AGENTS_SIZE_BUDGET_BYTES, f"AGENTS.md is {size} bytes")

    def test_agents_md_carries_the_non_negotiables(self):
        self.assertEqual(agents_violations(_text(AGENTS)), [])

    def test_project_status_is_an_index_without_state_columns(self):
        self.assertEqual(status_violations(_text(STATUS)), [])

    def test_every_governance_rule_names_its_owner(self):
        self.assertEqual(rules_violations(_text(GOVERNANCE / "rules.md")), [])

    def test_relative_links_in_entry_documents_resolve(self):
        for document in [AGENTS, STATUS, *sorted(GOVERNANCE.glob("*.md"))]:
            with self.subTest(document=document.name):
                self.assertEqual(link_violations(document, _text(document)), [])

    def test_no_provider_file_shadows_agents_md(self):
        self.assertEqual(shadow_violations(ROOT), [])


class WorkerEntryCheckerFixtureTests(unittest.TestCase):
    """Each checker must still see the violations it exists to catch."""

    def _agents_with(self, old, new):
        text = _text(AGENTS)
        self.assertIn(old, text)
        return text.replace(old, new, 1)

    def test_statement_hidden_in_comment_code_or_quote_is_not_counted(self):
        line = next(l for l in _text(AGENTS).splitlines() if "claims until verified" in l)
        for wrapped in (f"<!--\n{line}\n-->", f"```text\n{line}\n```", f"> {line}"):
            with self.subTest(wrapper=wrapped[:4]):
                violations = agents_violations(self._agents_with(line, wrapped))
                self.assertTrue(any("evidence authority" in v for v in violations), violations)

    def test_statement_moved_to_another_section_is_not_counted(self):
        line = next(l for l in _text(AGENTS).splitlines() if "do not reimplement" in l)
        text = self._agents_with(line + "\n", "")
        text = text.replace("## Handoff\n", "## Handoff\n\n" + line + "\n", 1)
        violations = agents_violations(text)
        self.assertTrue(any("no duplicate implementation" in v for v in violations), violations)

    def test_heading_inside_code_block_is_not_a_section(self):
        text = self._agents_with("## Handoff\n", "```\n## Handoff\n```\n")
        self.assertIn("missing section: Handoff", agents_violations(text))

    def test_status_declaration_only_in_comment_is_not_counted(self):
        text = _text(STATUS)
        declaration = next(l for l in text.splitlines() if "This file is an index" in l)
        violations = status_violations(text.replace(declaration, f"<!-- {declaration} -->", 1))
        self.assertIn("preamble does not declare the file an index", violations)

    def test_status_column_is_rejected(self):
        text = _text(STATUS).replace(
            "| Workstream | Authority Issue |", "| Workstream | Status | Authority Issue |", 1
        )
        self.assertTrue(any("'status' column" in v for v in status_violations(text)))

    def test_rule_without_owner_link_is_rejected(self):
        text = _text(GOVERNANCE / "rules.md")
        owner = "- Owner: [#200](https://github.com/oimus1976/agent-controller/issues/200).\n"
        self.assertIn(owner, text)
        for replacement in ("", "- Owner: #200.\n", "- See also [`README.md`](README.md).\n"):
            with self.subTest(replacement=replacement):
                violations = rules_violations(text.replace(owner, replacement, 1))
                self.assertTrue(any(v.startswith("5. ") for v in violations), violations)

    def test_broken_inline_and_reference_links_are_rejected(self):
        document = GOVERNANCE / "README.md"
        cases = {
            "inline": "See [rules](rulez.md).",
            "reference": "See [rules][r].\n\n[r]: rulez.md",
            "undefined reference": "See [rules][nowhere].",
        }
        for label, snippet in cases.items():
            with self.subTest(case=label):
                self.assertNotEqual(link_violations(document, snippet), [])
        self.assertEqual(link_violations(document, "See [rules][r].\n\n[r]: rules.md"), [])

    def test_shadow_files_are_found_at_any_depth(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "AGENTS.md").write_text("# entry\n", encoding="utf-8")
            (root / ".claude").mkdir()
            (root / "src").mkdir()
            (root / "CLAUDE.md").write_text("@AGENTS.md\n", encoding="utf-8")
            (root / ".claude" / "CLAUDE.md").write_text("@../AGENTS.md\n", encoding="utf-8")
            self.assertEqual(shadow_violations(root), [])

            cases = {
                "src/CLAUDE.md": "Use tabs.\n",
                "src/GEMINI.md": "@AGENTS.md\n",
                "src/AGENTS.override.md": "@../AGENTS.md\n",
            }
            for relative, content in cases.items():
                with self.subTest(file=relative):
                    path = root / relative
                    path.write_text(content, encoding="utf-8")
                    try:
                        self.assertTrue(any(v.startswith(relative) for v in shadow_violations(root)))
                    finally:
                        path.unlink()

            (root / ".claude" / "CLAUDE.md").write_text("@AGENTS.md\n", encoding="utf-8")
            self.assertEqual(
                shadow_violations(root), [".claude/CLAUDE.md must contain only @../AGENTS.md"]
            )


if __name__ == "__main__":
    unittest.main()
