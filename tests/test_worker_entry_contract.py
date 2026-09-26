"""Contract for the worker-neutral entry point (Issue #256).

These checks keep the entry documents usable by every worker:

- `AGENTS.md` stays a small bootloader that carries the non-negotiables.
- `PROJECT_STATUS.md` stays an index, not an authority.
- Every governance rule names its owning record.
- Every relative link in the entry documents resolves.
- No provider-specific instruction file shadows `AGENTS.md`.

The checks read the operative Markdown structure with a small line-based
reader, not a full CommonMark parser (the suite uses the standard library
only). Text inside fenced code blocks or HTML comments does not count, and
each required statement must sit in a list item of the section where a worker
will act on it. Inside those sections the reader fails closed: a list item
that contains a blockquote, an indented or fenced code block, or
strikethrough is reported as unsupported instead of being read, and text in
inline code does not count. A link the reader cannot parse is reported,
not skipped. Files are read with normalized line
endings, so a CRLF checkout behaves like an LF one. Each checker is also run
against small fixtures, so a checker that stops seeing a violation fails.
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

# Codex caps the combined size of the instruction files it loads
# (`project_doc_max_bytes`). The entry file stays far below any such cap so it
# is always loaded in full and actually read.
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
# The Active workstreams table carries pointers only. Any other column, such
# as "Current status", would invite a second source of truth.
STATUS_TABLE_COLUMNS = ("workstream", "authority issue", "related issues / prs", "checkpoints")

# The owning records of each numbered rule in docs/governance/rules.md. Each
# rule's Owner line must name exactly these records: every one of them, and no
# other linked Issue or document. Changing a rule's owner is a deliberate edit
# to both files.
RULE_OWNERS = {
    1: ("issue:1", "issue:12", "text:BASELINE §2–3"),
    2: ("issue:90",),
    3: ("issue:199",),
    4: ("issue:194",),
    5: ("issue:200",),
    6: ("issue:120", "doc:workstream-isolation.md"),
    7: ("issue:256", "issue:168", "issue:55"),
    8: ("issue:216", "issue:195"),
    9: ("text:BASELINE §8",),
    10: ("issue:12", "issue:179"),
    11: ("doc:PUBLIC_REPOSITORY_READINESS.md",),
    12: ("issue:256", "doc:post-merge-cleanup-candidates.md"),
    13: ("issue:256",),
}

# Files that make a provider read something other than AGENTS.md. By default
# Claude Code skips AGENTS.md when a CLAUDE.md or CLAUDE.local.md is present,
# so those may exist only as an import shim. Codex prefers AGENTS.override.md
# over AGENTS.md in the same directory. Antigravity reads AGENTS.md itself and
# adds GEMINI.md cumulatively, and its `@filename` form does not inline the
# target, so a GEMINI.md cannot be a faithful shim and is not allowed.
# Names are compared case-insensitively, because a case-insensitive checkout
# (Windows, macOS) resolves `claude.md` as `CLAUDE.md`.
SHIM_ONLY_FILES = frozenset({"claude.md", "claude.local.md"})
FORBIDDEN_FILES = frozenset({"agents.override.md", "gemini.md"})
# Provider-only instruction locations that load in addition to AGENTS.md, so
# they would give one provider rules the others never see. Claude Code loads
# `.claude/AGENTS.md` and every `.md` under `.claude/rules/` (recursively).
# Antigravity loads `.agents/AGENTS.md` and the `.md` files in `.agents/rules/`
# and the legacy `.agent/rules/`; rules there may also be registered from
# subdirectories, so any depth is rejected.
PROVIDER_AGENTS_DIRS = frozenset({".claude", ".agents"})
PROVIDER_RULE_DIRS = frozenset({".claude", ".agents", ".agent"})
SKIPPED_DIRS = frozenset({".git", "node_modules", ".venv", "venv", "__pycache__"})

# An inline link destination with an optional title in any of the three
# CommonMark forms: "double", 'single', or (parenthesized). A `](` that this
# pattern cannot read is reported instead of being skipped.
INLINE_LINK = re.compile(
    r"\]\(\s*<?([^)\s>]+)>?(?:\s+(?:\"[^\"]*\"|'[^']*'|\([^()]*\)))?\s*\)"
)
INLINE_LINK_OPEN = re.compile(r"\]\(")
REFERENCE_USE = re.compile(r"\[([^\]]+)\]\[([^\]]*)\]")
REFERENCE_DEFINITION = re.compile(r"^ {0,3}\[([^\]]+)\]:\s*<?([^\s>]+)>?")
FENCE = re.compile(r"^ {0,3}(`{3,}|~{3,})")
LIST_ITEM = re.compile(r"^\s*(?:[-*+]|\d+[.)])\s+")
BLOCK_START = re.compile(r"^ {0,3}(?:#|>|\||<|`{3,}|~{3,}|(?:[-*+]|\d+[.)])(?:\s|$))")
OWNER_ITEM = re.compile(r"^\s*-\s+Owners?:\s")


def _text(path):
    text = path.read_bytes().decode("utf-8")
    return text.replace("\r\n", "\n").replace("\r", "\n")


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
    """Return (items, unsupported) for the list items in ``lines``.

    An item is its marker line plus indented continuation lines and lazy
    continuation lines (unindented text that continues the paragraph).
    Items whose content opens a blockquote or an indented code block are
    returned in ``unsupported`` and left out of ``items``.
    """
    items = []
    unsupported = []
    current = None
    blank = False
    for line in lines:
        line = line.expandtabs(4)
        marker = LIST_ITEM.match(line)
        if marker:
            current = {"parts": [line[marker.end():]], "raw": line, "bad": False, "column": marker.end()}
            rest = line[marker.end():]
            gap = len(re.match(r"^\s*(?:[-*+]|\d+[.)])(\s*)", line).group(1))
            # Five or more spaces after the marker open an indented code block.
            if rest.startswith((">", "```", "~~~")) or gap >= 5:
                current["bad"] = True
            items.append(current)
            blank = False
            continue
        if current is None:
            continue
        if not line.strip():
            blank = True
            continue
        if line.startswith((" ", "\t")):
            indent = len(line) - len(line.lstrip())
            # After a blank line, four or more spaces beyond the item's content
            # column open an indented code block inside the item.
            if line.lstrip().startswith((">", "```", "~~~")) or (blank and indent >= current["column"] + 4):
                current["bad"] = True
            current["parts"].append(line.strip())
            blank = False
            continue
        if not blank and not BLOCK_START.match(line):
            current["parts"].append(line.strip())
            continue
        current = None
    for item in items:
        joined = " ".join(item["parts"])
        if "~~" in joined or re.search(r"<(?:del|s|strike)\b", joined, flags=re.I):
            item["bad"] = True
        if item["bad"]:
            unsupported.append(item["raw"].strip())
        else:
            # Inline code is an example or a name, not an instruction.
            item["text"] = _normalized(re.sub(r"(`+)[^`]*?\1", " ", " ".join(item["parts"])))
    return [item["text"] for item in items if not item["bad"]], unsupported


def agents_violations(text):
    violations = []
    _, sections = split_sections(operative_lines(text))
    for heading in AGENTS_REQUIRED_SECTIONS:
        if heading not in sections:
            violations.append(f"missing section: {heading}")
    for heading, statements in AGENTS_REQUIRED_STATEMENTS.items():
        items, unsupported = list_items(sections.get(heading, []))
        for raw in unsupported:
            violations.append(f"{heading}: unsupported Markdown inside a list item: {raw[:60]}")
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
        columns = tuple(cell.strip().lower() for cell in table[0].strip().strip("|").split("|"))
        if columns != STATUS_TABLE_COLUMNS:
            violations.append(f"Active workstreams columns {columns} are not {STATUS_TABLE_COLUMNS}")
    return violations


def _owner_matches(line, owner):
    kind, value = owner.split(":", 1)
    if kind == "issue":
        pattern = rf"\]\(https://github\.com/oimus1976/agent-controller/issues/{value}\)"
    elif kind == "doc":
        pattern = rf"\]\((?:[^)\s]*/)?{re.escape(value)}\)"
    else:
        pattern = re.escape(value)
    return re.search(pattern, line) is not None


def rules_violations(text, rule_owners=RULE_OWNERS):
    violations = []
    _, sections = split_sections(operative_lines(text))
    numbered = {}
    for title, lines in sections.items():
        match = re.match(r"^(\d+)\. ", title)
        if not match:
            violations.append(f"{title}: rule section is not numbered")
            continue
        numbered[int(match.group(1))] = (title, lines)
    if sorted(numbered) != sorted(rule_owners):
        violations.append(f"rule numbers {sorted(numbered)} do not match {sorted(rule_owners)}")
    for number, owners in sorted(rule_owners.items()):
        if number not in numbered:
            continue
        title, lines = numbered[number]
        owner_lines = [line for line in lines if OWNER_ITEM.match(line)]
        if not owner_lines:
            violations.append(f"{title}: no Owner line")
            continue
        for owner in owners:
            if not any(_owner_matches(line, owner) for line in owner_lines):
                violations.append(f"{title}: Owner line does not name {owner}")
        expected_issues = {o.split(":", 1)[1] for o in owners if o.startswith("issue:")}
        expected_docs = {o.split(":", 1)[1] for o in owners if o.startswith("doc:")}
        for line in owner_lines:
            for number in re.findall(r"/agent-controller/issues/(\d+)\)", line):
                if number not in expected_issues:
                    violations.append(f"{title}: Owner line links unexpected issue #{number}")
            for target in re.findall(r"\]\((?![a-z]+://)([^)\s#]+\.md)", line):
                if target.rsplit("/", 1)[-1] not in expected_docs:
                    violations.append(f"{title}: Owner line links unexpected document {target}")
    return violations


def link_violations(document, text):
    """Return unresolved relative links, inline or reference-style.

    Every `](` must parse as an inline link. One that does not, such as a link
    whose title uses an unsupported form, is reported rather than skipped, so a
    broken destination cannot hide behind link syntax the reader misses.
    """
    lines = operative_lines(text)
    body = "\n".join(lines)
    definitions = {}
    for line in lines:
        match = REFERENCE_DEFINITION.match(line)
        if match:
            definitions[match.group(1).strip().lower()] = match.group(2)
    targets = []
    violations = []
    for opening in INLINE_LINK_OPEN.finditer(body):
        match = INLINE_LINK.match(body, opening.start())
        if match:
            targets.append(match.group(1))
        else:
            snippet = body[opening.start():opening.start() + 60].split("\n", 1)[0]
            violations.append(f"unsupported link syntax {snippet}")
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


def _provider_location(parts):
    """Return why a path (lower-cased parts) is a provider-only location."""
    *dirs, name = parts
    if name == "agents.md" and dirs and dirs[-1] in PROVIDER_AGENTS_DIRS:
        return "is a provider-only instruction file"
    if name.endswith(".md"):
        for parent, child in zip(dirs, dirs[1:]):
            if parent in PROVIDER_RULE_DIRS and child == "rules":
                return "is in a provider-only rules folder"
    return None


def shadow_violations(root):
    """Return provider instruction files that would shadow root AGENTS.md."""
    agents = root / "AGENTS.md"
    violations = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d.lower() not in SKIPPED_DIRS)
        for name in sorted(filenames):
            path = Path(dirpath) / name
            relative = path.relative_to(root).as_posix()
            folded = name.lower()
            location = _provider_location(relative.lower().split("/"))
            if folded in FORBIDDEN_FILES:
                violations.append(f"{relative} must not exist")
            elif location:
                violations.append(f"{relative} {location} and must not exist")
            elif folded in SHIM_ONLY_FILES:
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

    def test_statement_nested_in_quote_or_code_inside_list_item_fails_closed(self):
        line = next(l for l in _text(AGENTS).splitlines() if "claims until verified" in l)
        body = line[2:]
        for wrapped in (
            f"- > {body}",
            f"-     {body}",
            f"- Evidence.\n  > {body}",
            f"- Evidence.\n\n      {body}",
            f"- ~~{body}~~",
            f"- <del>{body}</del>",
            f"- Evidence.\n    ```text\n    {body}\n    ```",
            f"- Evidence.\n\t```text\n\t{body}\n\t```",
            f"- Evidence.\n\n\t\t{body}",
            f"- ```text\n  {body}\n  ```",
        ):
            with self.subTest(wrapped=wrapped):
                violations = agents_violations(self._agents_with(line, wrapped))
                self.assertTrue(any("unsupported Markdown" in v for v in violations), violations)
                self.assertTrue(any("evidence authority" in v for v in violations), violations)

    def test_statement_only_in_inline_code_is_not_counted(self):
        line = next(l for l in _text(AGENTS).splitlines() if "claims until verified" in l)
        violations = agents_violations(self._agents_with(line, f"- `{line[2:]}`"))
        self.assertTrue(any("evidence authority" in v for v in violations), violations)

    def test_lazy_and_indented_continuations_are_read(self):
        for continuation in (
            "are claims\nuntil verified.",
            "are claims\n  until verified.",
            "are claims.\n\n  They stay claims until verified.",
        ):
            with self.subTest(continuation=continuation):
                text = self._agents_with("are claims until verified.", continuation)
                self.assertEqual(agents_violations(text), [])

    def test_crlf_checkout_reads_like_lf(self):
        with tempfile.TemporaryDirectory() as tmp:
            for source in (AGENTS, STATUS, GOVERNANCE / "rules.md"):
                copy = Path(tmp) / source.name
                copy.write_bytes(_text(source).replace("\n", "\r\n").encode("utf-8"))
                with self.subTest(document=source.name):
                    self.assertEqual(_text(copy), _text(source))
        with tempfile.TemporaryDirectory() as tmp:
            copy = Path(tmp) / "AGENTS.md"
            copy.write_bytes(_text(AGENTS).replace("\n", "\r\n").encode("utf-8"))
            self.assertEqual(agents_violations(_text(copy)), [])

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

    def test_status_table_columns_are_an_allowlist(self):
        for column in ("Status", "Current status", "Last CI", "Head"):
            with self.subTest(column=column):
                text = _text(STATUS).replace(
                    "| Workstream | Authority Issue |", f"| Workstream | {column} | Authority Issue |", 1
                )
                self.assertTrue(any("Active workstreams columns" in v for v in status_violations(text)))

    def test_rule_without_owner_link_is_rejected(self):
        text = _text(GOVERNANCE / "rules.md")
        owner = "- Owner: [#200](https://github.com/oimus1976/agent-controller/issues/200).\n"
        self.assertIn(owner, text)
        for replacement in (
            "",
            "- Owner: #200.\n",
            "- See also [#200](https://github.com/oimus1976/agent-controller/issues/200).\n",
            "- Owner: [unrelated README](README.md).\n",
            "- Owner: [#199](https://github.com/oimus1976/agent-controller/issues/199).\n",
        ):
            with self.subTest(replacement=replacement):
                violations = rules_violations(text.replace(owner, replacement, 1))
                self.assertTrue(any(v.startswith("5. ") for v in violations), violations)

    def test_owner_line_must_name_exactly_the_mapped_records(self):
        text = _text(GOVERNANCE / "rules.md")
        owner = next(l for l in text.splitlines() if l.startswith("- Owners: owner decision of 2026-09-25"))
        trimmed = re.sub(r"; capacity semantics in .*", ".", owner)
        violations = rules_violations(text.replace(owner, trimmed, 1))
        self.assertTrue(any("issue:168" in v for v in violations), violations)
        self.assertTrue(any("issue:55" in v for v in violations), violations)
        extra = "- Owner: [#200](https://github.com/oimus1976/agent-controller/issues/200)."
        violations = rules_violations(
            text.replace(extra, extra[:-1] + ", [#12](https://github.com/oimus1976/agent-controller/issues/12).", 1)
        )
        self.assertTrue(any("unexpected issue #12" in v for v in violations), violations)

    def test_rule_numbering_must_match_the_owner_map(self):
        text = _text(GOVERNANCE / "rules.md")
        self.assertIn("## 13. ", text)
        violations = rules_violations(text.replace("## 13. ", "## ", 1))
        self.assertTrue(any("not numbered" in v for v in violations), violations)
        self.assertTrue(any("do not match" in v for v in violations), violations)

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

    def test_broken_link_with_a_title_is_rejected(self):
        # Round-5 review: a single-quoted title hid a broken bootloader link.
        target = "](docs/governance/rules.md)"
        for title in ("\"Governance rules\"", "'Governance rules'", "(Governance rules)"):
            with self.subTest(title=title):
                good = self._agents_with(target, f"](docs/governance/rules.md {title})")
                self.assertEqual(link_violations(AGENTS, good), [])
                bad = self._agents_with(target, f"](docs/governance/rulez.md {title})")
                self.assertIn("broken link docs/governance/rulez.md", link_violations(AGENTS, bad))

    def test_unreadable_link_syntax_is_reported_not_skipped(self):
        target = "](docs/governance/rules.md)"
        for form in (
            "](docs/governance/rulez.md 'Governance rules)",
            "](docs/governance/rulez.md \"Governance\" 'rules')",
            "](<docs/governance/rulez 2.md>)",
        ):
            with self.subTest(form=form):
                violations = link_violations(AGENTS, self._agents_with(target, form))
                self.assertTrue(any(v.startswith("unsupported link syntax") for v in violations), violations)

    def test_shadow_files_are_found_at_any_depth(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "AGENTS.md").write_text("# entry\n", encoding="utf-8")
            (root / ".claude").mkdir()
            (root / "src").mkdir()
            (root / "CLAUDE.md").write_text("@AGENTS.md\n", encoding="utf-8")
            (root / "CLAUDE.local.md").write_text("@AGENTS.md\n", encoding="utf-8")
            (root / ".claude" / "CLAUDE.md").write_text("@../AGENTS.md\n", encoding="utf-8")
            self.assertEqual(shadow_violations(root), [])

            cases = {
                "src/CLAUDE.md": "Use tabs.\n",
                "GEMINI.md": "@AGENTS.md\n",
                "src/GEMINI.md": "@[AGENTS](../AGENTS.md)\n",
                "src/AGENTS.override.md": "@../AGENTS.md\n",
                # Round-6 review: mixed case and provider-only locations.
                "src/claude.md": "Use tabs.\n",
                "src/Claude.local.md": "Use tabs.\n",
                "Gemini.md": "Use tabs.\n",
                "src/agents.OVERRIDE.md": "Use tabs.\n",
                ".claude/AGENTS.md": "Use tabs.\n",
                ".claude/rules/code-style.md": "Use tabs.\n",
                ".claude/rules/frontend/react.md": "Use tabs.\n",
                ".claude/rules/CLAUDE.md": "@../../AGENTS.md\n",
                ".agents/AGENTS.md": "Use tabs.\n",
                ".agents/rules/code-style.md": "Use tabs.\n",
                ".agents/rules/sub/code-style.md": "Use tabs.\n",
                ".agent/rules/code-style.md": "Use tabs.\n",
                "src/.Agents/Rules/code-style.md": "Use tabs.\n",
                "src/.claude/agents.md": "Use tabs.\n",
            }
            for relative, content in cases.items():
                with self.subTest(file=relative):
                    path = root / relative
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text(content, encoding="utf-8")
                    try:
                        self.assertTrue(any(v.startswith(relative) for v in shadow_violations(root)))
                    finally:
                        path.unlink()

            # Other files in those folders are not instructions.
            (root / ".claude" / "settings.json").write_text("{}\n", encoding="utf-8")
            (root / ".agents" / "rules" / "notes.txt").write_text("x\n", encoding="utf-8")
            self.assertEqual(shadow_violations(root), [])

            (root / ".claude" / "CLAUDE.md").write_text("@AGENTS.md\n", encoding="utf-8")
            self.assertEqual(
                shadow_violations(root), [".claude/CLAUDE.md must contain only @../AGENTS.md"]
            )


if __name__ == "__main__":
    unittest.main()
