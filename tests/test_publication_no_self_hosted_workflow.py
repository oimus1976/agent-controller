from pathlib import Path
import re
import unittest


REPO_ROOT = Path(__file__).resolve(strict=True).parents[1]
WORKFLOW_DIR = REPO_ROOT / ".github" / "workflows"
RETIRED = WORKFLOW_DIR / "self-hosted-exact-head.yml"
ALLOWED_HOSTED_RUNNERS = {"ubuntu-latest", "windows-latest"}


def parse_local_job_runners(text):
    """Return every job and its literal runner; reject unsupported job shapes."""
    lines = text.splitlines()
    jobs_indexes = [index for index, line in enumerate(lines) if line == "jobs:"]
    if len(jobs_indexes) != 1:
        raise ValueError(
            "workflow must contain exactly one top-level jobs mapping"
        )
    jobs_index = jobs_indexes[0]

    jobs = []
    index = jobs_index + 1
    while index < len(lines):
        line = lines[index]

        if not line.strip() or line.lstrip().startswith("#"):
            index += 1
            continue

        if not line.startswith("  "):
            raise ValueError(
                f"unsupported top-level content after jobs begins: {line!r}"
            )

        if line.startswith("    "):
            raise ValueError(f"job content appeared before a job declaration: {line!r}")

        match = re.fullmatch(
            r"  (?:(?:\"([^\"]+)\")|(?:'([^']+)')|([A-Za-z0-9_-]+)):\s*",
            line,
        )
        if not match:
            raise ValueError(f"unsupported or flow-style job declaration: {line!r}")

        job_name = next(group for group in match.groups() if group is not None)
        start = index + 1
        index = start
        while index < len(lines):
            candidate = lines[index]
            if candidate.startswith("  ") and not candidate.startswith("    "):
                break
            if candidate and not candidate.startswith("    "):
                break
            index += 1

        block = lines[start:index]
        runner_values = []
        for block_line in block:
            key_match = re.fullmatch(
                r"    (?:(?:\"([^\"]+)\")|(?:'([^']+)')|([A-Za-z0-9_-]+)):\s*(.*?)\s*",
                block_line,
            )
            if not key_match:
                continue
            key = next(group for group in key_match.groups()[:3] if group is not None)
            value = key_match.group(4)
            key_lower = key.lower()
            if key_lower == "uses":
                raise ValueError(f"reusable job is not allowed for publication: {job_name}")
            if key_lower == "runs-on":
                runner_values.append(value)

        if len(runner_values) != 1:
            raise ValueError(
                f"job {job_name!r} must define exactly one local literal runs-on"
            )

        raw_runner = runner_values[0].strip()
        if (
            len(raw_runner) >= 2
            and raw_runner[0] == raw_runner[-1]
            and raw_runner[0] in ("'", '"')
        ):
            normalized = raw_runner[1:-1]
        else:
            normalized = raw_runner
        if normalized not in ALLOWED_HOSTED_RUNNERS:
            raise ValueError(
                f"job {job_name!r} runner is not an allowed GitHub-hosted literal: "
                f"{raw_runner!r}"
            )
        jobs.append((job_name, normalized))

    if not jobs:
        raise ValueError("workflow must define at least one local job")
    return jobs


class PublicationNoSelfHostedWorkflowTests(unittest.TestCase):
    def test_private_self_hosted_fallback_is_retired(self):
        self.assertFalse(
            RETIRED.exists(),
            "private-era self-hosted exact-head workflow must stay retired for publication",
        )

    def test_all_active_workflow_jobs_resolve_locally_to_allowed_hosted_runners(self):
        observed = []
        for workflow in sorted(WORKFLOW_DIR.glob("*.y*ml")):
            text = workflow.read_text(encoding="utf-8")
            for job_name, runner in parse_local_job_runners(text):
                observed.append((workflow.name, job_name, runner))

        self.assertTrue(observed, "at least one hosted workflow job must be validated")
        for _, _, runner in observed:
            self.assertIn(runner, ALLOWED_HOSTED_RUNNERS)

    def test_parser_rejects_reusable_job(self):
        text = """jobs:
  delegated:
    uses: owner/repo/.github/workflows/reusable.yml@main
"""
        with self.assertRaises(ValueError):
            parse_local_job_runners(text)

    def test_parser_rejects_missing_runner(self):
        text = """jobs:
  probe:
    timeout-minutes: 5
    steps:
      - run: echo unsafe
"""
        with self.assertRaises(ValueError):
            parse_local_job_runners(text)

    def test_parser_rejects_runner_indirection_and_nonliteral_shapes(self):
        candidates = (
            "${{ vars.RUNNER }}",
            "self-hosted",
            "[self-hosted, windows, x64]",
            "ac-ci-deadbeefdeadbeef",
        )
        for candidate in candidates:
            with self.subTest(candidate=candidate):
                text = f"""jobs:
  probe:
    runs-on: {candidate}
"""
                with self.assertRaises(ValueError):
                    parse_local_job_runners(text)

    def test_parser_rejects_nested_quoting_around_runner_literal(self):
        for candidate in (
            "\"'ubuntu-latest'\"",
            "'\"windows-latest\"'",
        ):
            with self.subTest(candidate=candidate):
                text = f"""jobs:
  probe:
    runs-on: {candidate}
"""
                with self.assertRaises(ValueError):
                    parse_local_job_runners(text)

    def test_parser_rejects_duplicate_top_level_jobs_mapping(self):
        text = """jobs:
  hosted:
    runs-on: ubuntu-latest
jobs:
  trusted:
    runs-on: self-hosted
"""
        with self.assertRaises(ValueError):
            parse_local_job_runners(text)
    def test_parser_rejects_yaml_equivalent_duplicate_jobs_spellings(self):
        duplicate_forms = (
            "jobs :",
            '"jobs":',
            "jobs: # duplicate",
        )
        for duplicate in duplicate_forms:
            with self.subTest(duplicate=duplicate):
                text = f"""jobs:
  hosted:
    runs-on: ubuntu-latest
{duplicate}
  trusted:
    runs-on: self-hosted
"""
                with self.assertRaises(ValueError):
                    parse_local_job_runners(text)

    def test_parser_rejects_unknown_top_level_content_after_jobs(self):
        text = """jobs:
  hosted:
    runs-on: ubuntu-latest
permissions:
  contents: write
"""
        with self.assertRaises(ValueError):
            parse_local_job_runners(text)
    def test_parser_rejects_flow_style_job_syntax(self):
        for declaration in (
            "  probe: { runs-on: ubuntu-latest }",
            "  probe: { uses: owner/repo/.github/workflows/reusable.yml@main }",
        ):
            with self.subTest(declaration=declaration):
                with self.assertRaises(ValueError):
                    parse_local_job_runners(f"jobs:\n{declaration}\n")

    def test_hosted_tests_workflow_keeps_read_only_checkout_contract(self):
        path = WORKFLOW_DIR / "tests.yml"
        text = path.read_text(encoding="utf-8")
        self.assertIn("permissions:\n  contents: read\n", text)
        self.assertNotRegex(text, r"(?m)^\s+[a-z-]+:\s*write\s*$")
        self.assertGreaterEqual(text.count("persist-credentials: false"), 2)


if __name__ == "__main__":
    unittest.main()