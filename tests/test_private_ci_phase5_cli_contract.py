import ast
import unittest
from pathlib import Path


class PrivateCiPhase5CliContractRedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repo_root = Path(__file__).resolve().parents[1]
        cls.path = cls.repo_root / "scripts" / "run_private_ci_phase5.py"

    def source(self):
        return self.path.read_text(encoding="utf-8")

    def test_phase5_controller_script_parses(self):
        source = self.source()
        ast.parse(source, filename=str(self.path))

    def test_apply_consumes_durable_authority_before_single_candidate_execution(self):
        source = self.source()
        ownership = source.index("_acquire_phase5_ownership(")
        marker = source.index(
            "consumption_raw, consumption_sha = _validate_phase5_consumption(",
            ownership,
        )
        execute = source.index(
            "completed = _completed(\n        \"powershell.exe\"",
            marker,
        )
        readback = source.index(
            "_read_exact_phase5_run_job(",
            execute,
        )
        result = source.index(
            "_write_exclusive(result_path, result_raw)",
            readback,
        )
        self.assertLess(ownership, marker)
        self.assertLess(marker, execute)
        self.assertLess(execute, readback)
        self.assertLess(readback, result)

    def test_apply_has_no_dispatch_retry_loop(self):
        source = self.source()
        self.assertEqual(
            source.count(
                "completed = _completed(\n        \"powershell.exe\""
            ),
            1,
        )
        self.assertNotIn("retry_dispatch", source)
        self.assertNotIn("rerun", source.lower())
        self.assertIn(
            "dispatch must not be retried",
            source,
        )

    def test_readback_uses_only_returned_workflow_run_id(self):
        source = self.source()
        required = (
            "PHASE5_WORKFLOW_RUN_ID=",
            "expected_workflow_run_id",
            "actions/runs/{workflow_run_id}",
            "actions/runs/{workflow_run_id}/jobs?filter=latest&per_page=100",
            "validate_phase5_run_job_readback",
        )
        for fragment in required:
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, source)
        self.assertNotIn("created_at", source)
        self.assertNotIn("run_number", source)

    def test_plan_is_read_only(self):
        source = self.source()
        plan_start = source.index("def command_plan()")
        apply_start = source.index("def command_apply(", plan_start)
        plan_region = source[plan_start:apply_start]
        self.assertNotIn("_acquire_phase5_ownership(", plan_region)
        self.assertNotIn("run.cmd", plan_region)
        self.assertNotIn("actions/runs/", plan_region)
        self.assertIn("NO_PHASE5_LIVE_EFFECT_PERFORMED", plan_region)


if __name__ == "__main__":
    unittest.main()
