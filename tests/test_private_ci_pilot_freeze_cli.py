import ast
import unittest
from pathlib import Path


class PrivateCiPilotFreezeCliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repo_root = Path(__file__).resolve().parents[1]
        cls.path = cls.repo_root / "scripts" / "create_private_ci_pilot_freeze.py"
        cls.source = cls.path.read_text(encoding="utf-8")

    def test_script_parses(self):
        ast.parse(self.source, filename=str(self.path))

    def test_target_and_workflow_sha_are_fresh_readback_not_arguments(self):
        self.assertIn("--repository", self.source)
        self.assertIn("--pull-request-number", self.source)
        self.assertIn("--workflow-path", self.source)
        self.assertNotIn("--target-sha", self.source)
        self.assertNotIn("--workflow-sha", self.source)
        self.assertIn("/pulls/{pull_request_number}", self.source)
        self.assertIn("/branches/main", self.source)
        self.assertIn("/contents/{workflow_path}?ref={workflow_sha}", self.source)

    def test_freeze_generation_has_no_live_mutation_surface(self):
        forbidden = (
            "--method",
            "registration-token",
            "config.cmd",
            "run.cmd",
            "/dispatches",
            "SELF_HOSTED_PRIVATE_CI_PASS",
        )
        for fragment in forbidden:
            with self.subTest(fragment=fragment):
                self.assertNotIn(fragment, self.source)
        self.assertIn(
            "NO_RUNNER_REGISTRATION_OR_WORKFLOW_DISPATCH_PERFORMED",
            self.source,
        )

    def test_freeze_is_fresh_single_artifact_and_no_overwrite(self):
        self.assertIn("secrets.token_hex(8)", self.source)
        self.assertIn("_write_exclusive(output, raw)", self.source)
        self.assertIn(
            "authoritative pilot identity freeze already exists",
            self.source,
        )
        self.assertIn(
            "_require_no_pilot_runner(freeze.repository, freeze.runner_name)",
            self.source,
        )
        self.assertIn(
            "generation_root.exists() or Path(freeze.runner_root).exists()",
            self.source,
        )

    def test_controller_and_local_zero_residual_are_read_before_freeze_write(self):
        controller = self.source.index("_require_controller_main_exact()")
        local = self.source.index("_local_zero_residual()", controller)
        target = self.source.index("_require_target_exact(", local)
        workflow_exclusive = self.source.index(
            "_require_workflow_runner_exclusivity(",
            target,
        )
        build = self.source.index(
            "build_fresh_pilot_identity_freeze(",
            workflow_exclusive,
        )
        remote_runner = self.source.index("_require_no_pilot_runner(", build)
        write = self.source.index("_write_exclusive(output, raw)", remote_runner)
        self.assertLess(controller, local)
        self.assertLess(local, target)
        self.assertLess(target, workflow_exclusive)
        self.assertLess(workflow_exclusive, build)
        self.assertLess(build, remote_runner)
        self.assertLess(remote_runner, write)


if __name__ == "__main__":
    unittest.main()
