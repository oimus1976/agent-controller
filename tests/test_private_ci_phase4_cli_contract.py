import ast
import unittest
from pathlib import Path


class PrivateCiPhase4CliContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repo_root = Path(__file__).resolve().parents[1]
        cls.phase4_path = cls.repo_root / "scripts" / "run_private_ci_phase4.py"
        cls.handoff_path = (
            cls.repo_root
            / "scripts"
            / "build_private_ci_registration_handoff.py"
        )
        cls.phase4_source = cls.phase4_path.read_text(encoding="utf-8")
        cls.handoff_source = cls.handoff_path.read_text(encoding="utf-8")

    def test_controller_scripts_parse_as_python(self):
        ast.parse(self.phase4_source, filename=str(self.phase4_path))
        ast.parse(self.handoff_source, filename=str(self.handoff_path))

    def test_phase4_harness_has_no_phase5_listener_or_dispatch_surface(self):
        forbidden = (
            '"run.cmd"',
            "'run.cmd'",
            "Runner.Listener",
            "/dispatches",
            '"workflow", "run"',
            "'workflow', 'run'",
            "SELF_HOSTED_PRIVATE_CI_PASS",
        )
        for fragment in forbidden:
            with self.subTest(fragment=fragment):
                self.assertNotIn(fragment, self.phase4_source)

        self.assertIn(
            "NO_RUNNER_LISTENER_START_OR_WORKFLOW_DISPATCH_PERFORMED",
            self.phase4_source,
        )

    def test_phase4_apply_consumes_durable_authority_before_candidate_execution(self):
        source = self.phase4_source
        ownership = source.index("_acquire_phase4_ownership(")
        consume_readback = source.index(
            "consumption_raw, consumption_sha = _validate_phase4_consumption("
        )
        execute_candidate = source.index(
            '"-File",\n        str(candidate_path),',
            consume_readback,
        )
        probe_validation = source.index(
            "parse_target_probe_result_bytes(",
            execute_candidate,
        )
        result_publication = source.index(
            "_write_exclusive(result_path, result_raw)",
            probe_validation,
        )

        self.assertLess(ownership, consume_readback)
        self.assertLess(consume_readback, execute_candidate)
        self.assertLess(execute_candidate, probe_validation)
        self.assertLess(probe_validation, result_publication)

    def test_phase4_apply_revalidates_after_durable_consumption(self):
        source = self.phase4_source
        consume_readback = source.index(
            "consumption_raw, consumption_sha = _validate_phase4_consumption("
        )
        execute_candidate = source.index(
            '"-File",\n        str(candidate_path),',
            consume_readback,
        )
        region = source[consume_readback:execute_candidate]

        required = (
            "plan_path.read_bytes() != plan_raw",
            "handoff_path.read_bytes() != handoff_raw",
            "candidate_path.read_bytes() != candidate_raw",
            "probe_source.read_bytes() != probe_raw",
            "_require_controller_source_exact(plan.binding)",
            "_require_remote_binding_exact(plan.binding)",
        )
        for fragment in required:
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, region)

    def test_handoff_builder_fresh_readback_precedes_protected_publication(self):
        source = self.handoff_source
        build = source.index("evidence = build_registration_handoff_evidence(")
        host = source.index("_require_host_identity(evidence.binding)", build)
        controller = source.index(
            "_require_controller_source_exact(evidence.binding)",
            host,
        )
        remote = source.index(
            "_require_remote_binding_exact(evidence.binding)",
            controller,
        )
        pending = source.index("_write_exclusive(pending_path, handoff_raw)", remote)
        publish = source.index("_publish_protected_handoff(", pending)
        protected_readback = source.index(
            "_require_regular_nonreparse_file(\n            handoff_path,",
            publish,
        )
        self.assertLess(build, host)
        self.assertLess(host, controller)
        self.assertLess(controller, remote)
        self.assertLess(remote, pending)
        self.assertLess(pending, publish)
        self.assertLess(publish, protected_readback)

    def test_handoff_builder_has_no_runner_start_or_dispatch(self):
        forbidden = (
            '"run.cmd"',
            "'run.cmd'",
            "Runner.Listener",
            "/dispatches",
            '"workflow", "run"',
            "'workflow', 'run'",
            "SELF_HOSTED_PRIVATE_CI_PASS",
        )
        for fragment in forbidden:
            with self.subTest(fragment=fragment):
                self.assertNotIn(fragment, self.handoff_source)
        self.assertIn(
            "NO_RUNNER_START_OR_WORKFLOW_DISPATCH_PERFORMED",
            self.handoff_source,
        )


if __name__ == "__main__":
    unittest.main()
