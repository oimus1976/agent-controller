import unittest
from pathlib import Path


class PrivateCiPhase4CliContractTests(unittest.TestCase):
    """Static surface boundaries for the Phase 4 harness and handoff builder.

    Ordering and fail-closed behavior is exercised by
    ``test_private_ci_phase4_harness_behavior``.
    """

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
