import hashlib
import importlib.util
import inspect
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "run_private_ci_live_registration.py"
SPEC = importlib.util.spec_from_file_location("run_private_ci_live_registration_apply_lock", SCRIPT_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class ApplyOwnershipTests(unittest.TestCase):
    def test_only_first_process_can_claim_apply_ownership(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            marker = Path(temporary_directory) / "apply.consumed.json"
            with mock.patch.object(MODULE, "_consumed_marker_path", return_value=marker):
                MODULE._acquire_apply_ownership("a" * 64, "b" * 64)
                original = marker.read_bytes()
                with self.assertRaisesRegex(RuntimeError, "apply ownership already claimed"):
                    MODULE._acquire_apply_ownership("a" * 64, "b" * 64)
                self.assertEqual(marker.read_bytes(), original)

    def test_host_revalidation_precedes_apply_ownership_and_live_execution(self):
        source = inspect.getsource(MODULE.command_apply)
        host_index = source.index("_require_exact_phase0_host(")
        claim_index = source.index("_acquire_apply_ownership(")
        execute_index = source.index("execute_live_registration(")
        self.assertLess(host_index, claim_index)
        self.assertLess(claim_index, execute_index)
        self.assertNotIn("prepare_with_durable_consumption", source)

    def test_losing_apply_cannot_execute_or_publish_shared_evidence(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            plan_raw = b"canonical-plan\n"
            phase0_raw = b"canonical-phase0\n"
            candidate = "candidate"
            expected_plan_sha = hashlib.sha256(plan_raw).hexdigest()

            plan_path = root / "plan.json"
            phase0_path = root / "phase0.json"
            candidate_path = root / "candidate.ps1"
            plan_path.write_bytes(plan_raw)
            phase0_path.write_bytes(phase0_raw)
            candidate_path.write_text(candidate, encoding="utf-8")

            plan = SimpleNamespace(
                candidate=candidate,
                spec_sha256="c" * 64,
                phase0_evidence_sha256="b" * 64,
                binding=object(),
            )
            evidence = SimpleNamespace(
                host="WOBBUFFET",
                broker_identity="WOBBUFFET\\c-admin",
            )

            with (
                mock.patch.object(MODULE, "_plan_path", return_value=plan_path),
                mock.patch.object(MODULE, "_phase0_path", return_value=phase0_path),
                mock.patch.object(MODULE, "_candidate_path", return_value=candidate_path),
                mock.patch.object(MODULE, "parse_plan_bytes", return_value=plan),
                mock.patch.object(MODULE, "_require_interactive_human_authorization"),
                mock.patch.object(MODULE, "validate_phase0_evidence_bytes", return_value=evidence),
                mock.patch.object(MODULE, "validate_frozen_plan", return_value=()),
                mock.patch.object(MODULE, "_require_exact_phase0_host"),
                mock.patch.object(MODULE, "_require_repo_matches_phase0"),
                mock.patch.object(MODULE, "_require_frozen_target_still_exact"),
                mock.patch.object(MODULE, "_require_live_outputs_absent"),
                mock.patch.object(MODULE, "_configure_authority", return_value=(b"a" * 32, b"b" * 32)),
                mock.patch.object(MODULE, "_powershell_attestation", return_value=object()),
                mock.patch.object(MODULE, "_authenticate_phase0", return_value=object()),
                mock.patch.object(MODULE, "WindowsEphemeralRegistrationRuntime", return_value=object()),
                mock.patch.object(
                    MODULE,
                    "_acquire_apply_ownership",
                    side_effect=RuntimeError("live apply ownership already claimed"),
                ),
                mock.patch.object(MODULE, "execute_live_registration") as execute,
                mock.patch.object(MODULE, "_write_exclusive") as publish,
            ):
                with self.assertRaisesRegex(RuntimeError, "ownership already claimed"):
                    MODULE.command_apply(expected_plan_sha)

            execute.assert_not_called()
            publish.assert_not_called()


if __name__ == "__main__":
    unittest.main()
