import importlib
import unittest

MODULE_NAME = "agent_controller.private_ci_phase4_contract"

REPOSITORY = "oimus1976/example-private"
TARGET_SHA = "1" * 40
WORKFLOW_SHA = "2" * 40
WORKFLOW_PATH = ".github/workflows/private-ci-windows-pilot.yml"
RUNNER_NAME = "ac-ci-0123456789abcdef"
RUNNER_LABEL = "private-ci-windows-pilot"
GENERATION = "ac-pilot-0123456789abcdef"
RUNNER_ROOT = (
    r"C:\\ProgramData\\agent-controller\\private-ci"
    rf"\\{GENERATION}\\runner"
)


def contract_module():
    try:
        return importlib.import_module(MODULE_NAME)
    except ModuleNotFoundError as error:
        raise AssertionError(
            "Phase 4 contract module is not implemented; RED is expected until "
            "the controller-owned cross-phase binding exists"
        ) from error


def valid_binding(module, **overrides):
    values = {
        "repository": REPOSITORY,
        "pull_request_number": 4,
        "target_sha": TARGET_SHA,
        "workflow_sha": WORKFLOW_SHA,
        "workflow_path": WORKFLOW_PATH,
        "runner_id": 23,
        "runner_name": RUNNER_NAME,
        "runner_label": RUNNER_LABEL,
        "environment_generation": GENERATION,
        "runner_root": RUNNER_ROOT,
        "work_folder": "_work",
        "host": "WOBBUFFET",
        "broker_identity": r"WOBBUFFET\\c-admin",
        "target_identity": "ac-runner",
    }
    values.update(overrides)
    return module.PrivateCiPilotBinding(**values)


class PrivateCiPhase4ContractRedTests(unittest.TestCase):
    def test_cross_phase_binding_contains_all_phase4_authority_fields(self):
        module = contract_module()
        binding = valid_binding(module)

        self.assertEqual(
            tuple(binding.__dataclass_fields__),
            (
                "repository",
                "pull_request_number",
                "target_sha",
                "workflow_sha",
                "workflow_path",
                "runner_id",
                "runner_name",
                "runner_label",
                "environment_generation",
                "runner_root",
                "work_folder",
                "host",
                "broker_identity",
                "target_identity",
            ),
        )
        self.assertEqual(module.pilot_binding_reason_codes(binding), ())

    def test_binding_rejects_identity_sha_and_runner_drift_shapes(self):
        module = contract_module()
        invalid_cases = (
            (
                {"target_sha": "A" * 40},
                "PILOT_BINDING_TARGET_SHA_INVALID",
            ),
            (
                {"workflow_sha": "short"},
                "PILOT_BINDING_WORKFLOW_SHA_INVALID",
            ),
            (
                {"runner_id": 0},
                "PILOT_BINDING_RUNNER_ID_INVALID",
            ),
            (
                {"broker_identity": "same", "target_identity": "same"},
                "PILOT_BINDING_IDENTITY_SEPARATION_INVALID",
            ),
        )
        for changes, expected_reason in invalid_cases:
            with self.subTest(changes=changes):
                reasons = module.pilot_binding_reason_codes(
                    valid_binding(module, **changes)
                )
                self.assertIn(expected_reason, reasons)

    def test_binding_rejects_untrusted_workflow_path_or_runner_root(self):
        module = contract_module()
        invalid_cases = (
            (
                {"workflow_path": "../private-ci.yml"},
                "PILOT_BINDING_WORKFLOW_PATH_INVALID",
            ),
            (
                {"workflow_path": ".github/workflows/../private-ci.yml"},
                "PILOT_BINDING_WORKFLOW_PATH_INVALID",
            ),
            (
                {"runner_root": r"relative\\runner"},
                "PILOT_BINDING_RUNNER_ROOT_INVALID",
            ),
            (
                {"work_folder": r"..\\work"},
                "PILOT_BINDING_WORK_FOLDER_INVALID",
            ),
        )
        for changes, expected_reason in invalid_cases:
            with self.subTest(changes=changes):
                reasons = module.pilot_binding_reason_codes(
                    valid_binding(module, **changes)
                )
                self.assertIn(expected_reason, reasons)

    def test_binding_is_generic_and_not_equal_to_consumed_historical_identity(self):
        module = contract_module()
        binding = valid_binding(module)

        self.assertNotEqual(binding.runner_name, "ac-ci-153d6e1a29fea2cd")
        self.assertNotEqual(
            binding.environment_generation,
            "ac-pilot-65bbb1dc7c48d6e3",
        )


if __name__ == "__main__":
    unittest.main()
