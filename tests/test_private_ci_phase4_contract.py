import importlib
import json
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


class PrivateCiRegistrationHandoffRedTests(unittest.TestCase):
    def handoff(self, module, **overrides):
        values = {
            "schema": module.REGISTRATION_HANDOFF_SCHEMA,
            "binding": valid_binding(module),
            "phase0_evidence_sha256": "3" * 64,
            "registration_plan_sha256": "4" * 64,
            "human_approval_sha256": "5" * 64,
            "registration_consumption_sha256": "6" * 64,
            "registration_result_sha256": "7" * 64,
            "local_runner_settings_sha256": "8" * 64,
            "registration_status": "REGISTERED",
        }
        values.update(overrides)
        return module.RegistrationHandoffEvidence(**values)

    def test_registration_handoff_is_canonical_and_hash_chained(self):
        module = contract_module()
        evidence = self.handoff(module)
        raw = module.registration_handoff_bytes(evidence)
        parsed = module.parse_registration_handoff_bytes(raw)

        self.assertEqual(parsed, evidence)
        self.assertEqual(module.registration_handoff_reason_codes(parsed), ())
        self.assertEqual(
            tuple(parsed.__dataclass_fields__),
            (
                "schema",
                "binding",
                "phase0_evidence_sha256",
                "registration_plan_sha256",
                "human_approval_sha256",
                "registration_consumption_sha256",
                "registration_result_sha256",
                "local_runner_settings_sha256",
                "registration_status",
            ),
        )

    def test_registration_handoff_rejects_nonregistered_or_invalid_hashes(self):
        module = contract_module()
        invalid_cases = (
            (
                {"registration_status": "FAILED"},
                "REGISTRATION_HANDOFF_STATUS_NOT_REGISTERED",
            ),
            (
                {"registration_result_sha256": "short"},
                "REGISTRATION_HANDOFF_RESULT_SHA256_INVALID",
            ),
            (
                {"local_runner_settings_sha256": "g" * 64},
                "REGISTRATION_HANDOFF_LOCAL_SETTINGS_SHA256_INVALID",
            ),
        )
        for changes, expected_reason in invalid_cases:
            with self.subTest(changes=changes):
                reasons = module.registration_handoff_reason_codes(
                    self.handoff(module, **changes)
                )
                self.assertIn(expected_reason, reasons)

    def test_registration_handoff_rejects_noncanonical_bytes(self):
        module = contract_module()
        evidence = self.handoff(module)
        payload = json.loads(
            module.registration_handoff_bytes(evidence).decode("utf-8")
        )
        noncanonical = (json.dumps(payload, indent=2) + "\n").encode("utf-8")

        with self.assertRaisesRegex(ValueError, "canonical"):
            module.parse_registration_handoff_bytes(noncanonical)

    def test_registration_handoff_contains_no_secret_or_console_fields(self):
        module = contract_module()
        evidence = self.handoff(module)
        payload = json.loads(
            module.registration_handoff_bytes(evidence).decode("utf-8")
        )

        forbidden = {
            "registration_token",
            "gh_token",
            "hmac_key",
            "credential",
            "password",
            "stdout",
            "stderr",
        }
        self.assertTrue(set(payload).isdisjoint(forbidden))


class PrivateCiPhase4OperatorSpecRedTests(unittest.TestCase):
    def test_phase4_spec_requires_exact_registration_handoff(self):
        module = contract_module()
        binding = valid_binding(module)
        handoff_sha = "9" * 64

        spec = module.build_phase4_target_environment_spec(
            binding,
            registration_handoff_sha256=handoff_sha,
        )

        self.assertEqual(spec.operation_id, "issue225-phase4-target-environment")
        self.assertEqual(spec.step_id, "prepare-target-environment")
        self.assertEqual(spec.repository, binding.repository)
        self.assertEqual(spec.pull_request_number, binding.pull_request_number)
        self.assertEqual(spec.target_sha, binding.target_sha)
        self.assertEqual(spec.target_host_role, "private-ci-owner-machine")
        self.assertEqual(spec.required_identity, "c-admin")
        self.assertEqual(
            spec.allowed_effect_families,
            ("PRIVATE_CI_PHASE4_TARGET_ENVIRONMENT",),
        )
        self.assertTrue(spec.require_parser_attestation)
        self.assertTrue(spec.require_child_exit_code)
        self.assertTrue(spec.require_fail_fast)
        self.assertIsNotNone(spec.prior_evidence_requirement)
        self.assertEqual(
            spec.prior_evidence_requirement.producer_operation_id,
            "issue225-registration-handoff",
        )
        self.assertEqual(
            spec.prior_evidence_requirement.producer_step_id,
            "registration-handoff",
        )
        self.assertEqual(
            spec.prior_evidence_requirement.evidence_sha256,
            handoff_sha,
        )

    def test_phase4_spec_rejects_invalid_binding_or_handoff_digest(self):
        module = contract_module()
        with self.assertRaisesRegex(ValueError, "pilot binding"):
            module.build_phase4_target_environment_spec(
                valid_binding(module, runner_id=0),
                registration_handoff_sha256="9" * 64,
            )
        with self.assertRaisesRegex(ValueError, "handoff SHA-256"):
            module.build_phase4_target_environment_spec(
                valid_binding(module),
                registration_handoff_sha256="short",
            )


if __name__ == "__main__":
    unittest.main()
