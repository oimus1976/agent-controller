import json
import unittest
from dataclasses import replace

from agent_controller.private_ci_phase0_evidence import (
    PHASE0_EVIDENCE_SCHEMA,
    Phase0Evidence,
    phase0_canonical_bytes,
    phase0_freeze_mismatch_reason_codes,
    phase0_reason_codes,
    validate_phase0_evidence_bytes,
)
from agent_controller.private_ci_pilot_identity import (
    PILOT_IDENTITY_FREEZE_SCHEMA,
    PRIVATE_CI_BROKER_IDENTITY,
    PRIVATE_CI_HOST,
    PRIVATE_CI_RUNNER_LABEL,
    PRIVATE_CI_TARGET_IDENTITY,
    PRIVATE_CI_WORK_FOLDER,
    PrivateCiPilotIdentityFreeze,
    canonical_runner_root,
)


CONTROLLER_SHA = "a" * 40
CONTROLLER_TREE = r"C:\Users\c-admin\agent-controller-pilot-225"
TARGET_SHA = "1" * 40
WORKFLOW_SHA = "2" * 40
WORKFLOW_PATH = ".github/workflows/private-ci-windows-pilot.yml"
RUNNER_NAME = "ac-ci-0123456789abcdef"
GENERATION = "ac-pilot-0123456789abcdef"


def valid_freeze():
    return PrivateCiPilotIdentityFreeze(
        schema=PILOT_IDENTITY_FREEZE_SCHEMA,
        repository="oimus1976/example-private",
        pull_request_number=4,
        target_sha=TARGET_SHA,
        workflow_sha=WORKFLOW_SHA,
        workflow_path=WORKFLOW_PATH,
        runner_name=RUNNER_NAME,
        runner_label=PRIVATE_CI_RUNNER_LABEL,
        environment_generation=GENERATION,
        runner_root=canonical_runner_root(GENERATION),
        work_folder=PRIVATE_CI_WORK_FOLDER,
        controller_main_sha=CONTROLLER_SHA,
        controller_tree=CONTROLLER_TREE,
        host=PRIVATE_CI_HOST,
        broker_identity=PRIVATE_CI_BROKER_IDENTITY,
        target_identity=PRIVATE_CI_TARGET_IDENTITY,
    )


def valid_evidence():
    freeze = valid_freeze()
    return Phase0Evidence(
        schema=PHASE0_EVIDENCE_SCHEMA,
        collected_at="2026-09-19T12:00:00+00:00",
        status="PHASE0_PASS",
        controller_main_sha=freeze.controller_main_sha,
        controller_tree=freeze.controller_tree,
        controller_tree_head_sha=freeze.controller_main_sha,
        controller_tree_clean=True,
        host=freeze.host,
        broker_identity=freeze.broker_identity,
        target_identity=freeze.target_identity,
        target_identity_enabled=True,
        target_identity_admin=False,
        repository=freeze.repository,
        repository_visibility="private",
        default_branch="main",
        pull_request_number=freeze.pull_request_number,
        pull_request_state="open",
        pull_request_draft=True,
        pull_request_head_repository=freeze.repository,
        pull_request_head_sha=freeze.target_sha,
        pull_request_base="main",
        workflow_sha=freeze.workflow_sha,
        workflow_path=freeze.workflow_path,
        runner_name=freeze.runner_name,
        runner_label=freeze.runner_label,
        environment_generation=freeze.environment_generation,
        runner_root=freeze.runner_root,
        work_folder=freeze.work_folder,
        runner_root_exists=False,
        matching_pilot_runner_count=0,
        runner_process_count=0,
        runner_service_count=0,
        runner_task_count=0,
        powershell_version="5.1.26100.9444",
        python_version="3.12.10",
        machine_policy="Undefined",
        target_user_policy="Undefined",
        execution_policy_target_identity=freeze.target_identity,
        execution_policy_target_sid="S-1-5-21-111-222-333-1007",
        effective_policy_with_process_bypass="Bypass",
    )


class PrivateCiPhase0EvidenceTests(unittest.TestCase):
    def test_group_policy_precedence_and_process_bypass_conclusion(self):
        cases = (
            ("Undefined", "Undefined", "Bypass", True),
            ("Restricted", "Undefined", "Restricted", False),
            ("Undefined", "AllSigned", "AllSigned", False),
            ("RemoteSigned", "Bypass", "RemoteSigned", False),
            ("Unrestricted", "Undefined", "Unrestricted", False),
            ("Bypass", "Restricted", "Bypass", True),
        )
        for machine, user, effective, accepted in cases:
            with self.subTest(machine=machine, user=user):
                evidence = replace(
                    valid_evidence(), machine_policy=machine, target_user_policy=user,
                    effective_policy_with_process_bypass=effective,
                )
                if accepted:
                    self.assertEqual(validate_phase0_evidence_bytes(phase0_canonical_bytes(evidence)), evidence)
                else:
                    with self.assertRaisesRegex(ValueError, "PROCESS_BYPASS_BLOCKED_BY_GROUP_POLICY"):
                        validate_phase0_evidence_bytes(phase0_canonical_bytes(evidence))

    def test_unknown_policy_and_forged_conclusion_fail_closed(self):
        for field in ("machine_policy", "target_user_policy"):
            for unknown in ("Unknown", "", None, False, [], {}):
                with self.subTest(field=field, unknown=unknown):
                    evidence = replace(valid_evidence(), **{field: unknown})
                    with self.assertRaisesRegex(ValueError, "POLICY_UNKNOWN"):
                        validate_phase0_evidence_bytes(phase0_canonical_bytes(evidence))
        evidence = replace(valid_evidence(), machine_policy="Restricted")
        self.assertIn("PHASE0_EFFECTIVE_POLICY_WITH_PROCESS_BYPASS_MISMATCH", phase0_reason_codes(evidence))

    def test_broker_policy_subject_cannot_substitute_for_target(self):
        evidence = replace(valid_evidence(), execution_policy_target_identity=PRIVATE_CI_BROKER_IDENTITY)
        with self.assertRaisesRegex(ValueError, "EXECUTION_POLICY_TARGET_IDENTITY_MISMATCH"):
            validate_phase0_evidence_bytes(phase0_canonical_bytes(evidence))
        for sid in ("", "S-1-5-18", "HKCU", None):
            with self.subTest(sid=sid):
                evidence = replace(valid_evidence(), execution_policy_target_sid=sid)
                with self.assertRaisesRegex(ValueError, "TARGET_SID_INVALID"):
                    validate_phase0_evidence_bytes(phase0_canonical_bytes(evidence))

    def test_historical_schemas_and_missing_policy_shape_are_not_upgraded(self):
        payload = valid_evidence().to_dict()
        policy_fields = (
            "machine_policy", "target_user_policy", "execution_policy_target_identity",
            "execution_policy_target_sid", "effective_policy_with_process_bypass",
        )
        for schema in ("v1", "v2", "v3"):
            with self.subTest(schema=schema):
                historical = {key: value for key, value in payload.items() if key not in policy_fields}
                historical["schema"] = "agent-controller.private-ci-phase0-evidence." + schema
                raw = (json.dumps(historical, sort_keys=True, separators=(",", ":")) + "\n").encode()
                with self.assertRaisesRegex(ValueError, "schema unsupported|fields invalid"):
                    validate_phase0_evidence_bytes(raw)
        with self.assertRaisesRegex(ValueError, "schema unsupported"):
            validate_phase0_evidence_bytes(phase0_canonical_bytes(replace(valid_evidence(), schema="agent-controller.private-ci-phase0-evidence.v2")))

    def test_policy_bytes_are_deterministic_and_bind_registration_digest(self):
        import hashlib
        from agent_controller.private_ci_live_registration import live_registration_binding_from_phase0_evidence_bytes

        evidence = valid_evidence()
        raw = phase0_canonical_bytes(evidence)
        self.assertEqual(raw, phase0_canonical_bytes(validate_phase0_evidence_bytes(raw)))
        other = replace(evidence, execution_policy_target_sid="S-1-5-21-111-222-333-1008")
        self.assertNotEqual(hashlib.sha256(raw).digest(), hashlib.sha256(phase0_canonical_bytes(other)).digest())
        binding = live_registration_binding_from_phase0_evidence_bytes(raw)
        self.assertEqual(binding.target_sha, valid_freeze().target_sha)
        self.assertEqual(binding.runner_name, valid_freeze().runner_name)
        historical = phase0_canonical_bytes(replace(evidence, schema="agent-controller.private-ci-phase0-evidence.v2"))
        with self.assertRaisesRegex(ValueError, "schema unsupported"):
            live_registration_binding_from_phase0_evidence_bytes(historical)

    def test_valid_canonical_evidence_passes(self):
        evidence = valid_evidence()
        raw = phase0_canonical_bytes(evidence)
        parsed = validate_phase0_evidence_bytes(raw)
        self.assertEqual(parsed, evidence)
        self.assertEqual(phase0_reason_codes(parsed), ())
        self.assertEqual(
            phase0_freeze_mismatch_reason_codes(parsed, valid_freeze()),
            (),
        )

    def test_noncanonical_json_is_rejected(self):
        evidence = valid_evidence()
        noncanonical = (json.dumps(evidence.to_dict(), indent=2) + "\n").encode("utf-8")
        with self.assertRaisesRegex(ValueError, "canonical"):
            validate_phase0_evidence_bytes(noncanonical)

    def test_required_boundary_drift_is_fail_closed(self):
        changes = (
            {"controller_main_sha": "b" * 40},
            {"controller_tree_clean": False},
            {"broker_identity": "WOBBUFFET\\other"},
            {"target_identity_admin": True},
            {"repository_visibility": "public"},
            {"pull_request_draft": False},
            {"pull_request_head_sha": "b" * 40},
            {"workflow_sha": "c" * 40},
            {"workflow_path": ".github/workflows/other.yml"},
            {"runner_root_exists": True},
            {"matching_pilot_runner_count": 1},
            {"runner_process_count": 1},
            {"runner_service_count": 1},
            {"runner_task_count": 1},
        )
        for change in changes:
            with self.subTest(change=change):
                evidence = replace(valid_evidence(), **change)
                reasons = phase0_reason_codes(evidence)
                mismatch = phase0_freeze_mismatch_reason_codes(
                    evidence,
                    valid_freeze(),
                )
                self.assertTrue(reasons or mismatch)

    def test_runtime_versions_are_bounded(self):
        self.assertIn(
            "PHASE0_POWERSHELL_VERSION_INVALID",
            phase0_reason_codes(replace(valid_evidence(), powershell_version="7.5.0")),
        )
        self.assertIn(
            "PHASE0_PYTHON_VERSION_INVALID",
            phase0_reason_codes(replace(valid_evidence(), python_version="3.13.0")),
        )


if __name__ == "__main__":
    unittest.main()
