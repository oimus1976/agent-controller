import json
import unittest
from dataclasses import replace

from agent_controller.private_ci_phase0_evidence import (
    EXPECTED_BROKER_IDENTITY,
    EXPECTED_CONTROLLER_MAIN,
    EXPECTED_CONTROLLER_TREE,
    EXPECTED_HOST,
    EXPECTED_TARGET_IDENTITY,
    PHASE0_EVIDENCE_SCHEMA,
    Phase0Evidence,
    phase0_canonical_bytes,
    phase0_reason_codes,
    validate_phase0_evidence_bytes,
)
from agent_controller.private_ci_live_registration import (
    FROZEN_ENVIRONMENT_GENERATION,
    FROZEN_PR_NUMBER,
    FROZEN_REPOSITORY,
    FROZEN_RUNNER_LABEL,
    FROZEN_RUNNER_NAME,
    FROZEN_RUNNER_ROOT,
    FROZEN_TARGET_SHA,
    FROZEN_WORKFLOW_PATH,
    FROZEN_WORKFLOW_SHA,
)


def valid_evidence():
    return Phase0Evidence(
        schema=PHASE0_EVIDENCE_SCHEMA,
        collected_at="2026-09-17T20:39:07+09:00",
        status="PHASE0_PASS",
        controller_main_sha=EXPECTED_CONTROLLER_MAIN,
        controller_tree=EXPECTED_CONTROLLER_TREE,
        controller_tree_head_sha=EXPECTED_CONTROLLER_MAIN,
        controller_tree_clean=True,
        host=EXPECTED_HOST,
        broker_identity=EXPECTED_BROKER_IDENTITY,
        target_identity=EXPECTED_TARGET_IDENTITY,
        target_identity_enabled=True,
        target_identity_admin=False,
        repository=FROZEN_REPOSITORY,
        repository_visibility="private",
        default_branch="main",
        pull_request_number=FROZEN_PR_NUMBER,
        pull_request_state="open",
        pull_request_draft=True,
        pull_request_head_repository=FROZEN_REPOSITORY,
        pull_request_head_sha=FROZEN_TARGET_SHA,
        pull_request_base="main",
        workflow_sha=FROZEN_WORKFLOW_SHA,
        workflow_path=FROZEN_WORKFLOW_PATH,
        runner_name=FROZEN_RUNNER_NAME,
        runner_label=FROZEN_RUNNER_LABEL,
        environment_generation=FROZEN_ENVIRONMENT_GENERATION,
        runner_root=FROZEN_RUNNER_ROOT,
        runner_root_exists=False,
        matching_pilot_runner_count=0,
        runner_process_count=0,
        runner_service_count=0,
        runner_task_count=0,
        powershell_version="5.1.26100.9444",
        python_version="3.12.10",
    )


class PrivateCiPhase0EvidenceTests(unittest.TestCase):
    def test_valid_canonical_evidence_passes(self):
        evidence = valid_evidence()
        raw = phase0_canonical_bytes(evidence)
        parsed = validate_phase0_evidence_bytes(raw)
        self.assertEqual(parsed, evidence)
        self.assertEqual(phase0_reason_codes(parsed), ())

    def test_noncanonical_json_is_rejected(self):
        evidence = valid_evidence()
        noncanonical = (json.dumps(evidence.to_dict(), indent=2) + "\n").encode("utf-8")
        with self.assertRaisesRegex(ValueError, "canonical"):
            validate_phase0_evidence_bytes(noncanonical)

    def test_required_boundary_drift_is_fail_closed(self):
        changes = (
            {"controller_main_sha": "a" * 40},
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
                self.assertTrue(reasons)

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
