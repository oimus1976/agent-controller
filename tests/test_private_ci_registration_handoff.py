import hashlib
import json
import unittest
from dataclasses import replace
from datetime import datetime, timezone

from agent_controller.operator_step_gate import operator_step_spec_sha256
from agent_controller.private_ci_consumption_marker import (
    CONSUMPTION_SCHEMA,
    canonical_consumption_bytes,
)
from agent_controller.private_ci_human_approval import APPROVAL_SCHEMA
from agent_controller.private_ci_live_registration import (
    build_live_registration_spec,
    live_registration_binding_from_phase0_evidence_bytes,
    phase0_evidence_sha256,
    render_live_registration_candidate,
)
from agent_controller.private_ci_live_registration_runtime import (
    RESULT_SCHEMA,
    RUNNER_PACKAGE_SHA256,
    RUNNER_PACKAGE_URL,
    RUNNER_VERSION,
    LiveRegistrationPlan,
    canonical_json_bytes,
    plan_bytes,
)
from agent_controller.private_ci_phase0_evidence import (
    PHASE0_EVIDENCE_SCHEMA,
    Phase0Evidence,
    phase0_canonical_bytes,
)
from agent_controller.private_ci_pilot_identity import (
    PRIVATE_CI_BROKER_IDENTITY,
    PRIVATE_CI_HOST,
    PRIVATE_CI_RUNNER_LABEL,
    PRIVATE_CI_TARGET_IDENTITY,
    PRIVATE_CI_WORK_FOLDER,
    canonical_runner_root,
)
from agent_controller.private_ci_registration_handoff import (
    HUMAN_AUTHORIZATION_METHOD,
    build_registration_handoff_evidence,
)


NOW = datetime(2026, 9, 19, 12, 30, tzinfo=timezone.utc)
GENERATION = "ac-pilot-0123456789abcdef"
RUNNER_NAME = "ac-ci-0123456789abcdef"
REPOSITORY = "oimus1976/example-private"
TARGET_SHA = "1" * 40
WORKFLOW_SHA = "2" * 40
WORKFLOW_PATH = ".github/workflows/private-ci-windows-pilot.yml"
CONTROLLER_SHA = "a" * 40
CONTROLLER_TREE = r"C:\Users\c-admin\agent-controller-pilot-225"


def phase0_bytes():
    evidence = Phase0Evidence(
        schema=PHASE0_EVIDENCE_SCHEMA,
        collected_at="2026-09-19T12:20:00+00:00",
        status="PHASE0_PASS",
        controller_main_sha=CONTROLLER_SHA,
        controller_tree=CONTROLLER_TREE,
        controller_tree_head_sha=CONTROLLER_SHA,
        controller_tree_clean=True,
        host=PRIVATE_CI_HOST,
        broker_identity=PRIVATE_CI_BROKER_IDENTITY,
        target_identity=PRIVATE_CI_TARGET_IDENTITY,
        target_identity_enabled=True,
        target_identity_admin=False,
        repository=REPOSITORY,
        repository_visibility="private",
        default_branch="main",
        pull_request_number=4,
        pull_request_state="open",
        pull_request_draft=True,
        pull_request_head_repository=REPOSITORY,
        pull_request_head_sha=TARGET_SHA,
        pull_request_base="main",
        workflow_sha=WORKFLOW_SHA,
        workflow_path=WORKFLOW_PATH,
        runner_name=RUNNER_NAME,
        runner_label=PRIVATE_CI_RUNNER_LABEL,
        environment_generation=GENERATION,
        runner_root=canonical_runner_root(GENERATION),
        work_folder=PRIVATE_CI_WORK_FOLDER,
        runner_root_exists=False,
        matching_pilot_runner_count=0,
        runner_process_count=0,
        runner_service_count=0,
        runner_task_count=0,
        powershell_version="5.1.26100.9444",
        python_version="3.12.10",
    )
    return phase0_canonical_bytes(evidence)


def registration_plan_bytes(raw_phase0):
    binding = live_registration_binding_from_phase0_evidence_bytes(raw_phase0)
    candidate = render_live_registration_candidate(binding)
    evidence_sha = phase0_evidence_sha256(raw_phase0)
    spec = build_live_registration_spec(
        binding,
        phase0_evidence_sha256=evidence_sha,
    )
    plan = LiveRegistrationPlan(
        schema="agent-controller.private-ci-live-registration-plan.v2",
        binding=binding,
        phase0_evidence_sha256=evidence_sha,
        candidate=candidate,
        candidate_sha256=hashlib.sha256(candidate.encode("utf-8")).hexdigest(),
        spec_sha256=operator_step_spec_sha256(spec),
        runner_version=RUNNER_VERSION,
        runner_package_url=RUNNER_PACKAGE_URL,
        runner_package_sha256=RUNNER_PACKAGE_SHA256,
    )
    return plan_bytes(plan)


def approval_bytes(plan_sha, *, approved_at="2026-09-19T12:25:00+00:00"):
    payload = {
        "schema": APPROVAL_SCHEMA,
        "plan_sha256": plan_sha,
        "host": PRIVATE_CI_HOST,
        "approver_identity": PRIVATE_CI_BROKER_IDENTITY,
        "approved_at": approved_at,
    }
    return (
        json.dumps(payload, separators=(",", ":"), ensure_ascii=True) + "\n"
    ).encode("utf-8")


def consumption_bytes(plan_sha, phase0_sha, approval_sha):
    return canonical_consumption_bytes(
        {
            "schema": CONSUMPTION_SCHEMA,
            "plan_sha256": plan_sha,
            "phase0_evidence_sha256": phase0_sha,
            "human_approval_sha256": approval_sha,
            "consumed_at": "2026-09-19T12:26:00+00:00",
        }
    )


def result_bytes(raw_phase0, raw_plan, approval_sha, *, runner_id=23, **overrides):
    binding = live_registration_binding_from_phase0_evidence_bytes(raw_phase0)
    plan_payload = json.loads(raw_plan.decode("utf-8"))
    payload = {
        "schema": RESULT_SCHEMA,
        "plan_sha256": hashlib.sha256(raw_plan).hexdigest(),
        "repository": binding.repository,
        "pull_request_number": binding.pull_request_number,
        "target_sha": binding.target_sha,
        "workflow_sha": binding.workflow_sha,
        "workflow_path": binding.workflow_path,
        "runner_name": binding.runner_name,
        "runner_label": binding.runner_label,
        "environment_generation": binding.environment_generation,
        "candidate_sha256": plan_payload["candidate_sha256"],
        "status": "REGISTERED",
        "reason_codes": [],
        "child_exit_code": 0,
        "runner_id": runner_id,
        "runner_readback_attempts": 1,
        "stdout": "",
        "stderr": "",
        "started_at": "2026-09-19T12:26:10+00:00",
        "ended_at": "2026-09-19T12:26:20+00:00",
        "human_authorization": HUMAN_AUTHORIZATION_METHOD,
        "human_approval_sha256": approval_sha,
        "registration_token_recorded": False,
    }
    payload.update(overrides)
    return canonical_json_bytes(payload)


def local_runner_bytes(*, runner_id=23, runner_name=RUNNER_NAME):
    return json.dumps(
        {
            "agentId": runner_id,
            "agentName": runner_name,
            "workFolder": PRIVATE_CI_WORK_FOLDER,
            "ephemeral": True,
            "disableUpdate": True,
        },
        separators=(",", ":"),
    ).encode("utf-8")


class PrivateCiRegistrationHandoffBuilderTests(unittest.TestCase):
    def artifacts(self):
        raw_phase0 = phase0_bytes()
        raw_plan = registration_plan_bytes(raw_phase0)
        plan_sha = hashlib.sha256(raw_plan).hexdigest()
        raw_approval = approval_bytes(plan_sha)
        approval_sha = hashlib.sha256(raw_approval).hexdigest()
        raw_consumption = consumption_bytes(
            plan_sha,
            hashlib.sha256(raw_phase0).hexdigest(),
            approval_sha,
        )
        raw_result = result_bytes(
            raw_phase0,
            raw_plan,
            approval_sha,
        )
        raw_runner = local_runner_bytes()
        return (
            raw_phase0,
            raw_plan,
            raw_approval,
            raw_consumption,
            raw_result,
            raw_runner,
        )

    def test_exact_artifact_chain_builds_secret_free_handoff(self):
        artifacts = self.artifacts()
        handoff = build_registration_handoff_evidence(
            phase0_evidence_bytes=artifacts[0],
            registration_plan_bytes=artifacts[1],
            human_approval_bytes=artifacts[2],
            registration_consumption_bytes=artifacts[3],
            registration_result_bytes=artifacts[4],
            local_runner_settings_bytes=artifacts[5],
            now=lambda: NOW,
        )

        self.assertEqual(handoff.registration_status, "REGISTERED")
        self.assertEqual(handoff.binding.runner_id, 23)
        self.assertEqual(handoff.binding.runner_name, RUNNER_NAME)
        self.assertEqual(
            handoff.local_runner_settings_sha256,
            hashlib.sha256(artifacts[5]).hexdigest(),
        )
        self.assertEqual(
            handoff.registration_result_sha256,
            hashlib.sha256(artifacts[4]).hexdigest(),
        )

    def test_local_agent_id_must_match_remote_runner_id(self):
        artifacts = list(self.artifacts())
        artifacts[5] = local_runner_bytes(runner_id=24)
        with self.assertRaisesRegex(ValueError, "agent id mismatch"):
            build_registration_handoff_evidence(
                phase0_evidence_bytes=artifacts[0],
                registration_plan_bytes=artifacts[1],
                human_approval_bytes=artifacts[2],
                registration_consumption_bytes=artifacts[3],
                registration_result_bytes=artifacts[4],
                local_runner_settings_bytes=artifacts[5],
                now=lambda: NOW,
            )

    def test_stale_registration_approval_cannot_create_handoff(self):
        raw_phase0 = phase0_bytes()
        raw_plan = registration_plan_bytes(raw_phase0)
        plan_sha = hashlib.sha256(raw_plan).hexdigest()
        raw_approval = approval_bytes(
            plan_sha,
            approved_at="2026-09-19T11:00:00+00:00",
        )
        approval_sha = hashlib.sha256(raw_approval).hexdigest()
        raw_consumption = consumption_bytes(
            plan_sha,
            hashlib.sha256(raw_phase0).hexdigest(),
            approval_sha,
        )
        with self.assertRaisesRegex(ValueError, "stale"):
            build_registration_handoff_evidence(
                phase0_evidence_bytes=raw_phase0,
                registration_plan_bytes=raw_plan,
                human_approval_bytes=raw_approval,
                registration_consumption_bytes=raw_consumption,
                registration_result_bytes=result_bytes(
                    raw_phase0,
                    raw_plan,
                    approval_sha,
                ),
                local_runner_settings_bytes=local_runner_bytes(),
                now=lambda: NOW,
            )

    def test_result_binding_mismatch_cannot_create_handoff(self):
        artifacts = list(self.artifacts())
        approval_sha = hashlib.sha256(artifacts[2]).hexdigest()
        artifacts[4] = result_bytes(
            artifacts[0],
            artifacts[1],
            approval_sha,
            runner_name="ac-ci-fedcba9876543210",
        )
        with self.assertRaisesRegex(ValueError, "result binding mismatch"):
            build_registration_handoff_evidence(
                phase0_evidence_bytes=artifacts[0],
                registration_plan_bytes=artifacts[1],
                human_approval_bytes=artifacts[2],
                registration_consumption_bytes=artifacts[3],
                registration_result_bytes=artifacts[4],
                local_runner_settings_bytes=artifacts[5],
                now=lambda: NOW,
            )


if __name__ == "__main__":
    unittest.main()
