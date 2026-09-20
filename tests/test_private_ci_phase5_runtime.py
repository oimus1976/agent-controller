import hashlib
import json
import unittest
from dataclasses import replace

from agent_controller.private_ci_phase4_contract import PrivateCiPilotBinding
from agent_controller.private_ci_phase4_result import (
    PHASE4_RESULT_SCHEMA,
    PHASE4_RESULT_STATUS,
    Phase4ResultEvidence,
    phase4_result_bytes,
)
from agent_controller.private_ci_phase5_contract import (
    build_phase5_exactly_one_job_spec,
    render_phase5_exactly_one_job_candidate,
)
from agent_controller.operator_step_gate import operator_step_spec_sha256


def binding():
    generation = "ac-pilot-0123456789abcdef"
    return PrivateCiPilotBinding(
        repository="oimus1976/example-private",
        pull_request_number=4,
        target_sha="1" * 40,
        controller_main_sha="a" * 40,
        controller_tree=r"C:\Users\c-admin\agent-controller-pilot-225",
        workflow_sha="2" * 40,
        workflow_path=".github/workflows/private-ci-windows-pilot.yml",
        runner_id=23,
        runner_name="ac-ci-0123456789abcdef",
        runner_label="private-ci-windows-pilot",
        environment_generation=generation,
        runner_root=(
            r"C:\ProgramData\agent-controller\private-ci"
            rf"\{generation}\runner"
        ),
        work_folder="_work",
        host="WOBBUFFET",
        broker_identity=r"WOBBUFFET\c-admin",
        target_identity="ac-runner",
    )


def phase4_result():
    return Phase4ResultEvidence(
        schema=PHASE4_RESULT_SCHEMA,
        binding=binding(),
        phase4_plan_sha256="1" * 64,
        registration_handoff_sha256="2" * 64,
        human_approval_sha256="3" * 64,
        phase4_consumption_sha256="4" * 64,
        candidate_sha256="5" * 64,
        target_probe_sha256="6" * 64,
        target_probe_result_sha256="7" * 64,
        target_probe_stdout_sha256="8" * 64,
        target_probe_stderr_sha256="9" * 64,
        runner_generation_snapshot_sha256="a" * 64,
        status=PHASE4_RESULT_STATUS,
        completed_at="2026-09-19T13:00:00+00:00",
    )


class PrivateCiPhase5PlanRedTests(unittest.TestCase):
    def module(self):
        from agent_controller import private_ci_phase5_runtime
        return private_ci_phase5_runtime

    def valid_plan(self):
        module = self.module()
        raw = phase4_result_bytes(phase4_result())
        phase4_sha = hashlib.sha256(raw).hexdigest()
        candidate = render_phase5_exactly_one_job_candidate(
            binding(),
            phase4_result_sha256=phase4_sha,
            target_probe_sha256=phase4_result().target_probe_sha256,
        )
        spec = build_phase5_exactly_one_job_spec(
            binding(),
            phase4_result_sha256=phase4_sha,
            target_probe_sha256=phase4_result().target_probe_sha256,
        )
        return module.Phase5Plan(
            schema=module.PHASE5_PLAN_SCHEMA,
            binding=binding(),
            phase4_result_sha256=phase4_sha,
            candidate=candidate,
            candidate_sha256=hashlib.sha256(
                candidate.encode("utf-8")
            ).hexdigest(),
            spec_sha256=operator_step_spec_sha256(spec),
        )

    def test_phase5_plan_roundtrips_canonically(self):
        module = self.module()
        plan = self.valid_plan()
        raw = module.phase5_plan_bytes(plan)

        self.assertEqual(module.parse_phase5_plan_bytes(raw), plan)
        self.assertEqual(
            module.phase5_plan_sha256(plan),
            hashlib.sha256(raw).hexdigest(),
        )

    def test_validate_plan_detects_phase4_candidate_and_spec_drift(self):
        module = self.module()
        plan = self.valid_plan()
        raw = phase4_result_bytes(phase4_result())
        self.assertEqual(
            module.validate_frozen_phase5_plan(
                plan,
                phase4_result_bytes=raw,
            ),
            (),
        )

        self.assertIn(
            "PHASE5_PLAN_PHASE4_RESULT_SHA_MISMATCH",
            module.validate_frozen_phase5_plan(
                replace(plan, phase4_result_sha256="f" * 64),
                phase4_result_bytes=raw,
            ),
        )
        self.assertIn(
            "PHASE5_PLAN_CANDIDATE_MISMATCH",
            module.validate_frozen_phase5_plan(
                replace(plan, candidate=plan.candidate + "# drift\n"),
                phase4_result_bytes=raw,
            ),
        )
        self.assertIn(
            "PHASE5_PLAN_SPEC_SHA_MISMATCH",
            module.validate_frozen_phase5_plan(
                replace(plan, spec_sha256="e" * 64),
                phase4_result_bytes=raw,
            ),
        )

    def test_extra_or_noncanonical_fields_are_rejected(self):
        module = self.module()
        payload = json.loads(
            module.phase5_plan_bytes(self.valid_plan()).decode("utf-8")
        )
        noncanonical = (json.dumps(payload, indent=2) + "\n").encode("utf-8")
        with self.assertRaisesRegex(ValueError, "canonical"):
            module.parse_phase5_plan_bytes(noncanonical)

        payload["retry_count"] = 1
        extra = (
            json.dumps(payload, sort_keys=True, separators=(",", ":"))
            + "\n"
        ).encode("utf-8")
        with self.assertRaisesRegex(ValueError, "shape"):
            module.parse_phase5_plan_bytes(extra)


if __name__ == "__main__":
    unittest.main()
