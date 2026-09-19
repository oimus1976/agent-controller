import hashlib
import json
import unittest
from dataclasses import replace

from agent_controller.private_ci_phase4_contract import (
    REGISTRATION_HANDOFF_SCHEMA,
    PrivateCiPilotBinding,
    RegistrationHandoffEvidence,
    build_phase4_target_environment_spec,
    registration_handoff_bytes,
    render_phase4_target_environment_candidate,
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


def handoff():
    return RegistrationHandoffEvidence(
        schema=REGISTRATION_HANDOFF_SCHEMA,
        binding=binding(),
        phase0_evidence_sha256="3" * 64,
        registration_plan_sha256="4" * 64,
        human_approval_sha256="5" * 64,
        registration_consumption_sha256="6" * 64,
        registration_result_sha256="7" * 64,
        local_runner_settings_sha256="8" * 64,
        runner_generation_snapshot_sha256="9" * 64,
        registration_status="REGISTERED",
    )


class PrivateCiPhase4PlanRedTests(unittest.TestCase):
    def module(self):
        from agent_controller import private_ci_phase4_runtime
        return private_ci_phase4_runtime

    def valid_plan(self):
        module = self.module()
        evidence = handoff()
        handoff_raw = registration_handoff_bytes(evidence)
        handoff_sha = hashlib.sha256(handoff_raw).hexdigest()
        probe_sha = "b" * 64
        candidate = render_phase4_target_environment_candidate(
            evidence.binding,
            evidence,
            target_probe_sha256=probe_sha,
        )
        spec = build_phase4_target_environment_spec(
            evidence.binding,
            registration_handoff_sha256=handoff_sha,
        )
        return module.Phase4Plan(
            schema=module.PHASE4_PLAN_SCHEMA,
            binding=evidence.binding,
            registration_handoff_sha256=handoff_sha,
            candidate=candidate,
            candidate_sha256=hashlib.sha256(candidate.encode("utf-8")).hexdigest(),
            spec_sha256=operator_step_spec_sha256(spec),
            target_probe_sha256=probe_sha,
        )

    def test_phase4_plan_roundtrips_as_canonical_json(self):
        module = self.module()
        plan = self.valid_plan()
        raw = module.phase4_plan_bytes(plan)

        self.assertEqual(module.parse_phase4_plan_bytes(raw), plan)
        self.assertEqual(
            module.phase4_plan_sha256(plan),
            hashlib.sha256(raw).hexdigest(),
        )
        self.assertEqual(
            tuple(plan.__dataclass_fields__),
            (
                "schema",
                "binding",
                "registration_handoff_sha256",
                "candidate",
                "candidate_sha256",
                "spec_sha256",
                "target_probe_sha256",
            ),
        )

    def test_noncanonical_or_secret_bearing_plan_is_rejected(self):
        module = self.module()
        plan = self.valid_plan()
        payload = json.loads(module.phase4_plan_bytes(plan).decode("utf-8"))
        noncanonical = (json.dumps(payload, indent=2) + "\n").encode("utf-8")
        with self.assertRaisesRegex(ValueError, "canonical"):
            module.parse_phase4_plan_bytes(noncanonical)

        payload["credential"] = "secret"
        secret_bearing = (
            json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        with self.assertRaisesRegex(ValueError, "shape"):
            module.parse_phase4_plan_bytes(secret_bearing)

    def test_validate_frozen_plan_detects_candidate_handoff_and_probe_drift(self):
        module = self.module()
        plan = self.valid_plan()
        handoff_raw = registration_handoff_bytes(handoff())
        probe_raw = b"tracked-probe\n"

        reasons = module.validate_frozen_phase4_plan(
            plan,
            registration_handoff_bytes=handoff_raw,
            target_probe_bytes=probe_raw,
        )
        self.assertIn("PHASE4_PLAN_TARGET_PROBE_SHA_MISMATCH", reasons)

        actual_probe_sha = hashlib.sha256(probe_raw).hexdigest()
        corrected = replace(plan, target_probe_sha256=actual_probe_sha)
        corrected_candidate = render_phase4_target_environment_candidate(
            corrected.binding,
            handoff(),
            target_probe_sha256=actual_probe_sha,
        )
        corrected_spec = build_phase4_target_environment_spec(
            corrected.binding,
            registration_handoff_sha256=hashlib.sha256(handoff_raw).hexdigest(),
        )
        corrected = replace(
            corrected,
            candidate=corrected_candidate,
            candidate_sha256=hashlib.sha256(
                corrected_candidate.encode("utf-8")
            ).hexdigest(),
            spec_sha256=operator_step_spec_sha256(corrected_spec),
        )
        self.assertEqual(
            module.validate_frozen_phase4_plan(
                corrected,
                registration_handoff_bytes=handoff_raw,
                target_probe_bytes=probe_raw,
            ),
            (),
        )

        drifted = replace(
            corrected,
            registration_handoff_sha256="f" * 64,
        )
        self.assertIn(
            "PHASE4_PLAN_HANDOFF_SHA_MISMATCH",
            module.validate_frozen_phase4_plan(
                drifted,
                registration_handoff_bytes=handoff_raw,
                target_probe_bytes=probe_raw,
            ),
        )


if __name__ == "__main__":
    unittest.main()
