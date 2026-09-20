import json
import unittest

from agent_controller.private_ci_phase4_contract import PrivateCiPilotBinding
from agent_controller.private_ci_phase4_result import (
    PHASE4_RESULT_SCHEMA,
    PHASE4_RESULT_STATUS,
    Phase4ResultEvidence,
    parse_phase4_result_bytes,
    parse_target_probe_result_bytes,
    phase4_result_bytes,
)


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


def evidence():
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
        completed_at="2026-09-19T12:40:00+00:00",
    )


def probe_bytes(**overrides):
    payload = {
        "schema": "agent-controller.private-ci-phase4-target-probe.v1",
        "status": "TARGET_PROBE_PASS",
        "host": "WOBBUFFET",
        "identity": r"WOBBUFFET\ac-runner",
        "admin_sid_present": False,
        "high_integrity_present": False,
        "forbidden_environment_count": 0,
        "broker_credential_roots_readable": 0,
        "gh_authenticated": False,
        "authority_marker_write_denied": True,
    }
    payload.update(overrides)
    return (
        json.dumps(payload, separators=(",", ":"), ensure_ascii=True) + "\n"
    ).encode("utf-8")


class PrivateCiPhase4ResultTests(unittest.TestCase):
    def test_phase4_result_roundtrips_canonically(self):
        raw = phase4_result_bytes(evidence())
        self.assertEqual(parse_phase4_result_bytes(raw), evidence())

    def test_probe_result_requires_runtime_identity_and_isolation(self):
        parsed = parse_target_probe_result_bytes(
            probe_bytes(),
            binding=binding(),
        )
        self.assertEqual(parsed["status"], "TARGET_PROBE_PASS")

        unsafe = (
            {"identity": r"WOBBUFFET\c-admin"},
            {"admin_sid_present": True},
            {"high_integrity_present": True},
            {"forbidden_environment_count": 1},
            {"broker_credential_roots_readable": 1},
            {"gh_authenticated": True},
            {"authority_marker_write_denied": False},
        )
        for changes in unsafe:
            with self.subTest(changes=changes):
                with self.assertRaises(ValueError):
                    parse_target_probe_result_bytes(
                        probe_bytes(**changes),
                        binding=binding(),
                    )

    def test_noncanonical_or_extra_phase4_result_fields_are_rejected(self):
        payload = json.loads(phase4_result_bytes(evidence()).decode("utf-8"))
        noncanonical = (json.dumps(payload, indent=2) + "\n").encode("utf-8")
        with self.assertRaisesRegex(ValueError, "canonical"):
            parse_phase4_result_bytes(noncanonical)

        payload["console_marker"] = "PHASE4_TARGET_ENVIRONMENT_PASS"
        extra = (
            json.dumps(payload, sort_keys=True, separators=(",", ":"))
            + "\n"
        ).encode("utf-8")
        with self.assertRaisesRegex(ValueError, "shape"):
            parse_phase4_result_bytes(extra)


if __name__ == "__main__":
    unittest.main()
