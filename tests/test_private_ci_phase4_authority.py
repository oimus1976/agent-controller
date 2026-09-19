import json
import unittest

from agent_controller.private_ci_phase4_authority import (
    PHASE4_CONSUMPTION_SCHEMA,
    canonical_phase4_consumption_bytes,
    phase4_approval_filename,
    phase4_consumption_marker_path,
    parse_phase4_consumption_marker_bytes,
)


PLAN_SHA = "a" * 64
HANDOFF_SHA = "b" * 64
APPROVAL_SHA = "c" * 64


def marker_bytes(**overrides):
    payload = {
        "schema": PHASE4_CONSUMPTION_SCHEMA,
        "phase4_plan_sha256": PLAN_SHA,
        "registration_handoff_sha256": HANDOFF_SHA,
        "human_approval_sha256": APPROVAL_SHA,
        "consumed_at": "2026-09-19T12:30:00+00:00",
    }
    payload.update(overrides)
    return canonical_phase4_consumption_bytes(payload)


class PrivateCiPhase4AuthorityRedTests(unittest.TestCase):
    def test_approval_and_consumption_paths_are_digest_bound(self):
        self.assertEqual(
            phase4_approval_filename(PLAN_SHA),
            f"issue225-phase4-approval-{PLAN_SHA}.json",
        )
        path = phase4_consumption_marker_path(HANDOFF_SHA)
        self.assertEqual(
            path.name,
            f"issue225-phase4-handoff-{HANDOFF_SHA}.consumed.json",
        )
        self.assertIn(
            r"C:\ProgramData\agent-controller-private-ci-authority",
            str(path),
        )

    def test_consumption_marker_roundtrips_exact_bindings(self):
        raw = marker_bytes()
        marker = parse_phase4_consumption_marker_bytes(
            raw,
            expected_plan_sha256=PLAN_SHA,
            expected_registration_handoff_sha256=HANDOFF_SHA,
            expected_human_approval_sha256=APPROVAL_SHA,
        )
        self.assertEqual(marker.phase4_plan_sha256, PLAN_SHA)
        self.assertEqual(marker.registration_handoff_sha256, HANDOFF_SHA)
        self.assertEqual(marker.human_approval_sha256, APPROVAL_SHA)

    def test_wrong_binding_or_noncanonical_marker_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "handoff SHA-256 mismatch"):
            parse_phase4_consumption_marker_bytes(
                marker_bytes(),
                expected_plan_sha256=PLAN_SHA,
                expected_registration_handoff_sha256="d" * 64,
                expected_human_approval_sha256=APPROVAL_SHA,
            )

        payload = json.loads(marker_bytes().decode("utf-8"))
        noncanonical = (json.dumps(payload, indent=2) + "\n").encode("utf-8")
        with self.assertRaisesRegex(ValueError, "canonical"):
            parse_phase4_consumption_marker_bytes(
                noncanonical,
                expected_plan_sha256=PLAN_SHA,
                expected_registration_handoff_sha256=HANDOFF_SHA,
                expected_human_approval_sha256=APPROVAL_SHA,
            )

    def test_digest_inputs_are_strict_lower_hex(self):
        with self.assertRaisesRegex(ValueError, "plan SHA-256"):
            phase4_approval_filename("A" * 64)
        with self.assertRaisesRegex(ValueError, "handoff SHA-256"):
            phase4_consumption_marker_path("short")


if __name__ == "__main__":
    unittest.main()
