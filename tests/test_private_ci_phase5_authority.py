import hashlib
import json
import unittest
from datetime import datetime, timezone


class PrivateCiPhase5AuthorityRedTests(unittest.TestCase):
    def module(self):
        from agent_controller import private_ci_phase5_authority
        return private_ci_phase5_authority

    def test_phase5_consumption_marker_roundtrips_and_binds_exact_authority(self):
        m = self.module()
        payload = {
            "schema": m.PHASE5_CONSUMPTION_SCHEMA,
            "phase5_plan_sha256": "1" * 64,
            "phase4_result_sha256": "2" * 64,
            "human_approval_sha256": "3" * 64,
            "consumed_at": "2026-09-19T13:30:00+00:00",
        }
        raw = m.canonical_phase5_consumption_bytes(payload)
        marker = m.parse_phase5_consumption_marker_bytes(
            raw,
            expected_plan_sha256="1" * 64,
            expected_phase4_result_sha256="2" * 64,
            expected_human_approval_sha256="3" * 64,
        )
        self.assertEqual(marker.phase5_plan_sha256, "1" * 64)
        self.assertEqual(marker.phase4_result_sha256, "2" * 64)
        self.assertEqual(marker.human_approval_sha256, "3" * 64)

    def test_phase5_marker_path_is_keyed_by_phase4_result(self):
        m = self.module()
        path = m.phase5_consumption_marker_path("a" * 64)
        self.assertIn("issue225-phase5-result-", path.name)
        self.assertTrue(path.name.endswith(".consumed.json"))
        self.assertIn("a" * 64, path.name)

    def test_marker_rejects_binding_or_canonical_drift(self):
        m = self.module()
        payload = {
            "schema": m.PHASE5_CONSUMPTION_SCHEMA,
            "phase5_plan_sha256": "1" * 64,
            "phase4_result_sha256": "2" * 64,
            "human_approval_sha256": "3" * 64,
            "consumed_at": "2026-09-19T13:30:00+00:00",
        }
        raw = m.canonical_phase5_consumption_bytes(payload)
        with self.assertRaisesRegex(ValueError, "Phase 4 result"):
            m.parse_phase5_consumption_marker_bytes(
                raw,
                expected_plan_sha256="1" * 64,
                expected_phase4_result_sha256="4" * 64,
                expected_human_approval_sha256="3" * 64,
            )

        noncanonical = (json.dumps(payload, indent=2) + "\n").encode("utf-8")
        with self.assertRaisesRegex(ValueError, "canonical"):
            m.parse_phase5_consumption_marker_bytes(
                noncanonical,
                expected_plan_sha256="1" * 64,
                expected_phase4_result_sha256="2" * 64,
                expected_human_approval_sha256="3" * 64,
            )


if __name__ == "__main__":
    unittest.main()
