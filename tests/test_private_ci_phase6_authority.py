import json
import unittest


class PrivateCiPhase6AuthorityRedTests(unittest.TestCase):
    def module(self):
        from agent_controller import private_ci_phase6_authority
        return private_ci_phase6_authority

    def test_cleanup_consumption_marker_binds_exact_plan_and_phase5_result(self):
        m = self.module()
        payload = {
            "schema": m.PHASE6_CONSUMPTION_SCHEMA,
            "phase6_plan_sha256": "1" * 64,
            "phase5_result_sha256": "2" * 64,
            "human_approval_sha256": "3" * 64,
            "consumed_at": "2026-09-22T12:30:00+00:00",
        }
        raw = m.canonical_phase6_consumption_bytes(payload)
        marker = m.parse_phase6_consumption_marker_bytes(
            raw,
            expected_plan_sha256="1" * 64,
            expected_phase5_result_sha256="2" * 64,
            expected_human_approval_sha256="3" * 64,
        )
        self.assertEqual(marker.phase6_plan_sha256, "1" * 64)
        self.assertEqual(marker.phase5_result_sha256, "2" * 64)
        self.assertEqual(marker.human_approval_sha256, "3" * 64)

    def test_cleanup_consumption_path_is_keyed_by_plan_digest(self):
        m = self.module()
        path = m.phase6_consumption_marker_path("a" * 64)
        self.assertIn("issue230-phase6-cleanup-", path.name)
        self.assertIn("a" * 64, path.name)
        self.assertTrue(path.name.endswith(".consumed.json"))

    def test_cleanup_consumption_rejects_binding_and_canonical_drift(self):
        m = self.module()
        payload = {
            "schema": m.PHASE6_CONSUMPTION_SCHEMA,
            "phase6_plan_sha256": "1" * 64,
            "phase5_result_sha256": "2" * 64,
            "human_approval_sha256": "3" * 64,
            "consumed_at": "2026-09-22T12:30:00+00:00",
        }
        raw = m.canonical_phase6_consumption_bytes(payload)

        with self.assertRaisesRegex(ValueError, "Phase 5 result"):
            m.parse_phase6_consumption_marker_bytes(
                raw,
                expected_plan_sha256="1" * 64,
                expected_phase5_result_sha256="4" * 64,
                expected_human_approval_sha256="3" * 64,
            )

        noncanonical = (json.dumps(payload, indent=2) + "\n").encode("utf-8")
        with self.assertRaisesRegex(ValueError, "canonical"):
            m.parse_phase6_consumption_marker_bytes(
                noncanonical,
                expected_plan_sha256="1" * 64,
                expected_phase5_result_sha256="2" * 64,
                expected_human_approval_sha256="3" * 64,
            )

    def test_cleanup_authority_is_single_use(self):
        m = self.module()
        authority = m.InMemoryPhase6CleanupAuthority()
        token = authority.issue_for_test(
            phase6_plan_sha256="1" * 64,
            phase5_result_sha256="2" * 64,
            human_approval_sha256="3" * 64,
        )
        authority.consume(
            token,
            phase6_plan_sha256="1" * 64,
            phase5_result_sha256="2" * 64,
            human_approval_sha256="3" * 64,
        )
        with self.assertRaisesRegex(ValueError, "already consumed"):
            authority.consume(
                token,
                phase6_plan_sha256="1" * 64,
                phase5_result_sha256="2" * 64,
                human_approval_sha256="3" * 64,
            )


if __name__ == "__main__":
    unittest.main()
