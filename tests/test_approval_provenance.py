import unittest

from agent_controller.approval_provenance import (
    ProvenanceAssurance,
    validate_github_workflow_dispatch_candidate,
)


class ApprovalProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.record = {
            "event_name": "workflow_dispatch",
            "actor": "human-owner",
            "actor_id": "123",
            "run_id": "456",
            "workflow_ref": "oimus1976/agent-controller/.github/workflows/approval-ingress-poc.yml@refs/heads/main",
            "controller_task_id": "task-1",
            "operation_id": "op-1",
            "operation_version": "v1",
            "approval_id": "approval-1",
            "effect": "MERGE",
            "repo": "oimus1976/agent-controller",
            "target_kind": "PULL_REQUEST",
            "target_id": "27",
            "expected_head_sha": "a" * 40,
        }
        self.expected = dict(
            expected_controller_task_id="task-1",
            expected_operation_id="op-1",
            expected_operation_version="v1",
            expected_approval_id="approval-1",
            expected_effect="MERGE",
            expected_repo="oimus1976/agent-controller",
            expected_target_kind="PULL_REQUEST",
            expected_target_id="27",
            expected_head_sha="a" * 40,
        )

    def validate(self, record=None, **expected_overrides):
        expected = dict(self.expected)
        expected.update(expected_overrides)
        return validate_github_workflow_dispatch_candidate(record=self.record if record is None else record, **expected)

    def test_exact_candidate_is_source_authenticated_only(self):
        result = self.validate()
        self.assertTrue(result.valid)
        self.assertEqual(ProvenanceAssurance.SOURCE_AUTHENTICATED_ONLY, result.assurance)
        self.assertEqual("456", result.provenance.source_event_id)

    def test_wrong_event_type_fails_closed(self):
        record = dict(self.record, event_name="push")
        result = self.validate(record)
        self.assertFalse(result.valid)
        self.assertEqual(ProvenanceAssurance.PROVENANCE_UNAVAILABLE, result.assurance)

    def test_missing_actor_fails_closed(self):
        record = dict(self.record)
        del record["actor"]
        result = self.validate(record)
        self.assertFalse(result.valid)

    def test_operation_version_mismatch_fails_closed(self):
        result = self.validate(expected_operation_version="v2")
        self.assertFalse(result.valid)
        self.assertEqual("BINDING_MISMATCH:operation_version", result.reason)

    def test_effect_mismatch_fails_closed(self):
        result = self.validate(expected_effect="DEPLOY")
        self.assertFalse(result.valid)
        self.assertEqual("BINDING_MISMATCH:effect", result.reason)

    def test_head_mismatch_fails_closed(self):
        result = self.validate(expected_head_sha="b" * 40)
        self.assertFalse(result.valid)
        self.assertEqual("BINDING_MISMATCH:expected_head_sha", result.reason)

    def test_distinct_runs_are_distinct_events(self):
        first = self.validate()
        second = self.validate(dict(self.record, run_id="457"))
        self.assertNotEqual(first.provenance.source_event_id, second.provenance.source_event_id)

    def test_duplicate_observation_is_same_event_identity(self):
        first = self.validate()
        second = self.validate(dict(self.record))
        self.assertEqual(first.provenance, second.provenance)

    def test_record_cannot_self_upgrade_assurance(self):
        record = dict(self.record, assurance="VERIFIED_EVENT_PROVENANCE")
        result = self.validate(record)
        self.assertTrue(result.valid)
        self.assertEqual(ProvenanceAssurance.SOURCE_AUTHENTICATED_ONLY, result.assurance)

    def test_approval_looking_text_is_not_an_input_surface(self):
        result = self.validate({"text": "APPROVE approval-1"})
        self.assertFalse(result.valid)
        self.assertEqual(ProvenanceAssurance.PROVENANCE_UNAVAILABLE, result.assurance)


if __name__ == "__main__":
    unittest.main()
