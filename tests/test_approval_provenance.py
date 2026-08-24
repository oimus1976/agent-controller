import unittest

from agent_controller.approval_provenance import (
    ProvenanceAssurance,
    TrustedGitHubWorkflowIngress,
    read_and_validate_github_workflow_dispatch_candidate,
)


class FakeWorkflowRunReader:
    def __init__(self, records=None, fail=False):
        self.records = records or {}
        self.fail = fail
        self.calls = []

    def get_workflow_run(self, run_id):
        self.calls.append(run_id)
        if self.fail:
            raise RuntimeError("read failed")
        return self.records[run_id]


class ApprovalProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.workflow_ref = "oimus1976/agent-controller/.github/workflows/approval-ingress-poc.yml@refs/heads/main"
        self.record = {
            "event_name": "workflow_dispatch",
            "actor": "human-owner",
            "actor_id": "123",
            "run_id": "456",
            "created_at": "2026-08-24T13:45:00Z",
            "workflow_ref": self.workflow_ref,
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
        self.reader = FakeWorkflowRunReader({"456": self.record})
        self.ingress = TrustedGitHubWorkflowIngress(
            source_name="github-workflow-dispatch",
            expected_workflow_ref=self.workflow_ref,
            reader=self.reader,
        )
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

    def validate(self, *, ingress=None, run_id="456", **expected_overrides):
        expected = dict(self.expected)
        expected.update(expected_overrides)
        return read_and_validate_github_workflow_dispatch_candidate(
            ingress=self.ingress if ingress is None else ingress,
            run_id=run_id,
            **expected,
        )

    def ingress_for_record(self, record, workflow_ref=None):
        return TrustedGitHubWorkflowIngress(
            source_name="github-workflow-dispatch",
            expected_workflow_ref=self.workflow_ref if workflow_ref is None else workflow_ref,
            reader=FakeWorkflowRunReader({record["run_id"]: record}),
        )

    def test_exact_candidate_is_source_authenticated_only(self):
        result = self.validate()
        self.assertTrue(result.valid)
        self.assertEqual(ProvenanceAssurance.SOURCE_AUTHENTICATED_ONLY, result.assurance)
        self.assertEqual("456", result.provenance.source_event_id)
        self.assertEqual("2026-08-24T13:45:00Z", result.provenance.source_created_at)

    def test_wrong_event_type_fails_closed(self):
        record = dict(self.record, event_name="push")
        result = self.validate(ingress=self.ingress_for_record(record))
        self.assertFalse(result.valid)
        self.assertEqual(ProvenanceAssurance.PROVENANCE_UNAVAILABLE, result.assurance)

    def test_missing_actor_or_created_at_fails_closed(self):
        for field in ("actor", "created_at"):
            record = dict(self.record)
            del record[field]
            result = self.validate(ingress=self.ingress_for_record(record))
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

    def test_workflow_ref_must_match_controller_configuration(self):
        record = dict(self.record, workflow_ref="oimus1976/agent-controller/.github/workflows/other.yml@refs/heads/main")
        result = self.validate(ingress=self.ingress_for_record(record))
        self.assertFalse(result.valid)
        self.assertEqual("WORKFLOW_REF_MISMATCH", result.reason)

    def test_reader_run_id_must_match_authoritative_record(self):
        record = dict(self.record, run_id="999")
        reader = FakeWorkflowRunReader({"456": record})
        ingress = TrustedGitHubWorkflowIngress("github-workflow-dispatch", self.workflow_ref, reader)
        result = self.validate(ingress=ingress)
        self.assertFalse(result.valid)
        self.assertEqual("RUN_ID_MISMATCH", result.reason)

    def test_distinct_runs_are_distinct_events(self):
        second_record = dict(self.record, run_id="457")
        second_ingress = self.ingress_for_record(second_record)
        first = self.validate()
        second = self.validate(ingress=second_ingress, run_id="457")
        self.assertNotEqual(first.provenance.source_event_id, second.provenance.source_event_id)

    def test_duplicate_observation_is_same_event_identity(self):
        first = self.validate()
        second = self.validate()
        self.assertEqual(first.provenance, second.provenance)
        self.assertEqual(["456", "456"], self.reader.calls)

    def test_record_cannot_self_upgrade_assurance(self):
        record = dict(self.record, assurance="VERIFIED_EVENT_PROVENANCE")
        result = self.validate(ingress=self.ingress_for_record(record))
        self.assertTrue(result.valid)
        self.assertEqual(ProvenanceAssurance.SOURCE_AUTHENTICATED_ONLY, result.assurance)

    def test_arbitrary_mapping_is_not_supported_public_input(self):
        import inspect
        params = inspect.signature(read_and_validate_github_workflow_dispatch_candidate).parameters
        self.assertNotIn("record", params)
        self.assertIn("ingress", params)
        self.assertIn("run_id", params)

    def test_approval_looking_text_is_not_an_input_surface(self):
        reader = FakeWorkflowRunReader({"456": {"text": "APPROVE approval-1"}})
        ingress = TrustedGitHubWorkflowIngress("github-workflow-dispatch", self.workflow_ref, reader)
        result = self.validate(ingress=ingress)
        self.assertFalse(result.valid)
        self.assertEqual(ProvenanceAssurance.PROVENANCE_UNAVAILABLE, result.assurance)

    def test_source_read_failure_is_provenance_unavailable(self):
        ingress = TrustedGitHubWorkflowIngress(
            "github-workflow-dispatch",
            self.workflow_ref,
            FakeWorkflowRunReader(fail=True),
        )
        result = self.validate(ingress=ingress)
        self.assertFalse(result.valid)
        self.assertEqual("SOURCE_READ_UNCERTAIN", result.reason)

    def test_invalid_reader_fails_closed(self):
        ingress = TrustedGitHubWorkflowIngress("github-workflow-dispatch", self.workflow_ref, object())
        result = self.validate(ingress=ingress)
        self.assertFalse(result.valid)
        self.assertEqual("READER_INVALID", result.reason)


if __name__ == "__main__":
    unittest.main()
