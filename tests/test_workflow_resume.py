"""Issue #307 acceptance tests; all approval/evidence adapters are synthetic."""
import ast
from dataclasses import replace
import inspect
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from agent_controller.approval_contract import ApprovalBinding
from agent_controller.approval_service import TrustedApprovalIngress
from agent_controller.provider_contract import ObjectiveScope, TaskBinding, VerificationResult as V
from agent_controller.workstream import WorkstreamBinding
from agent_controller.workflow_resume import (
    ResumeAction as A, ResumeCheckpoint, ResumeScope, ResumeStep,
    StepCheckpoint, StepFacts, TrustedResumeSource, plan_workflow_resume,
)


NOW = "2026-10-11T00:00:00Z"


def task():
    return TaskBinding("task", "workflow-operation", "synthetic", "owner/repo",
                       "main", "a" * 40, ObjectiveScope(), "PLAN_CONTINUATION",
                       ("SCOPE", "DIAGNOSTIC"), ("DISPATCH",), "human-final", NOW)


def scope(**changes):
    return replace(ResumeScope("owner/repo", "OPERATION", "diagnostic",
                              host="TEST-HOST", sid="synthetic-sid",
                              executable_sha256="b" * 64,
                              allowed_effects=("DIAGNOSTIC",),
                              risk_envelope=("normal-profile-writes",)), **changes)


class SyntheticVerifiedSource:
    """A configured test-only trusted adapter, not a supported live ingress.

    Its snapshots model externally reverified exact records and accepted scopes.
    Raw serialized checkpoint values never bypass these independent snapshots.
    """
    def __init__(self, stages=None):
        self.stages = tuple(stages or [
            ResumeStep(str(i), scope(), 1 if i != 4 else 3,
                       effect_bearing=i == 4, approval_id="decision-" + str(i),
                       approval_effect="SCOPE") for i in range(1, 6)])
        self.workstream = WorkstreamBinding("workflow", "owner/repo", "issue:307", ("task",))
        self.checkpoint = ResumeCheckpoint("checkpoint", "task", "workflow-operation", "workflow", tuple(
            StepCheckpoint(s, V.PASS if i < 3 else V.NOT_RUN,
                           "evidence-" + s.step_id if i < 3 else None)
            for i, s in enumerate(self.stages)))
        self.verified_checkpoint = self.checkpoint
        self.verified_records = {r.step.step_id: r for r in self.checkpoint.steps}
        self.accepted_scopes = {s.approval_id: s.scope for s in self.stages}
        self.decisions = {s.approval_id: "APPROVED" for s in self.stages}
        self.approvals = {s.approval_id: ApprovalBinding(
            s.approval_id, "human-final", "task", "workflow-operation", None,
            "PLAN_CONTINUATION", s.approval_effect, "owner/repo", s.scope.target_kind,
            s.scope.target_id, s.scope.head_sha, "HUMAN", "owner", "synthetic-trusted",
            "2026-10-10T00:00:00Z") for s in self.stages if s.approval_id}
        self.facts = {s.step_id: StepFacts(s.scope, V.PASS) for s in self.stages}
        self.checkpoint_verdict = V.PASS
        self.step_verdict = V.PASS
        self.error = False
        self.reads = []

    def read_checkpoint(self, **binding):
        self.reads.append("checkpoint")
        if self.error:
            raise OSError("source unavailable")
        return self.checkpoint

    def verify_checkpoint(self, checkpoint, **binding):
        return self.checkpoint_verdict if checkpoint == self.verified_checkpoint else V.UNCERTAIN

    def verify_step(self, record, **binding):
        return self.step_verdict if record == self.verified_records[record.step.step_id] else V.UNCERTAIN

    def decision_state(self, approval_id, *, step, **binding):
        self.reads.append(approval_id)
        if step.scope != self.accepted_scopes.get(approval_id):
            return "REVOKED"
        return self.decisions[approval_id]

    def read_facts(self, step, **binding):
        return self.facts[step.step_id]

    def get_approval(self, approval_id):
        return self.approvals.get(approval_id)

    def update_record(self, index, **changes):
        records = list(self.checkpoint.steps)
        records[index] = replace(records[index], **changes)
        self.checkpoint = replace(self.checkpoint, steps=tuple(records))
        self.verified_checkpoint = self.checkpoint
        self.verified_records = {r.step.step_id: r for r in records}

    def plan(self, **changes):
        values = dict(task=task(), workstream=self.workstream, steps=self.stages,
                      source=TrustedResumeSource(self, TrustedApprovalIngress("synthetic-trusted", self)), now=NOW)
        values.update(changes)
        return plan_workflow_resume(**values)


def checkpoint_from_json(data):
    """Rehydration belongs to a trusted upstream adapter, not an approval parser."""
    records = []
    for record in data["steps"]:
        stage = record["step"]
        binding = stage["scope"]
        binding["allowed_effects"] = tuple(binding["allowed_effects"])
        binding["risk_envelope"] = tuple(binding["risk_envelope"])
        stage["scope"] = ResumeScope(**binding)
        record["step"] = ResumeStep(**stage)
        record["outcome"] = V(record["outcome"])
        records.append(StepCheckpoint(**record))
    data["steps"] = tuple(records)
    return ResumeCheckpoint(**data)


class WorkflowResumeTests(unittest.TestCase):
    def test_ac1_five_steps_resume_at_four_without_repeat_approvals(self):
        source = SyntheticVerifiedSource()
        source.decisions["decision-4"] = "WITHHELD"
        plan = source.plan()
        self.assertEqual(plan.first_actionable_step, "4")
        self.assertEqual([p.action for p in plan.steps[:3]], [A.SKIP_VERIFIED] * 3)
        self.assertEqual([p.retained_approval_id for p in plan.steps[:3]], ["decision-1", "decision-2", "decision-3"])
        self.assertEqual(plan.steps[3].action, A.HUMAN_ACTION_REQUIRED)
        self.assertEqual(plan.steps[3].reason_codes, ("DECISION_WITHHELD",))

    def test_completed_freshness_recheck_does_not_rerun_mutation(self):
        source = SyntheticVerifiedSource()
        stage = replace(source.stages[0], effect_bearing=True, level=3)
        source.stages = (stage,) + source.stages[1:]
        source.update_record(0, step=stage, spent_attempt_id="spent-1")
        for freshness in (V.NOT_RUN, V.FAIL, V.BLOCKED):
            with self.subTest(freshness=freshness):
                source.facts["1"] = StepFacts(stage.scope, freshness)
                p = source.plan().steps[0]
                self.assertEqual(p.action, A.RECHECK)
                self.assertEqual(p.retained_approval_id, "decision-1")
                self.assertEqual(p.spent_attempt_id, "spent-1")

    def test_completed_blocked_stage_stops_before_follow_on_stage(self):
        for effect_bearing in (False, True):
            with self.subTest(effect_bearing=effect_bearing):
                stages = (ResumeStep("1", scope(), 3 if effect_bearing else 1,
                                     effect_bearing, "decision-1", "SCOPE"),
                          ResumeStep("2", scope(), 2))
                source = SyntheticVerifiedSource(stages)
                source.update_record(0, spent_attempt_id="spent-1" if effect_bearing else None)
                source.update_record(1, outcome=V.NOT_RUN, evidence_id=None)
                source.facts["1"] = StepFacts(stages[0].scope, V.PASS,
                                              ("PHASE0_READINESS=BLOCKED",))
                plan = source.plan()
                self.assertEqual(plan.steps[1].action, A.RERUN_NONLIVE)
                self.assertEqual(plan.first_actionable_step, "1")
                self.assertEqual(plan.steps[0].action, A.STOP_UNCERTAIN)
                self.assertEqual(plan.steps[0].reason_codes,
                                 ("COMPLETED_STEP_BLOCKED", "PHASE0_READINESS=BLOCKED"))
                self.assertEqual(plan.steps[0].retained_approval_id, "decision-1")
                self.assertEqual(plan.steps[0].evidence_id, "evidence-1")
                self.assertEqual(plan.steps[0].spent_attempt_id,
                                 "spent-1" if effect_bearing else None)
                self.assertFalse(plan.to_dict()["execution_authorized"])
                self.assertFalse(plan.to_dict()["spent_authority_reusable"])

    def test_completed_blocked_workflow_is_not_reported_all_complete(self):
        stages = (ResumeStep("1", scope(), 1), ResumeStep("2", scope(), 1))
        source = SyntheticVerifiedSource(stages)
        source.facts["1"] = StepFacts(stages[0].scope, V.PASS,
                                      ("PHASE0_READINESS=BLOCKED",))
        plan = source.plan()
        self.assertEqual(plan.steps[1].action, A.SKIP_VERIFIED)
        self.assertEqual(plan.first_actionable_step, "1")
        self.assertEqual(plan.steps[0].action, A.STOP_UNCERTAIN)
        self.assertIn("PHASE0_READINESS=BLOCKED", plan.steps[0].reason_codes)

    def test_completed_level3_effect_without_approval_binding_stops(self):
        stages = (ResumeStep("1", scope(), 3, True), ResumeStep("2", scope(), 2))
        source = SyntheticVerifiedSource(stages)
        source.update_record(0, spent_attempt_id="spent-1")
        source.update_record(1, outcome=V.NOT_RUN, evidence_id=None)
        plan = source.plan()
        self.assertEqual(plan.first_actionable_step, "1")
        self.assertEqual(plan.steps[0].action, A.STOP_UNCERTAIN)
        self.assertEqual(plan.steps[0].reason_codes, ("EFFECT_APPROVAL_BINDING_MISSING",))
        self.assertIsNone(plan.steps[0].retained_approval_id)
        self.assertEqual(plan.steps[0].evidence_id, "evidence-1")
        self.assertEqual(plan.steps[0].spent_attempt_id, "spent-1")
        self.assertFalse(plan.to_dict()["execution_authorized"])
        self.assertFalse(plan.to_dict()["spent_authority_reusable"])

    def test_not_run_level3_effect_without_prior_attempt_requests_human_action(self):
        stages = (ResumeStep("1", scope(), 3, True), ResumeStep("2", scope(), 2))
        for blockers in ((), ("PHASE0_READINESS=BLOCKED",)):
            with self.subTest(blockers=blockers):
                source = SyntheticVerifiedSource(stages)
                source.update_record(0, outcome=V.NOT_RUN, evidence_id=None)
                source.update_record(1, outcome=V.NOT_RUN, evidence_id=None)
                source.facts["1"] = StepFacts(stages[0].scope, V.PASS, blockers)
                plan = source.plan()
                self.assertEqual(plan.first_actionable_step, "1")
                self.assertEqual(plan.steps[0].action, A.HUMAN_ACTION_REQUIRED)
                self.assertEqual(plan.steps[0].reason_codes,
                                 ("HUMAN_EXECUTION_REQUIRED",) + blockers)
                self.assertIsNone(plan.steps[0].retained_approval_id)
                self.assertIsNone(plan.steps[0].spent_attempt_id)
                self.assertFalse(plan.to_dict()["execution_authorized"])
                self.assertFalse(plan.to_dict()["spent_authority_reusable"])

    def test_prior_attempt_without_approval_binding_still_stops(self):
        stages = (ResumeStep("1", scope(), 3, True), ResumeStep("2", scope(), 2))
        for outcome, spent in ((V.PASS, None), (V.FAIL, None), (V.NOT_RUN, "spent-1")):
            with self.subTest(outcome=outcome, spent=spent):
                source = SyntheticVerifiedSource(stages)
                evidence = None if outcome is V.NOT_RUN else "evidence-1"
                source.update_record(0, outcome=outcome, evidence_id=evidence,
                                     spent_attempt_id=spent)
                plan = source.plan()
                self.assertEqual(plan.first_actionable_step, "1")
                self.assertEqual(plan.steps[0].action, A.STOP_UNCERTAIN)
                self.assertEqual(plan.steps[0].reason_codes, ("EFFECT_APPROVAL_BINDING_MISSING",))
                self.assertEqual(plan.steps[0].evidence_id, evidence)
                self.assertEqual(plan.steps[0].spent_attempt_id, spent)

    def test_ac2_all_changed_scope_dimensions_need_a_delta(self):
        source = SyntheticVerifiedSource()
        changes = dict(repo="other/repo", target_id="other-pr", head_sha="c" * 40,
                       host="OTHER-HOST", sid="other-sid", executable_sha256="c" * 64,
                       allowed_effects=("SCOPE",), risk_envelope=("different-risk",))
        for key, value in changes.items():
            with self.subTest(key=key):
                source.facts["1"] = StepFacts(replace(scope(), **{key: value}), V.PASS)
                p = source.plan().steps[0]
                self.assertEqual(p.action, A.HUMAN_ACTION_REQUIRED)
                self.assertIsNone(p.retained_approval_id)
                self.assertEqual(p.reason_codes, ("CURRENT_SCOPE_CHANGED",))

    def test_current_spec_change_cannot_silently_rebind_old_evidence(self):
        source = SyntheticVerifiedSource()
        source.stages = (replace(source.stages[0], scope=scope(host="NEW")),) + source.stages[1:]
        self.assertEqual(source.plan().steps[0].reason_codes, ("STEP_SCOPE_CHANGED",))

    def test_scope_only_nonexpiring_decisions_survive_time_and_read_refresh(self):
        source = SyntheticVerifiedSource()
        before = source.plan().to_dict()
        after = source.plan(now="2030-10-11T00:00:00Z").to_dict()
        self.assertEqual(before, after)

    def test_revoked_and_expired_scope_requires_only_affected_decision(self):
        source = SyntheticVerifiedSource()
        source.decisions["decision-2"] = "REVOKED"
        source.approvals["decision-3"] = replace(source.approvals["decision-3"], expires_at=NOW)
        p = source.plan()
        self.assertEqual(p.steps[0].action, A.SKIP_VERIFIED)
        self.assertEqual(p.steps[1].reason_codes, ("DECISION_REVOKED",))
        self.assertEqual(p.steps[2].reason_codes, ("APPROVAL_EXPIRED",))

    def test_ac3_missing_raw_corrupt_and_ambiguous_checkpoint_stop(self):
        source = SyntheticVerifiedSource()
        for value in (None, "APPROVE decision-1", {"approved": True}, b"broken JSON",
                      replace(source.checkpoint, steps=source.checkpoint.steps[:-1]),
                      replace(source.checkpoint, steps=(source.checkpoint.steps[0],) * 5)):
            with self.subTest(value=repr(value)):
                source.checkpoint = value
                p = source.plan()
                self.assertEqual({s.action for s in p.steps}, {A.STOP_UNCERTAIN})

    def test_unverifiable_checkpoint_and_record_fail_closed(self):
        source = SyntheticVerifiedSource()
        for verdict in (V.NOT_RUN, V.FAIL, V.UNCERTAIN, "PASS", True):
            with self.subTest(verdict=verdict):
                source.checkpoint_verdict = verdict
                self.assertEqual(source.plan().reason_codes, ("CHECKPOINT_UNVERIFIED",))
        source.checkpoint_verdict = V.PASS
        source.step_verdict = V.FAIL
        self.assertEqual({p.action for p in source.plan().steps}, {A.STOP_UNCERTAIN})

    def test_missing_completed_evidence_and_malformed_types_stop(self):
        for changes in (dict(evidence_id=None), dict(outcome="PASS"),
                        dict(partial_effects="false"), dict(spent_attempt_id=42)):
            with self.subTest(changes=changes):
                source = SyntheticVerifiedSource()
                source.update_record(0, **changes)
                self.assertEqual(source.plan().reason_codes, ("CHECKPOINT_STEPS_MALFORMED",))

    def test_untrusted_approval_text_or_json_never_retains_a_decision(self):
        for value in ("APPROVE", {"approved": True}, None):
            source = SyntheticVerifiedSource()
            source.approvals["decision-1"] = value
            p = source.plan().steps[0]
            self.assertEqual(p.action, A.STOP_UNCERTAIN)
            self.assertIsNone(p.retained_approval_id)
            self.assertEqual(p.reason_codes, ("APPROVAL_NOT_FOUND" if value is None else "APPROVAL_SOURCE_PAYLOAD_INVALID",))

    def test_wrong_ingress_issuer_or_exact_binding_cannot_be_reused(self):
        changes = dict(ingress_source="issue-comment", issuer_kind="AGENT", repo="other/repo",
                       operation_id="other-operation", controller_task_id="other-task", approval_id="other-decision",
                       requested_capability="EXECUTE", effect="DISPATCH", expected_head_sha="c" * 40)
        for key, value in changes.items():
            with self.subTest(key=key):
                source = SyntheticVerifiedSource()
                source.approvals["decision-1"] = replace(source.approvals["decision-1"], **{key: value})
                p = source.plan().steps[0]
                self.assertEqual(p.action, A.STOP_UNCERTAIN)
                self.assertIsNone(p.retained_approval_id)

    def test_adapter_decision_uncertainty_and_read_errors_stop(self):
        source = SyntheticVerifiedSource()
        source.decisions["decision-1"] = "approved=true"
        self.assertEqual(source.plan().steps[0].action, A.STOP_UNCERTAIN)
        source.error = True
        self.assertEqual(source.plan().reason_codes, ("CHECKPOINT_READ_UNCERTAIN",))

    def test_ac4_consumed_failed_four_preserves_earlier_outcomes(self):
        source = SyntheticVerifiedSource()
        source.update_record(3, outcome=V.FAIL, evidence_id="failed-4", spent_attempt_id="spent-attempt-4")
        p = source.plan()
        self.assertEqual(p.first_actionable_step, "4")
        self.assertEqual([s.action for s in p.steps[:3]], [A.SKIP_VERIFIED] * 3)
        self.assertEqual(p.steps[3].action, A.HUMAN_ACTION_REQUIRED)
        self.assertEqual(p.steps[3].reason_codes, ("FRESH_ATTEMPT_REQUIRED",))
        self.assertEqual(p.steps[3].spent_attempt_id, "spent-attempt-4")
        self.assertFalse(p.to_dict()["spent_authority_reusable"])

    def test_partial_or_uncertain_effects_stop_before_retry(self):
        for changes in (dict(outcome=V.FAIL, partial_effects=True), dict(outcome=V.UNCERTAIN)):
            source = SyntheticVerifiedSource()
            source.update_record(3, evidence_id="uncertain-4", spent_attempt_id="spent-4", **changes)
            self.assertEqual(source.plan().steps[3].action, A.STOP_UNCERTAIN)
            source.stages = source.stages[:3] + (replace(source.stages[3], scope=scope(host="NEW")),) + source.stages[4:]
            self.assertEqual(source.plan().steps[3].reason_codes, ("PARTIAL_OR_UNCERTAIN_EFFECTS",))

    def test_ac5_305_shaped_fixture_preserves_a_withholds_b_and_policy_block(self):
        stages = (ResumeStep("A", scope(target_id="exception"), 1, approval_id="A", approval_effect="SCOPE"),
                  ResumeStep("B", scope(target_id="target-profile"), 3, True, "B", "DIAGNOSTIC"))
        source = SyntheticVerifiedSource(stages)
        source.update_record(1, outcome=V.NOT_RUN, evidence_id=None)
        source.decisions["B"] = "WITHHELD"
        source.facts["B"] = StepFacts(stages[1].scope, V.PASS, ("PHASE0_READINESS=BLOCKED",))
        p = source.plan()
        self.assertEqual(p.steps[0].action, A.SKIP_VERIFIED)
        self.assertEqual(p.steps[0].retained_approval_id, "A")
        self.assertEqual(p.first_actionable_step, "B")
        self.assertEqual(p.steps[1].action, A.HUMAN_ACTION_REQUIRED)
        self.assertIn("PHASE0_READINESS=BLOCKED", p.steps[1].reason_codes)
        self.assertNotIn("PASS_TO_OPERATOR", json.dumps(p.to_dict()))
        source.decisions["B"] = "APPROVED"
        p = source.plan()
        self.assertEqual(p.steps[1].reason_codes, ("HUMAN_EXECUTION_REQUIRED", "PHASE0_READINESS=BLOCKED"))
        self.assertEqual(p.steps[1].retained_approval_id, "B")
        self.assertFalse(p.to_dict()["execution_authorized"])
        source.approvals["B"] = replace(source.approvals["B"], expires_at=NOW)
        self.assertEqual(source.plan().steps[1].action, A.HUMAN_ACTION_REQUIRED)
        source.facts["B"] = StepFacts(scope(sid="drift"), V.PASS)
        self.assertEqual(source.plan().steps[1].reason_codes, ("CURRENT_SCOPE_CHANGED",))

    def test_ac6_persisted_input_stable_in_another_process(self):
        source = SyntheticVerifiedSource()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "existing-checkpoint.json"
            path.write_text(json.dumps(source.checkpoint.to_dict()), encoding="utf-8")
            script = """import json,sys
from tests.test_workflow_resume import SyntheticVerifiedSource, checkpoint_from_json
s=SyntheticVerifiedSource()
s.checkpoint=checkpoint_from_json(json.load(open(sys.argv[1],encoding='utf-8')))
print(json.dumps(s.plan().to_dict(),sort_keys=True))
"""
            result = subprocess.run([sys.executable, "-c", script, str(path)], check=True,
                                    capture_output=True, text=True, cwd=Path(__file__).resolve().parents[1])
            self.assertEqual(json.loads(result.stdout), json.loads(json.dumps(source.plan().to_dict())))

    def test_workflows_in_same_repository_cannot_cross_reuse_evidence(self):
        source = SyntheticVerifiedSource()
        for changes in (dict(workstream_id="other-lane"), dict(operation_id="other-operation"),
                        dict(controller_task_id="other-task")):
            with self.subTest(changes=changes):
                source.checkpoint = replace(source.verified_checkpoint, **changes)
                self.assertEqual(source.plan().reason_codes, ("CHECKPOINT_BINDING_MISMATCH",))

    def test_ac7_all_classifications_and_continued_nonlive_planning(self):
        source = SyntheticVerifiedSource()
        stages = list(source.stages)
        stages[3] = replace(stages[3], level=2, effect_bearing=False)
        source.stages = tuple(stages)
        source.update_record(3, step=stages[3])
        self.assertEqual(source.plan().steps[3].action, A.RERUN_NONLIVE)
        source.update_record(3, outcome=V.PASS, evidence_id="new-verified-4")
        self.assertEqual(source.plan().first_actionable_step, "5")
        source.update_record(4, outcome=V.PASS, evidence_id="new-verified-5")
        self.assertIsNone(source.plan().first_actionable_step)

    def test_public_api_has_no_effect_or_persistence_dependencies(self):
        import agent_controller.workflow_resume as module
        imports = [n.module for n in ast.walk(ast.parse(inspect.getsource(module))) if isinstance(n, ast.ImportFrom)]
        self.assertFalse(any(x and any(word in x for word in ("ledger", "consumption", "execution_handoff", "github", "windows")) for x in imports))
        self.assertNotIn("store", inspect.signature(plan_workflow_resume).parameters)
        source = SyntheticVerifiedSource()
        before = source.checkpoint.to_dict()
        for _ in range(2):
            result = source.plan().to_dict()
            self.assertFalse(result["execution_authorized"])
        self.assertEqual(before, source.checkpoint.to_dict())

    def test_malformed_or_unknown_facts_stop(self):
        source = SyntheticVerifiedSource()
        for facts in (None, {"fresh": True}, StepFacts(scope(), "PASS"),
                      StepFacts(scope(), V.UNCERTAIN)):
            with self.subTest(facts=facts):
                source.facts["1"] = facts
                self.assertEqual(source.plan().steps[0].action, A.STOP_UNCERTAIN)

    def test_invalid_scope_fields_steps_and_workstream_fail_closed(self):
        source = SyntheticVerifiedSource()
        for stages in ([], source.stages * 7, ["approved"],
                       [replace(source.stages[0], level=True)],
                       [replace(source.stages[0], scope=scope(head_sha="bad"))],
                       [replace(source.stages[0], scope=scope(allowed_effects=["DIAGNOSTIC"]))]):
            with self.subTest(stages=repr(stages)):
                self.assertTrue(source.plan(steps=stages).reason_codes)
        self.assertEqual(source.plan(now="no-time").reason_codes, ("CHECKPOINT_READ_UNCERTAIN",))
        self.assertEqual(source.plan(task=replace(task(), repo=42)).reason_codes, ("RESUME_BINDING_MALFORMED",))
        self.assertEqual(source.plan(workstream=replace(source.workstream, task_ids=("other",))).reason_codes,
                         ("WORKSTREAM_BINDING_MISMATCH",))


if __name__ == "__main__":
    unittest.main()
