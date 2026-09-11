import unittest

from agent_controller.provider_contract import VerificationResult
from agent_controller.verification_decision import (
    DiagnosticBudget,
    EvidenceLevel,
    InvariantEvidence,
    MatchedAnomalyPredicate,
    VerificationAction,
    VerificationClass,
    decide_verification,
)


class VerificationDecisionTests(unittest.TestCase):
    def inv(self, invariant_id, result):
        return InvariantEvidence(invariant_id=invariant_id, result=result)

    def test_direct_invariants_pass_truncated_wrapper_without_predicate_stops(self):
        decision = decide_verification(
            verification_class=VerificationClass.NORMAL,
            required_positive_invariants=(self.inv("artifact_exists", VerificationResult.PASS),),
            required_negative_invariants=(self.inv("no_unexpected_write", VerificationResult.PASS),),
            current_level=EvidenceLevel.L1,
            deeper_evidence_can_resolve=True,
            diagnostic_budget=DiagnosticBudget(remaining_attempts=3),
        )

        self.assertEqual(decision.action, VerificationAction.PASS_STOP)
        self.assertEqual(decision.result, VerificationResult.PASS)
        self.assertIsNone(decision.next_level)

    def test_final_allowed_evidence_attempt_can_still_produce_pass(self):
        exhausted_after_final_attempt = DiagnosticBudget(remaining_attempts=1).consume(EvidenceLevel.L1)

        decision = decide_verification(
            verification_class=VerificationClass.NORMAL,
            required_positive_invariants=(self.inv("artifact_exists", VerificationResult.PASS),),
            current_level=EvidenceLevel.L1,
            diagnostic_budget=exhausted_after_final_attempt,
        )

        self.assertEqual(exhausted_after_final_attempt.remaining_attempts, 0)
        self.assertEqual(decision.action, VerificationAction.PASS_STOP)
        self.assertEqual(decision.result, VerificationResult.PASS)

    def test_pre_predicate_same_level_probing_is_bounded(self):
        budget = DiagnosticBudget(remaining_attempts=3).consume(EvidenceLevel.L0)

        with self.assertRaises(ValueError):
            budget.consume(EvidenceLevel.L0)

        next_budget = budget.consume(EvidenceLevel.L1)
        self.assertEqual(next_budget.remaining_attempts, 1)
        self.assertEqual(next_budget.attempted_levels, (EvidenceLevel.L0, EvidenceLevel.L1))

    def test_trust_invariant_contradiction_is_fail_not_blocked(self):
        decision = decide_verification(
            verification_class=VerificationClass.SECURITY_SENSITIVE,
            required_positive_invariants=(self.inv("functional_success", VerificationResult.PASS),),
            trust_boundary_invariants=(self.inv("exact_head", VerificationResult.FAIL),),
            prerequisite_blocked=True,
            diagnostic_budget=DiagnosticBudget(remaining_attempts=0),
        )

        self.assertEqual(decision.action, VerificationAction.FAIL_STOP)
        self.assertEqual(decision.result, VerificationResult.FAIL)

    def test_explicit_trust_contradiction_is_not_ignored_when_classified_normal(self):
        decision = decide_verification(
            verification_class=VerificationClass.NORMAL,
            required_positive_invariants=(self.inv("functional_success", VerificationResult.PASS),),
            trust_boundary_invariants=(self.inv("exact_head", VerificationResult.FAIL),),
            diagnostic_budget=DiagnosticBudget(remaining_attempts=3),
        )

        self.assertEqual(decision.action, VerificationAction.FAIL_STOP)
        self.assertEqual(decision.result, VerificationResult.FAIL)

    def test_missing_trust_evidence_escalates_one_level_when_named_predicate_can_resolve_it(self):
        budget_after_l0 = DiagnosticBudget(remaining_attempts=2).consume(EvidenceLevel.L0)
        anomaly = MatchedAnomalyPredicate(
            predicate_id="EXACT_HEAD_EVIDENCE_MISSING",
            observed="missing",
            expected="verified exact head",
            affected_invariant="exact_head",
        )

        decision = decide_verification(
            verification_class=VerificationClass.SECURITY_SENSITIVE,
            required_positive_invariants=(self.inv("functional_success", VerificationResult.PASS),),
            trust_boundary_invariants=(self.inv("exact_head", VerificationResult.NOT_RUN),),
            anomaly=anomaly,
            current_level=EvidenceLevel.L0,
            deeper_evidence_can_resolve=True,
            diagnostic_budget=budget_after_l0,
        )

        self.assertEqual(decision.action, VerificationAction.ESCALATE_ONE_LEVEL)
        self.assertIsNone(decision.result)
        self.assertEqual(decision.next_level, EvidenceLevel.L1)

    def test_exit_zero_missing_artifact_predicate_can_request_one_level_escalation(self):
        decision = decide_verification(
            verification_class=VerificationClass.NORMAL,
            required_positive_invariants=(self.inv("artifact_exists", VerificationResult.NOT_RUN),),
            anomaly=MatchedAnomalyPredicate(
                predicate_id="EXIT_ZERO_ARTIFACT_MISSING",
                observed="exit=0; artifact=missing",
                expected="required artifact present",
                affected_invariant="artifact_exists",
            ),
            current_level=EvidenceLevel.L1,
            deeper_evidence_can_resolve=True,
            diagnostic_budget=DiagnosticBudget(remaining_attempts=1),
        )

        self.assertEqual(decision.action, VerificationAction.ESCALATE_ONE_LEVEL)
        self.assertEqual(decision.next_level, EvidenceLevel.L2)

    def test_path_mismatch_predicate_can_request_one_level_escalation(self):
        decision = decide_verification(
            verification_class=VerificationClass.SECURITY_SENSITIVE,
            required_positive_invariants=(self.inv("functional_success", VerificationResult.PASS),),
            trust_boundary_invariants=(self.inv("trusted_runtime_path", VerificationResult.UNCERTAIN),),
            anomaly=MatchedAnomalyPredicate(
                predicate_id="REGISTRATION_PATH_MISMATCH",
                observed="registered path A",
                expected="trusted path B",
                affected_invariant="trusted_runtime_path",
            ),
            current_level=EvidenceLevel.L0,
            deeper_evidence_can_resolve=True,
            diagnostic_budget=DiagnosticBudget(remaining_attempts=1),
        )

        self.assertEqual(decision.action, VerificationAction.ESCALATE_ONE_LEVEL)
        self.assertEqual(decision.next_level, EvidenceLevel.L1)

    def test_predicate_for_undeclared_invariant_cannot_authorize_escalation(self):
        decision = decide_verification(
            verification_class=VerificationClass.NORMAL,
            required_positive_invariants=(self.inv("artifact_exists", VerificationResult.NOT_RUN),),
            anomaly=MatchedAnomalyPredicate(
                predicate_id="UNRELATED_PATH_MISMATCH",
                observed="path A",
                expected="path B",
                affected_invariant="trusted_runtime_path",
            ),
            current_level=EvidenceLevel.L0,
            deeper_evidence_can_resolve=True,
            diagnostic_budget=DiagnosticBudget(remaining_attempts=3),
        )

        self.assertEqual(decision.action, VerificationAction.UNCERTAIN_STOP)
        self.assertEqual(decision.result, VerificationResult.UNCERTAIN)

    def test_free_form_suspicion_without_named_predicate_cannot_trigger_escalation(self):
        decision = decide_verification(
            verification_class=VerificationClass.NORMAL,
            required_positive_invariants=(self.inv("artifact_exists", VerificationResult.PASS),),
            current_level=EvidenceLevel.L0,
            deeper_evidence_can_resolve=True,
            diagnostic_budget=DiagnosticBudget(remaining_attempts=4),
        )

        self.assertEqual(decision.action, VerificationAction.PASS_STOP)

    def test_matched_predicate_prevents_pass_when_deeper_evidence_cannot_resolve(self):
        decision = decide_verification(
            verification_class=VerificationClass.NORMAL,
            required_positive_invariants=(self.inv("artifact_exists", VerificationResult.PASS),),
            anomaly=MatchedAnomalyPredicate(
                predicate_id="ARTIFACT_METADATA_MISMATCH",
                observed="unexpected metadata",
                expected="expected metadata",
                affected_invariant="artifact_exists",
            ),
            current_level=EvidenceLevel.L1,
            deeper_evidence_can_resolve=False,
            diagnostic_budget=DiagnosticBudget(remaining_attempts=2),
        )

        self.assertEqual(decision.action, VerificationAction.UNCERTAIN_STOP)
        self.assertEqual(decision.result, VerificationResult.UNCERTAIN)

    def test_missing_required_evidence_without_named_predicate_is_uncertain(self):
        decision = decide_verification(
            verification_class=VerificationClass.NORMAL,
            required_positive_invariants=(self.inv("artifact_exists", VerificationResult.NOT_RUN),),
            current_level=EvidenceLevel.L0,
            deeper_evidence_can_resolve=True,
            diagnostic_budget=DiagnosticBudget(remaining_attempts=4),
        )

        self.assertEqual(decision.action, VerificationAction.UNCERTAIN_STOP)
        self.assertEqual(decision.result, VerificationResult.UNCERTAIN)

    def test_exhausted_budget_without_terminal_outcome_is_uncertain(self):
        exhausted = DiagnosticBudget(remaining_attempts=1).consume(EvidenceLevel.L0)
        decision = decide_verification(
            verification_class=VerificationClass.SECURITY_SENSITIVE,
            required_positive_invariants=(self.inv("functional_success", VerificationResult.PASS),),
            trust_boundary_invariants=(self.inv("exact_head", VerificationResult.NOT_RUN),),
            anomaly=MatchedAnomalyPredicate(
                predicate_id="EXACT_HEAD_EVIDENCE_MISSING",
                observed="missing",
                expected="verified exact head",
                affected_invariant="exact_head",
            ),
            current_level=EvidenceLevel.L0,
            deeper_evidence_can_resolve=True,
            diagnostic_budget=exhausted,
        )

        self.assertEqual(decision.action, VerificationAction.UNCERTAIN_STOP)
        self.assertEqual(decision.result, VerificationResult.UNCERTAIN)

    def test_blocked_terminal_precedes_budget_exhaustion(self):
        decision = decide_verification(
            verification_class=VerificationClass.NORMAL,
            required_positive_invariants=(self.inv("artifact_exists", VerificationResult.NOT_RUN),),
            prerequisite_blocked=True,
            diagnostic_budget=DiagnosticBudget(remaining_attempts=0),
        )

        self.assertEqual(decision.action, VerificationAction.BLOCKED_STOP)
        self.assertEqual(decision.result, VerificationResult.BLOCKED)

    def test_fail_terminal_precedes_budget_exhaustion(self):
        decision = decide_verification(
            verification_class=VerificationClass.NORMAL,
            required_negative_invariants=(self.inv("no_unexpected_write", VerificationResult.FAIL),),
            diagnostic_budget=DiagnosticBudget(remaining_attempts=0),
        )

        self.assertEqual(decision.action, VerificationAction.FAIL_STOP)
        self.assertEqual(decision.result, VerificationResult.FAIL)

    def test_security_sensitive_pass_requires_explicit_trust_evidence(self):
        decision = decide_verification(
            verification_class=VerificationClass.SECURITY_SENSITIVE,
            required_positive_invariants=(self.inv("functional_success", VerificationResult.PASS),),
            diagnostic_budget=DiagnosticBudget(remaining_attempts=0),
        )

        self.assertEqual(decision.action, VerificationAction.UNCERTAIN_STOP)
        self.assertEqual(decision.result, VerificationResult.UNCERTAIN)

    def test_security_sensitive_pass_requires_all_regular_and_trust_invariants(self):
        decision = decide_verification(
            verification_class=VerificationClass.SECURITY_SENSITIVE,
            required_positive_invariants=(self.inv("functional_success", VerificationResult.PASS),),
            required_negative_invariants=(self.inv("no_unexpected_write", VerificationResult.PASS),),
            trust_boundary_invariants=(
                self.inv("exact_head", VerificationResult.PASS),
                self.inv("process_owner", VerificationResult.PASS),
            ),
            diagnostic_budget=DiagnosticBudget(remaining_attempts=0),
        )

        self.assertEqual(decision.action, VerificationAction.PASS_STOP)
        self.assertEqual(decision.result, VerificationResult.PASS)

    def test_l3_cannot_escalate_past_final_level(self):
        decision = decide_verification(
            verification_class=VerificationClass.NORMAL,
            required_positive_invariants=(self.inv("artifact_exists", VerificationResult.NOT_RUN),),
            anomaly=MatchedAnomalyPredicate(
                predicate_id="ARTIFACT_STILL_MISSING",
                observed="missing",
                expected="present",
                affected_invariant="artifact_exists",
            ),
            current_level=EvidenceLevel.L3,
            deeper_evidence_can_resolve=True,
            diagnostic_budget=DiagnosticBudget(remaining_attempts=1),
        )

        self.assertEqual(decision.action, VerificationAction.UNCERTAIN_STOP)
        self.assertEqual(decision.result, VerificationResult.UNCERTAIN)

    def test_already_attempted_next_level_cannot_be_repeated(self):
        budget = DiagnosticBudget(
            remaining_attempts=2,
            attempted_levels=(EvidenceLevel.L1,),
        )
        decision = decide_verification(
            verification_class=VerificationClass.NORMAL,
            required_positive_invariants=(self.inv("artifact_exists", VerificationResult.NOT_RUN),),
            anomaly=MatchedAnomalyPredicate(
                predicate_id="EXIT_ZERO_ARTIFACT_MISSING",
                observed="missing",
                expected="present",
                affected_invariant="artifact_exists",
            ),
            current_level=EvidenceLevel.L0,
            deeper_evidence_can_resolve=True,
            diagnostic_budget=budget,
        )

        self.assertEqual(decision.action, VerificationAction.UNCERTAIN_STOP)


class DiagnosticBudgetTests(unittest.TestCase):
    def test_rejects_negative_budget(self):
        with self.assertRaises(ValueError):
            DiagnosticBudget(remaining_attempts=-1)

    def test_rejects_duplicate_attempted_levels(self):
        with self.assertRaises(ValueError):
            DiagnosticBudget(
                remaining_attempts=1,
                attempted_levels=(EvidenceLevel.L0, EvidenceLevel.L0),
            )


if __name__ == "__main__":
    unittest.main()
