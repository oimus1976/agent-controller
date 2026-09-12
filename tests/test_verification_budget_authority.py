import unittest
from dataclasses import replace

from agent_controller.provider_contract import VerificationResult
from agent_controller.verification_decision import (
    DiagnosticBudget,
    EvidenceLevel,
    InvariantEvidence,
    VerificationAction,
    VerificationClass,
    decide_verification,
)


class DiagnosticBudgetCopyAuthorityTests(unittest.TestCase):
    def test_replace_after_consumption_cannot_revive_consumed_source(self):
        source = DiagnosticBudget(remaining_attempts=4)
        successor = source.consume(EvidenceLevel.L0)
        revived_candidate = replace(source)

        self.assertFalse(revived_candidate.can_collect(EvidenceLevel.L0))
        self.assertFalse(revived_candidate.accounts_for(EvidenceLevel.L0))
        with self.assertRaises(ValueError):
            revived_candidate.consume(EvidenceLevel.L0)
        self.assertTrue(successor.can_collect(EvidenceLevel.L1))

    def test_replacements_before_consumption_share_single_use_authority(self):
        source = DiagnosticBudget(remaining_attempts=4)
        first_copy = replace(source)
        second_copy = replace(source)

        successor = first_copy.consume(EvidenceLevel.L0)

        self.assertFalse(source.can_collect(EvidenceLevel.L0))
        self.assertFalse(second_copy.can_collect(EvidenceLevel.L0))
        with self.assertRaises(ValueError):
            second_copy.consume(EvidenceLevel.L0)
        self.assertTrue(successor.accounts_for(EvidenceLevel.L0))
        self.assertTrue(successor.can_collect(EvidenceLevel.L1))

    def test_replaced_successor_cannot_fork_next_level(self):
        after_l0 = DiagnosticBudget(remaining_attempts=4).consume(EvidenceLevel.L0)
        sibling = replace(after_l0)

        after_l1 = after_l0.consume(EvidenceLevel.L1)

        self.assertFalse(sibling.can_collect(EvidenceLevel.L1))
        self.assertFalse(sibling.accounts_for(EvidenceLevel.L0))
        with self.assertRaises(ValueError):
            sibling.consume(EvidenceLevel.L1)
        self.assertTrue(after_l1.accounts_for(EvidenceLevel.L1))
        self.assertTrue(after_l1.can_collect(EvidenceLevel.L2))

    def test_stale_replacement_cannot_restore_pass(self):
        source = DiagnosticBudget(remaining_attempts=2)
        live_after_l0 = source.consume(EvidenceLevel.L0)
        stale_copy = replace(source)
        invariant = InvariantEvidence("artifact_exists", VerificationResult.PASS)

        stale_decision = decide_verification(
            verification_class=VerificationClass.NORMAL,
            required_positive_invariants=(invariant,),
            current_level=EvidenceLevel.L0,
            diagnostic_budget=stale_copy,
        )
        live_decision = decide_verification(
            verification_class=VerificationClass.NORMAL,
            required_positive_invariants=(invariant,),
            current_level=EvidenceLevel.L0,
            diagnostic_budget=live_after_l0,
        )

        self.assertEqual(stale_decision.action, VerificationAction.UNCERTAIN_STOP)
        self.assertEqual(live_decision.action, VerificationAction.PASS_STOP)


if __name__ == "__main__":
    unittest.main()
