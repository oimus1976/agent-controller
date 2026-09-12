import unittest
from copy import copy, deepcopy
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
    def test_dataclasses_replace_is_rejected(self):
        source = DiagnosticBudget(remaining_attempts=4)

        with self.assertRaises(TypeError):
            replace(source)

    def test_shallow_copies_before_consumption_share_single_use_authority(self):
        source = DiagnosticBudget(remaining_attempts=4)
        first_copy = copy(source)
        second_copy = copy(source)

        successor = first_copy.consume(EvidenceLevel.L0)

        self.assertFalse(source.can_collect(EvidenceLevel.L0))
        self.assertFalse(second_copy.can_collect(EvidenceLevel.L0))
        with self.assertRaises(ValueError):
            second_copy.consume(EvidenceLevel.L0)
        self.assertTrue(successor.accounts_for(EvidenceLevel.L0))
        self.assertTrue(successor.can_collect(EvidenceLevel.L1))

    def test_deepcopy_cannot_fork_authority(self):
        source = DiagnosticBudget(remaining_attempts=4)
        first_copy = deepcopy(source)
        second_copy = deepcopy(source)

        successor = first_copy.consume(EvidenceLevel.L0)

        self.assertFalse(second_copy.can_collect(EvidenceLevel.L0))
        with self.assertRaises(ValueError):
            second_copy.consume(EvidenceLevel.L0)
        self.assertTrue(successor.can_collect(EvidenceLevel.L1))

    def test_copied_successor_cannot_fork_next_level(self):
        after_l0 = DiagnosticBudget(remaining_attempts=4).consume(EvidenceLevel.L0)
        sibling = copy(after_l0)

        after_l1 = after_l0.consume(EvidenceLevel.L1)

        self.assertFalse(sibling.can_collect(EvidenceLevel.L1))
        self.assertFalse(sibling.accounts_for(EvidenceLevel.L0))
        with self.assertRaises(ValueError):
            sibling.consume(EvidenceLevel.L1)
        self.assertTrue(after_l1.accounts_for(EvidenceLevel.L1))
        self.assertTrue(after_l1.can_collect(EvidenceLevel.L2))

    def test_stale_copy_cannot_restore_pass(self):
        source = DiagnosticBudget(remaining_attempts=2)
        live_after_l0 = source.consume(EvidenceLevel.L0)
        stale_copy = copy(source)
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
