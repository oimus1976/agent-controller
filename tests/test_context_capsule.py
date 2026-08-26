import dataclasses
import inspect
import unittest

from agent_controller.context_capsule import (
    CapsuleFact,
    ContextCapsule,
    ContextRetrievalPlanner,
    EvidenceAuthority,
    EvidenceFreshness,
    EvidencePointer,
    EvidenceSourceKind,
    RetrievalAction,
    RetrievalRequest,
    bound_capsule_fact_digest,
    canonicalize_context_capsule,
    capsule_fact_digest,
    context_capsule_digest,
)

DIGEST = "a" * 64

def pointer(**changes):
    values = dict(source_kind=EvidenceSourceKind.GITHUB_COMMIT, source_ref="commit:abc123", authority=EvidenceAuthority.OBJECTIVE_VERIFIED, freshness=EvidenceFreshness.IMMUTABLE, content_digest=DIGEST)
    values.update(changes)
    return EvidencePointer(**values)

def capsule(**changes):
    values = dict(controller_task_id="task-1", operation_id="op-1", operation_version="v1", facts=(CapsuleFact("architecture", "Reviewed architecture", (pointer(),)),))
    values.update(changes)
    return ContextCapsule(**values)

class FixtureVerifiedFactSource:
    def __init__(self, verified=()):
        self.verified = set(verified)
    def is_verified_fact(self, bound_fact_digest):
        return bound_fact_digest in self.verified

class ExplodingVerifiedFactSource:
    def is_verified_fact(self, bound_fact_digest):
        raise RuntimeError("source unavailable")

def planner_for(*pairs):
    return ContextRetrievalPlanner(verified_source=FixtureVerifiedFactSource(bound_capsule_fact_digest(capsule=item, fact=fact) for item, fact in pairs))

class ContextCapsuleTests(unittest.TestCase):
    def test_contract_is_frozen_and_deep_tuple_based(self):
        item = capsule()
        with self.assertRaises(dataclasses.FrozenInstanceError): item.operation_id = "changed"
        self.assertIsInstance(item.facts, tuple)
        self.assertIsInstance(item.facts[0].evidence, tuple)

    def test_logically_equivalent_order_canonicalizes_identically(self):
        a = CapsuleFact("a", "A", (pointer(source_ref="commit:a"),))
        b = CapsuleFact("b", "B", (pointer(source_ref="commit:b"),))
        first = capsule(facts=(a,b), must_recheck=("z","y"), unknowns=("u2","u1"))
        second = capsule(facts=(b,a), must_recheck=("y","z"), unknowns=("u1","u2"))
        self.assertEqual(canonicalize_context_capsule(first), canonicalize_context_capsule(second))
        self.assertEqual(context_capsule_digest(first), context_capsule_digest(second))

    def test_binding_evidence_or_summary_change_changes_digest(self):
        base = capsule()
        changed_binding = capsule(operation_version="v2")
        changed_evidence = capsule(facts=(CapsuleFact("architecture","Reviewed architecture",(pointer(content_digest="b"*64),)),))
        changed_summary = capsule(facts=(CapsuleFact("architecture","Attacker changed summary",(pointer(),)),))
        self.assertNotEqual(context_capsule_digest(base), context_capsule_digest(changed_binding))
        self.assertNotEqual(context_capsule_digest(base), context_capsule_digest(changed_evidence))
        self.assertNotEqual(context_capsule_digest(base), context_capsule_digest(changed_summary))
        self.assertNotEqual(capsule_fact_digest(base.facts[0]), capsule_fact_digest(changed_summary.facts[0]))

    def test_verified_immutable_fact_may_be_reused_only_via_external_source(self):
        item=capsule(); fact=item.facts[0]
        decision=planner_for((item,fact)).plan(capsule=item,controller_task_id="task-1",operation_id="op-1",operation_version="v1",requests=(RetrievalRequest("architecture"),))[0]
        self.assertIs(RetrievalAction.REUSE_VERIFIED_IMMUTABLE, decision.action)

    def test_other_operation_or_version_cannot_reuse(self):
        original=capsule()
        for other in (capsule(operation_id="op-2"), capsule(operation_version="v2")):
            decision=planner_for((original,original.facts[0])).plan(capsule=other,controller_task_id=other.controller_task_id,operation_id=other.operation_id,operation_version=other.operation_version,requests=(RetrievalRequest("architecture"),))[0]
            self.assertIs(RetrievalAction.FETCH_MISSING, decision.action)

    def test_real_verified_evidence_with_changed_summary_cannot_reuse(self):
        original=capsule(); attacker_fact=CapsuleFact("architecture","False summary",original.facts[0].evidence); attacker=capsule(facts=(attacker_fact,))
        decision=planner_for((original,original.facts[0])).plan(capsule=attacker,controller_task_id="task-1",operation_id="op-1",operation_version="v1",requests=(RetrievalRequest("architecture"),))[0]
        self.assertIs(RetrievalAction.FETCH_MISSING, decision.action)

    def test_mutable_agent_reported_unknown_and_security_gate_behaviors(self):
        mutable=CapsuleFact("pr_state","PR was open",(pointer(source_kind=EvidenceSourceKind.PR_HEAD,freshness=EvidenceFreshness.MUTABLE_RECHECK_REQUIRED),))
        item=capsule(facts=(mutable,))
        self.assertIs(RetrievalAction.FETCH_MUTABLE, planner_for((item,mutable)).plan(capsule=item,controller_task_id="task-1",operation_id="op-1",operation_version="v1",requests=(RetrievalRequest("pr_state"),))[0].action)
        agent=CapsuleFact("claim","Agent says done",(pointer(authority=EvidenceAuthority.AGENT_REPORTED),)); item2=capsule(facts=(agent,))
        self.assertIs(RetrievalAction.FETCH_MISSING, planner_for((item2,agent)).plan(capsule=item2,controller_task_id="task-1",operation_id="op-1",operation_version="v1",requests=(RetrievalRequest("claim"),))[0].action)
        self.assertIs(RetrievalAction.FETCH_FOR_SECURITY_GATE, planner_for((capsule(),capsule().facts[0])).plan(capsule=capsule(),controller_task_id="task-1",operation_id="op-1",operation_version="v1",requests=(RetrievalRequest("architecture",required_for_security_gate=True),))[0].action)

    def test_verification_failure_and_binding_mismatch_fail_closed(self):
        self.assertIs(RetrievalAction.FETCH_MISSING, ContextRetrievalPlanner(verified_source=ExplodingVerifiedFactSource()).plan(capsule=capsule(),controller_task_id="task-1",operation_id="op-1",operation_version="v1",requests=(RetrievalRequest("architecture"),))[0].action)
        with self.assertRaisesRegex(ValueError,"CONTEXT_CAPSULE_BINDING_MISMATCH"):
            planner_for().plan(capsule=capsule(),controller_task_id="other",operation_id="op-1",operation_version="v1",requests=(RetrievalRequest("architecture"),))

    def test_irrelevant_and_public_surface(self):
        self.assertIs(RetrievalAction.OMIT_IRRELEVANT, planner_for().plan(capsule=capsule(),controller_task_id="task-1",operation_id="op-1",operation_version="v1",requests=(RetrievalRequest("architecture",relevant=False),))[0].action)
        self.assertEqual({"self","capsule","controller_task_id","operation_id","operation_version","requests"}, set(inspect.signature(ContextRetrievalPlanner.plan).parameters))
        import agent_controller.context_capsule as module
        for forbidden in ("execute","merge","deploy","approve","select_model","downgrade_model","truncate_prompt","throttle"):
            self.assertNotIn(forbidden,set(dir(module)))

if __name__ == "__main__": unittest.main()
