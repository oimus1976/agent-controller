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
    canonicalize_context_capsule,
    context_capsule_digest,
)


DIGEST = "a" * 64


def pointer(**changes):
    values = dict(
        source_kind=EvidenceSourceKind.GITHUB_COMMIT,
        source_ref="commit:abc123",
        authority=EvidenceAuthority.OBJECTIVE_VERIFIED,
        freshness=EvidenceFreshness.IMMUTABLE,
        content_digest=DIGEST,
    )
    values.update(changes)
    return EvidencePointer(**values)


def capsule(**changes):
    values = dict(
        controller_task_id="task-1",
        operation_id="op-1",
        operation_version="v1",
        facts=(CapsuleFact("architecture", "Reviewed architecture", (pointer(),)),),
    )
    values.update(changes)
    return ContextCapsule(**values)


class FixtureVerifiedSource:
    def __init__(self, verified=()):
        self.verified = set(verified)

    @staticmethod
    def identity(item):
        return (item.source_kind, item.source_ref, item.content_digest)

    def is_verified(self, item):
        return self.identity(item) in self.verified


class ExplodingVerifiedSource:
    def is_verified(self, item):
        raise RuntimeError("source unavailable")


def planner_for(*items):
    return ContextRetrievalPlanner(
        verified_source=FixtureVerifiedSource(
            FixtureVerifiedSource.identity(item) for item in items
        )
    )


class ContextCapsuleTests(unittest.TestCase):
    def test_contract_is_frozen_and_deep_tuple_based(self):
        item = capsule()
        with self.assertRaises(dataclasses.FrozenInstanceError):
            item.operation_id = "changed"
        self.assertIsInstance(item.facts, tuple)
        self.assertIsInstance(item.facts[0].evidence, tuple)

    def test_logically_equivalent_order_canonicalizes_identically(self):
        a = CapsuleFact("a", "A", (pointer(source_ref="commit:a"),))
        b = CapsuleFact("b", "B", (pointer(source_ref="commit:b"),))
        first = capsule(facts=(a, b), must_recheck=("z", "y"), unknowns=("u2", "u1"))
        second = capsule(facts=(b, a), must_recheck=("y", "z"), unknowns=("u1", "u2"))
        self.assertEqual(canonicalize_context_capsule(first), canonicalize_context_capsule(second))
        self.assertEqual(context_capsule_digest(first), context_capsule_digest(second))

    def test_binding_or_evidence_change_changes_digest(self):
        base = capsule()
        self.assertNotEqual(context_capsule_digest(base), context_capsule_digest(capsule(operation_version="v2")))
        changed = capsule(
            facts=(CapsuleFact("architecture", "Reviewed architecture", (pointer(content_digest="b" * 64),)),)
        )
        self.assertNotEqual(context_capsule_digest(base), context_capsule_digest(changed))

    def test_mutable_pr_fact_always_fetches_without_verification_source_read(self):
        mutable = pointer(
            source_kind=EvidenceSourceKind.PR_HEAD,
            freshness=EvidenceFreshness.MUTABLE_RECHECK_REQUIRED,
        )
        item = capsule(facts=(CapsuleFact("pr_state", "PR was open", (mutable,)),))
        decision = planner_for(mutable).plan(
            capsule=item,
            controller_task_id="task-1",
            operation_id="op-1",
            operation_version="v1",
            requests=(RetrievalRequest("pr_state"),),
        )[0]
        self.assertIs(RetrievalAction.FETCH_MUTABLE, decision.action)

    def test_verified_immutable_evidence_may_be_reused_only_via_external_source(self):
        exact = pointer()
        decision = planner_for(exact).plan(
            capsule=capsule(),
            controller_task_id="task-1",
            operation_id="op-1",
            operation_version="v1",
            requests=(RetrievalRequest("architecture"),),
        )[0]
        self.assertIs(RetrievalAction.REUSE_VERIFIED_IMMUTABLE, decision.action)

    def test_capsule_self_assertion_cannot_create_verified_reuse(self):
        exact = pointer(authority=EvidenceAuthority.OBJECTIVE_VERIFIED)
        decision = planner_for().plan(
            capsule=capsule(facts=(CapsuleFact("architecture", "I claim verified", (exact,)),)),
            controller_task_id="task-1",
            operation_id="op-1",
            operation_version="v1",
            requests=(RetrievalRequest("architecture"),),
        )[0]
        self.assertIs(RetrievalAction.FETCH_MISSING, decision.action)

    def test_agent_reported_never_becomes_reusable_even_if_external_source_contains_identity(self):
        claimed = pointer(authority=EvidenceAuthority.AGENT_REPORTED)
        item = capsule(facts=(CapsuleFact("claim", "Agent says done", (claimed,)),))
        decision = planner_for(claimed).plan(
            capsule=item,
            controller_task_id="task-1",
            operation_id="op-1",
            operation_version="v1",
            requests=(RetrievalRequest("claim"),),
        )[0]
        self.assertIs(RetrievalAction.FETCH_MISSING, decision.action)

    def test_verification_source_failure_fails_closed_to_fetch(self):
        decision = ContextRetrievalPlanner(verified_source=ExplodingVerifiedSource()).plan(
            capsule=capsule(),
            controller_task_id="task-1",
            operation_id="op-1",
            operation_version="v1",
            requests=(RetrievalRequest("architecture"),),
        )[0]
        self.assertIs(RetrievalAction.FETCH_MISSING, decision.action)

    def test_unknown_and_missing_fetch_instead_of_inventing(self):
        item = capsule(unknowns=("quota",))
        decisions = planner_for().plan(
            capsule=item,
            controller_task_id="task-1",
            operation_id="op-1",
            operation_version="v1",
            requests=(RetrievalRequest("quota"), RetrievalRequest("new_fact")),
        )
        self.assertEqual(
            (RetrievalAction.FETCH_MISSING, RetrievalAction.FETCH_MISSING),
            tuple(item.action for item in decisions),
        )

    def test_security_gate_always_fetches_even_for_externally_verified_immutable(self):
        exact = pointer()
        decision = planner_for(exact).plan(
            capsule=capsule(),
            controller_task_id="task-1",
            operation_id="op-1",
            operation_version="v1",
            requests=(RetrievalRequest("architecture", required_for_security_gate=True),),
        )[0]
        self.assertIs(RetrievalAction.FETCH_FOR_SECURITY_GATE, decision.action)

    def test_explicit_must_recheck_overrides_immutable_reuse(self):
        exact = pointer()
        decision = planner_for(exact).plan(
            capsule=capsule(must_recheck=("architecture",)),
            controller_task_id="task-1",
            operation_id="op-1",
            operation_version="v1",
            requests=(RetrievalRequest("architecture"),),
        )[0]
        self.assertIs(RetrievalAction.FETCH_MUTABLE, decision.action)

    def test_binding_mismatch_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "CONTEXT_CAPSULE_BINDING_MISMATCH"):
            planner_for().plan(
                capsule=capsule(),
                controller_task_id="other",
                operation_id="op-1",
                operation_version="v1",
                requests=(RetrievalRequest("architecture"),),
            )

    def test_irrelevant_request_is_omitted_without_verified_evidence(self):
        decision = planner_for().plan(
            capsule=capsule(),
            controller_task_id="task-1",
            operation_id="op-1",
            operation_version="v1",
            requests=(RetrievalRequest("architecture", relevant=False),),
        )[0]
        self.assertIs(RetrievalAction.OMIT_IRRELEVANT, decision.action)

    def test_planner_has_no_per_call_verified_source_override(self):
        params = set(inspect.signature(ContextRetrievalPlanner.plan).parameters)
        self.assertEqual(
            {"self", "capsule", "controller_task_id", "operation_id", "operation_version", "requests"},
            params,
        )

    def test_public_module_has_no_effect_or_model_routing_surface(self):
        import agent_controller.context_capsule as module

        names = set(dir(module))
        for forbidden in (
            "execute",
            "merge",
            "deploy",
            "approve",
            "select_model",
            "downgrade_model",
            "truncate_prompt",
            "throttle",
        ):
            self.assertNotIn(forbidden, names)


if __name__ == "__main__":
    unittest.main()
