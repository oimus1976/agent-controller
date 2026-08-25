import dataclasses
import inspect
import unittest

from agent_controller.context_capsule import (
    CapsuleFact,
    ContextCapsule,
    EvidenceAuthority,
    EvidenceFreshness,
    EvidencePointer,
    EvidenceSourceKind,
    RetrievalAction,
    RetrievalRequest,
    canonicalize_context_capsule,
    context_capsule_digest,
    plan_retrieval,
)


DIGEST = "a" * 64


def pointer(**changes):
    values = dict(
        source_kind=EvidenceSourceKind.GITHUB_COMMIT,
        source_ref="commit:abc123",
        authority=EvidenceAuthority.OBJECTIVE_VERIFIED,
        freshness=EvidenceFreshness.IMMUTABLE,
        content_digest=DIGEST,
        previously_verified=True,
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

    def test_mutable_pr_fact_always_fetches(self):
        item = capsule(
            facts=(
                CapsuleFact(
                    "pr_state",
                    "PR was open",
                    (
                        pointer(
                            source_kind=EvidenceSourceKind.PR_HEAD,
                            freshness=EvidenceFreshness.MUTABLE_RECHECK_REQUIRED,
                        ),
                    ),
                ),
            )
        )
        decision = plan_retrieval(
            capsule=item,
            controller_task_id="task-1",
            operation_id="op-1",
            operation_version="v1",
            requests=(RetrievalRequest("pr_state"),),
        )[0]
        self.assertIs(RetrievalAction.FETCH_MUTABLE, decision.action)

    def test_verified_immutable_evidence_may_be_reused(self):
        decision = plan_retrieval(
            capsule=capsule(),
            controller_task_id="task-1",
            operation_id="op-1",
            operation_version="v1",
            requests=(RetrievalRequest("architecture"),),
        )[0]
        self.assertIs(RetrievalAction.REUSE_VERIFIED_IMMUTABLE, decision.action)

    def test_agent_reported_never_becomes_reusable_authority(self):
        item = capsule(
            facts=(
                CapsuleFact(
                    "claim",
                    "Agent says done",
                    (
                        pointer(
                            authority=EvidenceAuthority.AGENT_REPORTED,
                            previously_verified=True,
                        ),
                    ),
                ),
            )
        )
        decision = plan_retrieval(
            capsule=item,
            controller_task_id="task-1",
            operation_id="op-1",
            operation_version="v1",
            requests=(RetrievalRequest("claim"),),
        )[0]
        self.assertIs(RetrievalAction.FETCH_MISSING, decision.action)

    def test_unknown_and_missing_fetch_instead_of_inventing(self):
        item = capsule(unknowns=("quota",))
        decisions = plan_retrieval(
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

    def test_security_gate_always_fetches_even_for_verified_immutable(self):
        decision = plan_retrieval(
            capsule=capsule(),
            controller_task_id="task-1",
            operation_id="op-1",
            operation_version="v1",
            requests=(RetrievalRequest("architecture", required_for_security_gate=True),),
        )[0]
        self.assertIs(RetrievalAction.FETCH_FOR_SECURITY_GATE, decision.action)

    def test_explicit_must_recheck_overrides_immutable_reuse(self):
        decision = plan_retrieval(
            capsule=capsule(must_recheck=("architecture",)),
            controller_task_id="task-1",
            operation_id="op-1",
            operation_version="v1",
            requests=(RetrievalRequest("architecture"),),
        )[0]
        self.assertIs(RetrievalAction.FETCH_MUTABLE, decision.action)

    def test_binding_mismatch_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "CONTEXT_CAPSULE_BINDING_MISMATCH"):
            plan_retrieval(
                capsule=capsule(),
                controller_task_id="other",
                operation_id="op-1",
                operation_version="v1",
                requests=(RetrievalRequest("architecture"),),
            )

    def test_irrelevant_request_is_omitted_without_fetch(self):
        decision = plan_retrieval(
            capsule=capsule(),
            controller_task_id="task-1",
            operation_id="op-1",
            operation_version="v1",
            requests=(RetrievalRequest("architecture", relevant=False),),
        )[0]
        self.assertIs(RetrievalAction.OMIT_IRRELEVANT, decision.action)

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
        self.assertEqual(
            {"capsule", "controller_task_id", "operation_id", "operation_version", "requests"},
            set(inspect.signature(plan_retrieval).parameters),
        )


if __name__ == "__main__":
    unittest.main()
