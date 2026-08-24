import inspect
import unittest

import agent_controller.approval_consumption as approval_consumption
import agent_controller.approval_contract as approval_contract
import agent_controller.approval_ledger as approval_ledger
import agent_controller.approval_service as approval_service
import agent_controller.approval_validator as approval_validator
from agent_controller.approval_contract import ApprovalBinding, ApprovalResult
from agent_controller.approval_validator import validate_approval_binding
from agent_controller.provider_contract import ObjectiveScope, TaskBinding


class TestApprovalBoundary(unittest.TestCase):
    def test_pn2_public_callables_expose_no_high_risk_effect_executor(self):
        modules = (
            approval_consumption,
            approval_contract,
            approval_ledger,
            approval_service,
            approval_validator,
        )
        forbidden_method_names = {
            "merge", "merge_pr", "ready", "mark_ready", "deploy", "release",
            "approve_plan", "send_message", "write_ref", "update_ref", "execute_owner_machine",
        }
        for module in modules:
            public_callables = {
                name.lower()
                for name, value in vars(module).items()
                if not name.startswith("_")
                and (inspect.isfunction(value) or inspect.isclass(value))
                and getattr(value, "__module__", None) == module.__name__
            }
            self.assertTrue(public_callables.isdisjoint(forbidden_method_names), (module.__name__, public_callables))

    def test_expiry_before_or_equal_issue_time_is_uncertain(self):
        task = TaskBinding(
            controller_task_id="task-17",
            operation_id="op-17",
            provider="jules",
            repo="oimus1976/agent-controller",
            expected_start_ref="refs/heads/main",
            expected_start_sha="base-sha",
            objective_scope=ObjectiveScope(allowed_paths=("agent_controller/**",)),
            requested_capability="ACK_OPERATION",
            allowed_effects=("ACKNOWLEDGE",),
            forbidden_effects=(),
            approval_policy_id="policy-l3",
            created_at="2026-08-24T06:20:00Z",
        )
        for expires_at in ("2026-08-24T06:20:59Z", "2026-08-24T06:21:00Z"):
            approval = ApprovalBinding(
                approval_id="approval-1",
                approval_policy_id="policy-l3",
                controller_task_id="task-17",
                operation_id="op-17",
                provider="jules",
                requested_capability="ACK_OPERATION",
                effect="ACKNOWLEDGE",
                repo="oimus1976/agent-controller",
                target_kind="OPERATION",
                target_id="op-17",
                expected_head_sha=None,
                issuer_kind="HUMAN",
                issuer_subject="human-owner",
                ingress_source="trusted-control-plane",
                issued_at="2026-08-24T06:21:00Z",
                expires_at=expires_at,
            )
            result = validate_approval_binding(
                task=task,
                approval=approval,
                expected_effect="ACKNOWLEDGE",
                expected_target_kind="OPERATION",
                expected_target_id="op-17",
                expected_head_sha=None,
                trusted_ingress_sources=("trusted-control-plane",),
                now="2026-08-24T06:30:00Z",
            )
            self.assertEqual(result.result, ApprovalResult.UNCERTAIN)
            self.assertEqual(result.reason, "APPROVAL_TIME_ORDER_INVALID")

    def test_required_structured_approval_field_cannot_be_empty(self):
        task = TaskBinding(
            controller_task_id="task-17",
            operation_id="op-17",
            provider="jules",
            repo="oimus1976/agent-controller",
            expected_start_ref="refs/heads/main",
            expected_start_sha="base-sha",
            objective_scope=ObjectiveScope(allowed_paths=("agent_controller/**",)),
            requested_capability="ACK_OPERATION",
            allowed_effects=("ACKNOWLEDGE",),
            forbidden_effects=(),
            approval_policy_id="policy-l3",
            created_at="2026-08-24T06:20:00Z",
        )
        approval = ApprovalBinding(
            approval_id="approval-1",
            approval_policy_id="policy-l3",
            controller_task_id="task-17",
            operation_id="op-17",
            provider="jules",
            requested_capability="",
            effect="ACKNOWLEDGE",
            repo="oimus1976/agent-controller",
            target_kind="OPERATION",
            target_id="op-17",
            expected_head_sha=None,
            issuer_kind="HUMAN",
            issuer_subject="human-owner",
            ingress_source="trusted-control-plane",
            issued_at="2026-08-24T06:21:00Z",
        )
        result = validate_approval_binding(
            task=task,
            approval=approval,
            expected_effect="ACKNOWLEDGE",
            expected_target_kind="OPERATION",
            expected_target_id="op-17",
            expected_head_sha=None,
            trusted_ingress_sources=("trusted-control-plane",),
            now="2026-08-24T06:30:00Z",
        )
        self.assertEqual(result.result, ApprovalResult.BLOCKED)
        self.assertEqual(result.reason, "APPROVAL_FIELD_MISSING:requested_capability")


if __name__ == "__main__":
    unittest.main()
