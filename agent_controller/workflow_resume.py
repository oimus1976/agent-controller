"""Read-only advisory continuation; never an approval or execution capability."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
import re
from typing import Protocol, Sequence

from agent_controller.approval_contract import ApprovalResult
from agent_controller.approval_service import (
    TrustedApprovalIngress, read_and_validate_human_approval,
)
from agent_controller.approval_validator import _parse_time
from agent_controller.provider_contract import TaskBinding, VerificationResult
from agent_controller.workstream import WorkstreamBinding, validate_task_workstream


class ResumeAction(str, Enum):
    SKIP_VERIFIED = "SKIP_VERIFIED"
    RECHECK = "RECHECK"
    RERUN_NONLIVE = "RERUN_NONLIVE"
    HUMAN_ACTION_REQUIRED = "HUMAN_ACTION_REQUIRED"
    STOP_UNCERTAIN = "STOP_UNCERTAIN"


@dataclass(frozen=True)
class ResumeScope:
    repo: str
    target_kind: str
    target_id: str
    head_sha: str | None = None  # None means the decision is not head-sensitive.
    host: str | None = None
    sid: str | None = None
    executable_sha256: str | None = None
    allowed_effects: tuple[str, ...] = ()
    risk_envelope: tuple[str, ...] = ()


@dataclass(frozen=True)
class ResumeStep:
    step_id: str
    scope: ResumeScope
    level: int
    effect_bearing: bool = False
    approval_id: str | None = None
    approval_effect: str | None = None


@dataclass(frozen=True)
class StepCheckpoint:
    step: ResumeStep
    outcome: VerificationResult
    evidence_id: str | None = None
    spent_attempt_id: str | None = None
    partial_effects: bool = False


@dataclass(frozen=True)
class ResumeCheckpoint:
    checkpoint_id: str
    controller_task_id: str
    operation_id: str
    workstream_id: str
    steps: tuple[StepCheckpoint, ...]

    def to_dict(self) -> dict:
        data = asdict(self)
        for record in data["steps"]:
            record["outcome"] = record["outcome"].value
        return data


@dataclass(frozen=True)
class StepFacts:
    scope: ResumeScope
    freshness: VerificationResult
    blocked_conditions: tuple[str, ...] = ()


class ResumeEvidenceSource(Protocol):
    """Controller-configured read boundary, never a provider/content parser.

    The adapter loads persisted records and externally verifies exact content,
    identity, provenance, scope and revocation. PASS must bind the *entire*
    supplied checkpoint/record, not merely the existence of an evidence ID.
    A live adapter must use the existing inspector/client authority paths.
    This core neither authenticates an ingress nor turns JSON into authority.
    """

    def read_checkpoint(self, *, task: TaskBinding, workstream: WorkstreamBinding
                        ) -> ResumeCheckpoint | None: ...

    def verify_checkpoint(self, checkpoint: ResumeCheckpoint, *, task: TaskBinding,
                          workstream: WorkstreamBinding) -> VerificationResult: ...

    def verify_step(self, record: StepCheckpoint, *, task: TaskBinding,
                    workstream: WorkstreamBinding) -> VerificationResult: ...

    def decision_state(self, approval_id: str, *, step: ResumeStep,
                       task: TaskBinding, workstream: WorkstreamBinding) -> str: ...

    def read_facts(self, step: ResumeStep, *, task: TaskBinding,
                   workstream: WorkstreamBinding) -> StepFacts: ...


@dataclass(frozen=True)
class TrustedResumeSource:
    """Composition-owned configuration, never populated from untrusted text."""
    evidence: ResumeEvidenceSource
    approvals: TrustedApprovalIngress


@dataclass(frozen=True)
class StepResumePlan:
    step_id: str
    action: ResumeAction
    reason_codes: tuple[str, ...]
    evidence_id: str | None = None
    retained_approval_id: str | None = None
    spent_attempt_id: str | None = None


@dataclass(frozen=True)
class ResumePlan:
    steps: tuple[StepResumePlan, ...]
    first_actionable_step: str | None
    checkpoint_id: str | None
    reason_codes: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        data = asdict(self)
        for step in data["steps"]:
            step["action"] = step["action"].value
        # No receipt, nonce, claim or executable handoff is returned.
        data["advisory_only"] = True
        data["execution_authorized"] = False
        data["spent_authority_reusable"] = False
        return data


def _text(value: object) -> bool:
    return type(value) is str and bool(value.strip())


def _strings(value: object) -> bool:
    return (type(value) is tuple and all(_text(v) for v in value)
            and len(set(value)) == len(value))


def _scope_valid(scope: object) -> bool:
    return (type(scope) is ResumeScope
            and all(_text(v) for v in (scope.repo, scope.target_kind, scope.target_id))
            and scope.repo.count("/") == 1 and all(scope.repo.split("/"))
            and (scope.head_sha is None or type(scope.head_sha) is str
                 and re.fullmatch(r"[0-9a-f]{40}", scope.head_sha) is not None)
            and all(v is None or _text(v) for v in (scope.host, scope.sid))
            and (scope.executable_sha256 is None
                 or type(scope.executable_sha256) is str
                 and re.fullmatch(r"[0-9a-f]{64}", scope.executable_sha256) is not None)
            and _strings(scope.allowed_effects) and _strings(scope.risk_envelope))


def _step_valid(step: object) -> bool:
    return (type(step) is ResumeStep and _text(step.step_id) and _scope_valid(step.scope)
            and type(step.level) is int and 0 <= step.level <= 3
            and type(step.effect_bearing) is bool
            and ((step.approval_id is None and step.approval_effect is None)
                 or _text(step.approval_id) and _text(step.approval_effect)))


def _stop(steps: tuple[ResumeStep, ...], reason: str,
          checkpoint_id: str | None = None) -> ResumePlan:
    return ResumePlan(tuple(StepResumePlan(s.step_id, ResumeAction.STOP_UNCERTAIN,
                                          (reason,)) for s in steps),
                      steps[0].step_id if steps else None, checkpoint_id, (reason,))


def plan_workflow_resume(*, task: TaskBinding, workstream: WorkstreamBinding,
                         steps: Sequence[ResumeStep], source: TrustedResumeSource,
                         now: str) -> ResumePlan:
    """Classify up to 32 ordered stages without performing or authorizing effects.

    A missing/malformed/unverifiable checkpoint stops the whole plan. A normal
    incomplete stage is an explicit NOT_RUN record in a verified checkpoint.
    Each earlier completed mutation remains an outcome, never a retry request.
    """
    if (not isinstance(steps, (tuple, list)) or not 1 <= len(steps) <= 32
            or any(not _step_valid(s) for s in steps)):
        return _stop((), "STEPS_MALFORMED")
    steps = tuple(steps)
    if len({s.step_id for s in steps}) != len(steps):
        return _stop(steps, "STEPS_AMBIGUOUS")
    if (type(task) is not TaskBinding or type(workstream) is not WorkstreamBinding
            or not all(_text(v) for v in (task.controller_task_id, task.operation_id, task.repo))
            or type(source) is not TrustedResumeSource
            or type(source.approvals) is not TrustedApprovalIngress):
        return _stop(steps, "RESUME_BINDING_MALFORMED")
    if not validate_task_workstream(binding=workstream, task=task).valid:
        return _stop(steps, "WORKSTREAM_BINDING_MISMATCH")
    try:
        _parse_time(now)
        checkpoint = source.evidence.read_checkpoint(task=task, workstream=workstream)
        if type(checkpoint) is not ResumeCheckpoint or not _text(checkpoint.checkpoint_id):
            return _stop(steps, "CHECKPOINT_MISSING_OR_MALFORMED")
        if (checkpoint.controller_task_id, checkpoint.operation_id, checkpoint.workstream_id) != (
                task.controller_task_id, task.operation_id, workstream.workstream_id):
            return _stop(steps, "CHECKPOINT_BINDING_MISMATCH", checkpoint.checkpoint_id)
        records = checkpoint.steps
        if (type(records) is not tuple or len(records) != len(steps)
                or any(type(r) is not StepCheckpoint or not _step_valid(r.step)
                       or type(r.outcome) is not VerificationResult
                       or type(r.partial_effects) is not bool
                       or r.evidence_id is not None and not _text(r.evidence_id)
                       or r.spent_attempt_id is not None and not _text(r.spent_attempt_id)
                       or r.outcome is not VerificationResult.NOT_RUN and r.evidence_id is None
                       for r in records)
                or tuple(r.step.step_id for r in records) != tuple(s.step_id for s in steps)):
            return _stop(steps, "CHECKPOINT_STEPS_MALFORMED", checkpoint.checkpoint_id)
        if source.evidence.verify_checkpoint(checkpoint, task=task, workstream=workstream) is not VerificationResult.PASS:
            return _stop(steps, "CHECKPOINT_UNVERIFIED", checkpoint.checkpoint_id)
    except Exception:
        return _stop(steps, "CHECKPOINT_READ_UNCERTAIN")

    plans = []
    for step, record in zip(steps, records):
        retained = None
        reasons: tuple[str, ...] = ()
        try:
            if source.evidence.verify_step(record, task=task, workstream=workstream) is not VerificationResult.PASS:
                action, reasons = ResumeAction.STOP_UNCERTAIN, ("STEP_EVIDENCE_UNVERIFIED",)
            elif record.partial_effects or record.outcome is VerificationResult.UNCERTAIN:
                action, reasons = ResumeAction.STOP_UNCERTAIN, ("PARTIAL_OR_UNCERTAIN_EFFECTS",)
            elif record.step != step:
                action, reasons = ResumeAction.HUMAN_ACTION_REQUIRED, ("STEP_SCOPE_CHANGED",)
            elif step.scope.repo != task.repo or not set(step.scope.allowed_effects) <= set(task.allowed_effects) or set(step.scope.allowed_effects) & set(task.forbidden_effects):
                action, reasons = ResumeAction.STOP_UNCERTAIN, ("SCOPE_OUTSIDE_TASK",)
            else:
                facts = source.evidence.read_facts(step, task=task, workstream=workstream)
                if (type(facts) is not StepFacts or not _scope_valid(facts.scope)
                        or type(facts.freshness) is not VerificationResult
                        or not _strings(facts.blocked_conditions)):
                    raise ValueError("malformed facts")
                if facts.scope != step.scope:
                    action, reasons = ResumeAction.HUMAN_ACTION_REQUIRED, ("CURRENT_SCOPE_CHANGED",)
                elif facts.freshness is VerificationResult.UNCERTAIN:
                    action, reasons = ResumeAction.STOP_UNCERTAIN, ("FRESH_FACTS_UNCERTAIN",)
                else:
                    decision_reason = None
                    decision_action = ResumeAction.HUMAN_ACTION_REQUIRED
                    if step.approval_id is not None:
                        state = source.evidence.decision_state(step.approval_id, step=step, task=task, workstream=workstream)
                        if state not in ("APPROVED", "WITHHELD", "REVOKED"):
                            raise ValueError("unverifiable decision")
                        if state != "APPROVED":
                            decision_reason = "DECISION_" + state
                        else:
                            _, validation = read_and_validate_human_approval(
                                ingress=source.approvals, approval_id=step.approval_id,
                                task=task, expected_effect=step.approval_effect,
                                expected_target_kind=step.scope.target_kind,
                                expected_target_id=step.scope.target_id,
                                expected_head_sha=step.scope.head_sha, now=now)
                            if validation.valid:
                                retained = step.approval_id
                            else:
                                decision_reason = validation.reason or "DECISION_INVALID"
                                if not (validation.result is ApprovalResult.BLOCKED
                                        and validation.reason == "APPROVAL_EXPIRED"):
                                    decision_action = ResumeAction.STOP_UNCERTAIN
                    if decision_reason is not None:
                        action, reasons = decision_action, (decision_reason,)
                    elif facts.freshness is not VerificationResult.PASS:
                        action, reasons = ResumeAction.RECHECK, ("FRESH_FACTS_RECHECK_REQUIRED",)
                    elif record.outcome is VerificationResult.PASS:
                        if facts.blocked_conditions:
                            action, reasons = ResumeAction.STOP_UNCERTAIN, ("COMPLETED_STEP_BLOCKED",)
                        else:
                            action, reasons = ResumeAction.SKIP_VERIFIED, ("VERIFIED_OUTCOME_RETAINED",)
                    elif step.effect_bearing or step.level == 3:
                        action = ResumeAction.HUMAN_ACTION_REQUIRED
                        reasons = ("FRESH_ATTEMPT_REQUIRED" if record.spent_attempt_id
                                   else "HUMAN_EXECUTION_REQUIRED",)
                    else:
                        action, reasons = ResumeAction.RERUN_NONLIVE, ("INCOMPLETE_NONLIVE_STEP",)
                    reasons += facts.blocked_conditions
        except Exception:
            action, reasons = ResumeAction.STOP_UNCERTAIN, ("STEP_READ_UNCERTAIN",)
        plans.append(StepResumePlan(step.step_id, action, reasons, record.evidence_id,
                                    retained, record.spent_attempt_id))
    first = next((p.step_id for p in plans if p.action is not ResumeAction.SKIP_VERIFIED), None)
    return ResumePlan(tuple(plans), first, checkpoint.checkpoint_id)
