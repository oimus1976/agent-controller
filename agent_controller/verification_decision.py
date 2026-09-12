from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, IntEnum
from typing import Any, Optional, Sequence

from agent_controller.provider_contract import VerificationResult


class VerificationClass(str, Enum):
    NORMAL = "NORMAL"
    SECURITY_SENSITIVE = "SECURITY_SENSITIVE"


class EvidenceLevel(IntEnum):
    L0 = 0
    L1 = 1
    L2 = 2
    L3 = 3


class VerificationAction(str, Enum):
    PASS_STOP = "PASS_STOP"
    FAIL_STOP = "FAIL_STOP"
    BLOCKED_STOP = "BLOCKED_STOP"
    UNCERTAIN_STOP = "UNCERTAIN_STOP"
    ESCALATE_ONE_LEVEL = "ESCALATE_ONE_LEVEL"


@dataclass(frozen=True)
class InvariantEvidence:
    invariant_id: str
    result: VerificationResult

    def __post_init__(self) -> None:
        if not isinstance(self.invariant_id, str) or not self.invariant_id.strip():
            raise ValueError("invariant_id must be a non-empty string")
        object.__setattr__(self, "result", VerificationResult(self.result))


@dataclass(frozen=True)
class MatchedAnomalyPredicate:
    """A named observable anomaly predicate that the caller has already matched."""

    predicate_id: str
    observed: Any
    expected: Any
    affected_invariant: str

    def __post_init__(self) -> None:
        if not isinstance(self.predicate_id, str) or not self.predicate_id.strip():
            raise ValueError("predicate_id must be a non-empty string")
        if not isinstance(self.affected_invariant, str) or not self.affected_invariant.strip():
            raise ValueError("affected_invariant must be a non-empty string")


@dataclass(frozen=True)
class DiagnosticBudget:
    """Single-use finite evidence budget consumed sequentially from L0 through L3."""

    remaining_attempts: int
    attempted_levels: tuple[EvidenceLevel, ...] = ()
    _successor_issued: bool = field(default=False, init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if not isinstance(self.remaining_attempts, int) or isinstance(self.remaining_attempts, bool):
            raise ValueError("remaining_attempts must be an integer")
        if self.remaining_attempts < 0:
            raise ValueError("remaining_attempts must be non-negative")
        levels = tuple(EvidenceLevel(level) for level in self.attempted_levels)
        if len(set(levels)) != len(levels):
            raise ValueError("attempted_levels must not contain duplicates")
        if len(levels) > len(EvidenceLevel):
            raise ValueError("attempted_levels exceeds the evidence-level range")
        expected_prefix = tuple(EvidenceLevel(index) for index in range(len(levels)))
        if levels != expected_prefix:
            raise ValueError("attempted_levels must be a contiguous prefix starting at L0")
        object.__setattr__(self, "attempted_levels", levels)

    def _next_collectable_level(self) -> Optional[EvidenceLevel]:
        if len(self.attempted_levels) >= len(EvidenceLevel):
            return None
        return EvidenceLevel(len(self.attempted_levels))

    def accounts_for(self, level: EvidenceLevel) -> bool:
        """Return whether this live budget accounts for evidence through ``level``."""

        level = EvidenceLevel(level)
        expected_history = tuple(EvidenceLevel(index) for index in range(int(level) + 1))
        return not self._successor_issued and self.attempted_levels == expected_history

    def can_collect(self, level: EvidenceLevel) -> bool:
        level = EvidenceLevel(level)
        return (
            not self._successor_issued
            and self.remaining_attempts > 0
            and level == self._next_collectable_level()
        )

    def consume(self, level: EvidenceLevel) -> "DiagnosticBudget":
        """Consume the next sequential attempt and invalidate this source budget."""

        level = EvidenceLevel(level)
        if not self.can_collect(level):
            raise ValueError("diagnostic evidence collection is not permitted")
        object.__setattr__(self, "_successor_issued", True)
        return DiagnosticBudget(
            remaining_attempts=self.remaining_attempts - 1,
            attempted_levels=self.attempted_levels + (level,),
        )


@dataclass(frozen=True)
class VerificationDecision:
    action: VerificationAction
    result: Optional[VerificationResult]
    next_level: Optional[EvidenceLevel] = None
    reason: str = ""


def _next_level(level: EvidenceLevel) -> Optional[EvidenceLevel]:
    level = EvidenceLevel(level)
    if level == EvidenceLevel.L3:
        return None
    return EvidenceLevel(level + 1)


def _terminal(
    action: VerificationAction,
    result: VerificationResult,
    reason: str,
) -> VerificationDecision:
    return VerificationDecision(action=action, result=result, reason=reason)


def decide_verification(
    *,
    verification_class: VerificationClass,
    required_positive_invariants: Sequence[InvariantEvidence] = (),
    required_negative_invariants: Sequence[InvariantEvidence] = (),
    trust_boundary_invariants: Sequence[InvariantEvidence] = (),
    anomaly: Optional[MatchedAnomalyPredicate] = None,
    current_level: EvidenceLevel = EvidenceLevel.L0,
    deeper_evidence_can_resolve: bool = False,
    diagnostic_budget: DiagnosticBudget,
    prerequisite_blocked: bool = False,
) -> VerificationDecision:
    """Return the smallest policy decision for one bounded verification state.

    This function classifies already-collected evidence only. Evidence collection
    itself is bounded separately by ``DiagnosticBudget.consume`` so callers cannot
    repeat a same-level probe set, branch from a consumed budget, or jump over an
    evidence level. A non-``None`` ``anomaly`` represents a named observable
    predicate that has already matched; free-form suspicion has no input channel
    here and therefore cannot authorize escalation.
    """

    verification_class = VerificationClass(verification_class)
    current_level = EvidenceLevel(current_level)
    required = tuple(required_positive_invariants) + tuple(required_negative_invariants)
    trust = tuple(trust_boundary_invariants)

    # Explicitly supplied required trust evidence is never ignored, even if the
    # caller classified the verification as normal. Security-sensitive verification
    # additionally requires at least one explicitly declared trust invariant before
    # PASS is possible.
    applicable = required + trust

    # Terminal evidence is classified before budget/history uncertainty. Contradiction
    # remains FAIL even when a policy/prerequisite gate is also blocked.
    if any(item.result is VerificationResult.FAIL for item in applicable):
        return _terminal(
            VerificationAction.FAIL_STOP,
            VerificationResult.FAIL,
            "required invariant contradicted",
        )

    if prerequisite_blocked or any(item.result is VerificationResult.BLOCKED for item in applicable):
        return _terminal(
            VerificationAction.BLOCKED_STOP,
            VerificationResult.BLOCKED,
            "prerequisite or policy gate blocked valid verification",
        )

    # Evidence at current_level is valid for bounded decisions only when every level
    # through it has been charged exactly once to the live budget state. A consumed
    # parent budget is stale and cannot be reused to classify or branch evidence.
    if not diagnostic_budget.accounts_for(current_level):
        return _terminal(
            VerificationAction.UNCERTAIN_STOP,
            VerificationResult.UNCERTAIN,
            "diagnostic budget history does not account for current evidence level",
        )

    has_declared_required = bool(applicable)
    if verification_class is VerificationClass.SECURITY_SENSITIVE and not trust:
        has_declared_required = False

    if (
        has_declared_required
        and all(item.result is VerificationResult.PASS for item in applicable)
        and anomaly is None
    ):
        return _terminal(
            VerificationAction.PASS_STOP,
            VerificationResult.PASS,
            "all applicable required invariants passed",
        )

    missing_or_inconclusive = (
        not has_declared_required
        or any(
            item.result in {VerificationResult.UNCERTAIN, VerificationResult.NOT_RUN}
            for item in applicable
        )
    )

    declared_invariant_ids = {item.invariant_id for item in applicable}
    predicate_is_bound = anomaly is not None and anomaly.affected_invariant in declared_invariant_ids
    next_level = _next_level(current_level)
    if (
        predicate_is_bound
        and deeper_evidence_can_resolve
        and next_level is not None
        and diagnostic_budget.can_collect(next_level)
    ):
        return VerificationDecision(
            action=VerificationAction.ESCALATE_ONE_LEVEL,
            result=None,
            next_level=next_level,
            reason=(
                "named observable predicate can be resolved by one deeper evidence level"
                if not missing_or_inconclusive
                else "named predicate can resolve missing or inconclusive required evidence"
            ),
        )

    return _terminal(
        VerificationAction.UNCERTAIN_STOP,
        VerificationResult.UNCERTAIN,
        "required evidence remains unresolved within bounded diagnostics",
    )
