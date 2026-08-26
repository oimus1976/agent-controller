from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Mapping, Sequence


class AttentionCategory(str, Enum):
    HUMAN_ACTION = "HUMAN_ACTION"
    NEEDS_ATTENTION = "NEEDS_ATTENTION"
    IN_PROGRESS = "IN_PROGRESS"
    DONE = "DONE"
    NO_CHANGE = "NO_CHANGE"


@dataclass(frozen=True)
class AttentionItem:
    repo: str
    pr: int
    head_sha: str | None
    classification: str
    runtime_status: str
    transition: bool
    transition_reasons: tuple[str, ...]
    category: AttentionCategory
    reason: str
    human_action: str | None = None


_PRIORITY = {
    AttentionCategory.HUMAN_ACTION: 0,
    AttentionCategory.NEEDS_ATTENTION: 1,
    AttentionCategory.IN_PROGRESS: 2,
    AttentionCategory.DONE: 3,
    AttentionCategory.NO_CHANGE: 4,
}

_VALID_ACTIONS_CI_STATUSES = frozenset({"PASS", "FAIL", "PENDING", "MISSING", "UNAVAILABLE"})
_VALID_PR_STATES = frozenset({"open", "closed"})


def _nonempty_string(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def classify_attention(observation: Mapping[str, object]) -> AttentionItem:
    if not isinstance(observation, Mapping):
        raise TypeError("observation must be a mapping")

    repo = _nonempty_string(observation.get("repo"))
    pr = observation.get("pr")
    classification = _nonempty_string(observation.get("current_classification"))
    runtime_status = _nonempty_string(observation.get("runtime_status"))
    head_sha = _nonempty_string(observation.get("current_head_sha"))
    actions_ci_status = _nonempty_string(observation.get("actions_ci_status"))
    scope_status = _nonempty_string(observation.get("scope_status"))
    graphql_error = observation.get("graphql_error")
    transition = observation.get("transition")
    reasons = observation.get("transition_reasons", ())
    current_draft = observation.get("current_draft")
    current_merged = observation.get("current_merged")
    current_state_enum = observation.get("current_state_enum")

    if repo is None:
        raise ValueError("repo must be nonempty")
    if not isinstance(pr, int) or isinstance(pr, bool) or pr <= 0:
        raise ValueError("pr must be a positive integer")
    if classification is None:
        classification = "UNKNOWN"
    if runtime_status is None:
        runtime_status = "UNKNOWN"
    if actions_ci_status is not None and actions_ci_status not in _VALID_ACTIONS_CI_STATUSES:
        raise ValueError("actions_ci_status is invalid")
    if not isinstance(transition, bool):
        raise ValueError("transition must be bool")
    if not isinstance(reasons, Sequence) or isinstance(reasons, (str, bytes)):
        raise TypeError("transition_reasons must be a sequence")
    transition_reasons = tuple(str(reason) for reason in reasons)

    category: AttentionCategory
    reason: str
    human_action: str | None = None

    if runtime_status != "OK":
        category = AttentionCategory.NEEDS_ATTENTION
        reason = "EVIDENCE_UNAVAILABLE_OR_RUNTIME_ERROR"
    elif not isinstance(current_draft, bool) or not isinstance(current_merged, bool):
        category = AttentionCategory.NEEDS_ATTENTION
        reason = "PR_STATE_EVIDENCE_MISSING_OR_MALFORMED"
    elif not isinstance(current_state_enum, str) or current_state_enum not in _VALID_PR_STATES:
        category = AttentionCategory.NEEDS_ATTENTION
        reason = "PR_STATE_EVIDENCE_MISSING_OR_MALFORMED"
    elif current_merged and current_state_enum != "closed":
        category = AttentionCategory.NEEDS_ATTENTION
        reason = "CONTRADICTORY_PR_STATE"
    elif classification == "CLOSED":
        if current_state_enum != "closed":
            category = AttentionCategory.NEEDS_ATTENTION
            reason = "CONTRADICTORY_PR_STATE"
        elif current_merged:
            category = AttentionCategory.DONE
            reason = "TARGET_MERGED"
        else:
            category = AttentionCategory.DONE
            reason = "TARGET_CLOSED_WITHOUT_MERGE"
    elif current_state_enum != "open" or current_merged:
        category = AttentionCategory.NEEDS_ATTENTION
        reason = "CONTRADICTORY_PR_STATE"
    elif actions_ci_status == "PENDING":
        category = AttentionCategory.IN_PROGRESS
        reason = "CI_RUNNING_FOR_EXACT_HEAD"
    elif classification == "REVIEW_READY":
        if (
            head_sha is None
            or actions_ci_status != "PASS"
            or scope_status != "SATISFIED"
            or graphql_error is not False
        ):
            category = AttentionCategory.NEEDS_ATTENTION
            reason = "CONTRADICTORY_REVIEW_READY_EVIDENCE"
        else:
            category = AttentionCategory.HUMAN_ACTION
            if current_draft:
                reason = "VERIFIED_REVIEW_READY_MARK_READY_REQUIRED"
                human_action = "MARK_READY_FOR_REVIEW"
            else:
                reason = "VERIFIED_REVIEW_READY_MERGE_REQUIRED"
                human_action = "MERGE"
    elif classification == "NEEDS_REVIEW":
        category = AttentionCategory.NEEDS_ATTENTION
        reason = "REVIEW_OR_REMEDIATION_REQUIRED"
    elif classification == "IMPLEMENTATION_READY":
        if transition:
            category = AttentionCategory.IN_PROGRESS
            reason = "IMPLEMENTATION_READY_FOR_NEXT_AUTOMATED_STEP"
        else:
            category = AttentionCategory.NO_CHANGE
            reason = "STABLE_IMPLEMENTATION_READY_NO_NEW_HUMAN_EVENT"
    else:
        category = AttentionCategory.NEEDS_ATTENTION
        reason = "UNKNOWN_CLASSIFICATION"

    return AttentionItem(
        repo=repo,
        pr=pr,
        head_sha=head_sha,
        classification=classification,
        runtime_status=runtime_status,
        transition=transition,
        transition_reasons=transition_reasons,
        category=category,
        reason=reason,
        human_action=human_action,
    )


def build_attention_queue(
    observations: Sequence[Mapping[str, object]],
) -> tuple[AttentionItem, ...]:
    if not isinstance(observations, Sequence) or isinstance(observations, (str, bytes)):
        raise TypeError("observations must be a sequence")
    items = tuple(classify_attention(observation) for observation in observations)
    return tuple(
        sorted(
            items,
            key=lambda item: (_PRIORITY[item.category], item.repo, item.pr),
        )
    )
