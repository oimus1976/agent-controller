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


_PRIORITY = {
    AttentionCategory.HUMAN_ACTION: 0,
    AttentionCategory.NEEDS_ATTENTION: 1,
    AttentionCategory.IN_PROGRESS: 2,
    AttentionCategory.DONE: 3,
    AttentionCategory.NO_CHANGE: 4,
}


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
    transition = observation.get("transition")
    reasons = observation.get("transition_reasons", ())

    if repo is None:
        raise ValueError("repo must be nonempty")
    if not isinstance(pr, int) or isinstance(pr, bool) or pr <= 0:
        raise ValueError("pr must be a positive integer")
    if classification is None:
        classification = "UNKNOWN"
    if runtime_status is None:
        runtime_status = "UNKNOWN"
    if not isinstance(transition, bool):
        raise ValueError("transition must be bool")
    if not isinstance(reasons, Sequence) or isinstance(reasons, (str, bytes)):
        raise TypeError("transition_reasons must be a sequence")
    transition_reasons = tuple(str(reason) for reason in reasons)

    if runtime_status != "OK":
        category = AttentionCategory.NEEDS_ATTENTION
        reason = "EVIDENCE_UNAVAILABLE_OR_RUNTIME_ERROR"
    elif classification == "CLOSED":
        category = AttentionCategory.DONE
        reason = "TARGET_CLOSED_OR_MERGED"
    elif classification == "REVIEW_READY":
        category = AttentionCategory.HUMAN_ACTION
        reason = "VERIFIED_REVIEW_READY_HUMAN_GATE_CANDIDATE"
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
