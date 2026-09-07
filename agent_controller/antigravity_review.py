from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import json
from typing import Iterable


class AntigravityReviewStatus(str, Enum):
    PASS = "PASS"
    BLOCKED = "BLOCKED"


@dataclass(frozen=True)
class AntigravityDeniedAction:
    action: str
    display_name: str


@dataclass(frozen=True)
class AntigravityStreamResult:
    conversation_id: str
    top_level_status: str
    response: str
    denied_actions: tuple[AntigravityDeniedAction, ...]
    event_count: int


@dataclass(frozen=True)
class AntigravityReviewEvidence:
    expected_reviewed_sha: str
    before_head_sha: str
    after_head_sha: str
    process_exit_code: int
    stream_result: AntigravityStreamResult
    before_tracked_delta: tuple[str, ...] = ()
    after_tracked_delta: tuple[str, ...] = ()
    before_untracked: tuple[str, ...] = ()
    after_untracked: tuple[str, ...] = ()


@dataclass(frozen=True)
class AntigravityReviewDecision:
    status: AntigravityReviewStatus
    reason_codes: tuple[str, ...]


def _require_nonempty_string(name: str, value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a nonempty string")
    return value


def parse_antigravity_stream_json(lines: Iterable[str]) -> AntigravityStreamResult:
    """Parse one fresh ``agy --output-format stream-json`` review transcript.

    The parser is intentionally strict. Provider-native SUCCESS is retained as
    evidence only; callers must use ``classify_antigravity_review`` before
    treating the review operation as successful.
    """

    event_count = 0
    init_conversation_id: str | None = None
    terminal_result: AntigravityStreamResult | None = None

    for raw_line in lines:
        if not isinstance(raw_line, str):
            raise ValueError("stream lines must be strings")
        line = raw_line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError("malformed Antigravity stream-json") from exc
        if not isinstance(event, dict):
            raise ValueError("Antigravity stream event must be an object")

        event_count += 1
        event_type = event.get("event")
        if event_type == "init":
            conversation_id = _require_nonempty_string(
                "init conversation_id", event.get("conversation_id")
            )
            if init_conversation_id is not None:
                raise ValueError("multiple init events are not allowed")
            init_conversation_id = conversation_id
            continue

        if event_type != "result":
            continue

        if terminal_result is not None:
            raise ValueError("multiple terminal result events are not allowed")
        payload = event.get("result")
        if not isinstance(payload, dict):
            raise ValueError("result event must contain an object payload")

        conversation_id = _require_nonempty_string(
            "result conversation_id", payload.get("conversation_id")
        )
        top_level_status = _require_nonempty_string("result status", payload.get("status"))
        response = payload.get("response")
        if not isinstance(response, str):
            raise ValueError("result response must be a string")

        raw_denied = payload.get("denied_actions", [])
        if not isinstance(raw_denied, list):
            raise ValueError("denied_actions must be a list")
        denied_actions: list[AntigravityDeniedAction] = []
        for denied in raw_denied:
            if not isinstance(denied, dict):
                raise ValueError("denied_actions entries must be objects")
            denied_actions.append(
                AntigravityDeniedAction(
                    action=_require_nonempty_string("denied action", denied.get("action")),
                    display_name=_require_nonempty_string(
                        "denied display_name", denied.get("display_name")
                    ),
                )
            )

        terminal_result = AntigravityStreamResult(
            conversation_id=conversation_id,
            top_level_status=top_level_status,
            response=response,
            denied_actions=tuple(denied_actions),
            event_count=0,
        )

    if terminal_result is None:
        raise ValueError("Antigravity stream is missing terminal result")
    if init_conversation_id is None:
        raise ValueError("Antigravity stream is missing init event")
    if terminal_result.conversation_id != init_conversation_id:
        raise ValueError("Antigravity conversation identity changed within one stream")

    return AntigravityStreamResult(
        conversation_id=terminal_result.conversation_id,
        top_level_status=terminal_result.top_level_status,
        response=terminal_result.response,
        denied_actions=terminal_result.denied_actions,
        event_count=event_count,
    )


def classify_antigravity_review(
    evidence: AntigravityReviewEvidence,
) -> AntigravityReviewDecision:
    """Apply the fail-closed Controller gate for a review-only operation."""

    if not isinstance(evidence, AntigravityReviewEvidence):
        raise TypeError("evidence must be AntigravityReviewEvidence")

    for name, value in (
        ("expected_reviewed_sha", evidence.expected_reviewed_sha),
        ("before_head_sha", evidence.before_head_sha),
        ("after_head_sha", evidence.after_head_sha),
    ):
        _require_nonempty_string(name, value)

    reasons: list[str] = []
    stream = evidence.stream_result

    if evidence.before_head_sha != evidence.expected_reviewed_sha:
        reasons.append("START_SHA_MISMATCH")
    if evidence.after_head_sha != evidence.expected_reviewed_sha:
        reasons.append("END_SHA_MISMATCH")
    if evidence.after_head_sha != evidence.before_head_sha:
        reasons.append("HEAD_MUTATED")
    if evidence.process_exit_code != 0:
        reasons.append("PROCESS_EXIT_NONZERO")
    if stream.top_level_status != "SUCCESS":
        reasons.append("PROVIDER_STATUS_NOT_SUCCESS")
    if stream.denied_actions:
        reasons.append("DENIED_ACTION_PRESENT")
    if not stream.response.strip():
        reasons.append("EMPTY_REVIEW_RESPONSE")
    if evidence.after_tracked_delta != evidence.before_tracked_delta:
        reasons.append("TRACKED_BASELINE_MUTATED")
    if evidence.after_untracked != evidence.before_untracked:
        reasons.append("UNTRACKED_BASELINE_MUTATED")

    if reasons:
        return AntigravityReviewDecision(
            status=AntigravityReviewStatus.BLOCKED,
            reason_codes=tuple(reasons),
        )

    return AntigravityReviewDecision(
        status=AntigravityReviewStatus.PASS,
        reason_codes=("EXACT_SHA_REVIEW_COMPLETE_NO_MUTATION",),
    )
