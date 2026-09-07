from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import json
import ntpath
import re
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
    expected_review_input_sha256: str
    before_review_input_sha256: str
    after_review_input_sha256: str
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


_ALLOWED_REVIEW_EVENT_TYPES = frozenset({"init", "step_update", "result"})
_ALLOWED_STEP_UPDATE_TYPES = frozenset({"user_input", "agent_response", "tool"})
_ALLOWED_READ_ONLY_TOOLS = frozenset(
    {"find_by_name", "view_file", "grep_search", "list_dir"}
)
_TOOL_PATH_PARAMETER = {
    "find_by_name": "SearchDirectory",
    "view_file": "AbsolutePath",
    "grep_search": "SearchPath",
    "list_dir": "DirectoryPath",
}
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def _require_nonempty_string(name: str, value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a nonempty string")
    return value


def _require_sha256(name: str, value: object) -> str:
    text = _require_nonempty_string(name, value)
    if _SHA256_RE.fullmatch(text) is None:
        raise ValueError(f"{name} must be a 64-character hexadecimal SHA-256 digest")
    return text.lower()


def _normalize_windows_absolute_path(name: str, value: object) -> str:
    text = _require_nonempty_string(name, value)
    normalized = ntpath.normpath(text)
    drive, _ = ntpath.splitdrive(normalized)
    if not ntpath.isabs(normalized) or not drive:
        raise ValueError(f"{name} must be an absolute Windows path")
    return ntpath.normcase(normalized)


def _require_path_within_workspace(
    name: str,
    value: object,
    *,
    normalized_workspace: str,
) -> str:
    normalized_path = _normalize_windows_absolute_path(name, value)
    try:
        common = ntpath.commonpath((normalized_workspace, normalized_path))
    except ValueError as exc:
        raise ValueError(f"{name} must remain within the expected workspace") from exc
    if ntpath.normcase(common) != normalized_workspace:
        raise ValueError(f"{name} must remain within the expected workspace")
    return normalized_path


def parse_antigravity_stream_json(
    lines: Iterable[str],
    *,
    expected_workspace: str,
) -> AntigravityStreamResult:
    """Parse one fresh ``agy --output-format stream-json`` review transcript.

    The parser is intentionally strict. Only event shapes and read-only tool
    steps observed and accepted for the bounded review-only surface are allowed.
    The provider-reported cwd must equal the exact expected Windows workspace,
    and every characterized read tool must target that workspace or a descendant
    path. Provider-native SUCCESS is retained as evidence only; callers must use
    ``classify_antigravity_review`` before treating the operation as successful.
    """

    normalized_workspace = _normalize_windows_absolute_path(
        "expected_workspace", expected_workspace
    )
    event_count = 0
    init_conversation_id: str | None = None
    terminal_result: AntigravityStreamResult | None = None

    for raw_line in lines:
        if not isinstance(raw_line, str):
            raise ValueError("stream lines must be strings")
        line = raw_line.strip()
        if not line:
            continue
        if terminal_result is not None:
            raise ValueError("events after terminal result are not allowed")

        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError("malformed Antigravity stream-json") from exc
        if not isinstance(event, dict):
            raise ValueError("Antigravity stream event must be an object")

        event_count += 1
        event_type = _require_nonempty_string("stream event type", event.get("event"))
        if event_type not in _ALLOWED_REVIEW_EVENT_TYPES:
            raise ValueError(f"unsupported Antigravity review event: {event_type}")

        if init_conversation_id is None and event_type != "init":
            raise ValueError("first Antigravity stream event must be init")

        if event_type == "init":
            conversation_id = _require_nonempty_string(
                "init conversation_id", event.get("conversation_id")
            )
            if init_conversation_id is not None:
                raise ValueError("multiple init events are not allowed")
            init_payload = event.get("init")
            if not isinstance(init_payload, dict):
                raise ValueError("init event must contain an object payload")
            init_cwd = _normalize_windows_absolute_path(
                "init cwd", init_payload.get("cwd")
            )
            if init_cwd != normalized_workspace:
                raise ValueError("Antigravity init cwd must equal the expected workspace")
            init_conversation_id = conversation_id
            continue

        if event_type == "step_update":
            payload = event.get("step_update")
            if not isinstance(payload, dict):
                raise ValueError("step_update event must contain an object payload")
            conversation_id = _require_nonempty_string(
                "step_update conversation_id", payload.get("conversation_id")
            )
            if conversation_id != init_conversation_id:
                raise ValueError("Antigravity conversation identity changed within one stream")
            step_type = _require_nonempty_string(
                "step_update step_type", payload.get("step_type")
            )
            if step_type not in _ALLOWED_STEP_UPDATE_TYPES:
                raise ValueError(
                    f"unsupported Antigravity review step type: {step_type}"
                )
            if step_type == "tool":
                tool_name = _require_nonempty_string(
                    "step_update tool_name", payload.get("tool_name")
                )
                if tool_name not in _ALLOWED_READ_ONLY_TOOLS:
                    raise ValueError(
                        f"unsupported Antigravity review tool: {tool_name}"
                    )
                tool_info = payload.get("tool_info")
                if not isinstance(tool_info, dict):
                    raise ValueError("tool step must contain tool_info")
                tool_info_name = _require_nonempty_string(
                    "tool_info name", tool_info.get("name")
                )
                if tool_info_name != tool_name:
                    raise ValueError("Antigravity tool identity changed within one step")
                parameters = tool_info.get("parameters")
                if not isinstance(parameters, dict):
                    raise ValueError("tool step must contain parameters")
                path_parameter = _TOOL_PATH_PARAMETER[tool_name]
                _require_path_within_workspace(
                    f"{tool_name} {path_parameter}",
                    parameters.get(path_parameter),
                    normalized_workspace=normalized_workspace,
                )
            continue

        payload = event.get("result")
        if not isinstance(payload, dict):
            raise ValueError("result event must contain an object payload")

        conversation_id = _require_nonempty_string(
            "result conversation_id", payload.get("conversation_id")
        )
        if conversation_id != init_conversation_id:
            raise ValueError("Antigravity conversation identity changed within one stream")
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

    expected_review_input_sha256 = _require_sha256(
        "expected_review_input_sha256", evidence.expected_review_input_sha256
    )
    before_review_input_sha256 = _require_sha256(
        "before_review_input_sha256", evidence.before_review_input_sha256
    )
    after_review_input_sha256 = _require_sha256(
        "after_review_input_sha256", evidence.after_review_input_sha256
    )

    reasons: list[str] = []
    stream = evidence.stream_result

    if evidence.before_head_sha != evidence.expected_reviewed_sha:
        reasons.append("START_SHA_MISMATCH")
    if evidence.after_head_sha != evidence.expected_reviewed_sha:
        reasons.append("END_SHA_MISMATCH")
    if evidence.after_head_sha != evidence.before_head_sha:
        reasons.append("HEAD_MUTATED")
    if before_review_input_sha256 != expected_review_input_sha256:
        reasons.append("START_REVIEW_INPUT_DIGEST_MISMATCH")
    if after_review_input_sha256 != expected_review_input_sha256:
        reasons.append("END_REVIEW_INPUT_DIGEST_MISMATCH")
    if after_review_input_sha256 != before_review_input_sha256:
        reasons.append("REVIEW_INPUT_MUTATED")
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
