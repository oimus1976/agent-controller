from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import json
import ntpath
import re
from typing import Callable, Iterable


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
_ALLOWED_STEP_STATES = frozenset({"ACTIVE", "DONE"})
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
_GIT_SHA1_RE = re.compile(r"^[0-9a-fA-F]{40}$")


CanonicalPathResolver = Callable[[str], str]


def _require_nonempty_string(name: str, value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a nonempty string")
    return value


def _require_sha256(name: str, value: object) -> str:
    text = _require_nonempty_string(name, value)
    if _SHA256_RE.fullmatch(text) is None:
        raise ValueError(f"{name} must be a 64-character hexadecimal SHA-256 digest")
    return text.lower()


def _require_git_sha(name: str, value: object) -> str:
    text = _require_nonempty_string(name, value)
    if _GIT_SHA1_RE.fullmatch(text) is None:
        raise ValueError(f"{name} must be a full 40-character hexadecimal Git object ID")
    return text.lower()


def _require_int(name: str, value: object, *, minimum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an integer")
    if minimum is not None and value < minimum:
        raise ValueError(f"{name} must be >= {minimum}")
    return value


def _require_string_tuple(name: str, value: object) -> tuple[str, ...]:
    if not isinstance(value, tuple):
        raise ValueError(f"{name} must be a tuple")
    for item in value:
        _require_nonempty_string(f"{name} entry", item)
    return value


def _normalize_windows_absolute_path(name: str, value: object) -> str:
    text = _require_nonempty_string(name, value)
    normalized = ntpath.normpath(text)
    drive, _ = ntpath.splitdrive(normalized)
    if not ntpath.isabs(normalized) or not drive:
        raise ValueError(f"{name} must be an absolute Windows path")
    return ntpath.normcase(normalized)


def _resolve_windows_absolute_path(
    name: str,
    value: object,
    *,
    canonical_path_resolver: CanonicalPathResolver,
) -> str:
    lexical = _normalize_windows_absolute_path(name, value)
    try:
        resolved = canonical_path_resolver(lexical)
    except Exception as exc:
        raise ValueError(f"{name} canonical resolution failed") from exc
    return _normalize_windows_absolute_path(f"resolved {name}", resolved)


def _require_path_within_workspace(
    name: str,
    value: object,
    *,
    resolved_workspace: str,
    canonical_path_resolver: CanonicalPathResolver,
) -> str:
    resolved_path = _resolve_windows_absolute_path(
        name,
        value,
        canonical_path_resolver=canonical_path_resolver,
    )
    try:
        common = ntpath.commonpath((resolved_workspace, resolved_path))
    except ValueError as exc:
        raise ValueError(f"{name} must remain within the expected workspace") from exc
    if ntpath.normcase(common) != resolved_workspace:
        raise ValueError(f"{name} must remain within the expected workspace")
    return resolved_path


def parse_antigravity_stream_json(
    lines: Iterable[str],
    *,
    expected_workspace: str,
    canonical_path_resolver: CanonicalPathResolver,
) -> AntigravityStreamResult:
    """Parse one fresh ``agy --output-format stream-json`` review transcript.

    Only characterized event shapes and read-only tool steps are accepted. Tool
    paths are checked after owner-machine canonical resolution so lexical
    containment cannot hide a junction/symlink escape. Provider-native SUCCESS
    remains evidence only; callers must use ``classify_antigravity_review``.
    """

    if not callable(canonical_path_resolver):
        raise ValueError("canonical_path_resolver must be callable")
    resolved_workspace = _resolve_windows_absolute_path(
        "expected_workspace",
        expected_workspace,
        canonical_path_resolver=canonical_path_resolver,
    )
    event_count = 0
    init_conversation_id: str | None = None
    terminal_result: AntigravityStreamResult | None = None
    next_step_index = 0
    active_tool: tuple[int, str] | None = None

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
            init_cwd = _resolve_windows_absolute_path(
                "init cwd",
                init_payload.get("cwd"),
                canonical_path_resolver=canonical_path_resolver,
            )
            if init_cwd != resolved_workspace:
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
            step_index = _require_int("step_update step_index", payload.get("step_index"), minimum=0)
            state = _require_nonempty_string("step_update state", payload.get("state"))
            if state not in _ALLOWED_STEP_STATES:
                raise ValueError(f"unsupported Antigravity review step state: {state}")
            step_type = _require_nonempty_string(
                "step_update step_type", payload.get("step_type")
            )
            if step_type not in _ALLOWED_STEP_UPDATE_TYPES:
                raise ValueError(f"unsupported Antigravity review step type: {step_type}")

            if step_type != "tool":
                if "tool_name" in payload or "tool_info" in payload:
                    raise ValueError("non-tool step must not contain tool metadata")
                if state != "DONE":
                    raise ValueError("non-tool review steps must be DONE")
                if active_tool is not None:
                    raise ValueError("active tool step must complete before another step")
                if step_index != next_step_index:
                    raise ValueError("step_update indices must be contiguous from zero")
                next_step_index += 1
                continue

            tool_name = _require_nonempty_string(
                "step_update tool_name", payload.get("tool_name")
            )
            if tool_name not in _ALLOWED_READ_ONLY_TOOLS:
                raise ValueError(f"unsupported Antigravity review tool: {tool_name}")
            tool_info = payload.get("tool_info")
            if not isinstance(tool_info, dict):
                raise ValueError("tool step must contain tool_info")
            tool_info_name = _require_nonempty_string("tool_info name", tool_info.get("name"))
            if tool_info_name != tool_name:
                raise ValueError("Antigravity tool identity changed within one step")
            parameters = tool_info.get("parameters")
            if not isinstance(parameters, dict):
                raise ValueError("tool step must contain parameters")
            path_parameter = _TOOL_PATH_PARAMETER[tool_name]
            _require_path_within_workspace(
                f"{tool_name} {path_parameter}",
                parameters.get(path_parameter),
                resolved_workspace=resolved_workspace,
                canonical_path_resolver=canonical_path_resolver,
            )

            if state == "ACTIVE":
                if active_tool is not None:
                    raise ValueError("nested active tool steps are not allowed")
                if step_index != next_step_index:
                    raise ValueError("step_update indices must be contiguous from zero")
                active_tool = (step_index, tool_name)
                continue

            if active_tool is None:
                raise ValueError("tool DONE must match a preceding ACTIVE step")
            if active_tool != (step_index, tool_name):
                raise ValueError("tool DONE must match the active tool step")
            next_step_index += 1
            active_tool = None
            continue

        if active_tool is not None:
            raise ValueError("terminal result cannot arrive with an active tool step")
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

        if "denied_actions" not in payload:
            raise ValueError("result denied_actions evidence is required")
        raw_denied = payload["denied_actions"]
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


def _validate_stream_result(stream: object) -> AntigravityStreamResult:
    if not isinstance(stream, AntigravityStreamResult):
        raise ValueError("stream_result must be AntigravityStreamResult")
    _require_nonempty_string("stream_result conversation_id", stream.conversation_id)
    _require_nonempty_string("stream_result top_level_status", stream.top_level_status)
    if not isinstance(stream.response, str):
        raise ValueError("stream_result response must be a string")
    if not isinstance(stream.denied_actions, tuple):
        raise ValueError("stream_result denied_actions must be a tuple")
    for denied in stream.denied_actions:
        if not isinstance(denied, AntigravityDeniedAction):
            raise ValueError("stream_result denied_actions entries must be AntigravityDeniedAction")
        _require_nonempty_string("denied action", denied.action)
        _require_nonempty_string("denied display_name", denied.display_name)
    _require_int("stream_result event_count", stream.event_count, minimum=1)
    return stream


def classify_antigravity_review(
    evidence: AntigravityReviewEvidence,
) -> AntigravityReviewDecision:
    """Apply the fail-closed Controller gate for a review-only operation."""

    if not isinstance(evidence, AntigravityReviewEvidence):
        raise TypeError("evidence must be AntigravityReviewEvidence")

    expected_reviewed_sha = _require_git_sha(
        "expected_reviewed_sha", evidence.expected_reviewed_sha
    )
    before_head_sha = _require_git_sha("before_head_sha", evidence.before_head_sha)
    after_head_sha = _require_git_sha("after_head_sha", evidence.after_head_sha)
    expected_review_input_sha256 = _require_sha256(
        "expected_review_input_sha256", evidence.expected_review_input_sha256
    )
    before_review_input_sha256 = _require_sha256(
        "before_review_input_sha256", evidence.before_review_input_sha256
    )
    after_review_input_sha256 = _require_sha256(
        "after_review_input_sha256", evidence.after_review_input_sha256
    )
    process_exit_code = _require_int("process_exit_code", evidence.process_exit_code)
    stream = _validate_stream_result(evidence.stream_result)
    before_tracked_delta = _require_string_tuple(
        "before_tracked_delta", evidence.before_tracked_delta
    )
    after_tracked_delta = _require_string_tuple(
        "after_tracked_delta", evidence.after_tracked_delta
    )
    before_untracked = _require_string_tuple("before_untracked", evidence.before_untracked)
    after_untracked = _require_string_tuple("after_untracked", evidence.after_untracked)

    reasons: list[str] = []

    if before_head_sha != expected_reviewed_sha:
        reasons.append("START_SHA_MISMATCH")
    if after_head_sha != expected_reviewed_sha:
        reasons.append("END_SHA_MISMATCH")
    if after_head_sha != before_head_sha:
        reasons.append("HEAD_MUTATED")
    if before_review_input_sha256 != expected_review_input_sha256:
        reasons.append("START_REVIEW_INPUT_DIGEST_MISMATCH")
    if after_review_input_sha256 != expected_review_input_sha256:
        reasons.append("END_REVIEW_INPUT_DIGEST_MISMATCH")
    if after_review_input_sha256 != before_review_input_sha256:
        reasons.append("REVIEW_INPUT_MUTATED")
    if process_exit_code != 0:
        reasons.append("PROCESS_EXIT_NONZERO")
    if stream.top_level_status != "SUCCESS":
        reasons.append("PROVIDER_STATUS_NOT_SUCCESS")
    if stream.denied_actions:
        reasons.append("DENIED_ACTION_PRESENT")
    if not stream.response.strip():
        reasons.append("EMPTY_REVIEW_RESPONSE")
    if after_tracked_delta != before_tracked_delta:
        reasons.append("TRACKED_BASELINE_MUTATED")
    if after_untracked != before_untracked:
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
