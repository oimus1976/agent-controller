from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import tempfile
from typing import Callable

from agent_controller.antigravity_capacity import parse_antigravity_statusline_capacity
from agent_controller.provider_capacity_pool import ProviderCapacityPoolObservation


_MAX_CAPTURE_BYTES = 64 * 1024
_CAPTURE_SCHEMA_VERSION = 1
_CAPACITY_FIELDS = ("product", "version", "quota", "status", "error")


CanonicalPathResolver = Callable[[str], str]


@dataclass(frozen=True)
class AntigravityStatuslineCapture:
    captured_at: str
    payload: str


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _capacity_only_payload(payload: str) -> str:
    try:
        root = json.loads(payload, object_pairs_hook=_reject_duplicate_keys)
    except json.JSONDecodeError as exc:
        raise ValueError("malformed Antigravity statusline JSON") from exc
    if not isinstance(root, dict):
        raise ValueError("Antigravity statusline root must be an object")

    minimized = {name: root[name] for name in _CAPACITY_FIELDS if name in root}
    return json.dumps(minimized, ensure_ascii=False, separators=(",", ":"))


def _parse_aware_timestamp(name: str, value: object) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a nonempty timestamp")
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValueError(f"{name} must be ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{name} must include a timezone offset")
    return parsed


def _strict_realpath(path: str) -> str:
    return os.path.realpath(path, strict=True)


def _resolved_capture_path(
    capture_path: str | os.PathLike[str],
    capture_root: str | os.PathLike[str],
    *,
    canonical_path_resolver: CanonicalPathResolver,
    require_file: bool,
) -> tuple[Path, Path]:
    if not callable(canonical_path_resolver):
        raise ValueError("canonical_path_resolver must be callable")

    root = Path(capture_root)
    path = Path(capture_path)
    if not root.is_absolute() or not path.is_absolute():
        raise ValueError("capture root and path must be absolute")

    try:
        resolved_root = Path(canonical_path_resolver(str(root)))
        resolved_parent = Path(canonical_path_resolver(str(path.parent)))
        resolved_path = (
            Path(canonical_path_resolver(str(path))) if require_file else resolved_parent / path.name
        )
    except Exception as exc:
        raise ValueError("capture path canonical resolution failed") from exc

    if resolved_parent != resolved_root or resolved_path.parent != resolved_root:
        raise ValueError("capture path must resolve directly beneath capture root")
    return resolved_root, resolved_path


def write_statusline_capture(
    payload: str,
    *,
    capture_path: str | os.PathLike[str],
    capture_root: str | os.PathLike[str],
    captured_at: str | None = None,
    canonical_path_resolver: CanonicalPathResolver = _strict_realpath,
    max_bytes: int = _MAX_CAPTURE_BYTES,
) -> AntigravityStatuslineCapture:
    """Atomically persist only capacity-relevant Antigravity status-line telemetry.

    Duplicate keys are rejected against the original stdin JSON before unrelated
    status-line fields such as account identity, transcript path, workspace path,
    conversation identity, and token context are discarded.
    """

    if not isinstance(payload, str) or not payload.strip():
        raise ValueError("statusline payload must be a nonempty string")
    encoded = payload.encode("utf-8")
    if len(encoded) > max_bytes:
        raise ValueError("statusline payload exceeds size limit")

    minimized_payload = _capacity_only_payload(payload)
    timestamp = captured_at or datetime.now(timezone.utc).isoformat()
    _parse_aware_timestamp("captured_at", timestamp)
    resolved_root, resolved_path = _resolved_capture_path(
        capture_path,
        capture_root,
        canonical_path_resolver=canonical_path_resolver,
        require_file=False,
    )

    envelope = json.dumps(
        {
            "schema_version": _CAPTURE_SCHEMA_VERSION,
            "captured_at": timestamp,
            "payload": minimized_payload,
        },
        ensure_ascii=False,
        separators=(",", ":"),
    )

    fd, temp_name = tempfile.mkstemp(prefix=f".{resolved_path.name}.", dir=resolved_root, text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(envelope)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, resolved_path)
    except Exception:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass
        raise

    return AntigravityStatuslineCapture(captured_at=timestamp, payload=minimized_payload)


def read_statusline_capture(
    *,
    capture_path: str | os.PathLike[str],
    capture_root: str | os.PathLike[str],
    now: str,
    max_age_seconds: int,
    canonical_path_resolver: CanonicalPathResolver = _strict_realpath,
    max_bytes: int = _MAX_CAPTURE_BYTES,
) -> AntigravityStatuslineCapture:
    if isinstance(max_age_seconds, bool) or not isinstance(max_age_seconds, int) or max_age_seconds < 0:
        raise ValueError("max_age_seconds must be a nonnegative integer")

    _, resolved_path = _resolved_capture_path(
        capture_path,
        capture_root,
        canonical_path_resolver=canonical_path_resolver,
        require_file=True,
    )
    raw = resolved_path.read_bytes()
    if len(raw) > max_bytes * 2:
        raise ValueError("statusline capture artifact exceeds size limit")
    try:
        envelope = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("malformed statusline capture artifact") from exc
    if not isinstance(envelope, dict) or envelope.get("schema_version") != _CAPTURE_SCHEMA_VERSION:
        raise ValueError("unsupported statusline capture artifact")

    captured_at = envelope.get("captured_at")
    payload = envelope.get("payload")
    if not isinstance(payload, str) or not payload.strip():
        raise ValueError("capture payload must be a nonempty string")
    if len(payload.encode("utf-8")) > max_bytes:
        raise ValueError("statusline payload exceeds size limit")

    captured_dt = _parse_aware_timestamp("captured_at", captured_at)
    now_dt = _parse_aware_timestamp("now", now)
    age_seconds = (now_dt - captured_dt).total_seconds()
    if age_seconds < 0:
        raise ValueError("statusline capture timestamp is in the future")
    if age_seconds > max_age_seconds:
        raise ValueError("statusline capture is stale")

    return AntigravityStatuslineCapture(captured_at=captured_at, payload=payload)


def observe_antigravity_capacity_from_capture(
    *,
    capture_path: str | os.PathLike[str],
    capture_root: str | os.PathLike[str],
    now: str,
    max_age_seconds: int,
    controller_task_id: str,
    workstream_id: str,
    operation_id: str,
    operation_version: str,
    canonical_path_resolver: CanonicalPathResolver = _strict_realpath,
) -> tuple[ProviderCapacityPoolObservation, ...]:
    capture = read_statusline_capture(
        capture_path=capture_path,
        capture_root=capture_root,
        now=now,
        max_age_seconds=max_age_seconds,
        canonical_path_resolver=canonical_path_resolver,
    )
    return parse_antigravity_statusline_capacity(
        capture.payload,
        controller_task_id=controller_task_id,
        workstream_id=workstream_id,
        operation_id=operation_id,
        operation_version=operation_version,
        observed_at=capture.captured_at,
    )
