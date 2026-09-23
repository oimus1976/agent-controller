from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from agent_controller.operator_step_gate import (
    ResultPublicationCapability,
    consume_result_publication_capability,
)
from agent_controller.private_ci_consumption_marker import (
    CONSUMPTION_ROOT,
    read_consumption_acl_state,
    validate_consumption_acl_state,
    validate_consumption_container_acl_state,
)

FILE_ATTRIBUTE_REPARSE_POINT = 0x400


def _validate_authority_root_security(
    root: Path | None = None,
) -> None:
    if root is None:
        root = RESULT_AUTHORITY_ROOT
    if not root.is_dir() or root.is_symlink():
        raise ValueError("result authority root missing or not a directory")
    stat_result = root.lstat()
    if getattr(stat_result, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT:
        # Explicitly reject ReparsePoint for authority root
        raise ValueError("result authority root ReparsePoint blocked")
    acl_state = read_consumption_acl_state(root)
    validate_consumption_container_acl_state(acl_state)


def _validate_authority_marker_security(
    path: Path,
) -> None:
    if not path.is_file() or path.is_symlink():
        raise ValueError("result authority marker missing or unreadable")
    stat_result = path.lstat()
    if getattr(stat_result, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT:
        # Explicitly reject ReparsePoint for authority marker
        raise ValueError("result authority marker ReparsePoint blocked")
    acl_state = read_consumption_acl_state(path)
    validate_consumption_acl_state(acl_state)


RESULT_AUTHORITY_ROOT = CONSUMPTION_ROOT
PHASE6_RESULT_AUTHORITY_SCHEMA = "agent-controller.private-ci-phase6-result-authority.v1"
PHASE7_RESULT_AUTHORITY_SCHEMA = "agent-controller.private-ci-phase7-result-authority.v1"


@dataclass(frozen=True, slots=True)
class ResultAuthorityMarker:
    schema: str
    result_sha256: str
    upstream_sha256: str
    published_at: str


def _require_digest(value: object, field: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{field} invalid")
    return value


def canonical_result_authority_bytes(marker: ResultAuthorityMarker) -> bytes:
    payload = {
        "schema": marker.schema,
        "result_sha256": marker.result_sha256,
        "upstream_sha256": marker.upstream_sha256,
        "published_at": marker.published_at,
    }
    return (
        json.dumps(payload, separators=(",", ":"), ensure_ascii=True) + "\n"
    ).encode("utf-8")


def _marker_path(*, phase: int, result_sha256: str) -> Path:
    digest = _require_digest(result_sha256, "result authority SHA-256")
    if phase not in (6, 7):
        raise ValueError("result authority phase invalid")
    return RESULT_AUTHORITY_ROOT / (
        f"issue230-phase{phase}-result-{digest}.authority.json"
    )


def _publish(
    *,
    phase: int,
    schema: str,
    result_bytes: bytes,
    upstream_sha256: str,
    publication_capability: ResultPublicationCapability,
) -> ResultAuthorityMarker:
    if type(result_bytes) is not bytes:
        raise ValueError("result authority requires exact result bytes")
    upstream = _require_digest(
        upstream_sha256,
        "result authority upstream SHA-256",
    )
    result_sha = hashlib.sha256(result_bytes).hexdigest()
    consume_result_publication_capability(
        publication_capability,
        phase=phase,
        result_sha256=result_sha,
        upstream_sha256=upstream,
    )
    root = RESULT_AUTHORITY_ROOT
    _validate_authority_root_security(root)
    marker = ResultAuthorityMarker(
        schema=schema,
        result_sha256=result_sha,
        upstream_sha256=upstream,
        published_at=datetime.now(timezone.utc).isoformat(),
    )
    path = _marker_path(phase=phase, result_sha256=result_sha)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    # Note: 0o600 mode does not provide sufficient Windows ACL protection;
    # authority root and marker security must be proven via ACL state validation.
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError as error:
        raise ValueError("result authority already published") from error
    except OSError as error:
        raise ValueError("result authority publication failed") from error
    try:
        with os.fdopen(fd, "wb", closefd=True) as stream:
            stream.write(canonical_result_authority_bytes(marker))
            stream.flush()
            os.fsync(stream.fileno())
    except Exception as error:
        raise ValueError(
            "result authority marker write failed; authority is blocked"
        ) from error
    _validate_authority_marker_security(path)
    return marker


def _parse_and_validate(
    *,
    phase: int,
    schema: str,
    result_bytes: bytes,
    expected_upstream_sha256: str,
) -> ResultAuthorityMarker:
    if type(result_bytes) is not bytes:
        raise ValueError("result authority requires exact result bytes")
    root = RESULT_AUTHORITY_ROOT
    _validate_authority_root_security(root)
    result_sha = hashlib.sha256(result_bytes).hexdigest()
    path = _marker_path(phase=phase, result_sha256=result_sha)
    _validate_authority_marker_security(path)
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise ValueError("result authority marker missing or unreadable") from error
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("result authority marker JSON invalid") from error
    required = {
        "schema",
        "result_sha256",
        "upstream_sha256",
        "published_at",
    }
    if type(payload) is not dict or set(payload) != required:
        raise ValueError("result authority marker shape invalid")
    try:
        marker = ResultAuthorityMarker(**payload)
    except TypeError as error:
        raise ValueError("result authority marker fields invalid") from error
    if raw != canonical_result_authority_bytes(marker):
        raise ValueError("result authority marker is not canonical")
    if marker.schema != schema:
        raise ValueError("result authority marker schema invalid")
    if _require_digest(marker.result_sha256, "result authority result SHA-256") != result_sha:
        raise ValueError("result authority result SHA-256 mismatch")
    expected_upstream = _require_digest(
        expected_upstream_sha256,
        "expected result authority upstream SHA-256",
    )
    if _require_digest(
        marker.upstream_sha256,
        "result authority upstream SHA-256",
    ) != expected_upstream:
        raise ValueError("result authority upstream SHA-256 mismatch")
    if type(marker.published_at) is not str or not marker.published_at:
        raise ValueError("result authority published_at invalid")
    return marker


def publish_phase6_result_authority(
    result_bytes: bytes,
    *,
    phase6_consumption_sha256: str,
    publication_capability: ResultPublicationCapability,
) -> ResultAuthorityMarker:
    return _publish(
        phase=6,
        schema=PHASE6_RESULT_AUTHORITY_SCHEMA,
        result_bytes=result_bytes,
        upstream_sha256=phase6_consumption_sha256,
        publication_capability=publication_capability,
    )


def publish_phase7_result_authority(
    result_bytes: bytes,
    *,
    phase6_result_sha256: str,
    publication_capability: ResultPublicationCapability,
) -> ResultAuthorityMarker:
    return _publish(
        phase=7,
        schema=PHASE7_RESULT_AUTHORITY_SCHEMA,
        result_bytes=result_bytes,
        upstream_sha256=phase6_result_sha256,
        publication_capability=publication_capability,
    )


def validate_phase6_result_authority_marker(
    result_bytes: bytes,
    *,
    phase6_consumption_sha256: str,
) -> ResultAuthorityMarker:
    return _parse_and_validate(
        phase=6,
        schema=PHASE6_RESULT_AUTHORITY_SCHEMA,
        result_bytes=result_bytes,
        expected_upstream_sha256=phase6_consumption_sha256,
    )


def validate_phase7_result_authority_marker(
    result_bytes: bytes,
    *,
    phase6_result_sha256: str,
) -> ResultAuthorityMarker:
    return _parse_and_validate(
        phase=7,
        schema=PHASE7_RESULT_AUTHORITY_SCHEMA,
        result_bytes=result_bytes,
        expected_upstream_sha256=phase6_result_sha256,
    )
