from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from agent_controller.private_ci_consumption_marker import CONSUMPTION_ROOT


FINAL_PUBLICATION_SCHEMA = "agent-controller.private-ci-final-pass-published.v1"
FINAL_PUBLICATION_PREFIX = "issue230-final-pass-"
FINAL_PUBLICATION_ROOT = CONSUMPTION_ROOT


@dataclass(frozen=True, slots=True)
class FinalPassPublicationMarker:
    schema: str
    phase5_result_sha256: str
    phase6_result_sha256: str
    phase7_result_sha256: str
    published_at: str


def _digest(raw: bytes, field: str) -> str:
    if type(raw) is not bytes:
        raise ValueError(f"final PASS {field} must be exact bytes")
    return hashlib.sha256(raw).hexdigest()


def final_pass_publication_path(phase5_result_sha256: str) -> Path:
    if (
        type(phase5_result_sha256) is not str
        or len(phase5_result_sha256) != 64
        or any(c not in "0123456789abcdef" for c in phase5_result_sha256)
    ):
        raise ValueError("final PASS Phase 5 result SHA-256 invalid")
    return FINAL_PUBLICATION_ROOT / (
        f"{FINAL_PUBLICATION_PREFIX}{phase5_result_sha256}.published.json"
    )


def canonical_final_pass_publication_bytes(
    marker: FinalPassPublicationMarker,
) -> bytes:
    payload = {
        "schema": marker.schema,
        "phase5_result_sha256": marker.phase5_result_sha256,
        "phase6_result_sha256": marker.phase6_result_sha256,
        "phase7_result_sha256": marker.phase7_result_sha256,
        "published_at": marker.published_at,
    }
    return (
        json.dumps(payload, separators=(",", ":"), ensure_ascii=True) + "\n"
    ).encode("utf-8")


def consume_final_pass_publication(
    *,
    phase5_result_bytes: bytes,
    phase6_result_bytes: bytes,
    phase7_result_bytes: bytes,
) -> FinalPassPublicationMarker:
    phase5_sha = _digest(phase5_result_bytes, "Phase 5 result")
    phase6_sha = _digest(phase6_result_bytes, "Phase 6 result")
    phase7_sha = _digest(phase7_result_bytes, "Phase 7 result")

    root = FINAL_PUBLICATION_ROOT
    if not root.is_dir():
        raise ValueError("final PASS publication authority root missing")

    marker = FinalPassPublicationMarker(
        schema=FINAL_PUBLICATION_SCHEMA,
        phase5_result_sha256=phase5_sha,
        phase6_result_sha256=phase6_sha,
        phase7_result_sha256=phase7_sha,
        published_at=datetime.now(timezone.utc).isoformat(),
    )
    raw = canonical_final_pass_publication_bytes(marker)
    path = final_pass_publication_path(phase5_sha)

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError as error:
        raise ValueError("final PASS already published") from error
    except OSError as error:
        raise ValueError("final PASS publication reservation failed") from error

    try:
        with os.fdopen(fd, "wb", closefd=True) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception as error:
        raise ValueError(
            "final PASS publication marker write failed; publication is blocked"
        ) from error

    return marker
