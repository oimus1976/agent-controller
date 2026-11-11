"""#316 deferred Phase 0 transaction primitive.

A caller must supply an independently verified target release/poststate
callback (``private_ci_phase0_target_hold.TargetProfileHold`` for the real
path). This module never starts target processes, reads credentials, or claims
live authority.
"""
from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from agent_controller.private_ci_phase0_evidence import (
    phase0_canonical_bytes,
    validate_phase0_evidence_bytes,
)
from agent_controller.private_ci_pilot_identity import (
    parse_pilot_identity_freeze_bytes,
)


@dataclass(frozen=True)
class DeferredPhase0Result:
    sha256: str
    output: Path


def write_exclusive(path: Path, content: bytes) -> None:
    """Create-only write; an existing slot is never overwritten."""
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        try:
            path.unlink()
        except OSError:
            pass
        raise


def deferred_phase0_commit(
    *,
    freeze_path: Path,
    expected_freeze_sha256: str,
    output: Path,
    collect: Callable[[object], object],
    release_and_verify: Callable[[], bool],
    exclusive_write: Callable[[Path, bytes], None],
) -> DeferredPhase0Result:
    """Stage validated evidence in memory, release, then exclusively commit.

    Caller must hold the owner's exact authorization (including any #195
    decision) before *any* target profile load. This function grants none.
    The release callback MUST independently prove owned-child exit and restored
    PID/HKU/ProfileList/session baseline; false/exception means no canonical write.
    """
    if type(expected_freeze_sha256) is not str or len(expected_freeze_sha256) != 64 or any(
        c not in "0123456789abcdef" for c in expected_freeze_sha256
    ):
        raise RuntimeError("invalid expected freeze digest")
    if output.exists() or output.is_symlink():
        raise RuntimeError("canonical Phase 0 slot already occupied")
    if not freeze_path.is_file() or freeze_path.is_symlink():
        raise RuntimeError("freeze absent or not regular")
    raw_freeze = freeze_path.read_bytes()
    if hashlib.sha256(raw_freeze).hexdigest() != expected_freeze_sha256:
        raise RuntimeError("freeze digest mismatch")
    freeze = parse_pilot_identity_freeze_bytes(raw_freeze)
    pending: bytes | None = None
    collection_error: BaseException | None = None
    try:
        evidence = collect(freeze)
        pending = phase0_canonical_bytes(evidence)
        validate_phase0_evidence_bytes(pending)
    except BaseException as exc:
        collection_error = exc
    finally:
        # Release is attempted even if collection fails. Any uncertain release
        # blocks the canonical write; never treat a synthetic callback as proof
        # of the real WOBBUFFET native poststate.
        # An exception from the callback is as uncertain as a False result.
        try:
            restored = release_and_verify()
        except BaseException as exc:
            raise RuntimeError("STOP_PARTIAL_PROFILE_STATE") from exc
        if restored is not True:
            raise RuntimeError("STOP_PARTIAL_PROFILE_STATE")
    if collection_error is not None:
        raise collection_error
    if pending is None:
        raise RuntimeError("phase0 evidence unavailable")
    # Reject freeze drift between collection and commit, and rely on the
    # exclusive writer for the final race (no overwrite, no retry).
    if not freeze_path.is_file() or freeze_path.is_symlink():
        raise RuntimeError("freeze changed during collection")
    if freeze_path.read_bytes() != raw_freeze:
        raise RuntimeError("freeze changed during collection")
    exclusive_write(output, pending)
    # A mismatching file is left in place on purpose: the slot stays occupied,
    # so nothing can retry or overwrite it without a human decision.
    if output.read_bytes() != pending:
        raise RuntimeError("STOP_CANONICAL_READBACK_MISMATCH")
    return DeferredPhase0Result(hashlib.sha256(pending).hexdigest(), output)
