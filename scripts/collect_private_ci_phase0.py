#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import os
import sys
from pathlib import Path

from agent_controller.private_ci_live_registration_runtime import authoritative_path
from agent_controller.private_ci_phase0_collector import (
    collect_validated_phase0_evidence,
)
from agent_controller.private_ci_phase0_evidence import phase0_canonical_bytes
from agent_controller.private_ci_pilot_identity import (
    parse_pilot_identity_freeze_bytes,
)

PHASE0_FILENAME = "issue216-phase0-canonical.json"
PILOT_FREEZE_FILENAME = "issue216-pilot-identity-freeze.json"


def _controller_repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _write_exclusive(path: Path, content: bytes) -> None:
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


def _require_digest(value: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise RuntimeError("expected pilot freeze SHA-256 invalid")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Collect canonical #216 Phase 0 evidence from a reviewed fresh pilot identity freeze"
    )
    parser.add_argument("--expected-freeze-sha256", required=True)
    options = parser.parse_args()

    try:
        expected_freeze_sha = _require_digest(
            options.expected_freeze_sha256
        )
        output = authoritative_path(PHASE0_FILENAME)
        freeze_path = authoritative_path(PILOT_FREEZE_FILENAME)
        if output.exists():
            raise RuntimeError(
                "authoritative Phase 0 evidence already exists; do not overwrite automatically"
            )
        if not freeze_path.is_file() or freeze_path.is_symlink():
            raise RuntimeError(
                "authoritative pilot identity freeze is missing or invalid"
            )

        freeze_raw = freeze_path.read_bytes()
        observed_freeze_sha = hashlib.sha256(freeze_raw).hexdigest()
        if observed_freeze_sha != expected_freeze_sha:
            raise RuntimeError("pilot identity freeze SHA-256 mismatch")
        freeze = parse_pilot_identity_freeze_bytes(freeze_raw)

        controller_root = _controller_repo_root()
        if str(controller_root).casefold() != freeze.controller_tree.casefold():
            raise RuntimeError(
                "controller execution tree does not match pilot identity freeze"
            )

        evidence = collect_validated_phase0_evidence(
            controller_root,
            pilot_freeze=freeze,
        )
        raw = phase0_canonical_bytes(evidence)
        _write_exclusive(output, raw)
        print("PHASE0_PASS")
        print(f"pilot_freeze={freeze_path}")
        print(f"pilot_freeze_sha256={observed_freeze_sha}")
        print(f"evidence={output}")
        print(f"evidence_sha256={hashlib.sha256(raw).hexdigest()}")
        print("NO_LIVE_PILOT_EFFECT_PERFORMED")
        return 0
    except Exception as error:
        print(f"BLOCKED: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
