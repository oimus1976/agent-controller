#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path

from agent_controller.private_ci_live_registration_runtime import authoritative_path
from agent_controller.private_ci_phase0_collector import collect_validated_phase0_evidence
from agent_controller.private_ci_phase0_evidence import phase0_canonical_bytes

PHASE0_FILENAME = "issue216-phase0-canonical.json"


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


def main() -> int:
    try:
        output = authoritative_path(PHASE0_FILENAME)
        if output.exists():
            raise RuntimeError("authoritative Phase 0 evidence already exists; do not overwrite automatically")
        evidence = collect_validated_phase0_evidence(_controller_repo_root())
        raw = phase0_canonical_bytes(evidence)
        _write_exclusive(output, raw)
        print("PHASE0_PASS")
        print(f"evidence={output}")
        print(f"evidence_sha256={hashlib.sha256(raw).hexdigest()}")
        print("NO_LIVE_PILOT_EFFECT_PERFORMED")
        return 0
    except Exception as error:
        print(f"BLOCKED: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
