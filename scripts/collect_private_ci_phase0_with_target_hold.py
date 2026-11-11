#!/usr/bin/env python3
"""#316 one-shot: hold the target profile, collect Phase 0, release, verify, commit.

Owner-launched from the frozen controller tree:

    python.exe -s -E -B -m scripts.collect_private_ci_phase0_with_target_hold --expected-freeze-sha256 <sha>

The canonical Phase 0 file is written only after the target child has exited
and an independent observation shows the profile restored. ``--preflight-only``
performs the read-only checks and stops before any effect.
"""
from __future__ import annotations

import argparse
import hashlib
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from agent_controller.private_ci_live_registration_runtime import authoritative_path
from agent_controller.private_ci_phase0_collector import (
    collect_validated_phase0_evidence,
)
from agent_controller.private_ci_phase0_deferred import (
    deferred_phase0_commit,
    write_exclusive,
)
from agent_controller.private_ci_phase0_target_hold import (
    HOLD_SCRIPT_NAME,
    TargetProfileHold,
    read_target_profile_state,
)
from agent_controller.private_ci_pilot_identity import (
    parse_pilot_identity_freeze_bytes,
)

PHASE0_FILENAME = "issue216-phase0-canonical.json"
PILOT_FREEZE_FILENAME = "issue216-pilot-identity-freeze.json"
EXIT_BLOCKED = 2
EXIT_STOP_PARTIAL = 3


def _controller_repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _run(*command: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(command),
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
    )


class _Transcript:
    """Console plus an exclusive, secret-free log in the evidence root."""

    def __init__(self) -> None:
        self._handle = None

    def open(self) -> Path:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        path = authoritative_path(f"issue216-phase0-target-hold-{stamp}.log")
        self._handle = open(path, "x", encoding="utf-8")
        return path

    def __call__(self, message: str) -> None:
        line = f"{datetime.now(timezone.utc).isoformat()} {message}"
        print(line, flush=True)
        if self._handle is not None:
            self._handle.write(line + "\n")
            self._handle.flush()

    def close(self) -> None:
        if self._handle is not None:
            self._handle.close()
            self._handle = None


def run(
    expected_freeze_sha256: str,
    *,
    preflight_only: bool,
    hold_factory=TargetProfileHold,
    collector=collect_validated_phase0_evidence,
    state_command_runner=_run,
    controller_root: Path | None = None,
    hold_script: Path | None = None,
    output: Path | None = None,
    freeze_path: Path | None = None,
    log: _Transcript | None = None,
) -> int:
    log = log or _Transcript()
    hold = None
    try:
        if (
            type(expected_freeze_sha256) is not str
            or len(expected_freeze_sha256) != 64
            or any(c not in "0123456789abcdef" for c in expected_freeze_sha256)
        ):
            raise RuntimeError("expected pilot freeze SHA-256 invalid")
        output = output or authoritative_path(PHASE0_FILENAME)
        freeze_path = freeze_path or authoritative_path(PILOT_FREEZE_FILENAME)
        controller_root = controller_root or _controller_repo_root()
        if output.exists() or output.is_symlink():
            raise RuntimeError(
                "authoritative Phase 0 evidence already exists; do not overwrite automatically"
            )
        if not freeze_path.is_file() or freeze_path.is_symlink():
            raise RuntimeError("authoritative pilot identity freeze is missing or invalid")
        freeze_raw = freeze_path.read_bytes()
        if hashlib.sha256(freeze_raw).hexdigest() != expected_freeze_sha256:
            raise RuntimeError("pilot identity freeze SHA-256 mismatch")
        freeze = parse_pilot_identity_freeze_bytes(freeze_raw)
        if str(controller_root).casefold() != freeze.controller_tree.casefold():
            raise RuntimeError("controller execution tree does not match pilot identity freeze")
        hold_script = hold_script or controller_root / "scripts" / HOLD_SCRIPT_NAME
        if not hold_script.is_file() or hold_script.is_symlink():
            raise RuntimeError("target hold script missing")

        hold = hold_factory(
            hold_script=hold_script,
            host=freeze.host,
            state_reader=lambda: read_target_profile_state(
                state_command_runner, freeze.target_identity
            ),
            progress=log,
        )
        hold.preflight()
        if preflight_only:
            log("PREFLIGHT_OK target idle; freeze and tree bound")
            log("NO_EFFECT_PERFORMED")
            return 0

        transcript = log.open() if isinstance(log, _Transcript) else None
        log(f"start one-shot Phase 0 with target hold freeze_sha256={expected_freeze_sha256}")

        def collect(parsed_freeze):
            hold.acquire()
            log("collecting strict Phase 0 v3 evidence (staged in memory)")
            return collector(controller_root, pilot_freeze=parsed_freeze)

        result = deferred_phase0_commit(
            freeze_path=freeze_path,
            expected_freeze_sha256=expected_freeze_sha256,
            output=output,
            collect=collect,
            release_and_verify=hold.release_and_verify,
            exclusive_write=write_exclusive,
        )
        log(f"outcome={hold.outcome}")
        log("PHASE0_PASS")
        log(f"pilot_freeze={freeze_path}")
        log(f"pilot_freeze_sha256={expected_freeze_sha256}")
        log(f"evidence={result.output}")
        log(f"evidence_sha256={result.sha256}")
        if transcript is not None:
            log(f"transcript={transcript}")
        log("NO_RUNNER_REGISTRATION_OR_WORKFLOW_DISPATCH_PERFORMED")
        return 0
    except Exception as error:
        outcome = getattr(hold, "outcome", None)
        if outcome:
            log(f"outcome={outcome}")
        if str(error) == "STOP_PARTIAL_PROFILE_STATE":
            log(
                "STOP_PARTIAL_PROFILE_STATE: target profile restoration is not proven. "
                "No Phase 0 evidence written. Do not retry, unload or repair; "
                "report to the owner for a separate recovery decision."
            )
            return EXIT_STOP_PARTIAL
        log(f"BLOCKED: {error}")
        log("NO_PHASE0_EVIDENCE_WRITTEN")
        return EXIT_BLOCKED
    finally:
        if isinstance(log, _Transcript):
            log.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--expected-freeze-sha256", required=True)
    parser.add_argument(
        "--preflight-only",
        action="store_true",
        help="read-only checks; never opens the credential dialog or starts the target",
    )
    options = parser.parse_args()
    return run(options.expected_freeze_sha256, preflight_only=options.preflight_only)


if __name__ == "__main__":
    raise SystemExit(main())
