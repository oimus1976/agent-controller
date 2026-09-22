from __future__ import annotations

import hashlib

from agent_controller.private_ci_phase5_result import parse_phase5_result_bytes
from agent_controller.private_ci_phase6_result import parse_phase6_result_bytes
from agent_controller.private_ci_phase7_result import parse_phase7_result_bytes
from agent_controller.private_ci_final_publication import (
    consume_final_pass_publication,
)


FINAL_PRIVATE_CI_PASS = "SELF_HOSTED_PRIVATE_CI_PASS"


def classify_final_private_ci_pilot(
    phase5_result_bytes: bytes,
    phase6_result_bytes: bytes,
    phase7_result_bytes: bytes,
) -> str:
    phase5 = parse_phase5_result_bytes(phase5_result_bytes)
    phase6 = parse_phase6_result_bytes(phase6_result_bytes)
    phase7 = parse_phase7_result_bytes(phase7_result_bytes)

    if phase5.binding != phase6.binding or phase6.binding != phase7.binding:
        raise ValueError("final evidence binding mismatch")

    phase5_sha = hashlib.sha256(phase5_result_bytes).hexdigest()
    if phase6.phase5_result_sha256 != phase5_sha:
        raise ValueError("final Phase 5 evidence hash mismatch")

    phase6_sha = hashlib.sha256(phase6_result_bytes).hexdigest()
    if phase7.phase6_result_sha256 != phase6_sha:
        raise ValueError("final Phase 6 evidence hash mismatch")

    consume_final_pass_publication(
        phase5_result_bytes=phase5_result_bytes,
        phase6_result_bytes=phase6_result_bytes,
        phase7_result_bytes=phase7_result_bytes,
    )
    return FINAL_PRIVATE_CI_PASS
