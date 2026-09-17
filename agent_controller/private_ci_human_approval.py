from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable

from agent_controller.private_ci_phase0_evidence import (
    EXPECTED_BROKER_IDENTITY,
    EXPECTED_HOST,
)


APPROVAL_SCHEMA = "agent-controller.private-ci-human-approval.v1"
APPROVAL_FILENAME_PREFIX = "issue216-live-registration-approval-"
APPROVAL_MAX_AGE_SECONDS = 15 * 60
APPROVAL_FUTURE_SKEW_SECONDS = 30
SYSTEM_SID = "S-1-5-18"
ADMINISTRATORS_SID = "S-1-5-32-544"
TRUSTED_MUTATING_SIDS = frozenset((SYSTEM_SID, ADMINISTRATORS_SID))


@dataclass(frozen=True, slots=True)
class HumanApproval:
    schema: str
    plan_sha256: str
    host: str
    approver_identity: str
    approved_at: str


Now = Callable[[], datetime]


def approval_filename(plan_sha256: str) -> str:
    if (
        type(plan_sha256) is not str
        or len(plan_sha256) != 64
        or any(character not in "0123456789abcdef" for character in plan_sha256)
    ):
        raise ValueError("approval plan SHA-256 invalid")
    return f"{APPROVAL_FILENAME_PREFIX}{plan_sha256}.json"


def approval_sha256(raw: bytes) -> str:
    if type(raw) is not bytes:
        raise ValueError("approval artifact must be exact bytes")
    return hashlib.sha256(raw).hexdigest()


def parse_approval_bytes(
    raw: bytes,
    *,
    expected_plan_sha256: str,
    now: Now | None = None,
) -> HumanApproval:
    if type(raw) is not bytes:
        raise ValueError("approval artifact must be exact bytes")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("approval artifact JSON invalid") from error

    required = {
        "schema",
        "plan_sha256",
        "host",
        "approver_identity",
        "approved_at",
    }
    if type(payload) is not dict or set(payload) != required:
        raise ValueError("approval artifact shape invalid")
    if payload.get("schema") != APPROVAL_SCHEMA:
        raise ValueError("approval artifact schema invalid")
    if payload.get("plan_sha256") != expected_plan_sha256:
        raise ValueError("approval artifact plan SHA-256 mismatch")
    if payload.get("host") != EXPECTED_HOST:
        raise ValueError("approval artifact host mismatch")
    if payload.get("approver_identity") != EXPECTED_BROKER_IDENTITY:
        raise ValueError("approval artifact approver mismatch")

    approved_at_text = payload.get("approved_at")
    if type(approved_at_text) is not str or not approved_at_text:
        raise ValueError("approval artifact approved_at invalid")
    try:
        approved_at = datetime.fromisoformat(approved_at_text.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("approval artifact approved_at invalid") from error
    if approved_at.tzinfo is None or approved_at.utcoffset() is None:
        raise ValueError("approval artifact approved_at must be timezone-aware")

    current = (now or (lambda: datetime.now(timezone.utc)))()
    if current.tzinfo is None or current.utcoffset() is None:
        raise ValueError("approval validation clock must be timezone-aware")
    age_seconds = (current - approved_at).total_seconds()
    if age_seconds < -APPROVAL_FUTURE_SKEW_SECONDS:
        raise ValueError("approval artifact timestamp is in the future")
    if age_seconds > APPROVAL_MAX_AGE_SECONDS:
        raise ValueError("approval artifact is stale")

    return HumanApproval(
        schema=payload["schema"],
        plan_sha256=payload["plan_sha256"],
        host=payload["host"],
        approver_identity=payload["approver_identity"],
        approved_at=payload["approved_at"],
    )


def validate_approval_acl_state(payload: object) -> None:
    if type(payload) is not dict:
        raise ValueError("approval ACL readback shape invalid")
    if payload.get("protected") is not True:
        raise ValueError("approval ACL inheritance is not protected")

    owner_sid = payload.get("owner_sid")
    if owner_sid not in TRUSTED_MUTATING_SIDS:
        raise ValueError("approval ACL owner is not trusted")

    rules = payload.get("rules")
    if type(rules) is not list:
        raise ValueError("approval ACL rules shape invalid")

    trusted_mutating_allows: set[str] = set()
    for rule in rules:
        if type(rule) is not dict:
            raise ValueError("approval ACL rule shape invalid")
        sid = rule.get("sid")
        access_type = rule.get("access_type")
        inherited = rule.get("inherited")
        can_mutate = rule.get("can_mutate")
        if type(sid) is not str or access_type not in ("Allow", "Deny"):
            raise ValueError("approval ACL rule identity invalid")
        if type(inherited) is not bool or type(can_mutate) is not bool:
            raise ValueError("approval ACL rule flags invalid")
        if inherited:
            raise ValueError("approval ACL contains inherited rule")
        if access_type == "Allow" and can_mutate:
            if sid not in TRUSTED_MUTATING_SIDS:
                raise ValueError("approval ACL grants mutation to untrusted principal")
            trusted_mutating_allows.add(sid)

    if trusted_mutating_allows != set(TRUSTED_MUTATING_SIDS):
        raise ValueError("approval ACL missing trusted mutating principals")
