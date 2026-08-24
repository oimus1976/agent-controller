from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional


CONTROLLER_STATE_REF = "controller-state"


class RepositoryWritePurpose(str, Enum):
    IMPLEMENTATION_BRANCH = "IMPLEMENTATION_BRANCH"
    CONTROLLER_STATE = "CONTROLLER_STATE"
    DIRECT_DEFAULT_BRANCH_ADMIN = "DIRECT_DEFAULT_BRANCH_ADMIN"


class RepositoryWriteDecision(str, Enum):
    PASS = "PASS"
    BLOCKED = "BLOCKED"
    UNCERTAIN = "UNCERTAIN"


@dataclass(frozen=True)
class RepositoryWriteTarget:
    repo: str
    explicit_ref: Optional[str]
    purpose: RepositoryWritePurpose


@dataclass(frozen=True)
class RepositoryWritePolicy:
    repo: str
    default_branch: str
    controller_state_ref: str = CONTROLLER_STATE_REF
    allow_direct_default_branch_admin: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.repo, str) or not self.repo:
            raise ValueError("repo must be a non-empty string")
        if not isinstance(self.default_branch, str) or not self.default_branch:
            raise ValueError("default_branch must be a non-empty string")
        if self.controller_state_ref != CONTROLLER_STATE_REF:
            raise ValueError("controller_state_ref is fixed by Controller composition")


@dataclass(frozen=True)
class RepositoryWriteValidation:
    decision: RepositoryWriteDecision
    normalized_ref: Optional[str] = None
    reason: Optional[str] = None


def _normalize_ref(value: Optional[str]) -> Optional[str]:
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    if not stripped:
        return None
    if stripped.startswith("refs/heads/"):
        stripped = stripped[len("refs/heads/") :]
    return stripped or None


def validate_repository_write_target(
    *,
    policy: RepositoryWritePolicy,
    target: RepositoryWriteTarget,
) -> RepositoryWriteValidation:
    """Fail-closed policy gate for any repository content/ref mutation.

    This function does not perform a write. All write adapters must call it
    before invoking a write-side API. Omitting a ref is never interpreted as
    the repository default branch.
    """

    if not isinstance(policy, RepositoryWritePolicy):
        return RepositoryWriteValidation(
            RepositoryWriteDecision.UNCERTAIN, reason="WRITE_POLICY_INVALID"
        )
    if not isinstance(target, RepositoryWriteTarget):
        return RepositoryWriteValidation(
            RepositoryWriteDecision.BLOCKED, reason="WRITE_TARGET_INVALID"
        )
    if target.repo != policy.repo:
        return RepositoryWriteValidation(
            RepositoryWriteDecision.BLOCKED, reason="WRITE_REPO_MISMATCH"
        )
    if not isinstance(target.purpose, RepositoryWritePurpose):
        return RepositoryWriteValidation(
            RepositoryWriteDecision.BLOCKED, reason="WRITE_PURPOSE_INVALID"
        )

    ref = _normalize_ref(target.explicit_ref)
    if ref is None:
        return RepositoryWriteValidation(
            RepositoryWriteDecision.BLOCKED, reason="EXPLICIT_REF_REQUIRED"
        )
    if ref in {"HEAD", "head", ".", ".."}:
        return RepositoryWriteValidation(
            RepositoryWriteDecision.BLOCKED, reason="WRITE_REF_ALIAS_FORBIDDEN"
        )
    if "\x00" in ref or ref.startswith("/") or ref.endswith("/"):
        return RepositoryWriteValidation(
            RepositoryWriteDecision.BLOCKED, reason="WRITE_REF_INVALID"
        )

    if target.purpose is RepositoryWritePurpose.IMPLEMENTATION_BRANCH:
        if ref == policy.default_branch:
            return RepositoryWriteValidation(
                RepositoryWriteDecision.BLOCKED,
                normalized_ref=ref,
                reason="DEFAULT_BRANCH_WRITE_FORBIDDEN",
            )
        if ref == policy.controller_state_ref:
            return RepositoryWriteValidation(
                RepositoryWriteDecision.BLOCKED,
                normalized_ref=ref,
                reason="CONTROLLER_STATE_REQUIRES_DEDICATED_PURPOSE",
            )
        return RepositoryWriteValidation(RepositoryWriteDecision.PASS, normalized_ref=ref)

    if target.purpose is RepositoryWritePurpose.CONTROLLER_STATE:
        if ref != policy.controller_state_ref:
            return RepositoryWriteValidation(
                RepositoryWriteDecision.BLOCKED,
                normalized_ref=ref,
                reason="CONTROLLER_STATE_REF_MISMATCH",
            )
        return RepositoryWriteValidation(RepositoryWriteDecision.PASS, normalized_ref=ref)

    if target.purpose is RepositoryWritePurpose.DIRECT_DEFAULT_BRANCH_ADMIN:
        if ref != policy.default_branch:
            return RepositoryWriteValidation(
                RepositoryWriteDecision.BLOCKED,
                normalized_ref=ref,
                reason="DIRECT_DEFAULT_BRANCH_TARGET_MISMATCH",
            )
        if not policy.allow_direct_default_branch_admin:
            return RepositoryWriteValidation(
                RepositoryWriteDecision.BLOCKED,
                normalized_ref=ref,
                reason="DIRECT_DEFAULT_BRANCH_ADMIN_DISABLED",
            )
        return RepositoryWriteValidation(RepositoryWriteDecision.PASS, normalized_ref=ref)

    return RepositoryWriteValidation(
        RepositoryWriteDecision.BLOCKED, reason="WRITE_PURPOSE_INVALID"
    )
