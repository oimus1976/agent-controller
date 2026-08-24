from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional


CONTROLLER_STATE_REF = "controller-state"


class RepositoryWritePurpose(str, Enum):
    IMPLEMENTATION_BRANCH = "IMPLEMENTATION_BRANCH"
    CONTROLLER_STATE = "CONTROLLER_STATE"


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


class RepositoryWriteGuard:
    """Controller-composed fail-closed gate for repository mutations.

    The protected repository/default-branch identity is fixed when the Controller
    is composed. Per-mutation callers supply only a RepositoryWriteTarget and
    cannot redefine the default branch or enable direct-default-branch writes.

    Direct writes to the default branch are deliberately outside this generic
    guard. If ever supported, they require a separate high-risk capability and
    approval path.
    """

    __slots__ = ("_repo", "_default_branch")

    def __init__(self, *, repo: str, default_branch: str) -> None:
        if not isinstance(repo, str) or not repo:
            raise ValueError("repo must be a non-empty string")
        if not isinstance(default_branch, str) or not default_branch:
            raise ValueError("default_branch must be a non-empty string")
        self._repo = repo
        self._default_branch = default_branch

    @property
    def repo(self) -> str:
        return self._repo

    @property
    def default_branch(self) -> str:
        return self._default_branch

    def validate(self, *, target: RepositoryWriteTarget) -> RepositoryWriteValidation:
        if not isinstance(target, RepositoryWriteTarget):
            return RepositoryWriteValidation(
                RepositoryWriteDecision.BLOCKED, reason="WRITE_TARGET_INVALID"
            )
        if target.repo != self._repo:
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

        if ref == self._default_branch:
            return RepositoryWriteValidation(
                RepositoryWriteDecision.BLOCKED,
                normalized_ref=ref,
                reason="DEFAULT_BRANCH_WRITE_FORBIDDEN",
            )

        if target.purpose is RepositoryWritePurpose.IMPLEMENTATION_BRANCH:
            if ref == CONTROLLER_STATE_REF:
                return RepositoryWriteValidation(
                    RepositoryWriteDecision.BLOCKED,
                    normalized_ref=ref,
                    reason="CONTROLLER_STATE_REQUIRES_DEDICATED_PURPOSE",
                )
            return RepositoryWriteValidation(
                RepositoryWriteDecision.PASS, normalized_ref=ref
            )

        if target.purpose is RepositoryWritePurpose.CONTROLLER_STATE:
            if ref != CONTROLLER_STATE_REF:
                return RepositoryWriteValidation(
                    RepositoryWriteDecision.BLOCKED,
                    normalized_ref=ref,
                    reason="CONTROLLER_STATE_REF_MISMATCH",
                )
            return RepositoryWriteValidation(
                RepositoryWriteDecision.PASS, normalized_ref=ref
            )

        return RepositoryWriteValidation(
            RepositoryWriteDecision.BLOCKED, reason="WRITE_PURPOSE_INVALID"
        )
