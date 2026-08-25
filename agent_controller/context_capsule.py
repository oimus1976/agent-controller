from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import Enum
from typing import Optional, Protocol, runtime_checkable


CAPSULE_SCHEMA_VERSION = "agent-controller-context-capsule-v1"


class EvidenceSourceKind(str, Enum):
    GITHUB_COMMIT = "GITHUB_COMMIT"
    FILE_AT_COMMIT = "FILE_AT_COMMIT"
    PR_HEAD = "PR_HEAD"
    CI_RUN = "CI_RUN"
    ISSUE_COMMENT = "ISSUE_COMMENT"
    LOCAL_ARTIFACT = "LOCAL_ARTIFACT"
    PROVIDER_TELEMETRY = "PROVIDER_TELEMETRY"
    OTHER = "OTHER"


class EvidenceAuthority(str, Enum):
    OBJECTIVE_VERIFIED = "OBJECTIVE_VERIFIED"
    CONTROLLER_MEASURED = "CONTROLLER_MEASURED"
    PROVIDER_REPORTED = "PROVIDER_REPORTED"
    AGENT_REPORTED = "AGENT_REPORTED"
    UNKNOWN = "UNKNOWN"


class EvidenceFreshness(str, Enum):
    IMMUTABLE = "IMMUTABLE"
    MUTABLE_RECHECK_REQUIRED = "MUTABLE_RECHECK_REQUIRED"
    EPHEMERAL = "EPHEMERAL"


class RetrievalAction(str, Enum):
    REUSE_VERIFIED_IMMUTABLE = "REUSE_VERIFIED_IMMUTABLE"
    FETCH_MUTABLE = "FETCH_MUTABLE"
    FETCH_MISSING = "FETCH_MISSING"
    FETCH_FOR_SECURITY_GATE = "FETCH_FOR_SECURITY_GATE"
    OMIT_IRRELEVANT = "OMIT_IRRELEVANT"


@dataclass(frozen=True)
class EvidencePointer:
    source_kind: EvidenceSourceKind
    source_ref: str
    authority: EvidenceAuthority
    freshness: EvidenceFreshness
    content_digest: Optional[str] = None

    def __post_init__(self) -> None:
        if not isinstance(self.source_kind, EvidenceSourceKind):
            raise TypeError("source_kind must be EvidenceSourceKind")
        if not isinstance(self.authority, EvidenceAuthority):
            raise TypeError("authority must be EvidenceAuthority")
        if not isinstance(self.freshness, EvidenceFreshness):
            raise TypeError("freshness must be EvidenceFreshness")
        if not isinstance(self.source_ref, str) or not self.source_ref:
            raise ValueError("source_ref must be nonempty")
        if self.content_digest is not None and (
            not isinstance(self.content_digest, str)
            or len(self.content_digest) != 64
            or any(c not in "0123456789abcdef" for c in self.content_digest)
        ):
            raise ValueError("content_digest must be lowercase SHA-256 when present")


@dataclass(frozen=True)
class CapsuleFact:
    key: str
    summary: str
    evidence: tuple[EvidencePointer, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.key, str) or not self.key:
            raise ValueError("key must be nonempty")
        if not isinstance(self.summary, str) or not self.summary:
            raise ValueError("summary must be nonempty")
        if not isinstance(self.evidence, tuple) or not self.evidence:
            raise ValueError("evidence must be a nonempty tuple")
        if any(not isinstance(item, EvidencePointer) for item in self.evidence):
            raise TypeError("evidence must contain EvidencePointer values")


@dataclass(frozen=True)
class ContextCapsule:
    controller_task_id: str
    operation_id: str
    operation_version: str
    facts: tuple[CapsuleFact, ...]
    must_recheck: tuple[str, ...] = ()
    unknowns: tuple[str, ...] = ()
    schema_version: str = CAPSULE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        for name in ("controller_task_id", "operation_id", "operation_version"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value:
                raise ValueError(f"{name} must be nonempty")
        if self.schema_version != CAPSULE_SCHEMA_VERSION:
            raise ValueError("unsupported context capsule schema")
        if not isinstance(self.facts, tuple) or any(not isinstance(item, CapsuleFact) for item in self.facts):
            raise TypeError("facts must be a tuple of CapsuleFact")
        keys = [fact.key for fact in self.facts]
        if len(set(keys)) != len(keys):
            raise ValueError("fact keys must be unique")
        for name in ("must_recheck", "unknowns"):
            values = getattr(self, name)
            if not isinstance(values, tuple) or any(not isinstance(item, str) or not item for item in values):
                raise TypeError(f"{name} must be a tuple of nonempty strings")
            if len(set(values)) != len(values):
                raise ValueError(f"{name} values must be unique")


@dataclass(frozen=True)
class RetrievalRequest:
    key: str
    relevant: bool = True
    required_for_security_gate: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.key, str) or not self.key:
            raise ValueError("key must be nonempty")
        if not isinstance(self.relevant, bool) or not isinstance(self.required_for_security_gate, bool):
            raise TypeError("retrieval flags must be bool")


@dataclass(frozen=True)
class RetrievalDecision:
    key: str
    action: RetrievalAction
    reason: str


@runtime_checkable
class VerifiedImmutableFactSource(Protocol):
    """Read-only trust boundary for previously verified operation-bound facts."""

    def is_verified_fact(self, bound_fact_digest: str) -> bool: ...


def _pointer_dict(pointer: EvidencePointer) -> dict[str, object]:
    return {
        "authority_claim": pointer.authority.value,
        "content_digest": pointer.content_digest,
        "freshness": pointer.freshness.value,
        "source_kind": pointer.source_kind.value,
        "source_ref": pointer.source_ref,
    }


def canonicalize_capsule_fact(fact: CapsuleFact) -> bytes:
    if not isinstance(fact, CapsuleFact):
        raise TypeError("fact must be CapsuleFact")
    evidence = sorted(
        (_pointer_dict(pointer) for pointer in fact.evidence),
        key=lambda item: (
            str(item["source_kind"]),
            str(item["source_ref"]),
            str(item["content_digest"]),
            str(item["authority_claim"]),
            str(item["freshness"]),
        ),
    )
    payload = {"evidence": evidence, "key": fact.key, "summary": fact.summary}
    return (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def capsule_fact_digest(fact: CapsuleFact) -> str:
    return hashlib.sha256(canonicalize_capsule_fact(fact)).hexdigest()


def bound_capsule_fact_digest(*, capsule: ContextCapsule, fact: CapsuleFact) -> str:
    if not isinstance(capsule, ContextCapsule):
        raise TypeError("capsule must be ContextCapsule")
    if not isinstance(fact, CapsuleFact):
        raise TypeError("fact must be CapsuleFact")
    payload = {
        "controller_task_id": capsule.controller_task_id,
        "fact_digest": capsule_fact_digest(fact),
        "operation_id": capsule.operation_id,
        "operation_version": capsule.operation_version,
        "schema_version": capsule.schema_version,
    }
    canonical = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def canonicalize_context_capsule(capsule: ContextCapsule) -> bytes:
    if not isinstance(capsule, ContextCapsule):
        raise TypeError("capsule must be ContextCapsule")
    facts = [
        json.loads(canonicalize_capsule_fact(fact))
        for fact in sorted(capsule.facts, key=lambda item: item.key)
    ]
    payload = {
        "controller_task_id": capsule.controller_task_id,
        "facts": facts,
        "must_recheck": sorted(capsule.must_recheck),
        "operation_id": capsule.operation_id,
        "operation_version": capsule.operation_version,
        "schema_version": capsule.schema_version,
        "unknowns": sorted(capsule.unknowns),
    }
    return (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def context_capsule_digest(capsule: ContextCapsule) -> str:
    return hashlib.sha256(canonicalize_context_capsule(capsule)).hexdigest()


class ContextRetrievalPlanner:
    """Plan minimal reads without accepting capsule self-asserted truth."""

    __slots__ = ("_verified_source",)

    def __init__(self, *, verified_source: VerifiedImmutableFactSource) -> None:
        if not isinstance(verified_source, VerifiedImmutableFactSource):
            raise TypeError("verified_source must satisfy VerifiedImmutableFactSource")
        self._verified_source = verified_source

    def _reusable_fact(self, *, capsule: ContextCapsule, fact: CapsuleFact) -> bool:
        if any(pointer.freshness is not EvidenceFreshness.IMMUTABLE for pointer in fact.evidence):
            return False
        if any(
            pointer.authority not in {EvidenceAuthority.OBJECTIVE_VERIFIED, EvidenceAuthority.CONTROLLER_MEASURED}
            for pointer in fact.evidence
        ):
            return False
        try:
            return self._verified_source.is_verified_fact(
                bound_capsule_fact_digest(capsule=capsule, fact=fact)
            ) is True
        except Exception:
            return False

    def plan(
        self,
        *,
        capsule: ContextCapsule,
        controller_task_id: str,
        operation_id: str,
        operation_version: str,
        requests: tuple[RetrievalRequest, ...],
    ) -> tuple[RetrievalDecision, ...]:
        if not isinstance(capsule, ContextCapsule):
            raise TypeError("capsule must be ContextCapsule")
        if (capsule.controller_task_id, capsule.operation_id, capsule.operation_version) != (
            controller_task_id,
            operation_id,
            operation_version,
        ):
            raise ValueError("CONTEXT_CAPSULE_BINDING_MISMATCH")
        if not isinstance(requests, tuple) or any(not isinstance(request, RetrievalRequest) for request in requests):
            raise TypeError("requests must be a tuple of RetrievalRequest")

        facts = {fact.key: fact for fact in capsule.facts}
        must_recheck = set(capsule.must_recheck)
        unknowns = set(capsule.unknowns)
        decisions: list[RetrievalDecision] = []
        for request in requests:
            if not request.relevant:
                decisions.append(RetrievalDecision(request.key, RetrievalAction.OMIT_IRRELEVANT, "NOT_RELEVANT"))
                continue
            if request.required_for_security_gate:
                decisions.append(
                    RetrievalDecision(
                        request.key,
                        RetrievalAction.FETCH_FOR_SECURITY_GATE,
                        "SECURITY_GATE_REQUIRES_FRESH_EVIDENCE",
                    )
                )
                continue
            if request.key in unknowns or request.key not in facts:
                decisions.append(
                    RetrievalDecision(request.key, RetrievalAction.FETCH_MISSING, "EVIDENCE_UNKNOWN_OR_MISSING")
                )
                continue
            fact = facts[request.key]
            if request.key in must_recheck or any(
                pointer.freshness is not EvidenceFreshness.IMMUTABLE for pointer in fact.evidence
            ):
                decisions.append(
                    RetrievalDecision(request.key, RetrievalAction.FETCH_MUTABLE, "MUTABLE_EVIDENCE_RECHECK_REQUIRED")
                )
                continue
            if self._reusable_fact(capsule=capsule, fact=fact):
                decisions.append(
                    RetrievalDecision(
                        request.key,
                        RetrievalAction.REUSE_VERIFIED_IMMUTABLE,
                        "EXACT_VERIFIED_OPERATION_BOUND_IMMUTABLE_FACT",
                    )
                )
                continue
            decisions.append(
                RetrievalDecision(
                    request.key,
                    RetrievalAction.FETCH_MISSING,
                    "OPERATION_BOUND_IMMUTABLE_FACT_NOT_CONFIRMED_BY_VERIFICATION_SOURCE",
                )
            )
        return tuple(decisions)
