from __future__ import annotations

import base64
import binascii
import json
from dataclasses import asdict, dataclass
from enum import Enum
from types import MappingProxyType
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


SCHEMA_VERSION = "agent-controller-approval-challenge-v2"


class ProvenanceAssurance(str, Enum):
    VERIFIED_EVENT_PROVENANCE = "VERIFIED_EVENT_PROVENANCE"
    SOURCE_AUTHENTICATED_ONLY = "SOURCE_AUTHENTICATED_ONLY"
    PROVENANCE_UNAVAILABLE = "PROVENANCE_UNAVAILABLE"


# PoC-only Controller-pinned approval keys for deterministic test fixtures.
# Fixture private keys were generated only to create signatures and are not
# stored in this repository. Production enrollment/rotation remains separate.
_PINNED_APPROVAL_KEYS = MappingProxyType(
    {
        "human-key-poc-2": "Pxpq8/gqzFvE+96c3WI2QMsKIMHevr175Yy4e1EvS/E=",
        "human-key-poc-3": "wATGr7gy8bzoYR/1D6qjXQOU4bYb9akZCm3X9p/jUJ4=",
    }
)


@dataclass(frozen=True)
class ApprovalChallenge:
    approval_id: str
    approval_policy_id: str
    controller_task_id: str
    operation_id: str
    operation_version: str
    provider: str
    requested_capability: str
    effect: str
    repo: str
    target_kind: str
    target_id: str
    expected_head_sha: str
    challenge_nonce: str
    signer_key_id: str
    schema_version: str = SCHEMA_VERSION


@dataclass(frozen=True)
class SignedApprovalValidation:
    valid: bool
    assurance: ProvenanceAssurance
    reason: Optional[str] = None
    signer_key_id: Optional[str] = None


def canonicalize_approval_challenge(challenge: ApprovalChallenge) -> bytes:
    if not isinstance(challenge, ApprovalChallenge):
        raise TypeError("challenge must be ApprovalChallenge")
    values = asdict(challenge)
    for key, value in values.items():
        if not isinstance(value, str) or not value:
            raise ValueError(f"challenge field missing or invalid: {key}")
    if challenge.schema_version != SCHEMA_VERSION:
        raise ValueError("unsupported challenge schema")
    return (
        json.dumps(values, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode("utf-8")


def verify_signed_approval(
    *, challenge: ApprovalChallenge, signature_b64: str
) -> SignedApprovalValidation:
    try:
        message = canonicalize_approval_challenge(challenge)
    except (TypeError, ValueError) as exc:
        return SignedApprovalValidation(
            False, ProvenanceAssurance.PROVENANCE_UNAVAILABLE, str(exc)
        )

    pinned_public_key_b64 = _PINNED_APPROVAL_KEYS.get(challenge.signer_key_id)
    if pinned_public_key_b64 is None:
        return SignedApprovalValidation(
            False,
            ProvenanceAssurance.PROVENANCE_UNAVAILABLE,
            "SIGNER_KEY_NOT_CONFIGURED",
        )
    try:
        public_key_bytes = base64.b64decode(pinned_public_key_b64, validate=True)
        signature = base64.b64decode(signature_b64, validate=True)
    except (binascii.Error, ValueError):
        return SignedApprovalValidation(
            False,
            ProvenanceAssurance.PROVENANCE_UNAVAILABLE,
            "SIGNATURE_ENCODING_INVALID",
        )
    if len(public_key_bytes) != 32:
        return SignedApprovalValidation(
            False,
            ProvenanceAssurance.PROVENANCE_UNAVAILABLE,
            "PUBLIC_KEY_LENGTH_INVALID",
        )
    if len(signature) != 64:
        return SignedApprovalValidation(
            False,
            ProvenanceAssurance.PROVENANCE_UNAVAILABLE,
            "SIGNATURE_LENGTH_INVALID",
        )
    try:
        Ed25519PublicKey.from_public_bytes(public_key_bytes).verify(signature, message)
    except (ValueError, InvalidSignature):
        return SignedApprovalValidation(
            False,
            ProvenanceAssurance.PROVENANCE_UNAVAILABLE,
            "SIGNATURE_INVALID",
        )
    return SignedApprovalValidation(
        True,
        ProvenanceAssurance.VERIFIED_EVENT_PROVENANCE,
        signer_key_id=challenge.signer_key_id,
    )
