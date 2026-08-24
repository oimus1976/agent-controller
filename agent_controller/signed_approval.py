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


SCHEMA_VERSION = "agent-controller-approval-challenge-v1"


class ProvenanceAssurance(str, Enum):
    VERIFIED_EVENT_PROVENANCE = "VERIFIED_EVENT_PROVENANCE"
    SOURCE_AUTHENTICATED_ONLY = "SOURCE_AUTHENTICATED_ONLY"
    PROVENANCE_UNAVAILABLE = "PROVENANCE_UNAVAILABLE"


# PoC-only Controller-pinned approval keys. The supported verification API does
# not accept public-key material or a key store from the caller. Production key
# enrollment/rotation must be a separately gated administrative operation.
_PINNED_APPROVAL_KEYS = MappingProxyType(
    {
        "human-key-poc-1": "rF1T3bTO5L9g4Wu34X42Kqh55voQdsfU92eqQ38xP+Q=",
    }
)


@dataclass(frozen=True)
class ApprovalChallenge:
    approval_id: str
    controller_task_id: str
    operation_id: str
    operation_version: str
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
    """Return the exact canonical bytes signed outside Agent Controller."""

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
    *,
    challenge: ApprovalChallenge,
    signature_b64: str,
) -> SignedApprovalValidation:
    """Verify an Ed25519 signature against a Controller-pinned approval key.

    Public-key material is intentionally not a per-call input. A valid result
    proves possession of the private key corresponding to the configured key ID
    for the exact signed challenge. It does not prove physical presence.
    """

    try:
        message = canonicalize_approval_challenge(challenge)
    except (TypeError, ValueError) as exc:
        return SignedApprovalValidation(
            False,
            ProvenanceAssurance.PROVENANCE_UNAVAILABLE,
            str(exc),
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
