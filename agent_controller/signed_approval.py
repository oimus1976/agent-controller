from __future__ import annotations

import base64
import binascii
import json
from dataclasses import asdict, dataclass
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


SCHEMA_VERSION = "agent-controller-approval-challenge-v1"


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
    schema_version: str = SCHEMA_VERSION


@dataclass(frozen=True)
class SignedApprovalValidation:
    valid: bool
    assurance: str
    reason: Optional[str] = None
    signer_key_id: Optional[str] = None


def canonicalize_approval_challenge(challenge: ApprovalChallenge) -> bytes:
    """Return the single canonical byte representation used for signing.

    This function intentionally contains no signing capability and never accepts
    arbitrary extra fields. The private key belongs outside Agent Controller.
    """

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
    pinned_public_key_b64: str,
    signer_key_id: str,
) -> SignedApprovalValidation:
    """Verify an Ed25519 signature from a Controller-pinned human approval key.

    A valid signature proves possession of the private key corresponding to the
    pinned public key for the exact canonical challenge. It does not prove
    physical presence. The function has no private-key generation/storage and no
    effect executor.
    """

    if not signer_key_id:
        return SignedApprovalValidation(False, "PROVENANCE_UNAVAILABLE", "SIGNER_KEY_ID_MISSING")

    try:
        message = canonicalize_approval_challenge(challenge)
    except (TypeError, ValueError) as exc:
        return SignedApprovalValidation(False, "PROVENANCE_UNAVAILABLE", str(exc))

    try:
        public_key_bytes = base64.b64decode(pinned_public_key_b64, validate=True)
        signature = base64.b64decode(signature_b64, validate=True)
    except (binascii.Error, ValueError):
        return SignedApprovalValidation(False, "PROVENANCE_UNAVAILABLE", "SIGNATURE_ENCODING_INVALID")

    if len(public_key_bytes) != 32:
        return SignedApprovalValidation(False, "PROVENANCE_UNAVAILABLE", "PUBLIC_KEY_LENGTH_INVALID")
    if len(signature) != 64:
        return SignedApprovalValidation(False, "PROVENANCE_UNAVAILABLE", "SIGNATURE_LENGTH_INVALID")

    try:
        Ed25519PublicKey.from_public_bytes(public_key_bytes).verify(signature, message)
    except (ValueError, InvalidSignature):
        return SignedApprovalValidation(False, "PROVENANCE_UNAVAILABLE", "SIGNATURE_INVALID")

    return SignedApprovalValidation(
        True,
        "VERIFIED_EVENT_PROVENANCE",
        signer_key_id=signer_key_id,
    )
