from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import Enum
from typing import Optional

from agent_controller.signed_approval import (
    ApprovalChallengeV3,
    ProvenanceAssurance,
    SCHEMA_VERSION_V3,
    canonicalize_approval_challenge,
    verify_signed_approval,
)


class BrokerContinuityState(str, Enum):
    ACTIVE = "ACTIVE"
    RECOVERY_SUSPENDED = "RECOVERY_SUSPENDED"


@dataclass(frozen=True)
class TrustedBrokerAuthorityConfig:
    broker_authority_id: str
    broker_epoch: str
    continuity_state: BrokerContinuityState = BrokerContinuityState.ACTIVE

    def __post_init__(self) -> None:
        for name in ("broker_authority_id", "broker_epoch"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value:
                raise ValueError(f"{name} must be nonempty")
        if not isinstance(self.continuity_state, BrokerContinuityState):
            raise TypeError("continuity_state must be BrokerContinuityState")


@dataclass(frozen=True)
class EpochBoundApprovalValidation:
    valid: bool
    authorization_digest: Optional[str] = None
    reason: Optional[str] = None


class EpochBoundApprovalGate:
    """Validate production broker authority/epoch before anti-replay claim.

    The configured authority and epoch are Controller/broker composition inputs,
    never per-call values. This class does not mutate broker continuity state.
    """

    __slots__ = ("_config",)

    def __init__(self, *, config: TrustedBrokerAuthorityConfig) -> None:
        if not isinstance(config, TrustedBrokerAuthorityConfig):
            raise TypeError("config must be TrustedBrokerAuthorityConfig")
        self._config = config

    @property
    def config(self) -> TrustedBrokerAuthorityConfig:
        return self._config

    def validate_for_claim(
        self, *, challenge: ApprovalChallengeV3, signature_b64: str
    ) -> EpochBoundApprovalValidation:
        if self._config.continuity_state is not BrokerContinuityState.ACTIVE:
            return EpochBoundApprovalValidation(False, reason="BROKER_RECOVERY_SUSPENDED")
        if not isinstance(challenge, ApprovalChallengeV3):
            return EpochBoundApprovalValidation(False, reason="V3_CHALLENGE_REQUIRED")
        if challenge.schema_version != SCHEMA_VERSION_V3:
            return EpochBoundApprovalValidation(False, reason="V3_CHALLENGE_REQUIRED")
        if challenge.broker_authority_id != self._config.broker_authority_id:
            return EpochBoundApprovalValidation(False, reason="BROKER_AUTHORITY_MISMATCH")
        if challenge.broker_epoch != self._config.broker_epoch:
            return EpochBoundApprovalValidation(False, reason="BROKER_EPOCH_MISMATCH")
        verification = verify_signed_approval(
            challenge=challenge, signature_b64=signature_b64
        )
        if (
            not verification.valid
            or verification.assurance
            is not ProvenanceAssurance.VERIFIED_EVENT_PROVENANCE
            or verification.signer_key_id != challenge.signer_key_id
        ):
            return EpochBoundApprovalValidation(
                False, reason=verification.reason or "SIGNATURE_NOT_VERIFIED"
            )
        digest = hashlib.sha256(canonicalize_approval_challenge(challenge)).hexdigest()
        return EpochBoundApprovalValidation(True, authorization_digest=digest)
