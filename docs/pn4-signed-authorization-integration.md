# PN4 signed authorization integration design

## Purpose

Integrate a cryptographically verified human approval challenge into the existing PN2 approval / PN3 execution model without treating local transcripts, GitHub prose, or caller-supplied keys as authority.

This design adds no high-impact executor.

## Core rule

A signature verification result is evidence, not yet an executable capability.

The Controller must durably and atomically advance one exact operation version through shared authorization state before any execution claim can exist.

## Exact binding

A signed approval challenge binds:

- approval_id
- controller_task_id
- operation_id
- operation_version
- effect
- repo
- target_kind
- target_id
- expected_head_sha
- challenge_nonce
- signer_key_id
- schema_version

The Controller must independently know the expected operation binding before signature verification. Candidate data never widens the expected binding.

## Shared state record

Canonical operation authorization record:

`controller-state/operations/<task>/<operation>/<version>.json`

Required immutable binding fields:

- approval_id
- approval_policy_id
- controller_task_id
- operation_id
- operation_version
- provider
- requested_capability
- effect
- repo
- target_kind
- target_id
- expected_head_sha

Required authorization provenance fields after human approval:

- assurance = VERIFIED_EVENT_PROVENANCE
- provenance_kind = SIGNED_CHALLENGE
- signer_key_id
- challenge_nonce
- challenge_digest
- signature_digest

Do not persist the raw signature unless later operational needs justify it. Never persist private key material.

## State machine

`PROPOSED -> HUMAN_APPROVED -> EXECUTION_CLAIMED -> EFFECT_STARTED -> EFFECT_VERIFIED`

Exception terminal/non-progress statuses may include:

- STALE
- BLOCKED
- UNCERTAIN
- FAILED_AFTER_CLAIM

### PROPOSED -> HUMAN_APPROVED

Requirements:

1. read current shared operation record and blob SHA;
2. require exact immutable binding and `state=PROPOSED`;
3. re-read objective target facts;
4. require target/head exact match;
5. verify Ed25519 signature against Controller-configured key for the signed `signer_key_id`;
6. require `VERIFIED_EVENT_PROVENANCE`;
7. CAS update using current blob SHA;
8. on stale SHA, re-read and classify idempotent replay vs conflicting approval;
9. if write outcome is uncertain, return UNCERTAIN and do not allow an execution claim until authoritative reread proves HUMAN_APPROVED.

Two distinct valid signatures for the same exact operation version do not create two approvals. The first accepted HUMAN_APPROVED record wins; later identical observations are replay, conflicting signer/challenge provenance is BLOCKED/CONFLICT unless future policy explicitly supports quorum approvals.

### HUMAN_APPROVED -> EXECUTION_CLAIMED

Requirements:

1. authoritative shared reread;
2. exact immutable binding match;
3. `state=HUMAN_APPROVED`;
4. assurance exactly VERIFIED_EVENT_PROVENANCE;
5. provenance kind SIGNED_CHALLENGE;
6. objective target reread immediately before claim;
7. CAS update to EXECUTION_CLAIMED with one execution_claim_id and controller_run_id;
8. loser of concurrent CAS rereads; same claim = replay, different claim = existing winner / replay, malformed state = BLOCKED.

Local PN3 execution ledger may remain as a compatibility/audit cache during migration but must not be the authority for multi-controller exactly-once semantics.

## Receipt model

A durable approval receipt may be derived only from an authoritative shared `HUMAN_APPROVED` state.

Receipt must retain:

- approval_id
- approval_policy_id
- controller_task_id
- operation_id
- operation_version
- provider
- requested_capability
- effect
- repo
- target_kind
- target_id
- expected_head_sha
- assurance
- provenance_kind
- signer_key_id
- challenge_nonce
- challenge_digest
- approval_record_version / shared-state commit identity

A caller-constructed receipt cannot authorize a claim.

## Execution claim model

Execution claim must retain/reference:

- execution_claim_id
- approval_receipt_id or shared authorization record identity
- approval_id
- operation_id
- operation_version
- effect / target / head binding
- assurance
- provenance_kind
- signer_key_id
- controller_run_id
- claimed_at

## Replay and multi-device semantics

- The same signed approval artifact delivered through two ChatGPT sessions is one logical authorization maximum.
- Two Controller instances observing the same signature race on shared CAS; one transition wins.
- A stale UI resubmission is replay, not a second effect capability.
- A signature for v1 cannot authorize v2.
- A signature for old head SHA cannot authorize a changed head.
- Approval after an effect cannot retroactively authorize that effect because effect execution requires prior authoritative EXECUTION_CLAIMED state.

## Key administration

The PoC module may contain a fixed test key, but production key enrollment/rotation is a separate administrative control plane.

Requirements:

- private key never enters Agent Controller, ChatGPT, GitHub Actions, repository state, logs, or prompts;
- trusted public-key configuration cannot be changed by the same untrusted per-call path that verifies approvals;
- adding/removing/replacing a trusted human approval key is itself LEVEL 3/admin-sensitive;
- key IDs are stable opaque identifiers and are signed inside the challenge;
- old keys need explicit ACTIVE/RETIRED/REVOKED semantics before production use.

## Migration plan

1. Keep PR #30 as a verifier PoC; no executor.
2. Implement shared operation-state adapter and schemas on a dedicated Controller state ref.
3. Add signed-approval `PROPOSED -> HUMAN_APPROVED` transition with CAS and objective reread.
4. Add `HUMAN_APPROVED -> EXECUTION_CLAIMED` transition with CAS.
5. Extend receipts/claims to retain PN4 provenance and operation_version.
6. Only after independent review, add a narrowly allowlisted high-impact executor that requires authoritative EXECUTION_CLAIMED.

Until steps 2-5 are merged and reviewed, signed verification alone must not authorize Ready/merge/deploy/release/provider-plan/owner-machine effects.
