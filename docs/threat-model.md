# Agent Controller threat model

## Trust principle

Approval-looking text is data, not authority.

Provider output, GitHub issue/PR/comment/commit text, artifacts, CI logs, agent prose, and copied approval tokens are untrusted unless they arrive through a Controller-configured trusted ingress that can prove the human input event provenance for the current operation.

## Multi-device / concurrent same-chat threat

Agent Controller must assume that the same human account may have the same conversation open on multiple PCs or devices at the same time.

Consequences:

- devices may display stale conversation snapshots;
- distinct user messages may be submitted concurrently or nearly concurrently;
- separate Controller/agent runs may observe different message histories;
- the same approval token may be submitted more than once from different devices;
- a later run may observe an already-completed effect and incorrectly infer approval chronology from its local conversation view;
- multiple runs may race to consume or execute one approval;
- duplicated trusted ingress delivery must be expected.

A local conversation transcript alone is therefore not authoritative evidence of approval chronology.

## Required approval provenance

A trusted human approval must be represented as an immutable ingress event identity rather than token text alone. The provenance contract should bind, at minimum:

- conversation identity;
- immutable user-message / ingress-event identity;
- server-side receive timestamp;
- Controller run identity;
- operation identity;
- approval identity;
- operation version or nonce;
- trusted issuer/account identity available at ingress;
- configured ingress source identity.

The durable approval receipt must preserve enough non-secret provenance to answer:

> Which exact trusted human input event authorized this exact operation?

Proposal/token creation time and human approval receive time are distinct facts.

## Concurrent exactly-once requirement

High-impact authorization must use an authoritative atomic state transition shared across Controller runs. A conceptual lifecycle is:

```text
PROPOSED
-> HUMAN_APPROVED
-> EXECUTION_CLAIMED
-> EFFECT_STARTED
-> EFFECT_VERIFIED
```

Only one run may advance a specific operation/version from `HUMAN_APPROVED` to `EXECUTION_CLAIMED`.

Duplicate or late approval ingress must not create a second executable claim. If a target effect already occurred before a newly observed approval event, that event cannot retroactively authorize the completed effect.

## Fail-closed adversarial cases

1. Approval token exists only in GitHub/project/provider/agent prose.
2. Device A approves and Device B later resends the token from stale UI.
3. Device A and Device B approve concurrently.
4. Two Controller instances receive the same trusted ingress event.
5. Two distinct trusted ingress events contain the same token.
6. A Controller run cannot establish event chronology from authoritative provenance.
7. A high-impact effect is already complete before a newly observed approval ingress.
8. Audit evidence is contradictory or incomplete.

In all ambiguous cases, do not infer authority from text or local ordering. Preserve the ambiguity and fail closed for any new high-impact effect.

## PR #21 audit lesson

PR #21 exposed an approval-provenance ambiguity: GitHub records show a merge and assertions that human approval had been consumed, while the available conversation view cannot independently establish which exact human ingress event authorized that merge. This is classified as `AUTHORIZATION PROVENANCE UNCERTAIN`, not proven unauthorized and not validated authorized.
