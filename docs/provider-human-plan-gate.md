# Provider human plan gate flow

Issue #127 composes existing dispatch and bounded follow primitives across a human-final provider plan gate.

## Boundary

The Controller may dispatch one exactly bound provider operation and follow it until provider-neutral evidence reaches a genuine stop. When the final observation is `PLAN_REVIEW_REQUIRED` and/or `AwaitingInput.PLAN_APPROVAL`, Controller returns `HUMAN_PLAN_ACTION_REQUIRED` bound to the exact workstream, task, operation, provider operation id, and already-bound provider URL.

Controller does **not** approve or reject the provider plan.

The operator inspects and performs the provider-side action in the provider's own human-controlled UI. The operator does not need to copy a session id back into a new workflow or select a recent session.

## Resume rule

Resume requires the original `TaskBinding`, original `ProviderOperationRef`, and original `WorkstreamBinding` when named-lane mode is used.

Before the first resumed provider read, Controller revalidates task/operation/workstream identity. A changed provider operation id, provider, task id, operation id, or lane fails closed with zero resumed provider reads.

There is intentionally no `approved=True`, free-form human message, or similar parameter. Human prose is not authoritative lifecycle evidence. The resumed flow re-reads the provider and uses the existing provider-neutral mapper/follow policy:

- still awaiting plan approval -> surface the same exact human gate again;
- execution started -> continue following the same operation;
- blocked/failed/uncertain -> stop fail-closed;
- artifact/review/terminal boundary -> return that handoff.

Resume never redispatches a replacement session and never selects a session by repository proximity, recency, provider prose, or global attention ordering.

## Concurrent lanes

Same-repository workstreams remain isolated. A newer or more urgent provider operation in Lane B cannot replace the exact bound operation for Lane A. Workstream membership and operation binding remain Controller-owned facts.

## Operator interaction

At a plan gate, the structured action means only:

> Inspect and approve or reject the plan in the provider UI for this exact bound operation.

After the human action, invoke the resume path with the original bound identities. Controller then verifies what the provider actually did by re-reading authoritative provider state.

## Non-goals

This slice adds no provider plan-approval API call, `sendMessage`, automatic retry, replacement dispatch, routing, daemon/scheduler, GitHub Ready/merge/release/deploy, or owner-machine effect.

The next slice should connect provider artifact/terminal handoff into existing objective GitHub artifact/PR verification, CI, and review evidence.
