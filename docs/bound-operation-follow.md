# Bound provider operation follow — MVP boundary

Issue #122 adds a small provider-neutral read-only follow loop after live Jules dispatch/observe (#116/#117) and concurrent workstream isolation (#120/#121).

## Invariant

Controller follows one exact `TaskBinding -> ProviderOperationRef` chain. Repository proximity, recent provider sessions, provider prose, URLs, or account state do not authorize switching to another operation.

When a `WorkstreamBinding` is supplied, both the Controller task and provider operation must belong to that lane before the first provider read.

## Stop policy

The core follow policy uses only provider-neutral `AgentObservation` fields. It stops on:

- any `awaiting_input != NONE`;
- any terminal claim;
- `PLAN_REVIEW_REQUIRED`;
- `ARTIFACT_READY`, `REVIEW_REQUIRED`, or `REVIEW_READY`;
- `BLOCKED` or `UNCERTAIN`;
- an explicit elapsed-time bound;
- an explicit observation-count bound;
- malformed/mismatched observation or provider read failure.

Provider-native Jules/Codex state names remain adapter concerns and are not inspected by the core loop.

## Boundedness boundary

The elapsed/count limits bound the Controller polling loop and prevent infinite repeated polling. They are not a generic thread-cancellation mechanism for an individual `adapter.observe()` call. Each provider adapter/transport remains responsible for bounding its own provider I/O.

Accordingly, this MVP does **not** claim that `max_elapsed_seconds` can forcibly interrupt a provider read that never returns. Adding universal cross-provider call cancellation would require a separate transport/runtime design rather than hiding provider lifecycle behavior in the Controller core.

The follow loop does account for provider-read duration once the read returns, validates finite monotonic clock evidence, and fails closed on malformed/reversed clock evidence.

## Evidence shape

Repeated identical observations are counted but not appended to an unbounded transcript. The result retains:

- exact Controller task/operation/provider/workstream identity;
- first observation;
- final observation;
- only meaningful mapped-state / awaiting-input / terminal transitions;
- observation count;
- elapsed duration;
- stop/failure reason.

## Authority boundary

This slice is read-only. It adds no provider plan approval, `sendMessage`, cancellation/retry mutation, session creation, GitHub mutation, Ready/merge/release/deploy, owner-machine effect, routing, scheduler, daemon, or persistence service.

`PLAN_REVIEW_REQUIRED` / `PLAN_APPROVAL` is an attention boundary, never approval authority. Ready and merge remain human-final under ADR #90.
