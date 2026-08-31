# Jules REST per-request timeout — MVP boundary

Issue #124 closes the transport gap identified after Issue #122 / PR #123.

The provider-neutral follow loop has finite polling bounds, but those bounds can only be evaluated between completed `observe()` calls. The live Jules REST adapter therefore also needs a finite per-request HTTP timeout so one stalled network request does not leave normal Controller observation waiting indefinitely under its own transport configuration.

## Contract

`JulesApiClient` owns one explicit `request_timeout_seconds` setting. The default is finite and positive, and callers may provide another finite positive value.

Malformed values, booleans, zero/negative values, NaN, and infinities are rejected when the client is constructed, before provider/network I/O.

Every request performed through the real standard-library `urlopen` path receives this timeout, including source listing, session creation, and session reads.

The existing injectable `transport(req)` seam remains test plumbing and bypasses urllib itself. Deterministic timeout-forwarding tests therefore replace `agent_controller.jules_live.urlopen` with a fake rather than changing every existing provider fixture to a new transport protocol.

## Failure semantics

A timeout or network exception is sanitized using the existing Jules credential-redaction path. It is not a provider failure claim and does not grant retry, create-session, plan-approval, GitHub, Ready, merge, release, deploy, routing, or owner-machine authority.

When a Jules session read times out through the observation path, the bounded provider-neutral follow operation stops as a provider read error / `UNCERTAIN`. It does not retry automatically in this slice.

## Boundedness statement

Together:

- Issue #122 bounds repeated Controller polling by elapsed time / observation count; and
- Issue #124 bounds each normal live Jules urllib request by a finite per-request timeout.

This provides bounded normal observation attempts at the Controller + Jules HTTP transport layers. It does **not** claim an OS-level hard kill, process watchdog, or guarantee against every possible runtime/library failure mode.

## Non-goals

This slice does not add retries, backoff, async cancellation, scheduler/daemon behavior, provider routing, provider plan approval, `sendMessage`, GitHub mutation, Ready/merge, release/deploy, or owner-machine effects.
