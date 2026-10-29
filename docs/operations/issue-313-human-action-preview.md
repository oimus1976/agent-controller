# #313: agent-prepared action preview (Draft / NON_EXECUTABLE)

## Decision and trust boundary

The owner wants agents to do preparation, evidence collection, verification and
checkpoint writing, without copying GitHub approval comments, IDs, SHA-256
strings, time windows or terminal commands. **Human-final effects remain human
actions** under [ADR #90](https://github.com/oimus1976/agent-controller/issues/90).
This issue does not authorize a new #305 diagnostic.

The GitHub connector can write as the same GitHub principal as the owner.
Per [#29](https://github.com/oimus1976/agent-controller/issues/29), a comment
or workflow event posted through that credential cannot prove separate human
consent. A static CLI switch, generated approval-looking flag, issue comment,
or an agent-triggered GUI click is **not** human-final authorization.

The smallest prospective route is a **locally owner-triggered Run/Cancel entry**
which displays the precise operation and risks before claim reservation, binds
the confirmed choice to freshly rechecked immutable local bytes, and uses a
Windows trusted credential dialog only if required. The agent prepares all
non-effect steps and reads the postcondition; it does not operate that final
entry. This is a design, **not a currently verified available interface**.

## Implemented slice (read-only, no new authority)

The new Python module at scripts/issue313_action_preview.py reads an explicitly
supplied pair of existing #310 prospective packet/plan files and emits a compact
Japanese JSON review card. It checks basic JSON structure, duplicate keys,
non-finite numbers, exact plan raw SHA/size, candidate pin consistency,
expected schemas, and the packet's explicit authority_granted=false.
It does **not** open referenced paths, use GitHub APIs, inspect the Windows
host, write files, launch PowerShell, create a claim, or accept an approval.

The card always reports PREVIEW_ONLY_NO_AUTHORITY, with
native_freshness_verified=false, human_consent_verified=false,
execution_authorized=false and
next_human_action=UNAVAILABLE_UNTIL_TRUSTED_LOCAL_ENTRY_REVIEWED.

It omits local paths, SIDs, usernames, invocations and credentials. The
fingerprints in the card are **agent trace data**, not strings for the owner
to copy. The source packet is untrusted even if internal pins match. A stale
or fully forged but internally consistent source cannot become executable
through this module. It is a presentation adapter, not a new verifier or
approval primitive.

The previous #310 packet and #305 B are expired/non-reusable. Do not
repackage, rehash or reuse them to make a new runnable operation. The current
preview module has no path to the #310 effect stage.

## Synthetic acceptance and exclusions

| Criterion | State |
|---|---|
| Deterministic, non-secret Japanese risk/scope card | Covered by 7 synthetic Python tests |
| Bad schema, forged authority flag, bad plan SHA/size/candidate, duplicate keys, malformed JSON | Rejected in synthetic tests |
| Expired prospective window or altered authority reference cannot become a consent token | Covered: result stays non-authorizing; current freshness is not checked |
| No owner copy/paste or command transcription in the preview itself | Covered: output contains no execution command |
| One genuine local human Run/Cancel interaction | **Not implemented**; requires actual Windows entry/provenance capability |
| Fresh native preflight, claim, concurrency, execution and independent restoration | **Not implemented by #313**; existing #310 code is unchanged |
| Real #305 profile load, target state, credentials, WOBBUFFET operation | **Not run; not authorized** |
| Independent exact-head review and Windows CI | Pending until verified on this PR |

## Why this slice, and not a new service

A one-off manual Windows diagnostic might be cheaper than a new approval
service, signed challenge infrastructure, resident broker or generalized
approval protocol. This slice reuses the #310 packet and limits the new
surface to read-only presentation plus tests. It does not pretend to solve
the central owner-presence trust boundary in a GitHub-only environment.

**Next engineering gate:** on an owner-authorized Windows development
environment, independently inspect whether a native, non-agent-operable
owner-triggered entry can be built without a new trust service. The
pre-effect code must reject unattended invocations and spoofed approval,
and preserve the #310 fail-closed, one-claim, no-retry and postread behavior.
If that boundary cannot be demonstrated, stop and compare a simple
human-operated one-off diagnostic instead. Any new execution admission
path needs separate implementation, independent exact-head review and
human-final code integration, followed by separate explicit authority
for a real diagnostic.

This Draft does not change the old #310 B/window ingress or its PS1,
does not touch #312/PR #314, and grants no Ready, merge or live effect.
