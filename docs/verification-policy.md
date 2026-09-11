# Verification Policy

This policy defines how Agent Controller decides whether to stop verification or escalate it. It applies across workstreams unless a more specific runbook defines stricter requirements.

## 1. Declare observable invariants first

Before verification starts, define the smallest required set of observable invariants.

Use both when needed:

- **positive invariants**: facts that must be true;
- **negative invariants**: facts that must not be true.

Do not replace required invariants with free-form impressions such as "looks suspicious" or "seems fine".

## 2. Normal verification

For ordinary installation, configuration, recovery, build, and test work:

1. Verify the declared invariants directly where possible.
2. If all required invariants pass and no observable anomaly predicate matches, return `PASS` and stop.
3. Do not escalate only because a log is truncated, incomplete, noisy, or contains warnings. Treat that case according to whether required evidence is still available.
4. Escalate only when at least one of these is true:
   - a named observable anomaly predicate matches;
   - required evidence is missing;
   - observed state contradicts expected state.
5. Free-form suspicion is not a valid escalation reason until it is reduced to a reproducible predicate.

Normal stop condition:

```text
all required invariants PASS
AND no observable anomaly predicate matched
=> PASS
=> STOP
```

## 3. Security-sensitive verification

Treat authentication, authorization, identities/SIDs, secrets, ACLs, exact-head binding, isolation, sandboxing, process ownership, persistence, and cleanup across a trust boundary as security-sensitive.

For security-sensitive verification:

1. Declare all required trust-boundary invariants explicitly.
2. Do not infer a trust invariant from general functional success.
3. Do not substitute approximate, indirect, or missing evidence for a required trust invariant.
4. If a required trust invariant is not verified, return `UNCERTAIN` or `BLOCKED`; never promote it to `PASS`.
5. Preserve existing fail-closed behavior for ambiguous access, ownership, credentials, isolation, exact-head, persistence, and cleanup state.
6. Once every declared trust invariant is explicitly verified and no trust-boundary uncertainty remains, return `PASS` and stop; do not continue into implementation internals without a matching predicate.

Security stop condition:

```text
all required positive invariants PASS
AND all required negative invariants PASS
AND no trust-boundary uncertainty remains
=> PASS
=> STOP
```

## 4. Observable anomaly predicates

An escalation predicate must identify:

- a predicate ID or stable name;
- the observed value/state;
- the expected value/state;
- the affected invariant.

Examples:

```text
EXIT_ZERO_ARTIFACT_MISSING
observed: command exit = 0, required artifact absent
expected: required artifact present
affected invariant: artifact_exists
```

```text
REGISTRATION_PATH_MISMATCH
observed: registration points to path A
expected: registration points to path B
affected invariant: trusted_runtime_path
```

The statement `looks suspicious` without an observable predicate does not authorize deeper diagnostics.

## 5. Bounded escalation

When deeper evidence is required, escalate one level at a time:

```text
L0: direct observable state
L1: command / wrapper result
L2: subsystem log
L3: implementation / installer / framework internals
```

Move to the next level only when the current level establishes a concrete predicate or cannot supply required evidence.

Do not jump directly to deeper internals because more logs are available.

## 6. Outcomes

Use the existing `VerificationResult` vocabulary consistently:

- `PASS`: all required invariants are verified and no blocking predicate remains;
- `FAIL`: observed evidence contradicts a required invariant;
- `BLOCKED`: verification cannot validly proceed because a prerequisite, policy gate, or trust-boundary requirement blocks it;
- `UNCERTAIN`: required evidence is unavailable or inconclusive;
- `NOT_RUN`: verification was not attempted.

`UNCERTAIN` and `BLOCKED` must never be treated as `PASS`.

## 7. Prohibited behavior

Do not:

- expand investigation solely because something "looks suspicious";
- treat every truncated or incomplete log as failure or automatic escalation;
- continue deep diagnostics after sufficient evidence already satisfies the applicable stop condition;
- weaken or skip declared trust-boundary invariants because the operation appears to work;
- use fail-closed as a justification for unbounded investigation.

## 8. Minimal decision rule

```text
if security_sensitive:
    require every declared trust invariant

if all required invariants pass and no blocking predicate matches:
    PASS and STOP
elif observed state contradicts a required invariant:
    FAIL
elif a policy or trust-boundary prerequisite blocks valid verification:
    BLOCKED
elif required evidence is missing or inconclusive:
    UNCERTAIN
elif a named observable predicate matches and deeper evidence is required:
    escalate one level
```
