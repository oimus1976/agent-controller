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
   - a named observable anomaly predicate matches and deeper evidence is needed to resolve it;
   - required evidence is missing and a named predicate identifies what deeper evidence can resolve it.
5. If observed state directly contradicts a required invariant, return `FAIL`.
6. Free-form suspicion is not a valid escalation reason until it is reduced to a reproducible predicate.

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
4. If a required invariant is unverified and a named predicate identifies deeper evidence that can resolve it within the remaining escalation budget, escalate one level before returning a terminal result.
5. If a prerequisite or policy gate prevents valid verification, return `BLOCKED`. If required evidence remains unavailable or inconclusive after bounded escalation, return `UNCERTAIN`. Never promote either to `PASS`.
6. Preserve existing fail-closed behavior for ambiguous access, ownership, credentials, isolation, exact-head, persistence, and cleanup state.
7. Return `PASS` only when every applicable required invariant, including every trust-boundary invariant, is explicitly verified, no observable anomaly predicate matches, and no trust-boundary uncertainty remains.

Security stop condition:

```text
all applicable required invariants PASS
AND all required trust-boundary invariants PASS
AND no observable anomaly predicate matched
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

Move to the next level only when the current level establishes a concrete predicate or cannot supply required evidence and a named predicate identifies what the next level can resolve.

Each verification run must have a finite escalation budget. A more specific runbook may define a stricter finite budget. Otherwise, allow at most one escalation transition per level and no same-level diagnostic retry after a predicate is established. Budget exhaustion terminates as `UNCERTAIN` unless observed evidence already requires `FAIL` or a prerequisite/policy gate requires `BLOCKED`.

Do not jump directly to deeper internals because more logs are available.

## 6. Outcomes

Use the existing `VerificationResult` vocabulary consistently:

- `PASS`: all applicable required invariants are verified, no observable anomaly predicate matches, and no required uncertainty remains;
- `FAIL`: observed evidence contradicts a required invariant;
- `BLOCKED`: verification cannot validly proceed because a prerequisite, policy gate, or trust-boundary requirement blocks it;
- `UNCERTAIN`: required evidence is unavailable or inconclusive and bounded escalation cannot currently resolve it;
- `NOT_RUN`: verification was not attempted.

`UNCERTAIN` and `BLOCKED` must never be treated as `PASS`.

## 7. Prohibited behavior

Do not:

- expand investigation solely because something "looks suspicious";
- treat every truncated or incomplete log as failure or automatic escalation;
- continue deep diagnostics after sufficient evidence already satisfies the applicable stop condition;
- weaken or skip declared trust-boundary invariants because the operation appears to work;
- exceed the declared escalation budget;
- use fail-closed as a justification for unbounded investigation.

## 8. Minimal decision rule

```text
if observed state contradicts a required invariant:
    FAIL and STOP
elif a prerequisite or policy gate blocks valid verification:
    BLOCKED and STOP
elif all applicable required invariants pass
     and no observable anomaly predicate matches
     and no required uncertainty remains:
    PASS and STOP
elif a named observable predicate matches
     and deeper evidence can resolve it
     and escalation budget remains:
    escalate one level
elif required evidence is missing or inconclusive
     or escalation budget is exhausted:
    UNCERTAIN and STOP
```
