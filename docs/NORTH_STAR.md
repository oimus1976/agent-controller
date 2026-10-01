# Agent Controller North Star

The intended North Star for Agent Controller is a **provider-neutral control plane that turns a human task into bounded AI work, routes that work to suitable providers/models using capability plus capacity/cost evidence, coordinates implementation/review/remediation across heterogeneous agents, verifies results from authoritative evidence, and returns only consequential decisions to the human.**

This document restates the existing product direction. It does not replace the owning Issues/ADRs and does not grant new authority.

## End-to-end product path

```text
Human intent
    |
    v
Natural-language / task intake
    |
    v
Canonical TaskSpec
    |
    v
Task / risk / reasoning classification
    |
    v
Provider + model eligibility
    |
    v
Capacity / cost-aware routing
    |
    +----------------+----------------+----------------+
    |                |                |                |
    v                v                v                v
  Codex            Jules         Antigravity       other agents
    |                |                |                |
    +----------------+----------------+----------------+
                         |
                         v
              Bounded execution / implementation
                         |
                         v
             GitHub-authoritative publication/evidence
                         |
                         v
                 Deterministic CI
                         |
                         v
              Independent exact-head review
                         |
                         v
              Bounded remediation loop
                         |
                         v
                 HUMAN_GATE_READY
                         |
                         v
          Human Ready / merge / other human-final effects
```

The Controller should automate work and verification, not silently absorb final authority.

## What exists now

These are current building blocks, not yet one unattended product flow.

| Capability | Current status | Primary authority / implementation |
|---|---|---|
| Provider-neutral core and heterogeneous-agent architecture | Available as standing architecture | ADR #12 |
| Human-final boundary for Ready, merge, release/deploy, destructive and other LEVEL 3 effects | Available as standing policy | ADR #90 |
| GitHub-authoritative evidence, exact-head inspection, CI/review separation | Available | #194 and current inspector/review paths |
| Codex task observation and exact GitHub target verification | Available as bounded primitives | current CLI `observe-codex`, `verify-codex-target` |
| Codex independent review/remediation request primitives | Available as bounded primitives | current CLI `request-codex-review`, `request-codex-remediation` |
| Jules dispatch/observation adapter | Available as bounded provider adapter | current CLI `dispatch-jules`, `observe-jules` |
| Antigravity bounded review-only evidence adapter | Available as bounded review/evidence adapter; not a general implementation adapter | #183 / PR #184 |
| Provider-capacity observation and recommendation | Available as recommendation, not automatic fallback | #168, parent #55 |
| Resource/token/context efficiency and reasoning-tier direction | Standing optimization direction | #55 |
| Windows private one-job CI execution substrate | Live pilot in progress | #216 |
| Personal/single-owner cost-effectiveness priority | Standing policy | #279 |

## Designed or specified, but not yet composed into the product flow

| Capability | Status | Primary issue |
|---|---|---|
| Canonical provider-neutral TaskSpec / operation binding | Design exists; implementation not complete | #178 |
| Draft PR review -> remediation -> rereview loop | Bounded state-machine design exists; not yet fully composed | #215 |
| Codex completed-task vs branch-apply state enforcement | Specified; not yet fully enforced | #200 |
| Broader provider-capacity-aware dispatch composition | Recommendation exists; automatic dispatch/fallback remains deferred | #168 / #55 |

## Not current capabilities

The following are part of the intended product experience or plausible future composition, but must not be described as existing Agent Controller behavior today:

- conversational Japanese/natural-language intake that converts a user request into a canonical TaskSpec;
- automatic selection of the best model/reasoning level directly from an arbitrary user prompt;
- automatic second-choice / third-choice provider fallback when allowance is depleted;
- fully unattended end-to-end orchestration from user request through implementation, CI, review, remediation, and Draft PR.

Starting paid-provider usage without explicit human authorization is **not a future automation target** under the standing capacity policy; routing may only use paid capacity after the human has authorized that paid usage.

Automatic Ready, merge, release, deployment, destructive cleanup, and other human-final effects are **not future automation targets** under ADR #90; they remain human-final unless that governing authority is explicitly changed by the owner.

Future routing should prefer explicit eligibility and reason codes over opaque "best model" scoring. Capacity, cost, role separation, expected completion chain, and provider fitness are separate inputs.

## Multi-agent intent

Multi-agent means **specialized heterogeneous workers under one control plane**, not necessarily a group chat of agents.

A representative composition is:

```text
Task planning / binding     -> Controller-owned contract
Implementation              -> eligible coding provider (for example Jules or Codex)
Independent review          -> materially independent provider/context
Remediation                 -> bounded provider operation
Deterministic verification  -> Controller / GitHub / CI, not provider self-report
Final authority             -> human
```

The specific provider may change with capability, capacity, cost, and independence needs. Provider-native states remain adapter-level observations rather than Controller truth.

## Where #216 fits

**Issue #216 is an execution-substrate milestone, not the product end-state.**

Its purpose is to prove that the Controller can safely execute exactly one human-authorized private Windows CI job under a bounded non-admin identity, then tear it down and prove zero residual authority.

In the North Star, #216 belongs under one execution channel:

```text
Agent Controller
  |
  +-- hosted provider execution
  |
  +-- provider review / analysis
  |
  +-- owner-machine / private local CI execution   <- #216
```

Completing #216 proves an important execution path. It does not by itself deliver natural-language intake, provider/model routing, multi-agent composition, or unattended orchestration.

## Decision priority

Unless the owner explicitly changes the context, Agent Controller is a personal, single-owner development project.

Optimize first for:

1. cost-effectiveness;
2. time to a usable release;
3. the smallest reliable mechanism that addresses a concrete, likely, material failure mode.

Do not add organization-scale ceremony, speculative automation, or another Controller mechanism when an existing supported path or concise human step has better marginal value.

These priorities do not weaken secret protection, evidence integrity, consumed-authority rules, destructive-action boundaries, or human-final authority.

## Product compass

When choosing the next implementation work, ask:

1. Does this move the end-to-end path closer to **human intent -> verified AI work -> human-only consequential decisions**?
2. Does it improve provider/model choice, multi-agent specialization, verified execution, or operator effort in a measurable way?
3. Is the capability already available through an existing provider/API/CLI or current Controller primitive?
4. Is the added safety/control proportional to a realistic personal-development failure mode?
5. Are we improving the product flow, or only making one execution substrate more elaborate?

Owning records remain authoritative: ADR #12, ADR #90, #55, #168, #178, #183, #200, #215, #216, #279, and their current successors.
