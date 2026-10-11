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

## Verified checkpoint resume (#307)

`agent_controller.workflow_resume.plan_workflow_resume` is a separate read-only Python API for continuing one exact task/operation/workstream. It accepts 1–32 ordered `ResumeStep` values, an existing `TaskBinding` and `WorkstreamBinding`, a UTC/offset-aware `now`, and a Controller-configured `TrustedResumeSource`. It returns per-stage actions/reasons, checkpoint/evidence IDs, retained decision IDs, spent attempt IDs and the first actionable stage. Only that first stage is the next planning item; later classifications are context, never permission to bypass it. `to_dict()` always reports `advisory_only=true`, `execution_authorized=false` and `spent_authority_reusable=false`.

```python
from agent_controller.workflow_resume import TrustedResumeSource, plan_workflow_resume

# These objects come from the existing Controller composition, not provider text.
plan = plan_workflow_resume(
    task=bound_task, workstream=bound_workstream, steps=ordered_steps,
    source=TrustedResumeSource(verified_checkpoint_adapter, trusted_approval_ingress),
    now="2026-10-11T00:00:00Z",
)
next_stage = plan.first_actionable_step
print(plan.to_dict())  # Advisory output only; no executor or authority receipt.
```

The configured adapter implements `ResumeEvidenceSource` read methods. It loads the existing persisted checkpoint into typed immutable records and externally verifies **the entire exact checkpoint and each record**, including identity, provenance, accepted scope and revocation; an evidence ID's existence alone is insufficient. `decision_state` must verify that the human accepted the full `ResumeScope` (repo, target/optional head, host/SID, executable hash, allowed effects and risk envelope), and `read_facts` supplies fresh objective facts. Existing `TrustedApprovalIngress` validation separately checks human issuer, ingress, task/operation, target/head, effect, policy and time conditions. A live adapter must use the existing canonical inspector/client authority paths. This slice provides the classifier and synthetic adapters, not a new live ingestion path: neither deserializing JSON, wrapping a source nor an issue/chat/provider assertion authenticates evidence.

Persisted records have an explicit outcome for every stage, including `NOT_RUN` for incomplete stages. `ResumeCheckpoint.to_dict()` supplies a JSON-compatible representation; a trusted upstream owns storage, typed rehydration and independent verification after restart. No new database or approval ledger is needed. Corrupt/missing/ambiguous records, wrong task/operation/workstream or unverified content stop deterministically. Scope-only decisions may omit `head_sha` and expiry; head-sensitive decisions must provide the exact head. Revalidation never extends or retroactively widens the accepted scope.

| Action | Meaning at continuation |
|---|---|
| `SKIP_VERIFIED` | Exact completed outcome, applicable decision and current facts are verified; retain the outcome. |
| `RECHECK` | Refresh objective read-only facts; a completed effect is never rerun because freshness expired. |
| `RERUN_NONLIVE` | Incomplete LEVEL 0–2 non-effect stage may be planned within existing authority. |
| `HUMAN_ACTION_REQUIRED` | Changed/withheld/revoked/expired decision or a new effect-bearing/LEVEL 3 attempt needs human action. |
| `STOP_UNCERTAIN` | Unverified evidence, malformed input or partial/uncertain effects must be resolved before retry. |

For a consumed failed Stage 4, the plan preserves the spent attempt ID as history and asks for a fresh attempt. It returns no reusable capability, nonce, marker or `PASS_TO_OPERATOR`. Freshness conditions such as `PHASE0_READINESS=BLOCKED` remain reported blockers even when a scope decision is retained. Human Ready, merge and live effects remain outside this API.

Concrete operator trace (synthetic five-stage workflow):

```text
Before: 1–3 PASS; 4 FAIL / attempt-4 spent → ask approvals 1, 2, 3, then new 4.
After:  reverify exact checkpoint + fresh facts → 1–3 SKIP_VERIFIED;
        retain decision-1/2/3 → first_actionable_step=4;
        HUMAN_ACTION_REQUIRED / FRESH_ATTEMPT_REQUIRED; attempt-4 cannot replay.
        Repeat approvals for 1–3: 3 → 0. Human decisions needed now: new 4 only.
```

Acceptance evidence in `tests/test_workflow_resume.py`:

| AC | Deterministic evidence |
|---|---|
| AC-1 | Five stages resume at 4; retained decisions for 1–3; stale completed mutation requests `RECHECK`. |
| AC-2 | Every scope dimension, revocation/expiry and unchanged scope-only decisions after time/read refresh. |
| AC-3 | Missing/raw/corrupt/ambiguous/unverified checkpoints, malformed facts, wrong ingress/issuer/binding. |
| AC-4 | Consumed failed 4 preserves earlier outcomes; partial/uncertain effects stop even with scope drift. |
| AC-5 | Synthetic A-approved/B-withheld and B-approved/expired/drifted fixtures; unloaded hive reported as `PHASE0_READINESS=BLOCKED`, no execution handoff authority. |
| AC-6 | Persisted JSON rehydrated in a separate process; same-repository workflows cannot cross-reuse evidence. |
| AC-7 | All classifications and continued planning, unchanged input/no mutation dependencies; existing `test_approval_consumption`, `test_execution_handoff`, `test_operator_step_gate` protect one-shot semantics. |
| AC-8 | Draft PR checkpoint records exact-head Linux/Windows CI and independent review; the trace above shows reduced approvals. Ready/merge remain human actions. |
