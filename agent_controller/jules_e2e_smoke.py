from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Mapping, Protocol

from agent_controller.github_draft_publication import GitHubRestDraftPublicationBackend
from agent_controller.jules_changesets import JulesChangeSetReadClient
from agent_controller.jules_draft_publication import (
    DraftPublicationResult,
    publish_jules_changeset_to_draft_pr,
)
from agent_controller.jules_live import JulesApiClient, JulesDispatchClient, JulesReadClient
from agent_controller.operation_follow import FollowStopReason
from agent_controller.provider_adapters import JulesObservationAdapter
from agent_controller.provider_artifacts import JulesArtifactAdapter
from agent_controller.provider_contract import (
    ObjectiveScope,
    ProviderOperationRef,
    TaskBinding,
    TerminalClaim,
)
from agent_controller.provider_plan_gate_flow import (
    PlanGateFlowResult,
    PlanGateFlowStatus,
    resume_plan_gate_flow,
    start_plan_gate_flow,
)
from agent_controller.provider_runtime import JulesAgentAdapter
from agent_controller.published_draft_inspection import (
    PublishedDraftInspectionResult,
    inspect_published_draft_pr_live,
)
from agent_controller.workstream import WorkstreamBinding


SMOKE_REPO = "oimus1976/agent-controller"
SMOKE_BASE_REF = "main"
SMOKE_DOC_PATH = "docs/live-jules-e2e-smoke-result.md"
SMOKE_DESTINATION_PREFIX = "controller/live-jules-e2e-smoke-"
SMOKE_MAX_ELAPSED_SECONDS = 900.0
SMOKE_MAX_OBSERVATIONS = 60
SMOKE_POLL_INTERVAL_SECONDS = 10.0


def _observed_at_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class HumanGateWaiter(Protocol):
    def __call__(self, action: Mapping[str, Any]) -> None: ...


@dataclass(frozen=True)
class JulesE2ESmokeResult:
    status: str
    stage: str
    reason: str | None = None
    start_sha: str | None = None
    provider_operation_id: str | None = None
    provider_url: str | None = None
    destination_branch: str | None = None
    publication: DraftPublicationResult | None = None
    inspection: PublishedDraftInspectionResult | None = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        return data


class _UnusedArtifactReadClient:
    def list_artifacts_raw(self, operation: ProviderOperationRef):
        return ()


def _terminal_success(result: PlanGateFlowResult) -> bool:
    follow = result.follow_result
    if result.status is not PlanGateFlowStatus.FOLLOW_STOPPED or follow is None:
        return False
    final = follow.final_observation
    return (
        follow.stop_reason is FollowStopReason.TERMINAL_CLAIM
        and final is not None
        and final.terminal_claim is TerminalClaim.SUCCESS
    )


def run_operator_assisted_smoke(
    *,
    task: TaskBinding,
    workstream: WorkstreamBinding,
    destination_branch: str,
    adapter: JulesAgentAdapter,
    change_reader: JulesChangeSetReadClient,
    github: GitHubRestDraftPublicationBackend,
    wait_for_human: HumanGateWaiter,
    start_flow: Callable[..., PlanGateFlowResult] = start_plan_gate_flow,
    resume_flow: Callable[..., PlanGateFlowResult] = resume_plan_gate_flow,
    publish: Callable[..., DraftPublicationResult] = publish_jules_changeset_to_draft_pr,
    inspect: Callable[..., PublishedDraftInspectionResult] = inspect_published_draft_pr_live,
) -> JulesE2ESmokeResult:
    """Compose one exact live Jules operation through a human plan gate to Draft PR.

    The wait callback is notification/pacing only. It cannot approve a plan. After
    it returns, resume_flow re-reads the exact checkpointed provider operation.
    """

    started = start_flow(
        task=task,
        adapter=adapter,
        max_elapsed_seconds=SMOKE_MAX_ELAPSED_SECONDS,
        max_observations=SMOKE_MAX_OBSERVATIONS,
        poll_interval_seconds=SMOKE_POLL_INTERVAL_SECONDS,
        workstream_binding=workstream,
    )
    operation = started.operation
    if (
        started.status is not PlanGateFlowStatus.HUMAN_PLAN_ACTION_REQUIRED
        or started.checkpoint is None
        or started.human_action is None
        or operation is None
    ):
        return JulesE2ESmokeResult(
            "BLOCKED",
            "PLAN_GATE",
            started.failure_reason or "HUMAN_PLAN_GATE_NOT_REACHED",
            start_sha=task.expected_start_sha,
            provider_operation_id=(operation.provider_operation_id if operation else None),
            provider_url=(operation.provider_url if operation else None),
            destination_branch=destination_branch,
        )

    wait_for_human(started.human_action.to_dict())

    resumed = resume_flow(
        checkpoint=started.checkpoint,
        adapter=adapter,
        max_elapsed_seconds=SMOKE_MAX_ELAPSED_SECONDS,
        max_observations=SMOKE_MAX_OBSERVATIONS,
        poll_interval_seconds=SMOKE_POLL_INTERVAL_SECONDS,
    )
    if resumed.status is PlanGateFlowStatus.HUMAN_PLAN_ACTION_REQUIRED:
        return JulesE2ESmokeResult(
            "BLOCKED",
            "RESUME",
            "PROVIDER_STILL_REQUIRES_PLAN_ACTION",
            start_sha=task.expected_start_sha,
            provider_operation_id=operation.provider_operation_id,
            provider_url=operation.provider_url,
            destination_branch=destination_branch,
        )
    if not _terminal_success(resumed):
        reason = resumed.failure_reason
        if reason is None and resumed.follow_result is not None:
            reason = resumed.follow_result.failure_reason or resumed.follow_result.stop_reason.value
        return JulesE2ESmokeResult(
            "BLOCKED",
            "RESUME",
            reason or "JULES_TERMINAL_SUCCESS_NOT_OBSERVED",
            start_sha=task.expected_start_sha,
            provider_operation_id=operation.provider_operation_id,
            provider_url=operation.provider_url,
            destination_branch=destination_branch,
        )

    publication = publish(
        task=task,
        operation=operation,
        workstream=workstream,
        destination_branch=destination_branch,
        observe=adapter.observe,
        change_reader=change_reader,
        github=github,
        pr_title="Live Jules E2E smoke artifact",
        pr_body=(
            "Implements the Issue #139 live smoke artifact only.\n\n"
            "This PR was published by the bounded Agent Controller Jules E2E smoke. "
            "It must remain Draft until a human marks it Ready. Ready/merge are human-final."
        ),
    )
    if publication.status != "PASS":
        return JulesE2ESmokeResult(
            "UNCERTAIN" if publication.status == "UNCERTAIN" else "BLOCKED",
            "PUBLICATION",
            publication.reason or "PUBLICATION_NOT_PASS",
            start_sha=task.expected_start_sha,
            provider_operation_id=operation.provider_operation_id,
            provider_url=operation.provider_url,
            destination_branch=destination_branch,
            publication=publication,
        )

    inspection = inspect(publication=publication, task=task, workstream=workstream)
    if inspection.status != "PASS":
        return JulesE2ESmokeResult(
            "UNCERTAIN" if inspection.status == "UNCERTAIN" else "BLOCKED",
            "INSPECTION",
            inspection.reason or "INSPECTION_NOT_PASS",
            start_sha=task.expected_start_sha,
            provider_operation_id=operation.provider_operation_id,
            provider_url=operation.provider_url,
            destination_branch=destination_branch,
            publication=publication,
            inspection=inspection,
        )

    return JulesE2ESmokeResult(
        "PASS",
        "COMPLETE",
        start_sha=task.expected_start_sha,
        provider_operation_id=operation.provider_operation_id,
        provider_url=operation.provider_url,
        destination_branch=destination_branch,
        publication=publication,
        inspection=inspection,
    )


def build_live_smoke(
    *,
    github: GitHubRestDraftPublicationBackend | None = None,
    api_client: JulesApiClient | None = None,
) -> tuple[
    TaskBinding,
    WorkstreamBinding,
    str,
    JulesAgentAdapter,
    JulesChangeSetReadClient,
    GitHubRestDraftPublicationBackend,
]:
    """Freeze current main and build the one allowed Issue #139 live smoke lane."""

    github = github or GitHubRestDraftPublicationBackend()
    api_client = api_client or JulesApiClient()
    start_sha = github.get_ref_sha(SMOKE_REPO, SMOKE_BASE_REF)
    if not isinstance(start_sha, str) or len(start_sha) != 40:
        raise RuntimeError("LIVE_SMOKE_START_SHA_UNAVAILABLE")
    if github.get_file_text(SMOKE_REPO, start_sha, SMOKE_DOC_PATH) is not None:
        raise RuntimeError("LIVE_SMOKE_DOC_ALREADY_EXISTS")

    suffix = start_sha[:12].lower()
    task_id = f"task-live-jules-e2e-{suffix}"
    operation_id = f"op-live-jules-e2e-{suffix}"
    destination_branch = f"{SMOKE_DESTINATION_PREFIX}{suffix}"

    task = TaskBinding(
        controller_task_id=task_id,
        operation_id=operation_id,
        provider="jules",
        repo=SMOKE_REPO,
        expected_start_ref=SMOKE_BASE_REF,
        expected_start_sha=start_sha,
        objective_scope=ObjectiveScope(
            allowed_paths=(SMOKE_DOC_PATH,),
            denied_paths=("agent_controller/**", "tests/**", ".github/**"),
        ),
        requested_capability="LIVE_JULES_E2E_SMOKE_DOC_ONLY",
        allowed_effects=("SESSION_CREATE", "DRAFT_PR_CREATE"),
        forbidden_effects=("AUTO_CREATE_PR", "PLAN_APPROVAL", "READY", "MERGE"),
        approval_policy_id="adr-90-human-final",
        created_at=_observed_at_now(),
    )
    workstream = WorkstreamBinding(
        workstream_id=f"live-jules-e2e-{suffix}",
        repo=SMOKE_REPO,
        root_work_item_ref="github:issue:139",
        task_ids=(task_id,),
        github_issues=(139,),
        branch_refs=(destination_branch,),
    )

    prompt = (
        f"Create exactly one new file `{SMOKE_DOC_PATH}` and modify no other file. "
        "The file must contain a short Markdown heading `# Live Jules E2E smoke` and one sentence "
        "stating that it is a harmless Agent Controller end-to-end smoke artifact for Issue #139. "
        "Do not edit code, tests, workflows, configuration, existing files, branches, or pull requests."
    )
    observation = JulesObservationAdapter(
        client=JulesReadClient(api_client),
        observed_at=_observed_at_now,
    )
    adapter = JulesAgentAdapter(
        dispatch_client=JulesDispatchClient(api_client, default_prompt=prompt),
        observation=observation,
        artifacts=JulesArtifactAdapter(
            client=_UnusedArtifactReadClient(),
            observed_at=_observed_at_now,
        ),
    )
    change_reader = JulesChangeSetReadClient(api_client, _observed_at_now)
    return task, workstream, destination_branch, adapter, change_reader, github
