from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
from typing import Any, Callable, Mapping, Optional
from urllib.parse import quote

from agent_controller.binding_validator import validate_operation_binding
from agent_controller.jules_live import JulesApiClient
from agent_controller.provider_contract import ProviderOperationRef, TaskBinding


@dataclass(frozen=True)
class JulesChangeSetEvidence:
    """Untrusted provider-reported Jules code change evidence.

    This object deliberately is not ArtifactEvidence. A ChangeSet is not yet a
    GitHub branch/commit/PR and therefore cannot be independently verified by
    the GitHub artifact verifier until a later, separately guarded publication
    step creates an objective GitHub target.
    """

    provider: str
    provider_operation_id: str
    activity_id: str
    activity_name: str
    source: str
    unidiff_patch: str
    base_commit_id: str
    suggested_commit_message: Optional[str]
    observed_at: str
    patch_sha256: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class JulesActivitiesApiClient(JulesApiClient):
    """Read-only Jules client extension for the official activities.list API."""

    def list_activities(
        self,
        session_id: str,
        *,
        max_pages: int = 50,
    ) -> list[dict[str, Any]]:
        if not isinstance(session_id, str) or not session_id.strip():
            raise ValueError("session_id must be a non-empty string")
        if isinstance(max_pages, bool) or not isinstance(max_pages, int) or max_pages <= 0:
            raise ValueError("max_pages must be a positive integer")

        clean_id = session_id.strip()
        if clean_id.startswith("sessions/"):
            clean_id = clean_id[len("sessions/") :]
        if not clean_id or "/" in clean_id:
            raise ValueError("session_id must identify exactly one Jules session")

        activities: list[dict[str, Any]] = []
        page_token: Optional[str] = None
        seen_page_tokens: set[str] = set()
        page_count = 0

        while True:
            page_count += 1
            if page_count > max_pages:
                raise RuntimeError(
                    f"Exceeded maximum page limit ({max_pages}) while listing Jules activities"
                )

            path = f"sessions/{clean_id}/activities?pageSize=100"
            if page_token is not None:
                path += f"&pageToken={quote(page_token, safe='')}"

            response = self._request("GET", path)
            if not isinstance(response, Mapping):
                raise RuntimeError("Malformed response payload from Jules activities API")

            page_activities = response.get("activities", [])
            if not isinstance(page_activities, list):
                raise RuntimeError("Malformed 'activities' field in Jules activities API response")
            activities.extend(page_activities)

            if "nextPageToken" not in response:
                break

            next_token = response.get("nextPageToken")
            if not isinstance(next_token, str) or not next_token.strip():
                raise RuntimeError("Malformed 'nextPageToken' in Jules activities API response")
            if next_token in seen_page_tokens:
                raise RuntimeError(
                    f"Detected pagination cycle with nextPageToken: {next_token!r}"
                )

            seen_page_tokens.add(next_token)
            page_token = next_token

        return activities


ObservedAtFactory = Callable[[], str]


class JulesChangeSetReadClient:
    """Extract strictly validated ChangeSet.gitPatch evidence for one bound task."""

    def __init__(
        self,
        api_client: JulesActivitiesApiClient,
        observed_at: ObservedAtFactory,
    ) -> None:
        self.api_client = api_client
        self.observed_at = observed_at

    def list_change_sets(
        self,
        *,
        task: TaskBinding,
        operation: ProviderOperationRef,
        max_activity_pages: int = 50,
    ) -> tuple[JulesChangeSetEvidence, ...]:
        if not isinstance(task, TaskBinding):
            raise ValueError("task must be a TaskBinding")
        if not isinstance(operation, ProviderOperationRef):
            raise ValueError("operation must be a ProviderOperationRef")

        binding = validate_operation_binding(task=task, operation=operation)
        if not binding.valid:
            raise ValueError(binding.reason or "operation binding invalid")
        if task.provider != "jules" or operation.provider != "jules":
            raise ValueError("Jules ChangeSet reads require provider='jules'")
        if not isinstance(task.repo, str) or not task.repo:
            raise ValueError("TaskBinding.repo is required for Jules ChangeSet reads")

        clean_session_id = operation.provider_operation_id
        if clean_session_id.startswith("sessions/"):
            clean_session_id = clean_session_id[len("sessions/") :]
        if not clean_session_id or "/" in clean_session_id:
            raise ValueError("operation.provider_operation_id must identify one session")

        expected_source = self.api_client.resolve_source(task.repo)
        activities = self.api_client.list_activities(
            clean_session_id,
            max_pages=max_activity_pages,
        )

        observed_at = self.observed_at()
        if not isinstance(observed_at, str) or not observed_at:
            raise RuntimeError("observed_at must return a non-empty string")

        results: list[JulesChangeSetEvidence] = []
        expected_activity_prefix = f"sessions/{clean_session_id}/activities/"

        for activity in activities:
            if not isinstance(activity, Mapping):
                raise RuntimeError("Malformed Jules activity entry")

            activity_id = activity.get("id")
            activity_name = activity.get("name")
            originator = activity.get("originator")
            if not isinstance(activity_id, str) or not activity_id:
                raise RuntimeError("Malformed Jules activity id")
            if not isinstance(activity_name, str) or not activity_name:
                raise RuntimeError("Malformed Jules activity name")
            if activity_name != f"{expected_activity_prefix}{activity_id}":
                raise RuntimeError("Jules activity does not belong to the bound session")
            if not isinstance(originator, str) or not originator:
                raise RuntimeError("Malformed Jules activity originator")

            raw_artifacts = activity.get("artifacts", [])
            if not isinstance(raw_artifacts, list):
                raise RuntimeError("Malformed Jules activity artifacts field")

            for raw_artifact in raw_artifacts:
                if not isinstance(raw_artifact, Mapping):
                    raise RuntimeError("Malformed Jules activity artifact")
                if "changeSet" not in raw_artifact:
                    continue
                if originator != "agent":
                    # Never promote a user/system-originated patch as agent output.
                    continue

                change_set = raw_artifact.get("changeSet")
                if not isinstance(change_set, Mapping):
                    raise RuntimeError("Malformed Jules ChangeSet artifact")

                source = change_set.get("source")
                git_patch = change_set.get("gitPatch")
                if not isinstance(source, str) or not source:
                    raise RuntimeError("Jules ChangeSet source is missing or malformed")
                if source != expected_source:
                    raise RuntimeError("Jules ChangeSet source does not match the task repository")
                if not isinstance(git_patch, Mapping):
                    raise RuntimeError("Jules ChangeSet gitPatch is missing or malformed")

                patch = git_patch.get("unidiffPatch")
                base_commit_id = git_patch.get("baseCommitId")
                suggested = git_patch.get("suggestedCommitMessage")
                if not isinstance(patch, str) or not patch:
                    raise RuntimeError("Jules ChangeSet unidiffPatch is missing or empty")
                if not isinstance(base_commit_id, str) or not base_commit_id:
                    raise RuntimeError("Jules ChangeSet baseCommitId is missing or empty")
                if suggested is not None and (
                    not isinstance(suggested, str) or not suggested
                ):
                    raise RuntimeError(
                        "Jules ChangeSet suggestedCommitMessage is malformed"
                    )

                results.append(
                    JulesChangeSetEvidence(
                        provider="jules",
                        provider_operation_id=operation.provider_operation_id,
                        activity_id=activity_id,
                        activity_name=activity_name,
                        source=source,
                        unidiff_patch=patch,
                        base_commit_id=base_commit_id,
                        suggested_commit_message=suggested,
                        observed_at=observed_at,
                        patch_sha256=sha256(patch.encode("utf-8")).hexdigest(),
                    )
                )

        return tuple(results)
