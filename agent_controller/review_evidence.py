from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import Any, Mapping, Sequence

from .binding_validator import validate_operation_binding
from .provider_contract import ProviderOperationRef, TaskBinding


CANONICAL_REVIEW_SCHEMA = "agent-controller/review-evidence/v1"
JULES_REVIEW_SCHEMA = "agent-controller/jules-review/v1"
REQUIRED_GITHUB_SURFACES = (
    "formal_reviews",
    "issue_comments",
    "inline_threads",
    "reactions",
)
VALID_VERDICTS = frozenset({"CLEAN", "BLOCKING", "PENDING", "ABSENT", "UNCERTAIN"})
VERIFIED_PROVIDER_REVIEW_INDEPENDENCE = frozenset({"VERIFIED_DIFFERENT_OPERATION"})
VERIFIED_PROVIDER_REVIEW_BINDINGS = frozenset({"CONTROLLER_PRE_DISPATCH_EXACT_HEAD"})


@dataclass(frozen=True)
class ReviewSurfaceStatus:
    surface: str
    status: str
    pagination_exhausted: bool
    error: str | None = None

    @property
    def complete(self) -> bool:
        return self.status == "COMPLETE" and self.pagination_exhausted and self.error is None


@dataclass(frozen=True)
class ProviderReviewEvidence:
    provider: str
    provider_operation_id: str
    repo: str
    pr: int
    reviewed_head_sha: str
    verdict: str
    complete: bool
    independence: str
    binding_strength: str
    errors: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class CanonicalReviewEvidence:
    schema: str
    repo: str
    pr: int
    observed_head_sha: str
    collection_complete: bool
    verdict: str
    surfaces: tuple[ReviewSurfaceStatus, ...]
    provider_reviews: tuple[ProviderReviewEvidence, ...]
    errors: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "repo": self.repo,
            "pr": self.pr,
            "observed_head_sha": self.observed_head_sha,
            "collection_complete": self.collection_complete,
            "verdict": self.verdict,
            "surfaces": [asdict(item) for item in self.surfaces],
            "provider_reviews": [item.to_dict() for item in self.provider_reviews],
            "errors": list(self.errors),
        }


def _valid_sha(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 40
        and all(character in "0123456789abcdefABCDEF" for character in value)
    )


def build_jules_review_evidence(
    *,
    task: TaskBinding,
    operation: ProviderOperationRef,
    repo: str,
    pr: int,
    current_head_sha: str,
    session: Mapping[str, Any],
    activities: Sequence[Mapping[str, Any]],
    activities_complete: bool,
    fresh_session: bool,
    implementation_operation_id: str | None,
) -> ProviderReviewEvidence:
    """Normalize a bound Jules review without trusting relayed GitHub prose.

    The caller must obtain ``session`` and every activity through the official
    read APIs. Pagination completeness is explicit because an empty final page
    and a truncated read are materially different evidence.
    """

    errors: list[str] = []
    binding = validate_operation_binding(task=task, operation=operation)
    if not binding.valid:
        errors.append(binding.reason or "OPERATION_BINDING_INVALID")
    if task.provider != "jules" or operation.provider != "jules":
        errors.append("PROVIDER_NOT_JULES")
    if task.requested_capability != "REVIEW":
        errors.append("TASK_CAPABILITY_NOT_REVIEW")
    if task.repo != repo:
        errors.append("REPOSITORY_MISMATCH")
    if task.expected_start_sha != current_head_sha:
        errors.append("EXPECTED_HEAD_MISMATCH")
    if not _valid_sha(current_head_sha):
        errors.append("CURRENT_HEAD_MALFORMED")
    if not isinstance(pr, int) or isinstance(pr, bool) or pr <= 0:
        errors.append("PR_IDENTITY_MALFORMED")

    session_id = operation.provider_operation_id.removeprefix("sessions/")
    session_name = session.get("name")
    session_state = session.get("state")
    if session_name != f"sessions/{session_id}":
        errors.append("SESSION_IDENTITY_MISMATCH")
    if session_state != "COMPLETED":
        errors.append("SESSION_NOT_COMPLETED")
    if not activities_complete:
        errors.append("ACTIVITIES_INCOMPLETE")
    if not fresh_session:
        errors.append("REVIEW_SESSION_NOT_FRESH")

    expected_prefix = f"sessions/{session_id}/activities/"
    completion_count = 0
    results: list[Mapping[str, Any]] = []
    for activity in activities:
        if not isinstance(activity, Mapping):
            errors.append("ACTIVITY_MALFORMED")
            continue
        name = activity.get("name")
        activity_id = activity.get("id")
        if (
            not isinstance(activity_id, str)
            or not activity_id
            or name != f"{expected_prefix}{activity_id}"
        ):
            errors.append("ACTIVITY_SESSION_MISMATCH")
        if "sessionCompleted" in activity:
            if not isinstance(activity.get("sessionCompleted"), Mapping):
                errors.append("SESSION_COMPLETION_MALFORMED")
            completion_count += 1
        message_event = activity.get("agentMessaged")
        if message_event is not None:
            if activity.get("originator") != "agent" or not isinstance(message_event, Mapping):
                errors.append("REVIEW_RESULT_ORIGIN_INVALID")
                continue
            message = message_event.get("agentMessage")
            if not isinstance(message, str):
                errors.append("REVIEW_RESULT_MESSAGE_MALFORMED")
                continue
            try:
                candidate = json.loads(message)
            except json.JSONDecodeError:
                if JULES_REVIEW_SCHEMA in message:
                    errors.append("REVIEW_RESULT_JSON_MALFORMED")
                continue
            if isinstance(candidate, Mapping) and candidate.get("schema") == JULES_REVIEW_SCHEMA:
                results.append(candidate)
    if completion_count == 0:
        errors.append("SESSION_COMPLETION_MISSING")
    elif completion_count > 1:
        errors.append("SESSION_COMPLETION_AMBIGUOUS")

    if len(results) != 1:
        errors.append("REVIEW_RESULT_MISSING" if not results else "REVIEW_RESULT_AMBIGUOUS")
        result: Mapping[str, Any] = {}
    else:
        result = results[0]
    reviewed_sha = result.get("reviewed_head_sha")
    verdict = result.get("verdict")
    findings = result.get("findings")
    if reviewed_sha != current_head_sha:
        errors.append("REVIEWED_HEAD_MISMATCH")
    if verdict not in {"CLEAN", "BLOCKING"}:
        errors.append("REVIEW_VERDICT_MALFORMED")
        verdict = "UNCERTAIN"
    if (
        not isinstance(findings, list)
        or any(not isinstance(item, str) or not item.strip() for item in findings)
    ):
        errors.append("REVIEW_FINDINGS_MALFORMED")
    elif verdict == "CLEAN" and findings:
        errors.append("CLEAN_REVIEW_HAS_FINDINGS")
    elif verdict == "BLOCKING" and not findings:
        errors.append("BLOCKING_REVIEW_HAS_NO_FINDINGS")

    independence = "VERIFIED_DIFFERENT_OPERATION"
    if not implementation_operation_id:
        independence = "UNKNOWN"
        errors.append("IMPLEMENTATION_OPERATION_UNKNOWN")
    elif implementation_operation_id == operation.operation_id:
        independence = "SELF_REVIEW"
        errors.append("REVIEW_REUSES_IMPLEMENTATION_OPERATION")

    # The official Jules create-session API binds a branch, while Controller
    # verifies that branch at dispatch. It does not currently return the
    # checkout SHA, so this distinction remains visible to policy/diagnostics.
    binding_strength = "CONTROLLER_PRE_DISPATCH_EXACT_HEAD"
    complete = not errors
    return ProviderReviewEvidence(
        provider="jules",
        provider_operation_id=operation.provider_operation_id,
        repo=repo,
        pr=pr,
        reviewed_head_sha=reviewed_sha if _valid_sha(reviewed_sha) else "",
        verdict=verdict if complete else "UNCERTAIN",
        complete=complete,
        independence=independence,
        binding_strength=binding_strength,
        errors=tuple(errors),
    )


def canonical_review_from_mapping(
    value: Any,
    *,
    repo: str,
    pr: int,
    head_sha: str,
) -> CanonicalReviewEvidence | None:
    """Validate serialized canonical evidence at a consumer boundary."""

    if not isinstance(value, Mapping) or value.get("schema") != CANONICAL_REVIEW_SCHEMA:
        return None
    if value.get("repo") != repo or value.get("pr") != pr:
        return None
    if value.get("observed_head_sha") != head_sha:
        return None
    verdict = value.get("verdict")
    complete = value.get("collection_complete")
    if verdict not in VALID_VERDICTS or not isinstance(complete, bool):
        return None

    surfaces_raw = value.get("surfaces")
    providers_raw = value.get("provider_reviews")
    errors_raw = value.get("errors")
    if not isinstance(surfaces_raw, list) or not isinstance(providers_raw, list):
        return None
    if not isinstance(errors_raw, list) or any(not isinstance(item, str) for item in errors_raw):
        return None

    try:
        surfaces = tuple(ReviewSurfaceStatus(**item) for item in surfaces_raw)
        providers = tuple(
            ProviderReviewEvidence(
                provider=item["provider"],
                provider_operation_id=item["provider_operation_id"],
                repo=item["repo"],
                pr=item["pr"],
                reviewed_head_sha=item["reviewed_head_sha"],
                verdict=item["verdict"],
                complete=item["complete"],
                independence=item["independence"],
                binding_strength=item["binding_strength"],
                errors=tuple(item.get("errors", ())),
            )
            for item in providers_raw
        )
    except (KeyError, TypeError, ValueError):
        return None

    if any(
        not isinstance(item.surface, str)
        or item.status not in {"COMPLETE", "UNAVAILABLE"}
        or type(item.pagination_exhausted) is not bool
        or (item.error is not None and not isinstance(item.error, str))
        for item in surfaces
    ):
        return None
    if {item.surface for item in surfaces} != set(REQUIRED_GITHUB_SURFACES):
        return None
    if len(surfaces) != len(REQUIRED_GITHUB_SURFACES):
        return None
    if complete and (errors_raw or any(not item.complete for item in surfaces)):
        return None
    if any(
        not isinstance(item.provider, str)
        or not item.provider
        or not isinstance(item.provider_operation_id, str)
        or not item.provider_operation_id
        or item.verdict not in {"CLEAN", "BLOCKING", "UNCERTAIN"}
        or item.repo != repo
        or item.pr != pr
        or item.reviewed_head_sha != head_sha
        or type(item.complete) is not bool
        or not isinstance(item.independence, str)
        or not item.independence
        or not isinstance(item.binding_strength, str)
        or not item.binding_strength
        or any(not isinstance(error, str) for error in item.errors)
        or (item.complete and item.errors)
        or (item.complete and item.verdict not in {"CLEAN", "BLOCKING"})
        or (
            item.complete
            and item.independence not in VERIFIED_PROVIDER_REVIEW_INDEPENDENCE
        )
        or (
            item.complete
            and item.binding_strength not in VERIFIED_PROVIDER_REVIEW_BINDINGS
        )
        for item in providers
    ):
        return None
    if complete and any(not item.complete for item in providers):
        return None
    if any(item.complete and item.verdict == "BLOCKING" for item in providers):
        if verdict != "BLOCKING":
            return None
    return CanonicalReviewEvidence(
        schema=CANONICAL_REVIEW_SCHEMA,
        repo=repo,
        pr=pr,
        observed_head_sha=head_sha,
        collection_complete=complete,
        verdict=verdict,
        surfaces=surfaces,
        provider_reviews=providers,
        errors=tuple(errors_raw),
    )
