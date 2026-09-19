from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime

from agent_controller.private_ci_phase4_contract import (
    PrivateCiPilotBinding,
    pilot_binding_reason_codes,
)


PHASE5_RESULT_SCHEMA = "agent-controller.private-ci-phase5-result.v1"
PHASE5_RESULT_STATUS = "PHASE5_EXACTLY_ONE_JOB_PASS"
PHASE5_EXPECTED_JOB_NAME = "exact-head-windows-pilot"
PHASE5_EXPECTED_ACTOR = "oimus1976"
PHASE5_EXPECTED_STEPS = (
    "Validate frozen workflow, runner, and PR binding",
    "Checkout exact frozen head without persisted credentials",
    "Verify exact checkout metadata only",
)


@dataclass(frozen=True, slots=True)
class Phase5RunJobReadback:
    workflow_run_id: int
    run_attempt: int
    job_id: int
    runner_id: int
    runner_name: str
    runner_label: str


@dataclass(frozen=True, slots=True)
class Phase5ResultEvidence:
    schema: str
    binding: PrivateCiPilotBinding
    phase5_plan_sha256: str
    phase4_result_sha256: str
    human_approval_sha256: str
    phase5_consumption_sha256: str
    candidate_sha256: str
    workflow_run_id: int
    workflow_run_attempt: int
    job_id: int
    runner_id: int
    runner_name: str
    runner_label: str
    runner_child_exit_code: int
    runner_stdout_sha256: str
    runner_stderr_sha256: str
    status: str
    completed_at: str


def _digest(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _positive_int(value: object) -> bool:
    return type(value) is int and value > 0


def _actor_login(value: object) -> str:
    if type(value) is not dict or type(value.get("login")) is not str:
        raise ValueError("Phase 5 workflow actor shape invalid")
    return value["login"]


def _workflow_path_matches(observed: object, expected: str) -> bool:
    if type(observed) is not str:
        return False
    return observed in (
        expected,
        expected + "@refs/heads/main",
    )


def validate_phase5_run_job_readback(
    *,
    run_payload: object,
    jobs_payload: object,
    binding: PrivateCiPilotBinding,
    expected_workflow_run_id: int,
) -> Phase5RunJobReadback:
    binding_reasons = pilot_binding_reason_codes(binding)
    if binding_reasons:
        raise ValueError(
            "Phase 5 pilot binding invalid: " + ",".join(binding_reasons)
        )
    if not _positive_int(expected_workflow_run_id):
        raise ValueError("Phase 5 expected workflow run id invalid")
    if type(run_payload) is not dict:
        raise ValueError("Phase 5 workflow run readback shape invalid")

    run_checks = (
        (
            run_payload.get("id") == expected_workflow_run_id,
            "workflow run id mismatch",
        ),
        (
            run_payload.get("event") == "workflow_dispatch",
            "workflow event mismatch",
        ),
        (
            run_payload.get("status") == "completed",
            "workflow run not completed",
        ),
        (
            run_payload.get("conclusion") == "success",
            "workflow run did not succeed",
        ),
        (
            run_payload.get("head_sha") == binding.workflow_sha,
            "workflow run trusted SHA mismatch",
        ),
        (
            run_payload.get("head_branch") == "main",
            "workflow run branch mismatch",
        ),
        (
            _workflow_path_matches(
                run_payload.get("path"),
                binding.workflow_path,
            ),
            "workflow run path mismatch",
        ),
        (
            _actor_login(run_payload.get("actor"))
            == PHASE5_EXPECTED_ACTOR,
            "workflow actor mismatch",
        ),
        (
            _actor_login(run_payload.get("triggering_actor"))
            == PHASE5_EXPECTED_ACTOR,
            "workflow triggering actor mismatch",
        ),
        (
            run_payload.get("run_attempt") == 1,
            "workflow run was rerun",
        ),
    )
    for passed, message in run_checks:
        if not passed:
            raise ValueError("Phase 5 " + message)

    if type(jobs_payload) is not dict:
        raise ValueError("Phase 5 jobs readback shape invalid")
    jobs = jobs_payload.get("jobs")
    total_count = jobs_payload.get("total_count")
    if (
        type(jobs) is not list
        or total_count != 1
        or len(jobs) != 1
        or type(jobs[0]) is not dict
    ):
        raise ValueError("Phase 5 exactly-one-job cardinality invalid")
    job = jobs[0]

    if not _positive_int(job.get("id")):
        raise ValueError("Phase 5 job id invalid")
    if job.get("name") != PHASE5_EXPECTED_JOB_NAME:
        raise ValueError("Phase 5 job name mismatch")
    if job.get("status") != "completed":
        raise ValueError("Phase 5 job not completed")
    if job.get("conclusion") != "success":
        raise ValueError("Phase 5 job did not succeed")
    if job.get("runner_id") != binding.runner_id:
        raise ValueError("Phase 5 job runner id mismatch")
    if job.get("runner_name") != binding.runner_name:
        raise ValueError("Phase 5 job runner name mismatch")

    labels = job.get("labels")
    if (
        type(labels) is not list
        or any(type(label) is not str for label in labels)
        or binding.runner_label not in labels
    ):
        raise ValueError("Phase 5 job runner label mismatch")

    steps = job.get("steps")
    if type(steps) is not list:
        raise ValueError("Phase 5 job steps shape invalid")
    for expected_name in PHASE5_EXPECTED_STEPS:
        matching = [
            step
            for step in steps
            if type(step) is dict and step.get("name") == expected_name
        ]
        if len(matching) != 1:
            raise ValueError(
                "Phase 5 expected job step cardinality invalid: "
                + expected_name
            )
        step = matching[0]
        if (
            step.get("status") != "completed"
            or step.get("conclusion") != "success"
        ):
            raise ValueError(
                "Phase 5 expected job step did not succeed: "
                + expected_name
            )

    return Phase5RunJobReadback(
        workflow_run_id=expected_workflow_run_id,
        run_attempt=1,
        job_id=job["id"],
        runner_id=binding.runner_id,
        runner_name=binding.runner_name,
        runner_label=binding.runner_label,
    )


def phase5_result_reason_codes(
    evidence: object,
) -> tuple[str, ...]:
    if type(evidence) is not Phase5ResultEvidence:
        return ("PHASE5_RESULT_TYPE_INVALID",)
    reasons: list[str] = []
    if evidence.schema != PHASE5_RESULT_SCHEMA:
        reasons.append("PHASE5_RESULT_SCHEMA_INVALID")
    for reason in pilot_binding_reason_codes(evidence.binding):
        reasons.append("PHASE5_RESULT_" + reason)

    digest_fields = (
        ("PHASE5_RESULT_PLAN_SHA_INVALID", evidence.phase5_plan_sha256),
        (
            "PHASE5_RESULT_PHASE4_SHA_INVALID",
            evidence.phase4_result_sha256,
        ),
        (
            "PHASE5_RESULT_APPROVAL_SHA_INVALID",
            evidence.human_approval_sha256,
        ),
        (
            "PHASE5_RESULT_CONSUMPTION_SHA_INVALID",
            evidence.phase5_consumption_sha256,
        ),
        (
            "PHASE5_RESULT_CANDIDATE_SHA_INVALID",
            evidence.candidate_sha256,
        ),
        (
            "PHASE5_RESULT_RUNNER_STDOUT_SHA_INVALID",
            evidence.runner_stdout_sha256,
        ),
        (
            "PHASE5_RESULT_RUNNER_STDERR_SHA_INVALID",
            evidence.runner_stderr_sha256,
        ),
    )
    for reason, value in digest_fields:
        if not _digest(value):
            reasons.append(reason)

    positive_fields = (
        ("PHASE5_RESULT_WORKFLOW_RUN_ID_INVALID", evidence.workflow_run_id),
        ("PHASE5_RESULT_JOB_ID_INVALID", evidence.job_id),
        ("PHASE5_RESULT_RUNNER_ID_INVALID", evidence.runner_id),
    )
    for reason, value in positive_fields:
        if not _positive_int(value):
            reasons.append(reason)
    if evidence.workflow_run_attempt != 1:
        reasons.append("PHASE5_RESULT_RUN_ATTEMPT_INVALID")
    if evidence.runner_id != evidence.binding.runner_id:
        reasons.append("PHASE5_RESULT_RUNNER_ID_MISMATCH")
    if evidence.runner_name != evidence.binding.runner_name:
        reasons.append("PHASE5_RESULT_RUNNER_NAME_MISMATCH")
    if evidence.runner_label != evidence.binding.runner_label:
        reasons.append("PHASE5_RESULT_RUNNER_LABEL_MISMATCH")
    if evidence.runner_child_exit_code != 0:
        reasons.append("PHASE5_RESULT_CHILD_EXIT_INVALID")
    if evidence.status != PHASE5_RESULT_STATUS:
        reasons.append("PHASE5_RESULT_STATUS_INVALID")
    if type(evidence.completed_at) is not str or not evidence.completed_at:
        reasons.append("PHASE5_RESULT_COMPLETED_AT_INVALID")
    else:
        try:
            parsed = datetime.fromisoformat(
                evidence.completed_at.replace("Z", "+00:00")
            )
        except ValueError:
            reasons.append("PHASE5_RESULT_COMPLETED_AT_INVALID")
        else:
            if parsed.tzinfo is None or parsed.utcoffset() is None:
                reasons.append("PHASE5_RESULT_COMPLETED_AT_INVALID")
    return tuple(reasons)


def phase5_result_bytes(evidence: Phase5ResultEvidence) -> bytes:
    reasons = phase5_result_reason_codes(evidence)
    if reasons:
        raise ValueError("Phase 5 result invalid: " + ",".join(reasons))
    return (
        json.dumps(
            asdict(evidence),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
        + "\n"
    ).encode("utf-8")


def parse_phase5_result_bytes(raw: bytes) -> Phase5ResultEvidence:
    if type(raw) is not bytes:
        raise ValueError("Phase 5 result must be exact bytes")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("Phase 5 result JSON invalid") from error
    expected = set(Phase5ResultEvidence.__dataclass_fields__)
    if type(payload) is not dict or set(payload) != expected:
        raise ValueError("Phase 5 result shape invalid")
    binding_payload = payload.get("binding")
    if (
        type(binding_payload) is not dict
        or set(binding_payload) != set(PrivateCiPilotBinding.__dataclass_fields__)
    ):
        raise ValueError("Phase 5 result binding shape invalid")
    try:
        evidence = Phase5ResultEvidence(
            schema=payload["schema"],
            binding=PrivateCiPilotBinding(**binding_payload),
            phase5_plan_sha256=payload["phase5_plan_sha256"],
            phase4_result_sha256=payload["phase4_result_sha256"],
            human_approval_sha256=payload["human_approval_sha256"],
            phase5_consumption_sha256=payload[
                "phase5_consumption_sha256"
            ],
            candidate_sha256=payload["candidate_sha256"],
            workflow_run_id=payload["workflow_run_id"],
            workflow_run_attempt=payload["workflow_run_attempt"],
            job_id=payload["job_id"],
            runner_id=payload["runner_id"],
            runner_name=payload["runner_name"],
            runner_label=payload["runner_label"],
            runner_child_exit_code=payload["runner_child_exit_code"],
            runner_stdout_sha256=payload["runner_stdout_sha256"],
            runner_stderr_sha256=payload["runner_stderr_sha256"],
            status=payload["status"],
            completed_at=payload["completed_at"],
        )
    except TypeError as error:
        raise ValueError("Phase 5 result fields invalid") from error
    if raw != phase5_result_bytes(evidence):
        raise ValueError("Phase 5 result is not canonical")
    return evidence
