from __future__ import annotations

import hashlib
import json
import subprocess
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Optional

from agent_controller.operator_step_gate import (
    AUTHORITATIVE_EVIDENCE_ROOT,
    PRIVATE_LOCAL_CI_WORKSTREAM,
    WINDOWS_POWERSHELL_51,
    AuthenticatedAstAttestation,
    OperatorEffectClass,
    OperatorGateResult,
    OperatorGateStatus,
    OperatorStepSpec,
    PriorEvidenceCapability,
    PriorEvidenceRequirement,
    _attestation_reason_codes,
    _candidate_sha256,
    _spec_reason_codes,
    validate_operator_step,
)
from agent_controller.owner_machine_jit_bridge import (
    OWNER_MACHINE_HOST_ROLE,
    REGISTRATION_EFFECTS,
    TRUSTED_BROKER_IDENTITY,
)

LIVE_REGISTRATION_OPERATION_ID = "issue217-live-registration"
LIVE_REGISTRATION_STEP_ID = "register-ephemeral-runner"
LIVE_REGISTRATION_TRANSCRIPT = "issue217-live-registration.log"
LIVE_REGISTRATION_SUCCESS_MARKER = "ISSUE217_LIVE_REGISTRATION_PASS"

PHASE0_OPERATION_ID = "issue216-phase0"
PHASE0_STEP_ID = "canonical-preflight"

FROZEN_REPOSITORY = "oimus1976/ai-dev-starter-adoption-smoke-2"
FROZEN_PR_NUMBER = 4
FROZEN_TARGET_SHA = "17a17c04af8adadd61b8d9447493404da8e00a73"
FROZEN_WORKFLOW_SHA = "c13ea3ad4fa66c0583e251a71143934a36025992"
FROZEN_RUNNER_NAME = "ac-ci-153d6e1a29fea2cd"
FROZEN_RUNNER_LABEL = "private-ci-windows-pilot"
FROZEN_ENVIRONMENT_GENERATION = "ac-pilot-65bbb1dc7c48d6e3"
FROZEN_RUNNER_ROOT = (
    r"C:\ProgramData\agent-controller\private-ci"
    rf"\{FROZEN_ENVIRONMENT_GENERATION}\runner"
)
FROZEN_WORK_FOLDER = "_work"

REGISTRATION_TOKEN_ENVIRONMENT_NAME = "ACTIONS_RUNNER_INPUT_TOKEN"


@dataclass(frozen=True, slots=True)
class LiveRegistrationBinding:
    repository: str
    pull_request_number: int
    target_sha: str
    workflow_sha: str
    runner_name: str
    runner_label: str
    environment_generation: str
    runner_root: str
    work_folder: str = FROZEN_WORK_FOLDER


def frozen_live_registration_binding() -> LiveRegistrationBinding:
    return LiveRegistrationBinding(
        repository=FROZEN_REPOSITORY,
        pull_request_number=FROZEN_PR_NUMBER,
        target_sha=FROZEN_TARGET_SHA,
        workflow_sha=FROZEN_WORKFLOW_SHA,
        runner_name=FROZEN_RUNNER_NAME,
        runner_label=FROZEN_RUNNER_LABEL,
        environment_generation=FROZEN_ENVIRONMENT_GENERATION,
        runner_root=FROZEN_RUNNER_ROOT,
        work_folder=FROZEN_WORK_FOLDER,
    )


def _binding_reason_codes(binding: object) -> tuple[str, ...]:
    if type(binding) is not LiveRegistrationBinding:
        return ("LIVE_REGISTRATION_BINDING_TYPE_INVALID",)
    expected = frozen_live_registration_binding()
    reasons: list[str] = []
    fields = (
        ("LIVE_REGISTRATION_REPOSITORY_MISMATCH", binding.repository, expected.repository),
        ("LIVE_REGISTRATION_PR_MISMATCH", binding.pull_request_number, expected.pull_request_number),
        ("LIVE_REGISTRATION_TARGET_SHA_MISMATCH", binding.target_sha, expected.target_sha),
        ("LIVE_REGISTRATION_WORKFLOW_SHA_MISMATCH", binding.workflow_sha, expected.workflow_sha),
        ("LIVE_REGISTRATION_RUNNER_NAME_MISMATCH", binding.runner_name, expected.runner_name),
        ("LIVE_REGISTRATION_RUNNER_LABEL_MISMATCH", binding.runner_label, expected.runner_label),
        (
            "LIVE_REGISTRATION_ENVIRONMENT_GENERATION_MISMATCH",
            binding.environment_generation,
            expected.environment_generation,
        ),
        ("LIVE_REGISTRATION_RUNNER_ROOT_MISMATCH", binding.runner_root, expected.runner_root),
        ("LIVE_REGISTRATION_WORK_FOLDER_MISMATCH", binding.work_folder, expected.work_folder),
    )
    for reason, observed, required in fields:
        if observed != required:
            reasons.append(reason)
    return tuple(reasons)


def build_live_registration_spec(
    binding: LiveRegistrationBinding,
    *,
    phase0_evidence_sha256: str,
) -> OperatorStepSpec:
    return OperatorStepSpec(
        operation_id=LIVE_REGISTRATION_OPERATION_ID,
        step_id=LIVE_REGISTRATION_STEP_ID,
        workstream=PRIVATE_LOCAL_CI_WORKSTREAM,
        repository=binding.repository,
        pull_request_number=binding.pull_request_number,
        target_sha=binding.target_sha,
        target_host_role=OWNER_MACHINE_HOST_ROLE,
        required_identity=TRUSTED_BROKER_IDENTITY,
        shell_runtime=WINDOWS_POWERSHELL_51,
        effect_class=OperatorEffectClass.BOUNDED_MUTATION,
        evidence_root=AUTHORITATIVE_EVIDENCE_ROOT,
        transcript_filename=LIVE_REGISTRATION_TRANSCRIPT,
        expected_success_marker=LIVE_REGISTRATION_SUCCESS_MARKER,
        allowed_effect_families=REGISTRATION_EFFECTS,
        prior_evidence_requirement=PriorEvidenceRequirement(
            producer_operation_id=PHASE0_OPERATION_ID,
            producer_step_id=PHASE0_STEP_ID,
            evidence_sha256=phase0_evidence_sha256,
        ),
        require_parser_attestation=True,
        require_heartbeat_or_progress=False,
        require_child_exit_code=False,
        require_fail_fast=False,
    )


def _ps_single_quoted(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def render_live_registration_candidate(binding: LiveRegistrationBinding) -> str:
    repository_url = f"https://github.com/{binding.repository}"
    lines = [
        f"$BridgeRepository = {_ps_single_quoted(binding.repository)}",
        f"$BridgePullRequestNumber = {binding.pull_request_number}",
        f"$BridgeTargetSha = {_ps_single_quoted(binding.target_sha)}",
        f"$BridgeTargetHostRole = {_ps_single_quoted(OWNER_MACHINE_HOST_ROLE)}",
        f"$BridgeRequiredIdentity = {_ps_single_quoted(TRUSTED_BROKER_IDENTITY)}",
        f"$BridgeEvidenceRoot = {_ps_single_quoted(AUTHORITATIVE_EVIDENCE_ROOT)}",
        f"$BridgeTranscriptFilename = {_ps_single_quoted(LIVE_REGISTRATION_TRANSCRIPT)}",
        f"$BridgeExpectedSuccessMarker = {_ps_single_quoted(LIVE_REGISTRATION_SUCCESS_MARKER)}",
        f"$BridgeWorkflowSha = {_ps_single_quoted(binding.workflow_sha)}",
        f"$BridgeRunnerName = {_ps_single_quoted(binding.runner_name)}",
        f"$BridgeRunnerLabel = {_ps_single_quoted(binding.runner_label)}",
        f"$BridgeEnvironmentGeneration = {_ps_single_quoted(binding.environment_generation)}",
        f"$BridgeRunnerRoot = {_ps_single_quoted(binding.runner_root)}",
        (
            ".\\config.cmd --unattended "
            f"--url {_ps_single_quoted(repository_url)} "
            f"--name {_ps_single_quoted(binding.runner_name)} "
            f"--labels {_ps_single_quoted(binding.runner_label)} "
            f"--work {_ps_single_quoted(binding.work_folder)} "
            "--ephemeral --disableupdate --no-default-labels"
        ),
        "",
    ]
    return "\n".join(lines)


def phase0_evidence_sha256(evidence_bytes: bytes) -> str:
    if type(evidence_bytes) is not bytes:
        raise ValueError("phase0 evidence must be exact bytes")
    return hashlib.sha256(evidence_bytes).hexdigest()


def plan_live_registration(
    binding: LiveRegistrationBinding,
    *,
    phase0_evidence_bytes: bytes,
    candidate: str,
    ast_attestation: AuthenticatedAstAttestation,
) -> OperatorGateResult:
    evidence_sha256 = phase0_evidence_sha256(phase0_evidence_bytes)
    spec = build_live_registration_spec(binding, phase0_evidence_sha256=evidence_sha256)
    candidate_sha256 = _candidate_sha256(candidate if type(candidate) is str else "")

    reasons = list(_binding_reason_codes(binding))
    if candidate != render_live_registration_candidate(binding):
        reasons.append("LIVE_REGISTRATION_CANDIDATE_NOT_CANONICAL")

    spec_reasons = _spec_reason_codes(spec)
    reasons.extend(spec_reasons)
    if reasons:
        return OperatorGateResult(
            OperatorGateStatus.BLOCKED,
            tuple(reasons),
            candidate_sha256,
        )
    status, attestation_reasons = _attestation_reason_codes(
        spec,
        candidate_sha256,
        ast_attestation,
    )
    return OperatorGateResult(status, attestation_reasons, candidate_sha256)


@dataclass(frozen=True, slots=True)
class RegistrationExecution:
    exit_code: int
    stdout: str
    stderr: str
    output_decoding_uncertain: bool = False


@dataclass(frozen=True, slots=True)
class RunnerReadback:
    runner_id: int
    name: str
    status: str
    busy: bool
    labels: tuple[str, ...]
    ephemeral: Optional[bool] = None


class LiveRegistrationStatus(str, Enum):
    BLOCKED = "BLOCKED"
    FAILED = "FAILED"
    REGISTERED = "REGISTERED"


@dataclass(frozen=True, slots=True)
class LiveRegistrationResult:
    status: LiveRegistrationStatus
    reason_codes: tuple[str, ...]
    candidate_sha256: str
    child_exit_code: Optional[int]
    stdout: str
    stderr: str
    runner_id: Optional[int]

    @property
    def registered(self) -> bool:
        return self.status is LiveRegistrationStatus.REGISTERED


PrepareRunner = Callable[[LiveRegistrationBinding], None]
AcquireRegistrationToken = Callable[[str], str]
RunRegistration = Callable[[LiveRegistrationBinding, str], RegistrationExecution]
CredentialHandoffCleared = Callable[[LiveRegistrationBinding, str], bool]
ReadRunners = Callable[[str], tuple[RunnerReadback, ...]]


def _gh_json(*arguments: str) -> object:
    completed = subprocess.run(
        ("gh.exe", "api", *arguments),
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise RuntimeError("GitHub readback failed")
    return json.loads(completed.stdout)


def _github_runner_items(repository: str) -> tuple[dict[str, object], ...]:
    from agent_controller.private_ci_runner_readback import read_all_runner_items

    base = f"repos/{repository}/actions/runners?per_page=100"

    def fetch_page(page: int) -> object:
        endpoint = base if page == 1 else f"{base}&page={page}"
        return _gh_json(endpoint)

    return read_all_runner_items(fetch_page)


def _require_frozen_target_still_exact(phase0_evidence_bytes: bytes) -> None:
    """Perform the concrete authoritative read used by the live executor.

    This operation is deliberately not supplied by an execution caller: accepting
    behavior here would let that caller replace the live read with a no-op.
    """

    # Imported lazily because the evidence schema freezes constants from this
    # module and therefore intentionally depends on it.
    from agent_controller.private_ci_phase0_evidence import validate_phase0_evidence_bytes

    evidence = validate_phase0_evidence_bytes(phase0_evidence_bytes)
    repo = _gh_json(f"repos/{evidence.repository}")
    if type(repo) is not dict:
        raise RuntimeError("repository readback invalid")
    if repo.get("visibility") != "private" or repo.get("default_branch") != "main":
        raise RuntimeError("repository visibility/default branch drift")

    pr = _gh_json(f"repos/{evidence.repository}/pulls/{evidence.pull_request_number}")
    if type(pr) is not dict:
        raise RuntimeError("PR readback invalid")
    if pr.get("state") != "open" or pr.get("draft") is not True:
        raise RuntimeError("PR state drift")
    head = pr.get("head")
    base = pr.get("base")
    if type(head) is not dict or type(base) is not dict:
        raise RuntimeError("PR ref readback invalid")
    head_repo = head.get("repo")
    if type(head_repo) is not dict or head_repo.get("full_name") != evidence.repository:
        raise RuntimeError("PR head repository drift")
    if head.get("sha") != evidence.pull_request_head_sha or base.get("ref") != "main":
        raise RuntimeError("PR exact-head/base drift")

    branch = _gh_json(f"repos/{evidence.repository}/branches/main")
    if type(branch) is not dict or type(branch.get("commit")) is not dict:
        raise RuntimeError("trusted workflow branch readback invalid")
    if branch["commit"].get("sha") != evidence.workflow_sha:
        raise RuntimeError("trusted workflow SHA drift")

    for runner in _github_runner_items(evidence.repository):
        if type(runner.get("labels")) is not list:
            raise RuntimeError("runner readback item invalid")
        labels = {
            item.get("name")
            for item in runner["labels"]
            if type(item) is dict and type(item.get("name")) is str
        }
        if evidence.runner_label in labels or runner.get("name") == evidence.runner_name:
            raise RuntimeError("pilot runner already registered before live authorization")


def _redact_secret(text: str, secret: str) -> tuple[str, bool]:
    if type(text) is not str:
        text = str(text)
    leaked = bool(secret) and secret in text
    return (text.replace(secret, "***") if leaked else text), leaked


def _eligible_runner_readback(
    binding: LiveRegistrationBinding,
    runners: tuple[RunnerReadback, ...],
) -> tuple[Optional[RunnerReadback], tuple[str, ...]]:
    if type(runners) is not tuple or not all(type(item) is RunnerReadback for item in runners):
        return None, ("RUNNER_READBACK_TYPE_INVALID",)
    eligible = [item for item in runners if binding.runner_label in item.labels]
    if len(eligible) != 1:
        return None, ("RUNNER_ELIGIBILITY_COUNT_INVALID",)
    runner = eligible[0]
    reasons: list[str] = []
    if runner.name != binding.runner_name:
        reasons.append("RUNNER_NAME_READBACK_MISMATCH")
    if runner.ephemeral is not None and runner.ephemeral is not True:
        reasons.append("RUNNER_NOT_EPHEMERAL")
    return (runner if not reasons else None), tuple(reasons)


def execute_live_registration(
    binding: LiveRegistrationBinding,
    *,
    phase0_evidence_bytes: bytes,
    candidate: str,
    ast_attestation: AuthenticatedAstAttestation,
    prior_evidence_capability: PriorEvidenceCapability,
    prepare_runner: PrepareRunner,
    acquire_registration_token: AcquireRegistrationToken,
    run_registration: RunRegistration,
    credential_handoff_cleared: CredentialHandoffCleared,
    read_runners: ReadRunners,
) -> LiveRegistrationResult:
    plan = plan_live_registration(
        binding,
        phase0_evidence_bytes=phase0_evidence_bytes,
        candidate=candidate,
        ast_attestation=ast_attestation,
    )
    if plan.status is not OperatorGateStatus.PASS_TO_OPERATOR:
        return LiveRegistrationResult(
            LiveRegistrationStatus.BLOCKED,
            tuple(f"PLAN_{reason}" for reason in plan.reason_codes) or ("PLAN_NOT_PASS",),
            plan.candidate_sha256,
            None,
            "",
            "",
            None,
        )

    evidence_sha256 = phase0_evidence_sha256(phase0_evidence_bytes)
    spec = build_live_registration_spec(binding, phase0_evidence_sha256=evidence_sha256)
    gate = validate_operator_step(
        spec,
        candidate,
        ast_attestation=ast_attestation,
        prior_evidence_capability=prior_evidence_capability,
    )
    if gate.status is not OperatorGateStatus.PASS_TO_OPERATOR:
        return LiveRegistrationResult(
            LiveRegistrationStatus.BLOCKED,
            tuple(f"LIVE_GATE_{reason}" for reason in gate.reason_codes) or ("LIVE_GATE_NOT_PASS",),
            gate.candidate_sha256,
            None,
            "",
            "",
            None,
        )

    def mutation_target_is_revalidated() -> bool:
        try:
            _require_frozen_target_still_exact(phase0_evidence_bytes)
        except Exception:
            return False
        return True

    if not mutation_target_is_revalidated():
        return LiveRegistrationResult(
            LiveRegistrationStatus.FAILED,
            ("MUTATION_TIME_TARGET_REVALIDATION_FAILED",),
            gate.candidate_sha256,
            None,
            "",
            "",
            None,
        )

    try:
        prepare_runner(binding)
    except Exception:
        return LiveRegistrationResult(
            LiveRegistrationStatus.FAILED,
            ("RUNNER_PREPARATION_FAILED",),
            gate.candidate_sha256,
            None,
            "",
            "",
            None,
        )

    # Preparation can take long enough for any of the frozen target facts to
    # drift.  Repeat the complete evidence-bound check at the token boundary;
    # the runtime's narrower runner-collision check remains defense in depth.
    if not mutation_target_is_revalidated():
        return LiveRegistrationResult(
            LiveRegistrationStatus.FAILED,
            ("MUTATION_TIME_TARGET_REVALIDATION_FAILED",),
            gate.candidate_sha256,
            None,
            "",
            "",
            None,
        )

    try:
        registration_token = acquire_registration_token(binding.repository)
    except Exception:
        return LiveRegistrationResult(
            LiveRegistrationStatus.FAILED,
            ("REGISTRATION_TOKEN_ACQUISITION_FAILED",),
            gate.candidate_sha256,
            None,
            "",
            "",
            None,
        )
    if type(registration_token) is not str or not registration_token.strip():
        return LiveRegistrationResult(
            LiveRegistrationStatus.FAILED,
            ("REGISTRATION_TOKEN_INVALID",),
            gate.candidate_sha256,
            None,
            "",
            "",
            None,
        )
    if registration_token in candidate:
        return LiveRegistrationResult(
            LiveRegistrationStatus.FAILED,
            ("REGISTRATION_TOKEN_PRESENT_IN_CANDIDATE",),
            gate.candidate_sha256,
            None,
            "",
            "",
            None,
        )

    try:
        execution = run_registration(binding, registration_token)
    except Exception:
        return LiveRegistrationResult(
            LiveRegistrationStatus.FAILED,
            ("REGISTRATION_CHILD_LAUNCH_FAILED",),
            gate.candidate_sha256,
            None,
            "",
            "",
            None,
        )

    stdout, stdout_leaked = _redact_secret(execution.stdout, registration_token)
    stderr, stderr_leaked = _redact_secret(execution.stderr, registration_token)

    try:
        handoff_cleared = credential_handoff_cleared(binding, registration_token)
    except Exception:
        handoff_cleared = False

    if stdout_leaked or stderr_leaked:
        return LiveRegistrationResult(
            LiveRegistrationStatus.FAILED,
            ("REGISTRATION_TOKEN_LEAKED_TO_CHILD_OUTPUT",),
            gate.candidate_sha256,
            execution.exit_code,
            stdout,
            stderr,
            None,
        )
    if execution.output_decoding_uncertain:
        reasons = ["REGISTRATION_NATIVE_OUTPUT_DECODE_FAILED"]
        if execution.exit_code != 0:
            reasons.append("REGISTRATION_CHILD_EXIT_NONZERO")
        observed_runner_id: Optional[int] = None
        try:
            decode_failure_runners = read_runners(binding.repository)
        except Exception:
            reasons.append("RUNNER_READBACK_UNCERTAIN_AFTER_DECODE_FAILURE")
        else:
            decode_failure_runner, decode_failure_readback_reasons = _eligible_runner_readback(
                binding,
                decode_failure_runners,
            )
            if decode_failure_runner is not None and not decode_failure_readback_reasons:
                observed_runner_id = decode_failure_runner.runner_id
                reasons.append("REGISTRATION_MUTATION_OBSERVED_AFTER_DECODE_FAILURE")
            elif decode_failure_runners and decode_failure_readback_reasons:
                reasons.append("RUNNER_READBACK_UNCERTAIN_AFTER_DECODE_FAILURE")
        if not handoff_cleared:
            reasons.append("REGISTRATION_TOKEN_HANDOFF_NOT_CLEARED")
        return LiveRegistrationResult(
            LiveRegistrationStatus.FAILED,
            tuple(reasons),
            gate.candidate_sha256,
            execution.exit_code,
            stdout,
            stderr,
            observed_runner_id,
        )
    if execution.exit_code != 0:
        reasons = ["REGISTRATION_CHILD_EXIT_NONZERO"]
        observed_runner_id: Optional[int] = None
        try:
            failure_runners = read_runners(binding.repository)
        except Exception:
            reasons.append("RUNNER_READBACK_UNCERTAIN_AFTER_CHILD_FAILURE")
        else:
            failure_runner, failure_readback_reasons = _eligible_runner_readback(
                binding,
                failure_runners,
            )
            if failure_runner is not None and not failure_readback_reasons:
                observed_runner_id = failure_runner.runner_id
                reasons.append("REGISTRATION_MUTATION_OBSERVED_AFTER_CHILD_FAILURE")
            elif failure_runners and failure_readback_reasons:
                reasons.append("RUNNER_READBACK_UNCERTAIN_AFTER_CHILD_FAILURE")
        if not handoff_cleared:
            reasons.append("REGISTRATION_TOKEN_HANDOFF_NOT_CLEARED")
        return LiveRegistrationResult(
            LiveRegistrationStatus.FAILED,
            tuple(reasons),
            gate.candidate_sha256,
            execution.exit_code,
            stdout,
            stderr,
            observed_runner_id,
        )
    if not handoff_cleared:
        return LiveRegistrationResult(
            LiveRegistrationStatus.FAILED,
            ("REGISTRATION_TOKEN_HANDOFF_NOT_CLEARED",),
            gate.candidate_sha256,
            execution.exit_code,
            stdout,
            stderr,
            None,
        )

    try:
        runners = read_runners(binding.repository)
    except Exception:
        return LiveRegistrationResult(
            LiveRegistrationStatus.FAILED,
            ("RUNNER_READBACK_FAILED",),
            gate.candidate_sha256,
            execution.exit_code,
            stdout,
            stderr,
            None,
        )
    runner, readback_reasons = _eligible_runner_readback(binding, runners)
    if readback_reasons or runner is None:
        return LiveRegistrationResult(
            LiveRegistrationStatus.FAILED,
            readback_reasons or ("RUNNER_READBACK_NOT_PASS",),
            gate.candidate_sha256,
            execution.exit_code,
            stdout,
            stderr,
            None,
        )

    return LiveRegistrationResult(
        LiveRegistrationStatus.REGISTERED,
        (),
        gate.candidate_sha256,
        execution.exit_code,
        stdout,
        stderr,
        runner.runner_id,
    )
