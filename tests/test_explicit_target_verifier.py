from agent_controller.explicit_target_verifier import run_explicit_target_verification
from agent_controller.provider_contract import (
    AgentObservation,
    AwaitingInput,
    ControllerState,
    ObjectiveScope,
    ProviderOperationRef,
    TaskBinding,
    TerminalClaim,
    VerificationResult,
)


class FakeObserver:
    def __init__(self, observation):
        self.observation = observation
        self.calls = 0

    def observe(self, operation):
        self.calls += 1
        return self.observation


class FakeGitHub:
    def __init__(self, *, sha="head", merge_base="base", files=None, fail_ref=False, fail_compare=False):
        self.sha = sha
        self.merge_base = merge_base
        self.files = [{"filename": "src/app.py"}] if files is None else files
        self.fail_ref = fail_ref
        self.fail_compare = fail_compare
        self.ref_calls = 0
        self.compare_calls = 0

    def get_ref_sha(self, repo, ref):
        self.ref_calls += 1
        if self.fail_ref:
            raise RuntimeError("read failed")
        return self.sha

    def compare_commits(self, repo, base_sha, head_sha):
        self.compare_calls += 1
        if self.fail_compare:
            raise RuntimeError("compare failed")
        return {"merge_base_sha": self.merge_base, "files": self.files}


def task(**overrides):
    values = dict(
        controller_task_id="task-1",
        operation_id="op-1",
        provider="codex",
        repo="oimus1976/example",
        expected_start_ref="main",
        expected_start_sha="base",
        objective_scope=ObjectiveScope(allowed_paths=("src/*",), denied_paths=()),
        requested_capability="implement",
        allowed_effects=("branch_write",),
        forbidden_effects=("merge",),
        approval_policy_id="policy",
        created_at="2026-08-28T00:00:00Z",
    )
    values.update(overrides)
    return TaskBinding(**values)


def operation(**overrides):
    values = dict(
        provider="codex",
        provider_operation_id="thread-1",
        provider_url=None,
        controller_task_id="task-1",
        operation_id="op-1",
    )
    values.update(overrides)
    return ProviderOperationRef(**values)


def observation(**overrides):
    values = dict(
        provider="codex",
        provider_operation_id="thread-1",
        observed_at="2026-08-28T00:01:00Z",
        provider_updated_at=None,
        provider_raw_state={"status": "done"},
        mapped_state=ControllerState.ARTIFACT_READY,
        awaiting_input=AwaitingInput.NONE,
        terminal_claim=TerminalClaim.SUCCESS,
        reported_effects=(),
        provider_refs=("thread-1",),
        uncertainty_reason=None,
    )
    values.update(overrides)
    return AgentObservation(**values)


def test_operation_binding_mismatch_blocks_before_any_reads():
    observer = FakeObserver(observation())
    github = FakeGitHub()

    result = run_explicit_target_verification(
        task=task(),
        operation=operation(controller_task_id="wrong"),
        target_ref="refs/heads/work",
        observer=observer,
        github=github,
    )

    assert result.verification_result is VerificationResult.BLOCKED
    assert result.binding.valid is False
    assert observer.calls == 0
    assert github.ref_calls == 0


def test_provider_terminal_success_is_necessary_but_not_sufficient():
    observer = FakeObserver(observation())
    github = FakeGitHub(sha="base")

    result = run_explicit_target_verification(
        task=task(),
        operation=operation(),
        target_ref="refs/heads/work",
        observer=observer,
        github=github,
    )

    assert result.observation.terminal_claim is TerminalClaim.SUCCESS
    assert result.verification_result is VerificationResult.FAIL
    assert result.evidence.reason == "TARGET_UNCHANGED_FROM_EXPECTED_START"


def test_nonterminal_provider_state_never_reads_github():
    observer = FakeObserver(
        observation(mapped_state=ControllerState.EXECUTING, terminal_claim=TerminalClaim.NONE)
    )
    github = FakeGitHub()

    result = run_explicit_target_verification(
        task=task(), operation=operation(), target_ref="work", observer=observer, github=github
    )

    assert result.verification_result is VerificationResult.BLOCKED
    assert github.ref_calls == 0
    assert github.compare_calls == 0


def test_observation_identity_mismatch_blocks_before_github():
    observer = FakeObserver(observation(provider_operation_id="other-thread"))
    github = FakeGitHub()

    result = run_explicit_target_verification(
        task=task(), operation=operation(), target_ref="work", observer=observer, github=github
    )

    assert result.verification_result is VerificationResult.BLOCKED
    assert result.binding.valid is False
    assert github.ref_calls == 0


def test_missing_scope_blocks_before_provider_read():
    observer = FakeObserver(observation())
    github = FakeGitHub()

    result = run_explicit_target_verification(
        task=task(objective_scope=ObjectiveScope()),
        operation=operation(),
        target_ref="work",
        observer=observer,
        github=github,
    )

    assert result.verification_result is VerificationResult.BLOCKED
    assert result.evidence.reason == "OBJECTIVE_SCOPE_MISSING"
    assert observer.calls == 0


def test_missing_target_fails_closed_without_compare():
    github = FakeGitHub(sha=None)
    result = run_explicit_target_verification(
        task=task(), operation=operation(), target_ref="work", observer=FakeObserver(observation()), github=github
    )

    assert result.verification_result is VerificationResult.FAIL
    assert result.evidence.reason == "GITHUB_TARGET_MISSING"
    assert github.compare_calls == 0


def test_divergent_target_does_not_pass():
    github = FakeGitHub(sha="head", merge_base="other-base")
    result = run_explicit_target_verification(
        task=task(), operation=operation(), target_ref="work", observer=FakeObserver(observation()), github=github
    )

    assert result.verification_result is VerificationResult.FAIL
    assert result.evidence.reason == "TARGET_NOT_DESCENDANT_OF_EXPECTED_START"


def test_scope_violation_does_not_pass():
    github = FakeGitHub(sha="head", files=[{"filename": "secrets/key.txt"}])
    result = run_explicit_target_verification(
        task=task(), operation=operation(), target_ref="work", observer=FakeObserver(observation()), github=github
    )

    assert result.verification_result is VerificationResult.FAIL
    assert result.evidence.reason == "OBJECTIVE_SCOPE_VIOLATION"


def test_malformed_scope_evidence_is_uncertain():
    github = FakeGitHub(sha="head", files=None)
    github.files = None
    result = run_explicit_target_verification(
        task=task(), operation=operation(), target_ref="work", observer=FakeObserver(observation()), github=github
    )

    assert result.verification_result is VerificationResult.UNCERTAIN
    assert result.evidence.reason == "GITHUB_SCOPE_EVIDENCE_UNAVAILABLE"


def test_github_read_failure_is_uncertain():
    github = FakeGitHub(fail_ref=True)
    result = run_explicit_target_verification(
        task=task(), operation=operation(), target_ref="work", observer=FakeObserver(observation()), github=github
    )

    assert result.verification_result is VerificationResult.UNCERTAIN
    assert result.evidence.reason == "GITHUB_TARGET_READ_UNAVAILABLE"


def test_success_uses_controller_target_and_github_resolved_sha():
    github = FakeGitHub(sha="head", merge_base="base", files=[{"filename": "src/app.py"}])
    result = run_explicit_target_verification(
        task=task(),
        operation=operation(),
        target_ref="refs/heads/controller-selected",
        observer=FakeObserver(observation(provider_refs=("provider-only-ref",))),
        github=github,
    )

    assert result.verification_result is VerificationResult.PASS
    assert result.evidence.repo == "oimus1976/example"
    assert result.evidence.target_ref == "refs/heads/controller-selected"
    assert result.evidence.resolved_sha == "head"
    assert result.evidence.verification_source.value == "GITHUB"
    assert result.evidence.reason == "GITHUB_TARGET_VERIFIED"
