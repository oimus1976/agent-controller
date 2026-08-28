import unittest

from agent_controller.objective_target import (
    GitHubTargetExpectation,
    run_objective_target_handoff,
)
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


START_SHA = "a" * 40
HEAD_SHA = "b" * 40
THREAD_ID = "123e4567-e89b-12d3-a456-426614174000"
GITHUB_OBSERVED_AT = "2026-08-28T00:00:02Z"


def _task(*, repo="oimus1976/example", allowed=("src/*",), denied=()):
    return TaskBinding(
        controller_task_id="task-1",
        operation_id="op-1",
        provider="codex",
        repo=repo,
        expected_start_ref=None,
        expected_start_sha=START_SHA,
        objective_scope=ObjectiveScope(allowed_paths=allowed, denied_paths=denied),
        requested_capability="verify-target",
        allowed_effects=(),
        forbidden_effects=("github_write",),
        approval_policy_id="adr-90-human-final",
        created_at="2026-08-28T00:00:00Z",
    )


def _operation(**overrides):
    values = {
        "provider": "codex",
        "provider_operation_id": THREAD_ID,
        "provider_url": None,
        "controller_task_id": "task-1",
        "operation_id": "op-1",
    }
    values.update(overrides)
    return ProviderOperationRef(**values)


def _observation(
    *,
    mapped_state=ControllerState.ARTIFACT_READY,
    terminal_claim=TerminalClaim.SUCCESS,
    provider="codex",
    provider_operation_id=THREAD_ID,
    raw_state=None,
):
    return AgentObservation(
        provider=provider,
        provider_operation_id=provider_operation_id,
        observed_at="2026-08-28T00:00:01Z",
        provider_updated_at=None,
        provider_raw_state=raw_state or {"status": "done", "result": "success"},
        mapped_state=mapped_state,
        awaiting_input=AwaitingInput.NONE,
        terminal_claim=terminal_claim,
        reported_effects=(),
        provider_refs=(THREAD_ID,),
        uncertainty_reason=None,
    )


class FakeObserver:
    def __init__(self, observation=None, error=None):
        self.observation = _observation() if observation is None else observation
        self.error = error
        self.calls = 0

    def observe(self, operation):
        self.calls += 1
        if self.error:
            raise self.error
        return self.observation


class FakeGitHub:
    def __init__(self, *, ref_sha=HEAD_SHA, merge_base=START_SHA, files=None):
        self.ref_sha = ref_sha
        self.merge_base = merge_base
        self.files = files if files is not None else [
            {"filename": "src/app.py", "changes": 3}
        ]
        self.ref_calls = 0
        self.compare_calls = 0
        self.ref_error = None
        self.compare_error = None

    def get_ref_sha(self, repo, ref):
        self.ref_calls += 1
        if self.ref_error:
            raise self.ref_error
        return self.ref_sha

    def compare_commits(self, repo, base_sha, head_sha):
        self.compare_calls += 1
        if self.compare_error:
            raise self.compare_error
        return {"merge_base_sha": self.merge_base, "files": self.files}


def _run(*, task=None, operation=None, observer=None, target=None, github=None, observed_at=None):
    return run_objective_target_handoff(
        task=task or _task(),
        operation=operation or _operation(),
        observer=observer or FakeObserver(),
        target=target or GitHubTargetExpectation(
            repo="oimus1976/example",
            ref="feature/task-1",
        ),
        github=github or FakeGitHub(),
        github_observed_at=observed_at or (lambda: GITHUB_OBSERVED_AT),
    )


class ObjectiveTargetHandoffTests(unittest.TestCase):
    def test_success_requires_provider_completion_and_objective_github_verification(self):
        observer = FakeObserver()
        github = FakeGitHub()

        result = _run(observer=observer, github=github)

        self.assertEqual(VerificationResult.PASS, result.verification_result)
        self.assertEqual(HEAD_SHA, result.target_evidence.resolved_sha)
        self.assertEqual(GITHUB_OBSERVED_AT, result.target_evidence.github_observed_at)
        self.assertEqual("GITHUB_TARGET_VERIFIED", result.target_evidence.reason)
        self.assertEqual(1, observer.calls)
        self.assertEqual(1, github.ref_calls)
        self.assertEqual(1, github.compare_calls)

    def test_nonterminal_provider_claim_blocks_before_github_reads(self):
        observer = FakeObserver(
            _observation(
                mapped_state=ControllerState.EXECUTING,
                terminal_claim=TerminalClaim.NONE,
            )
        )
        github = FakeGitHub()

        result = _run(observer=observer, github=github)

        self.assertEqual(VerificationResult.BLOCKED, result.verification_result)
        self.assertEqual("OBSERVATION_NOT_ARTIFACT_READY_SUCCESS", result.target_evidence.reason)
        self.assertEqual(0, github.ref_calls)
        self.assertEqual(0, github.compare_calls)

    def test_operation_binding_mismatch_blocks_before_any_reads(self):
        observer = FakeObserver()
        github = FakeGitHub()

        result = _run(
            operation=_operation(operation_id="wrong"),
            observer=observer,
            github=github,
        )

        self.assertEqual(VerificationResult.BLOCKED, result.verification_result)
        self.assertEqual("OPERATION_ID_MISMATCH", result.binding.reason)
        self.assertEqual(0, observer.calls)
        self.assertEqual(0, github.ref_calls)

    def test_target_repo_mismatch_blocks_before_provider_read(self):
        observer = FakeObserver()
        github = FakeGitHub()

        result = _run(
            observer=observer,
            target=GitHubTargetExpectation(repo="oimus1976/other", ref="feature/task-1"),
            github=github,
        )

        self.assertEqual(VerificationResult.BLOCKED, result.verification_result)
        self.assertEqual("TARGET_REPO_MISMATCH", result.binding.reason)
        self.assertEqual(0, observer.calls)
        self.assertEqual(0, github.ref_calls)

    def test_missing_objective_scope_blocks_before_provider_read(self):
        observer = FakeObserver()
        github = FakeGitHub()

        result = _run(
            task=_task(allowed=(), denied=()),
            observer=observer,
            github=github,
        )

        self.assertEqual(VerificationResult.BLOCKED, result.verification_result)
        self.assertEqual("OBJECTIVE_SCOPE_MISSING", result.binding.reason)
        self.assertEqual(0, observer.calls)
        self.assertEqual(0, github.ref_calls)

    def test_provider_git_info_does_not_choose_target_identity(self):
        observer = FakeObserver(
            _observation(
                raw_state={
                    "status": "done",
                    "result": "success",
                    "gitInfo": {
                        "branch": "provider-claimed-branch",
                        "sha": "c" * 40,
                    },
                }
            )
        )
        target = GitHubTargetExpectation(repo="oimus1976/example", ref="controller-target")

        result = _run(observer=observer, target=target)

        self.assertEqual(VerificationResult.PASS, result.verification_result)
        self.assertEqual("controller-target", result.target_evidence.target_ref)
        self.assertEqual(HEAD_SHA, result.target_evidence.resolved_sha)

    def test_unchanged_target_does_not_pass(self):
        github = FakeGitHub(ref_sha=START_SHA)

        result = _run(github=github)

        self.assertEqual(VerificationResult.FAIL, result.verification_result)
        self.assertEqual("TARGET_UNCHANGED_FROM_START", result.target_evidence.reason)
        self.assertEqual(0, github.compare_calls)

    def test_divergent_target_does_not_pass(self):
        result = _run(github=FakeGitHub(merge_base="d" * 40))

        self.assertEqual(VerificationResult.FAIL, result.verification_result)
        self.assertEqual("TARGET_DIVERGED_FROM_EXPECTED_START", result.target_evidence.reason)

    def test_scope_violation_does_not_pass(self):
        result = _run(
            github=FakeGitHub(files=[{"filename": "secrets/key.txt", "changes": 1}])
        )

        self.assertEqual(VerificationResult.FAIL, result.verification_result)
        self.assertEqual("OBJECTIVE_SCOPE_VIOLATION", result.target_evidence.reason)

    def test_github_read_failure_is_uncertain_not_pass(self):
        github = FakeGitHub()
        github.ref_error = RuntimeError("network down")

        result = _run(github=github)

        self.assertEqual(VerificationResult.UNCERTAIN, result.verification_result)
        self.assertEqual("GITHUB_REF_READ_UNAVAILABLE", result.target_evidence.reason)
        self.assertEqual(GITHUB_OBSERVED_AT, result.target_evidence.github_observed_at)

    def test_provider_observation_failure_is_uncertain_and_skips_github(self):
        observer = FakeObserver(error=RuntimeError("provider unavailable"))
        github = FakeGitHub()

        result = _run(observer=observer, github=github)

        self.assertEqual(VerificationResult.UNCERTAIN, result.verification_result)
        self.assertEqual("PROVIDER_OBSERVATION_UNAVAILABLE", result.target_evidence.reason)
        self.assertEqual(0, github.ref_calls)

    def test_malformed_provider_observation_is_uncertain_and_skips_github(self):
        observer = FakeObserver(observation={"status": "done"})
        github = FakeGitHub()

        result = _run(observer=observer, github=github)

        self.assertEqual(VerificationResult.UNCERTAIN, result.verification_result)
        self.assertEqual("PROVIDER_OBSERVATION_MALFORMED", result.target_evidence.reason)
        self.assertEqual(0, github.ref_calls)

    def test_github_timestamp_failure_is_uncertain_and_skips_github(self):
        github = FakeGitHub()

        def fail_timestamp():
            raise RuntimeError("clock unavailable")

        result = _run(github=github, observed_at=fail_timestamp)

        self.assertEqual(VerificationResult.UNCERTAIN, result.verification_result)
        self.assertEqual("GITHUB_OBSERVED_AT_UNAVAILABLE", result.target_evidence.reason)
        self.assertEqual(0, github.ref_calls)


if __name__ == "__main__":
    unittest.main()
