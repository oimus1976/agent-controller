import unittest
from concurrent.futures import ThreadPoolExecutor

from agent_controller.private_ci_contract import (
    PrivateCiExecutionResult,
    PrivateCiNonceAuthority,
    PrivateCiPhaseStatus,
    PrivateCiRequest,
    PrivateCiTargetOs,
    validate_and_reserve_private_ci_request,
    validate_private_ci_result,
)


REPOSITORY = "oimus1976/example-private"
HEAD = "1" * 40
NONCE = "nonce-207-alpha"
LABEL = f"ac-private-ci-{NONCE}"
GENERATION = "generation-207-alpha"
WORKFLOW = "trusted-default-branch-private-ci-v1"


def valid_request(**overrides):
    values = {
        "repository": REPOSITORY,
        "repository_visibility": "private",
        "pull_request_number": 17,
        "pull_request_state": "open",
        "pull_request_head_repository": REPOSITORY,
        "expected_head_sha": HEAD,
        "observed_head_sha": HEAD,
        "workflow_identity": WORKFLOW,
        "target_os": PrivateCiTargetOs.WINDOWS,
        "runner_scope_repository": REPOSITORY,
        "runner_nonce": NONCE,
        "runner_label": LABEL,
        "environment_generation": GENERATION,
        "residual_runner_count": 0,
        "environment_reset_proven": True,
    }
    values.update(overrides)
    return PrivateCiRequest(**values)


def valid_result(**overrides):
    values = {
        "repository": REPOSITORY,
        "pull_request_number": 17,
        "exact_head_sha": HEAD,
        "workflow_identity": WORKFLOW,
        "target_os": PrivateCiTargetOs.WINDOWS,
        "runner_scope_repository": REPOSITORY,
        "runner_nonce": NONCE,
        "runner_label": LABEL,
        "environment_generation": GENERATION,
        "registration": PrivateCiPhaseStatus.PASS,
        "dispatch": PrivateCiPhaseStatus.PASS,
        "target_execution": PrivateCiPhaseStatus.PASS,
        "cleanup": PrivateCiPhaseStatus.PASS,
        "post_cleanup_readback": PrivateCiPhaseStatus.PASS,
        "residual_runner_count": 0,
        "environment_reset_proven": True,
    }
    values.update(overrides)
    return PrivateCiExecutionResult(**values)


class PrivateCiRequestValidationTests(unittest.TestCase):
    def validate(self, request, *, allowed=None, workflows=None, authority=None):
        return validate_and_reserve_private_ci_request(
            request,
            allowed_repositories=frozenset({REPOSITORY}) if allowed is None else frozenset(allowed),
            allowed_workflow_identities=frozenset({WORKFLOW}) if workflows is None else frozenset(workflows),
            nonce_authority=PrivateCiNonceAuthority() if authority is None else authority,
        )

    def test_accepts_exact_private_same_repo_request_and_burns_nonce(self):
        authority = PrivateCiNonceAuthority()
        decision = self.validate(valid_request(), authority=authority)
        self.assertTrue(decision.valid)
        self.assertTrue(authority.is_used(NONCE))

    def test_rejects_public_repository_without_burning_nonce(self):
        authority = PrivateCiNonceAuthority()
        decision = self.validate(valid_request(repository_visibility="public"), authority=authority)
        self.assertFalse(decision.valid)
        self.assertFalse(authority.is_used(NONCE))

    def test_rejects_repository_outside_allowlist(self):
        decision = self.validate(valid_request(), allowed={"oimus1976/other-private"})
        self.assertFalse(decision.valid)

    def test_rejects_closed_pull_request(self):
        decision = self.validate(valid_request(pull_request_state="closed"))
        self.assertFalse(decision.valid)

    def test_rejects_fork_head(self):
        decision = self.validate(valid_request(pull_request_head_repository="attacker/fork"))
        self.assertFalse(decision.valid)

    def test_rejects_head_drift(self):
        decision = self.validate(valid_request(observed_head_sha="2" * 40))
        self.assertFalse(decision.valid)

    def test_rejects_short_or_uppercase_sha(self):
        self.assertFalse(self.validate(valid_request(expected_head_sha="1" * 39)).valid)
        self.assertFalse(self.validate(valid_request(expected_head_sha="A" * 40, observed_head_sha="A" * 40)).valid)

    def test_rejects_unallowlisted_workflow_identity(self):
        decision = self.validate(valid_request(), workflows={"another-trusted-workflow"})
        self.assertFalse(decision.valid)

    def test_rejects_wrong_repository_runner_scope(self):
        decision = self.validate(valid_request(runner_scope_repository="oimus1976/other-private"))
        self.assertFalse(decision.valid)

    def test_rejects_reused_nonce(self):
        authority = PrivateCiNonceAuthority({NONCE})
        decision = self.validate(valid_request(), authority=authority)
        self.assertFalse(decision.valid)

    def test_concurrent_same_nonce_allows_exactly_one_request(self):
        authority = PrivateCiNonceAuthority()

        def attempt():
            return self.validate(valid_request(), authority=authority).valid

        with ThreadPoolExecutor(max_workers=2) as executor:
            outcomes = list(executor.map(lambda _: attempt(), range(2)))
        self.assertEqual(sorted(outcomes), [False, True])

    def test_rejects_runner_label_not_bound_to_nonce(self):
        decision = self.validate(valid_request(runner_label="ac-private-ci-other"))
        self.assertFalse(decision.valid)

    def test_rejects_residual_runner_registration(self):
        decision = self.validate(valid_request(residual_runner_count=1))
        self.assertFalse(decision.valid)

    def test_rejects_uncertain_environment_reset(self):
        decision = self.validate(valid_request(environment_reset_proven=False))
        self.assertFalse(decision.valid)

    def test_rejects_bool_as_integer_fields(self):
        self.assertFalse(self.validate(valid_request(pull_request_number=True)).valid)
        self.assertFalse(self.validate(valid_request(residual_runner_count=False)).valid)


class PrivateCiResultValidationTests(unittest.TestCase):
    def test_accepts_complete_zero_residual_result(self):
        decision = validate_private_ci_result(valid_request(), valid_result())
        self.assertTrue(decision.valid)

    def test_rejects_cross_repository_result_mixup(self):
        decision = validate_private_ci_result(
            valid_request(),
            valid_result(repository="oimus1976/other-private"),
        )
        self.assertFalse(decision.valid)

    def test_rejects_runner_scope_mixup(self):
        decision = validate_private_ci_result(
            valid_request(),
            valid_result(runner_scope_repository="oimus1976/other-private"),
        )
        self.assertFalse(decision.valid)

    def test_rejects_stale_sha_result(self):
        decision = validate_private_ci_result(valid_request(), valid_result(exact_head_sha="2" * 40))
        self.assertFalse(decision.valid)

    def test_rejects_nonce_or_environment_generation_mixup(self):
        self.assertFalse(
            validate_private_ci_result(valid_request(), valid_result(runner_nonce="different-nonce")).valid
        )
        self.assertFalse(
            validate_private_ci_result(valid_request(), valid_result(environment_generation="different-generation")).valid
        )

    def test_rejects_any_nonpass_required_phase(self):
        for field_name in (
            "registration",
            "dispatch",
            "target_execution",
            "cleanup",
            "post_cleanup_readback",
        ):
            with self.subTest(field_name=field_name):
                decision = validate_private_ci_result(
                    valid_request(),
                    valid_result(**{field_name: PrivateCiPhaseStatus.UNCERTAIN}),
                )
                self.assertFalse(decision.valid)

    def test_rejects_residual_runner_after_cleanup(self):
        decision = validate_private_ci_result(valid_request(), valid_result(residual_runner_count=1))
        self.assertFalse(decision.valid)

    def test_rejects_unproven_post_cleanup_reset(self):
        decision = validate_private_ci_result(valid_request(), valid_result(environment_reset_proven=False))
        self.assertFalse(decision.valid)


if __name__ == "__main__":
    unittest.main()
