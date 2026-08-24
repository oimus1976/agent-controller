import unittest

from agent_controller.repository_write_guard import (
    CONTROLLER_STATE_REF,
    RepositoryWriteDecision,
    RepositoryWritePolicy,
    RepositoryWritePurpose,
    RepositoryWriteTarget,
    validate_repository_write_target,
)


class RepositoryWriteGuardTests(unittest.TestCase):
    def setUp(self):
        self.policy = RepositoryWritePolicy(
            repo="oimus1976/agent-controller",
            default_branch="main",
        )

    def validate(self, ref, purpose=RepositoryWritePurpose.IMPLEMENTATION_BRANCH, policy=None):
        return validate_repository_write_target(
            policy=policy or self.policy,
            target=RepositoryWriteTarget(
                repo="oimus1976/agent-controller",
                explicit_ref=ref,
                purpose=purpose,
            ),
        )

    def test_missing_or_empty_ref_is_blocked(self):
        for ref in (None, "", "   "):
            with self.subTest(ref=ref):
                result = self.validate(ref)
                self.assertEqual(RepositoryWriteDecision.BLOCKED, result.decision)
                self.assertEqual("EXPLICIT_REF_REQUIRED", result.reason)

    def test_normal_implementation_branch_passes(self):
        result = self.validate("phase-4c-repository-write-guard")
        self.assertEqual(RepositoryWriteDecision.PASS, result.decision)
        self.assertEqual("phase-4c-repository-write-guard", result.normalized_ref)

    def test_refs_heads_prefix_is_normalized(self):
        result = self.validate("refs/heads/feature/x")
        self.assertEqual(RepositoryWriteDecision.PASS, result.decision)
        self.assertEqual("feature/x", result.normalized_ref)

    def test_explicit_default_branch_is_blocked_for_normal_write(self):
        result = self.validate("main")
        self.assertEqual(RepositoryWriteDecision.BLOCKED, result.decision)
        self.assertEqual("DEFAULT_BRANCH_WRITE_FORBIDDEN", result.reason)

    def test_default_branch_alias_cannot_bypass(self):
        result = self.validate("refs/heads/main")
        self.assertEqual(RepositoryWriteDecision.BLOCKED, result.decision)
        self.assertEqual("DEFAULT_BRANCH_WRITE_FORBIDDEN", result.reason)

    def test_head_aliases_are_blocked(self):
        for ref in ("HEAD", "head", ".", ".."):
            with self.subTest(ref=ref):
                result = self.validate(ref)
                self.assertEqual(RepositoryWriteDecision.BLOCKED, result.decision)
                self.assertEqual("WRITE_REF_ALIAS_FORBIDDEN", result.reason)

    def test_controller_state_requires_dedicated_purpose(self):
        result = self.validate(CONTROLLER_STATE_REF)
        self.assertEqual(RepositoryWriteDecision.BLOCKED, result.decision)
        self.assertEqual("CONTROLLER_STATE_REQUIRES_DEDICATED_PURPOSE", result.reason)

    def test_controller_state_exact_fixed_ref_passes(self):
        result = self.validate(
            CONTROLLER_STATE_REF,
            purpose=RepositoryWritePurpose.CONTROLLER_STATE,
        )
        self.assertEqual(RepositoryWriteDecision.PASS, result.decision)

    def test_controller_state_cannot_be_redirected(self):
        result = self.validate(
            "controller-state-other",
            purpose=RepositoryWritePurpose.CONTROLLER_STATE,
        )
        self.assertEqual(RepositoryWriteDecision.BLOCKED, result.decision)
        self.assertEqual("CONTROLLER_STATE_REF_MISMATCH", result.reason)

    def test_direct_default_branch_admin_is_disabled_by_default(self):
        result = self.validate(
            "main",
            purpose=RepositoryWritePurpose.DIRECT_DEFAULT_BRANCH_ADMIN,
        )
        self.assertEqual(RepositoryWriteDecision.BLOCKED, result.decision)
        self.assertEqual("DIRECT_DEFAULT_BRANCH_ADMIN_DISABLED", result.reason)

    def test_direct_default_branch_admin_requires_explicit_separate_policy(self):
        enabled = RepositoryWritePolicy(
            repo="oimus1976/agent-controller",
            default_branch="main",
            allow_direct_default_branch_admin=True,
        )
        result = self.validate(
            "main",
            purpose=RepositoryWritePurpose.DIRECT_DEFAULT_BRANCH_ADMIN,
            policy=enabled,
        )
        self.assertEqual(RepositoryWriteDecision.PASS, result.decision)

    def test_direct_default_branch_admin_cannot_target_other_branch(self):
        enabled = RepositoryWritePolicy(
            repo="oimus1976/agent-controller",
            default_branch="main",
            allow_direct_default_branch_admin=True,
        )
        result = self.validate(
            "feature/x",
            purpose=RepositoryWritePurpose.DIRECT_DEFAULT_BRANCH_ADMIN,
            policy=enabled,
        )
        self.assertEqual(RepositoryWriteDecision.BLOCKED, result.decision)
        self.assertEqual("DIRECT_DEFAULT_BRANCH_TARGET_MISMATCH", result.reason)

    def test_repo_mismatch_is_blocked(self):
        result = validate_repository_write_target(
            policy=self.policy,
            target=RepositoryWriteTarget(
                repo="other/repo",
                explicit_ref="feature/x",
                purpose=RepositoryWritePurpose.IMPLEMENTATION_BRANCH,
            ),
        )
        self.assertEqual(RepositoryWriteDecision.BLOCKED, result.decision)
        self.assertEqual("WRITE_REPO_MISMATCH", result.reason)

    def test_invalid_ref_shape_is_blocked(self):
        for ref in ("/feature", "feature/", "bad\x00ref"):
            with self.subTest(ref=ref):
                result = self.validate(ref)
                self.assertEqual(RepositoryWriteDecision.BLOCKED, result.decision)
                self.assertEqual("WRITE_REF_INVALID", result.reason)

    def test_controller_state_ref_is_fixed_by_composition(self):
        with self.assertRaises(ValueError):
            RepositoryWritePolicy(
                repo="oimus1976/agent-controller",
                default_branch="main",
                controller_state_ref="main",
            )


if __name__ == "__main__":
    unittest.main()
