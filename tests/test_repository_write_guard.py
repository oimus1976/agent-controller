import inspect
import unittest

from agent_controller.repository_write_guard import (
    CONTROLLER_STATE_REF,
    RepositoryWriteDecision,
    RepositoryWriteGuard,
    RepositoryWritePurpose,
    RepositoryWriteTarget,
)


class RepositoryWriteGuardTests(unittest.TestCase):
    def setUp(self):
        self.guard = RepositoryWriteGuard(
            repo="oimus1976/agent-controller",
            default_branch="main",
        )

    def validate(self, ref, purpose=RepositoryWritePurpose.IMPLEMENTATION_BRANCH):
        return self.guard.validate(
            target=RepositoryWriteTarget(
                repo="oimus1976/agent-controller",
                explicit_ref=ref,
                purpose=purpose,
            )
        )

    def test_supported_validate_api_has_no_per_call_policy_override(self):
        self.assertEqual({"target"}, set(inspect.signature(self.guard.validate).parameters))

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

    def test_explicit_default_branch_is_always_blocked(self):
        for ref in ("main", "refs/heads/main"):
            with self.subTest(ref=ref):
                result = self.validate(ref)
                self.assertEqual(RepositoryWriteDecision.BLOCKED, result.decision)
                self.assertEqual("DEFAULT_BRANCH_WRITE_FORBIDDEN", result.reason)

    def test_generic_guard_exposes_no_direct_default_branch_admin_purpose(self):
        self.assertNotIn("DIRECT_DEFAULT_BRANCH_ADMIN", RepositoryWritePurpose.__members__)

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

    def test_repo_mismatch_is_blocked(self):
        result = self.guard.validate(
            target=RepositoryWriteTarget(
                repo="other/repo",
                explicit_ref="feature/x",
                purpose=RepositoryWritePurpose.IMPLEMENTATION_BRANCH,
            )
        )
        self.assertEqual(RepositoryWriteDecision.BLOCKED, result.decision)
        self.assertEqual("WRITE_REPO_MISMATCH", result.reason)

    def test_invalid_ref_shape_is_blocked(self):
        for ref in ("/feature", "feature/", "bad\x00ref"):
            with self.subTest(ref=ref):
                result = self.validate(ref)
                self.assertEqual(RepositoryWriteDecision.BLOCKED, result.decision)
                self.assertEqual("WRITE_REF_INVALID", result.reason)

    def test_composed_default_branch_is_read_only(self):
        self.assertEqual("main", self.guard.default_branch)
        with self.assertRaises(AttributeError):
            self.guard.default_branch = "develop"

    def test_caller_cannot_use_controller_state_purpose_for_main(self):
        result = self.validate(
            "main",
            purpose=RepositoryWritePurpose.CONTROLLER_STATE,
        )
        self.assertEqual(RepositoryWriteDecision.BLOCKED, result.decision)
        self.assertEqual("DEFAULT_BRANCH_WRITE_FORBIDDEN", result.reason)


if __name__ == "__main__":
    unittest.main()
