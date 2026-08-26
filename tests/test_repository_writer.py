import unittest

from agent_controller.repository_write_guard import (
    RepositoryWriteGuard,
    RepositoryWritePurpose,
)
from agent_controller.repository_writer import (
    GuardedRepositoryWriter,
    RepositoryWriteResult,
)


class FakeBackend:
    def __init__(self):
        self.calls = []

    def create_file(self, **kwargs):
        self.calls.append(("create_file", kwargs))
        return RepositoryWriteResult(True, revision="r1")

    def update_file(self, **kwargs):
        self.calls.append(("update_file", kwargs))
        return RepositoryWriteResult(True, revision="r2")

    def delete_file(self, **kwargs):
        self.calls.append(("delete_file", kwargs))
        return RepositoryWriteResult(True, revision="r3")

    def move_ref(self, **kwargs):
        self.calls.append(("move_ref", kwargs))
        return RepositoryWriteResult(True, revision="r4")


class InvalidBackend:
    pass


class GuardedRepositoryWriterTests(unittest.TestCase):
    def setUp(self):
        self.backend = FakeBackend()
        self.writer = GuardedRepositoryWriter(
            guard=RepositoryWriteGuard(
                repo="oimus1976/agent-controller",
                default_branch="main",
            ),
            backend=self.backend,
        )

    def test_invalid_backend_rejected(self):
        with self.assertRaises(TypeError):
            GuardedRepositoryWriter(
                guard=RepositoryWriteGuard(
                    repo="oimus1976/agent-controller", default_branch="main"
                ),
                backend=InvalidBackend(),
            )

    def test_create_without_ref_blocks_before_backend(self):
        result = self.writer.create_file(
            explicit_ref=None,
            purpose=RepositoryWritePurpose.IMPLEMENTATION_BRANCH,
            path="x.txt",
            content="x",
            message="add x",
        )
        self.assertTrue(result.blocked)
        self.assertEqual("EXPLICIT_REF_REQUIRED", result.reason)
        self.assertEqual([], self.backend.calls)

    def test_update_default_branch_blocks_before_backend(self):
        result = self.writer.update_file(
            explicit_ref="main",
            purpose=RepositoryWritePurpose.IMPLEMENTATION_BRANCH,
            path="x.txt",
            content="y",
            message="update x",
            expected_revision="blob1",
        )
        self.assertTrue(result.blocked)
        self.assertEqual("DEFAULT_BRANCH_WRITE_FORBIDDEN", result.reason)
        self.assertEqual([], self.backend.calls)

    def test_delete_default_branch_alias_blocks_before_backend(self):
        result = self.writer.delete_file(
            explicit_ref="refs/heads/main",
            purpose=RepositoryWritePurpose.IMPLEMENTATION_BRANCH,
            path="x.txt",
            message="delete x",
            expected_revision="blob1",
        )
        self.assertTrue(result.blocked)
        self.assertEqual([], self.backend.calls)

    def test_low_level_ref_move_default_branch_blocks_before_backend(self):
        result = self.writer.move_ref(
            explicit_ref="main",
            purpose=RepositoryWritePurpose.IMPLEMENTATION_BRANCH,
            target_sha="a" * 40,
            expected_old_sha="b" * 40,
        )
        self.assertTrue(result.blocked)
        self.assertEqual("DEFAULT_BRANCH_WRITE_FORBIDDEN", result.reason)
        self.assertEqual([], self.backend.calls)

    def test_implementation_create_uses_normalized_explicit_ref(self):
        result = self.writer.create_file(
            explicit_ref="refs/heads/feature/x",
            purpose=RepositoryWritePurpose.IMPLEMENTATION_BRANCH,
            path="x.txt",
            content="x",
            message="add x",
        )
        self.assertTrue(result.written)
        method, kwargs = self.backend.calls[-1]
        self.assertEqual("create_file", method)
        self.assertEqual("feature/x", kwargs["ref"])
        self.assertEqual("oimus1976/agent-controller", kwargs["repo"])

    def test_controller_state_create_only_uses_fixed_ref(self):
        result = self.writer.create_file(
            explicit_ref="controller-state",
            purpose=RepositoryWritePurpose.CONTROLLER_STATE,
            path="controller-state/operations/task/op/v1.json",
            content="{}",
            message="create operation state",
        )
        self.assertTrue(result.written)
        self.assertEqual("controller-state", self.backend.calls[-1][1]["ref"])

    def test_controller_state_redirection_blocks_before_backend(self):
        result = self.writer.create_file(
            explicit_ref="other-state",
            purpose=RepositoryWritePurpose.CONTROLLER_STATE,
            path="x.json",
            content="{}",
            message="bad",
        )
        self.assertTrue(result.blocked)
        self.assertEqual("CONTROLLER_STATE_REF_MISMATCH", result.reason)
        self.assertEqual([], self.backend.calls)

    def test_all_content_operations_require_explicit_ref(self):
        calls = [
            lambda: self.writer.create_file(
                explicit_ref=None,
                purpose=RepositoryWritePurpose.IMPLEMENTATION_BRANCH,
                path="x", content="x", message="m"
            ),
            lambda: self.writer.update_file(
                explicit_ref=None,
                purpose=RepositoryWritePurpose.IMPLEMENTATION_BRANCH,
                path="x", content="x", message="m", expected_revision="r"
            ),
            lambda: self.writer.delete_file(
                explicit_ref=None,
                purpose=RepositoryWritePurpose.IMPLEMENTATION_BRANCH,
                path="x", message="m", expected_revision="r"
            ),
            lambda: self.writer.move_ref(
                explicit_ref=None,
                purpose=RepositoryWritePurpose.IMPLEMENTATION_BRANCH,
                target_sha="a" * 40,
                expected_old_sha=None,
            ),
        ]
        for call in calls:
            result = call()
            self.assertTrue(result.blocked)
            self.assertEqual("EXPLICIT_REF_REQUIRED", result.reason)
        self.assertEqual([], self.backend.calls)


if __name__ == "__main__":
    unittest.main()
