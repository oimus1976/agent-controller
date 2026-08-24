import unittest

from agent_controller.github_controller_state import (
    CONTROLLER_STATE_REF,
    GitHubContentsResponse,
    GitHubControllerStateAdapter,
)


class FakeTransport:
    def __init__(self):
        self.files = {}
        self.rev = 0
        self.calls = []
        self.raise_read = False
        self.raise_write = False

    def _next(self):
        self.rev += 1
        return f"blob-{self.rev}"

    def read_file(self, *, repo, ref, path):
        self.calls.append(("read", repo, ref, path))
        if self.raise_read:
            raise RuntimeError("network")
        item = self.files.get((repo, ref, path))
        if item is None:
            return GitHubContentsResponse(404)
        content, revision = item
        return GitHubContentsResponse(200, content=content, revision=revision)

    def create_file(self, *, repo, ref, path, content, message):
        self.calls.append(("create", repo, ref, path, content, message))
        if self.raise_write:
            raise RuntimeError("network")
        key = (repo, ref, path)
        if key in self.files:
            return GitHubContentsResponse(422)
        revision = self._next()
        self.files[key] = (content, revision)
        return GitHubContentsResponse(201, revision=revision)

    def update_file(self, *, repo, ref, path, content, message, expected_revision):
        self.calls.append(("update", repo, ref, path, content, message, expected_revision))
        if self.raise_write:
            raise RuntimeError("network")
        key = (repo, ref, path)
        item = self.files.get(key)
        if item is None or item[1] != expected_revision:
            return GitHubContentsResponse(409)
        revision = self._next()
        self.files[key] = (content, revision)
        return GitHubContentsResponse(200, revision=revision)

    def delete_file(self, *, repo, ref, path, message, expected_revision):
        self.calls.append(("delete", repo, ref, path, message, expected_revision))
        if self.raise_write:
            raise RuntimeError("network")
        key = (repo, ref, path)
        item = self.files.get(key)
        if item is None or item[1] != expected_revision:
            return GitHubContentsResponse(409)
        del self.files[key]
        return GitHubContentsResponse(200, revision=self._next())

    def move_ref(self, *, repo, ref, target_sha, expected_old_sha):
        self.calls.append(("move_ref", repo, ref, target_sha, expected_old_sha))
        return GitHubContentsResponse(200, revision=target_sha)


class InvalidTransport:
    pass


class GitHubControllerStateAdapterTests(unittest.TestCase):
    def setUp(self):
        self.transport = FakeTransport()
        self.adapter = GitHubControllerStateAdapter(
            repo="oimus1976/agent-controller",
            default_branch="main",
            transport=self.transport,
        )
        self.path = "controller-state/probe/test.json"

    def test_invalid_transport_rejected(self):
        with self.assertRaises(TypeError):
            GitHubControllerStateAdapter(
                repo="oimus1976/agent-controller",
                default_branch="main",
                transport=InvalidTransport(),
            )

    def test_state_ref_is_fixed(self):
        self.assertEqual(CONTROLLER_STATE_REF, self.adapter.state_ref)

    def test_read_missing_returns_none_on_fixed_ref(self):
        self.assertIsNone(self.adapter.read(path=self.path))
        self.assertEqual(CONTROLLER_STATE_REF, self.transport.calls[-1][2])

    def test_create_missing_succeeds_and_rereads(self):
        created = self.adapter.create_if_absent(
            path=self.path, content='{"v":1}', message="probe create"
        )
        self.assertTrue(created.written)
        snapshot = self.adapter.read(path=self.path)
        self.assertEqual('{"v":1}', snapshot.content)
        self.assertEqual(created.revision, snapshot.revision)
        create_call = [c for c in self.transport.calls if c[0] == "create"][-1]
        self.assertEqual(CONTROLLER_STATE_REF, create_call[2])

    def test_second_create_conflicts(self):
        self.adapter.create_if_absent(path=self.path, content="one", message="create")
        second = self.adapter.create_if_absent(path=self.path, content="two", message="create")
        self.assertFalse(second.written)
        self.assertTrue(second.conflict)
        self.assertFalse(second.uncertain)

    def test_cas_with_exact_revision_succeeds(self):
        created = self.adapter.create_if_absent(path=self.path, content="one", message="create")
        updated = self.adapter.compare_and_swap(
            path=self.path,
            expected_revision=created.revision,
            content="two",
            message="update",
        )
        self.assertTrue(updated.written)
        self.assertEqual("two", self.adapter.read(path=self.path).content)

    def test_cas_with_stale_revision_conflicts_and_preserves_winner(self):
        created = self.adapter.create_if_absent(path=self.path, content="one", message="create")
        winner = self.adapter.compare_and_swap(
            path=self.path,
            expected_revision=created.revision,
            content="winner",
            message="winner",
        )
        stale = self.adapter.compare_and_swap(
            path=self.path,
            expected_revision=created.revision,
            content="loser",
            message="loser",
        )
        self.assertTrue(winner.written)
        self.assertTrue(stale.conflict)
        snapshot = self.adapter.read(path=self.path)
        self.assertEqual("winner", snapshot.content)
        self.assertEqual(winner.revision, snapshot.revision)

    def test_write_transport_exception_is_uncertain(self):
        self.transport.raise_write = True
        result = self.adapter.create_if_absent(path=self.path, content="x", message="m")
        self.assertFalse(result.written)
        self.assertTrue(result.uncertain)
        self.assertEqual("GITHUB_TRANSPORT_UNCERTAIN", result.reason)

    def test_read_transport_exception_is_uncertain_exception(self):
        self.transport.raise_read = True
        with self.assertRaisesRegex(RuntimeError, "GITHUB_STATE_READ_UNCERTAIN"):
            self.adapter.read(path=self.path)

    def test_success_without_revision_is_uncertain(self):
        class MissingRevisionTransport(FakeTransport):
            def create_file(self, **kwargs):
                return GitHubContentsResponse(201)

        adapter = GitHubControllerStateAdapter(
            repo="oimus1976/agent-controller",
            default_branch="main",
            transport=MissingRevisionTransport(),
        )
        result = adapter.create_if_absent(path=self.path, content="x", message="m")
        self.assertTrue(result.uncertain)
        self.assertEqual("GITHUB_REVISION_MISSING", result.reason)

    def test_unexpected_write_status_is_uncertain(self):
        class ErrorTransport(FakeTransport):
            def create_file(self, **kwargs):
                return GitHubContentsResponse(500)

        adapter = GitHubControllerStateAdapter(
            repo="oimus1976/agent-controller",
            default_branch="main",
            transport=ErrorTransport(),
        )
        result = adapter.create_if_absent(path=self.path, content="x", message="m")
        self.assertTrue(result.uncertain)
        self.assertEqual("GITHUB_WRITE_STATUS_500", result.reason)

    def test_no_default_branch_write_reaches_transport(self):
        self.adapter.create_if_absent(path=self.path, content="x", message="m")
        write_calls = [c for c in self.transport.calls if c[0] in {"create", "update", "delete", "move_ref"}]
        self.assertTrue(write_calls)
        self.assertTrue(all(c[2] == CONTROLLER_STATE_REF for c in write_calls))
        self.assertTrue(all(c[2] != "main" for c in write_calls))


if __name__ == "__main__":
    unittest.main()
