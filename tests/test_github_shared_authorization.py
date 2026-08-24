import json
import unittest

from agent_controller.github_controller_state import (
    GitHubContentsResponse,
    GitHubControllerStateAdapter,
)
from agent_controller.github_shared_authorization import GitHubSharedAuthorizationBackend
from agent_controller.shared_authorization import (
    AuthorizationDecision,
    OperationAuthorizationBinding,
    SharedAuthorizationStore,
    propose_operation,
    read_operation,
)


class FakeTransport:
    def __init__(self):
        self.files = {}
        self.rev = 0

    def _next(self):
        self.rev += 1
        return f"blob-{self.rev}"

    def read_ref(self, *, repo, ref):
        return GitHubContentsResponse(200, revision="state-ref-sha")

    def read_file(self, *, repo, ref, path):
        item = self.files.get((repo, ref, path))
        if item is None:
            return GitHubContentsResponse(404)
        return GitHubContentsResponse(200, content=item[0], revision=item[1])

    def create_file(self, *, repo, ref, path, content, message):
        key = (repo, ref, path)
        if key in self.files:
            return GitHubContentsResponse(422)
        revision = self._next()
        self.files[key] = (content, revision)
        return GitHubContentsResponse(201, revision=revision)

    def update_file(self, *, repo, ref, path, content, message, expected_revision):
        key = (repo, ref, path)
        current = self.files.get(key)
        if current is None or current[1] != expected_revision:
            return GitHubContentsResponse(409)
        revision = self._next()
        self.files[key] = (content, revision)
        return GitHubContentsResponse(200, revision=revision)

    def delete_file(self, **kwargs):
        return GitHubContentsResponse(500)

    def move_ref(self, **kwargs):
        return GitHubContentsResponse(500)


class GitHubSharedAuthorizationBackendTests(unittest.TestCase):
    def setUp(self):
        self.transport = FakeTransport()
        state = GitHubControllerStateAdapter(
            repo="oimus1976/agent-controller",
            default_branch="main",
            transport=self.transport,
        )
        self.backend = GitHubSharedAuthorizationBackend(state_adapter=state)
        self.store = SharedAuthorizationStore(self.backend)
        self.binding = OperationAuthorizationBinding(
            approval_id="approval-1",
            approval_policy_id="policy-level3-v1",
            controller_task_id="task-1",
            operation_id="op-1",
            operation_version="v1",
            provider="codex",
            requested_capability="MERGE_PR",
            effect="MERGE",
            repo="oimus1976/agent-controller",
            target_kind="PULL_REQUEST",
            target_id="999",
            expected_head_sha="a" * 40,
        )

    def test_propose_round_trips_through_canonical_json_state(self):
        created = propose_operation(store=self.store, binding=self.binding)
        self.assertEqual(AuthorizationDecision.PASS, created.decision)
        reread = read_operation(store=self.store, binding=self.binding)
        self.assertEqual(AuthorizationDecision.PASS, reread.decision)
        self.assertEqual(self.binding, reread.snapshot.record.binding)
        raw = next(iter(self.transport.files.values()))[0]
        parsed = json.loads(raw)
        self.assertEqual("PROPOSED", parsed["state"])
        self.assertEqual("agent-controller-shared-authorization-v2", parsed["schema_version"])

    def test_duplicate_propose_uses_github_create_conflict_then_reread(self):
        first = propose_operation(store=self.store, binding=self.binding)
        second = propose_operation(store=self.store, binding=self.binding)
        self.assertEqual(AuthorizationDecision.PASS, first.decision)
        self.assertEqual(AuthorizationDecision.REPLAYED, second.decision)

    def test_corrupt_authoritatively_read_json_is_blocked(self):
        propose_operation(store=self.store, binding=self.binding)
        key = next(iter(self.transport.files))
        _, revision = self.transport.files[key]
        self.transport.files[key] = ("not-json", revision)
        result = read_operation(store=self.store, binding=self.binding)
        self.assertEqual(AuthorizationDecision.BLOCKED, result.decision)
        self.assertEqual("STATE_RECORD_INVALID", result.reason)

    def test_extra_json_field_is_blocked(self):
        propose_operation(store=self.store, binding=self.binding)
        key = next(iter(self.transport.files))
        raw, revision = self.transport.files[key]
        data = json.loads(raw)
        data["attacker_field"] = "ignored?"
        self.transport.files[key] = (json.dumps(data), revision)
        result = read_operation(store=self.store, binding=self.binding)
        self.assertEqual(AuthorizationDecision.BLOCKED, result.decision)
        self.assertEqual("STATE_RECORD_INVALID", result.reason)

    def test_backend_rejects_non_controller_state_ref(self):
        with self.assertRaises(ValueError):
            self.backend.read(state_ref="main", path="x")


if __name__ == "__main__":
    unittest.main()
