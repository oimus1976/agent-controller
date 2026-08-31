import json
import unittest

from agent_controller.jules_changesets import (
    JulesActivitiesApiClient,
    JulesChangeSetReadClient,
)
from agent_controller.provider_contract import (
    ObjectiveScope,
    ProviderOperationRef,
    TaskBinding,
)


SOURCE = "sources/github/oimus1976/agent-controller"
BASE_SHA = "1" * 40
PATCH = "diff --git a/a.txt b/a.txt\n--- a/a.txt\n+++ b/a.txt\n@@ -1 +1 @@\n-old\n+new\n"


def make_task(provider="jules"):
    return TaskBinding(
        controller_task_id="task-a",
        operation_id="op-a",
        provider=provider,
        repo="oimus1976/agent-controller",
        expected_start_ref="refs/heads/main",
        expected_start_sha=BASE_SHA,
        objective_scope=ObjectiveScope(allowed_paths=("agent_controller/**",)),
        requested_capability="IMPLEMENT",
        allowed_effects=("SESSION_CREATE",),
        forbidden_effects=("AUTO_CREATE_PR",),
        approval_policy_id="policy-1",
        created_at="2026-08-31T00:00:00Z",
    )


def make_operation(provider="jules", task_id="task-a", operation_id="op-a"):
    return ProviderOperationRef(
        provider=provider,
        provider_operation_id="session-a",
        provider_url="https://jules.google.com/session/session-a",
        controller_task_id=task_id,
        operation_id=operation_id,
    )


def source_payload():
    return {
        "sources": [
            {
                "name": SOURCE,
                "githubRepo": {"owner": "oimus1976", "repo": "agent-controller"},
            }
        ]
    }


def valid_activity(activity_id="act-1", patch=PATCH, base_commit_id=BASE_SHA):
    return {
        "name": f"sessions/session-a/activities/{activity_id}",
        "id": activity_id,
        "originator": "agent",
        "artifacts": [
            {
                "changeSet": {
                    "source": SOURCE,
                    "gitPatch": {
                        "unidiffPatch": patch,
                        "baseCommitId": base_commit_id,
                        "suggestedCommitMessage": "Implement change",
                    },
                }
            }
        ],
    }


class FakeTransport:
    def __init__(self, activity_pages=None, error=None):
        self.activity_pages = list(activity_pages or [{"activities": [valid_activity()]}])
        self.error = error
        self.calls = []
        self.activity_index = 0

    def __call__(self, req):
        self.calls.append(req.full_url)
        if self.error is not None and "/activities" in req.full_url:
            raise self.error
        if "/sources" in req.full_url:
            payload = source_payload()
        elif "/activities" in req.full_url:
            index = min(self.activity_index, len(self.activity_pages) - 1)
            payload = self.activity_pages[index]
            self.activity_index += 1
        else:
            raise AssertionError(f"unexpected URL: {req.full_url}")
        return 200, {}, json.dumps(payload).encode("utf-8")


def make_reader(transport):
    api = JulesActivitiesApiClient(api_key="secret-key", transport=transport)
    return JulesChangeSetReadClient(
        api_client=api,
        observed_at=lambda: "2026-08-31T00:00:01Z",
    )


class JulesChangeSetTests(unittest.TestCase):
    def test_one_page_valid_changeset_preserves_untrusted_patch_evidence(self):
        transport = FakeTransport()
        evidence = make_reader(transport).list_change_sets(
            task=make_task(), operation=make_operation()
        )

        self.assertEqual(len(evidence), 1)
        item = evidence[0]
        self.assertEqual(item.provider, "jules")
        self.assertEqual(item.provider_operation_id, "session-a")
        self.assertEqual(item.activity_id, "act-1")
        self.assertEqual(item.source, SOURCE)
        self.assertEqual(item.unidiff_patch, PATCH)
        self.assertEqual(item.base_commit_id, BASE_SHA)
        self.assertEqual(item.suggested_commit_message, "Implement change")
        self.assertEqual(len(item.patch_sha256), 64)
        self.assertEqual(len(transport.calls), 2)

    def test_multi_page_activity_pagination(self):
        pages = [
            {"activities": [valid_activity("act-1")], "nextPageToken": "page-2"},
            {"activities": [valid_activity("act-2")]},
        ]
        transport = FakeTransport(pages)
        evidence = make_reader(transport).list_change_sets(
            task=make_task(), operation=make_operation()
        )
        self.assertEqual([item.activity_id for item in evidence], ["act-1", "act-2"])
        self.assertIn("pageToken=page-2", transport.calls[-1])

    def test_pagination_cycle_max_pages_and_malformed_tokens_fail_closed(self):
        cycle = FakeTransport(
            [
                {"activities": [], "nextPageToken": "x"},
                {"activities": [], "nextPageToken": "x"},
            ]
        )
        with self.assertRaisesRegex(RuntimeError, "pagination cycle"):
            make_reader(cycle).list_change_sets(task=make_task(), operation=make_operation())

        bounded = FakeTransport([{"activities": [], "nextPageToken": "x"}])
        with self.assertRaisesRegex(RuntimeError, "maximum page limit"):
            make_reader(bounded).list_change_sets(
                task=make_task(), operation=make_operation(), max_activity_pages=1
            )

        for token in ("", "   ", 3, True):
            malformed = FakeTransport([{"activities": [], "nextPageToken": token}])
            with self.assertRaisesRegex(RuntimeError, "nextPageToken"):
                make_reader(malformed).list_change_sets(
                    task=make_task(), operation=make_operation()
                )

    def test_wrong_provider_or_binding_blocks_before_network(self):
        for task, operation in (
            (make_task("codex"), make_operation("codex")),
            (make_task(), make_operation(task_id="other-task")),
            (make_task(), make_operation(operation_id="other-op")),
        ):
            transport = FakeTransport()
            with self.assertRaises(ValueError):
                make_reader(transport).list_change_sets(task=task, operation=operation)
            self.assertEqual(transport.calls, [])

    def test_malformed_top_level_activities_fails_closed(self):
        for payload in ({"activities": {}}, {"activities": "bad"}):
            transport = FakeTransport([payload])
            with self.assertRaisesRegex(RuntimeError, "activities"):
                make_reader(transport).list_change_sets(
                    task=make_task(), operation=make_operation()
                )

    def test_non_changeset_and_non_agent_changeset_are_not_promoted(self):
        activity = valid_activity()
        activity["artifacts"] = [{"media": {"mimeType": "text/plain"}}]
        non_agent = valid_activity("act-2")
        non_agent["originator"] = "user"
        transport = FakeTransport([{"activities": [activity, non_agent]}])

        evidence = make_reader(transport).list_change_sets(
            task=make_task(), operation=make_operation()
        )
        self.assertEqual(evidence, ())

    def test_malformed_changeset_source_patch_and_base_fail_closed(self):
        mutations = []

        malformed_change_set = valid_activity()
        malformed_change_set["artifacts"][0]["changeSet"] = "bad"
        mutations.append(malformed_change_set)

        wrong_source = valid_activity()
        wrong_source["artifacts"][0]["changeSet"]["source"] = "sources/github/other/repo"
        mutations.append(wrong_source)

        empty_patch = valid_activity(patch="")
        mutations.append(empty_patch)

        empty_base = valid_activity(base_commit_id="")
        mutations.append(empty_base)

        malformed_message = valid_activity()
        malformed_message["artifacts"][0]["changeSet"]["gitPatch"]["suggestedCommitMessage"] = 7
        mutations.append(malformed_message)

        for activity in mutations:
            transport = FakeTransport([{"activities": [activity]}])
            with self.assertRaises(RuntimeError):
                make_reader(transport).list_change_sets(
                    task=make_task(), operation=make_operation()
                )

    def test_activity_must_belong_to_exact_bound_session(self):
        activity = valid_activity()
        activity["name"] = "sessions/session-b/activities/act-1"
        transport = FakeTransport([{"activities": [activity]}])
        with self.assertRaisesRegex(RuntimeError, "bound session"):
            make_reader(transport).list_change_sets(
                task=make_task(), operation=make_operation()
            )

    def test_activity_read_error_redacts_api_key(self):
        transport = FakeTransport(error=RuntimeError("secret-key leaked"))
        with self.assertRaises(RuntimeError) as ctx:
            make_reader(transport).list_change_sets(
                task=make_task(), operation=make_operation()
            )
        self.assertNotIn("secret-key", str(ctx.exception))
        self.assertIn("[REDACTED]", str(ctx.exception))

    def test_public_surface_is_read_only(self):
        api_names = set(dir(JulesActivitiesApiClient))
        reader_names = set(dir(JulesChangeSetReadClient))
        for forbidden in (
            "approve_plan",
            "approvePlan",
            "send_message",
            "sendMessage",
            "create_pull_request",
            "merge_pull_request",
            "apply_patch",
        ):
            self.assertNotIn(forbidden, api_names)
            self.assertNotIn(forbidden, reader_names)


if __name__ == "__main__":
    unittest.main()
