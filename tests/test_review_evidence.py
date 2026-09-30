import unittest
import json

from agent_controller.inspector import build_canonical_review_evidence, classify_pr
from agent_controller.provider_contract import (
    ObjectiveScope,
    ProviderOperationRef,
    TaskBinding,
)
from agent_controller.review_evidence import (
    REQUIRED_GITHUB_SURFACES,
    ReviewSurfaceStatus,
    build_jules_review_evidence,
    canonical_review_from_mapping,
)


HEAD = "a" * 40
REPO = "oimus1976/agent-controller"


def task():
    return TaskBinding(
        controller_task_id="review-255",
        operation_id="jules-review-255",
        provider="jules",
        repo=REPO,
        expected_start_ref="refs/heads/issue-254-pilot-freeze-behavior-tests",
        expected_start_sha=HEAD,
        objective_scope=ObjectiveScope(),
        requested_capability="REVIEW",
        allowed_effects=("SESSION_CREATE",),
        forbidden_effects=("CREATE_COMMIT", "PUBLISH_BRANCH", "MERGE"),
        approval_policy_id="review-only-v1",
        created_at="2026-09-29T00:00:00Z",
    )


def operation():
    return ProviderOperationRef(
        provider="jules",
        provider_operation_id="session-255",
        provider_url="https://jules.google.com/session/session-255",
        controller_task_id="review-255",
        operation_id="jules-review-255",
    )


def activities(*, reviewed_pr=255, reviewed_head_sha=HEAD, verdict="CLEAN", findings=None):
    result = {
        "schema": "agent-controller/jules-review/v1",
        "reviewed_pr": reviewed_pr,
        "reviewed_head_sha": reviewed_head_sha,
        "verdict": verdict,
        "findings": [] if findings is None else findings,
    }
    return [
        {
            "name": "sessions/session-255/activities/result",
            "id": "result",
            "originator": "agent",
            "agentMessaged": {"agentMessage": json.dumps(result)},
        },
        {
            "name": "sessions/session-255/activities/complete",
            "id": "complete",
            "originator": "agent",
            "sessionCompleted": {},
        },
    ]


def jules(**overrides):
    values = {
        "task": task(),
        "operation": operation(),
        "repo": REPO,
        "pr": 255,
        "current_head_sha": HEAD,
        "session": {"name": "sessions/session-255", "state": "COMPLETED"},
        "activities": activities(),
        "activities_complete": True,
        "fresh_session": True,
        "implementation_operation_id": "claude-implementation-254",
    }
    values.update(overrides)
    return build_jules_review_evidence(**values)


def surfaces():
    return tuple(
        ReviewSurfaceStatus(name, "COMPLETE", True)
        for name in REQUIRED_GITHUB_SURFACES
    )


class ReviewEvidenceTests(unittest.TestCase):
    def test_serialized_evidence_rejects_matching_malformed_head_sha(self):
        snapshot = build_canonical_review_evidence(
            repo=REPO,
            pr_number=255,
            head_sha=HEAD,
            reviews=[],
            issue_comments=[],
            review_threads_graphql=[],
            surfaces=surfaces(),
        ).to_dict()
        snapshot["observed_head_sha"] = "not-a-git-sha"

        self.assertIsNone(
            canonical_review_from_mapping(
                snapshot,
                repo=REPO,
                pr=255,
                head_sha="not-a-git-sha",
            )
        )

    def test_bound_complete_jules_clean_can_feed_canonical_inspector(self):
        provider = jules()
        self.assertTrue(provider.complete)
        self.assertEqual("VERIFIED_DIFFERENT_OPERATION", provider.independence)

        canonical = build_canonical_review_evidence(
            repo=REPO,
            pr_number=255,
            head_sha=HEAD,
            reviews=[],
            issue_comments=[],
            review_threads_graphql=[],
            surfaces=surfaces(),
            provider_review_evidence=(provider,),
        )
        evidence = {
            "repo": REPO,
            "pr": 255,
            "head_sha": HEAD,
            "state": "open",
            "merged": False,
            "scope_status": "SATISFIED",
            "actions_ci_status": "PASS",
            "canonical_review_evidence": canonical.to_dict(),
        }
        self.assertTrue(canonical.collection_complete)
        self.assertEqual("CLEAN", canonical.verdict)
        self.assertEqual("REVIEW_READY", classify_pr(evidence))

    def test_serialized_complete_provider_requires_verified_independence_and_binding(self):
        canonical = build_canonical_review_evidence(
            repo=REPO,
            pr_number=255,
            head_sha=HEAD,
            reviews=[],
            issue_comments=[],
            review_threads_graphql=[],
            surfaces=surfaces(),
            provider_review_evidence=(jules(),),
        ).to_dict()

        for field, value in (
            ("independence", "SELF_REVIEW"),
            ("binding_strength", "UNVERIFIED"),
        ):
            with self.subTest(field=field):
                snapshot = json.loads(json.dumps(canonical))
                snapshot["provider_reviews"][0][field] = value
                self.assertIsNone(
                    canonical_review_from_mapping(
                        snapshot,
                        repo=REPO,
                        pr=255,
                        head_sha=HEAD,
                    )
                )

    def test_serialized_clean_verdict_cannot_hide_blocking_provider(self):
        blocking_provider = jules(
            activities=activities(verdict="BLOCKING", findings=["P1: regression"])
        )
        snapshot = build_canonical_review_evidence(
            repo=REPO,
            pr_number=255,
            head_sha=HEAD,
            reviews=[],
            issue_comments=[],
            review_threads_graphql=[],
            surfaces=surfaces(),
            provider_review_evidence=(blocking_provider,),
        ).to_dict()
        self.assertEqual("BLOCKING", snapshot["verdict"])
        self.assertIsNotNone(
            canonical_review_from_mapping(
                snapshot,
                repo=REPO,
                pr=255,
                head_sha=HEAD,
            )
        )

        snapshot["verdict"] = "CLEAN"
        self.assertIsNone(
            canonical_review_from_mapping(
                snapshot,
                repo=REPO,
                pr=255,
                head_sha=HEAD,
            )
        )

    def test_serialized_complete_provider_requires_conclusive_verdict(self):
        snapshot = build_canonical_review_evidence(
            repo=REPO,
            pr_number=255,
            head_sha=HEAD,
            reviews=[],
            issue_comments=[],
            review_threads_graphql=[],
            surfaces=surfaces(),
            provider_review_evidence=(jules(),),
        ).to_dict()
        snapshot["provider_reviews"][0]["verdict"] = "UNCERTAIN"

        self.assertIsNone(
            canonical_review_from_mapping(
                snapshot,
                repo=REPO,
                pr=255,
                head_sha=HEAD,
            )
        )

    def test_serialized_absent_verdict_cannot_hide_clean_provider(self):
        snapshot = build_canonical_review_evidence(
            repo=REPO,
            pr_number=255,
            head_sha=HEAD,
            reviews=[],
            issue_comments=[],
            review_threads_graphql=[],
            surfaces=surfaces(),
            provider_review_evidence=(jules(),),
        ).to_dict()
        self.assertEqual("CLEAN", snapshot["verdict"])

        snapshot["verdict"] = "ABSENT"
        self.assertIsNone(
            canonical_review_from_mapping(
                snapshot,
                repo=REPO,
                pr=255,
                head_sha=HEAD,
            )
        )


    def test_jules_review_cannot_be_retargeted_to_same_head_other_pr(self):
        source = jules()
        self.assertTrue(source.complete)
        self.assertEqual("CLEAN", source.verdict)
        retargeted = jules(pr=256)
        self.assertFalse(retargeted.complete)
        self.assertEqual("UNCERTAIN", retargeted.verdict)
        self.assertIn("REVIEWED_PR_MISMATCH", retargeted.errors)
        canonical = build_canonical_review_evidence(
            repo=REPO, pr_number=256, head_sha=HEAD,
            reviews=[], issue_comments=[], review_threads_graphql=[],
            surfaces=surfaces(), provider_review_evidence=(retargeted,),
        )
        self.assertFalse(canonical.collection_complete)
        self.assertEqual("UNCERTAIN", canonical.verdict)
        self.assertIn("REVIEWED_PR_MISMATCH", canonical.errors)
        self.assertEqual("NEEDS_REVIEW", classify_pr({
            "repo": REPO, "pr": 256, "head_sha": HEAD,
            "state": "open", "merged": False, "scope_status": "SATISFIED",
            "actions_ci_status": "PASS", "canonical_review_evidence": canonical.to_dict(),
        }))

    def test_jules_missing_or_malformed_reviewed_pr_fails_closed(self):
        identities = ({}, *({"reviewed_pr": value} for value in (
            None, 0, -1, False, True, "255", [], {}, [255], 255.0,
        )))
        for identity in identities:
            with self.subTest(identity=identity):
                records = activities()
                result = json.loads(records[0]["agentMessaged"]["agentMessage"])
                result.pop("reviewed_pr")
                result.update(identity)
                records[0]["agentMessaged"]["agentMessage"] = json.dumps(result)
                provider = jules(activities=records)
                self.assertFalse(provider.complete)
                self.assertEqual("UNCERTAIN", provider.verdict)
                self.assertIn("REVIEWED_PR_MALFORMED", provider.errors)

    def test_jules_pr_binding_preserves_repo_and_head_validation(self):
        cases = (
            ({"repo": "owner/another-repo"}, "REPOSITORY_MISMATCH"),
            ({"current_head_sha": "b" * 40}, "EXPECTED_HEAD_MISMATCH"),
            ({"activities": activities(reviewed_head_sha="b" * 40)}, "REVIEWED_HEAD_MISMATCH"),
            ({"current_head_sha": "not-a-git-sha"}, "CURRENT_HEAD_MALFORMED"),
            ({"activities": activities(reviewed_head_sha="not-a-git-sha")}, "REVIEWED_HEAD_MISMATCH"),
        )
        for overrides, error in cases:
            with self.subTest(error=error):
                provider = jules(**overrides)
                self.assertFalse(provider.complete)
                self.assertEqual("UNCERTAIN", provider.verdict)
                self.assertIn(error, provider.errors)

    def test_jules_canonical_provider_identity_cannot_cross_pr(self):
        provider = jules()
        snapshot = build_canonical_review_evidence(
            repo=REPO, pr_number=255, head_sha=HEAD,
            reviews=[], issue_comments=[], review_threads_graphql=[],
            surfaces=surfaces(), provider_review_evidence=(provider,),
        ).to_dict()
        entry = snapshot["provider_reviews"][0]
        self.assertEqual((REPO, 255, HEAD),
                         (entry["repo"], entry["pr"], entry["reviewed_head_sha"]))
        self.assertIsNotNone(canonical_review_from_mapping(
            snapshot, repo=REPO, pr=255, head_sha=HEAD,
        ))
        self.assertIsNone(canonical_review_from_mapping(
            snapshot, repo=REPO, pr=256, head_sha=HEAD,
        ))
        snapshot["pr"] = 256
        self.assertIsNone(canonical_review_from_mapping(
            snapshot, repo=REPO, pr=256, head_sha=HEAD,
        ))
        other = build_canonical_review_evidence(
            repo=REPO, pr_number=256, head_sha=HEAD,
            reviews=[], issue_comments=[], review_threads_graphql=[],
            surfaces=surfaces(), provider_review_evidence=(provider,),
        )
        self.assertFalse(other.collection_complete)
        self.assertEqual("UNCERTAIN", other.verdict)
        self.assertIn("PROVIDER_REVIEW_IDENTITY_MISMATCH", other.errors)

    def test_owner_relayed_jules_prose_is_not_provider_evidence(self):
        canonical = build_canonical_review_evidence(
            repo=REPO,
            pr_number=255,
            head_sha=HEAD,
            reviews=[],
            issue_comments=[
                {
                    "user": {"login": "oimus1976"},
                    "body": f"Jules review clean. Reviewed exact head: {HEAD}",
                }
            ],
            review_threads_graphql=[],
            surfaces=surfaces(),
        )
        self.assertEqual("ABSENT", canonical.verdict)

    def test_jules_stale_incomplete_self_or_malformed_evidence_fails_closed(self):
        cases = (
            jules(activities=activities(reviewed_head_sha="b" * 40)),
            jules(activities_complete=False),
            jules(implementation_operation_id="jules-review-255"),
            jules(session={"name": "sessions/session-255", "state": "ACTIVE"}),
            jules(activities=[]),
            jules(activities=activities(findings=["P1"])),
            jules(activities=activities(verdict="BLOCKING", findings=[])),
            jules(activities=activities(verdict="UNKNOWN")),
            jules(activities=activities(findings="not-a-list")),
        )
        for provider in cases:
            with self.subTest(errors=provider.errors):
                self.assertFalse(provider.complete)
                self.assertEqual("UNCERTAIN", provider.verdict)

    def test_jules_completeness_flags_must_be_boolean_true(self):
        cases = (
            ({"activities_complete": "false"}, "ACTIVITIES_INCOMPLETE"),
            ({"activities_complete": 1}, "ACTIVITIES_INCOMPLETE"),
            ({"fresh_session": "unknown"}, "REVIEW_SESSION_NOT_FRESH"),
            ({"fresh_session": 1}, "REVIEW_SESSION_NOT_FRESH"),
        )
        for overrides, expected_error in cases:
            with self.subTest(overrides=overrides):
                provider = jules(**overrides)
                self.assertFalse(provider.complete)
                self.assertEqual("UNCERTAIN", provider.verdict)
                self.assertIn(expected_error, provider.errors)

    def test_current_head_blocking_jules_finding_overrides_clean_codex(self):
        blocking = jules(
            activities=activities(verdict="BLOCKING", findings=["P1: regression"])
        )
        canonical = build_canonical_review_evidence(
            repo=REPO,
            pr_number=255,
            head_sha=HEAD,
            reviews=[],
            issue_comments=[
                {
                    "user": {"login": "chatgpt-codex-connector[bot]"},
                    "body": f"Didn't find any major issues. Reviewed commit: {HEAD}",
                }
            ],
            review_threads_graphql=[],
            surfaces=surfaces(),
            provider_review_evidence=(blocking,),
        )
        self.assertEqual("BLOCKING", canonical.verdict)

    def test_jules_result_must_be_one_agent_originated_activity(self):
        owner_spoof = activities()
        owner_spoof[0]["originator"] = "user"
        duplicate = activities()
        duplicate.insert(1, dict(duplicate[0], id="result-2", name="sessions/session-255/activities/result-2"))
        malformed = activities()
        malformed[0]["agentMessaged"] = {
            "agentMessage": '{"schema":"agent-controller/jules-review/v1"'
        }
        for provider in (
            jules(activities=owner_spoof),
            jules(activities=duplicate),
            jules(activities=malformed),
        ):
            with self.subTest(errors=provider.errors):
                self.assertFalse(provider.complete)
                self.assertEqual("UNCERTAIN", provider.verdict)

    def test_missing_surface_and_head_drift_preserve_reason(self):
        incomplete = list(surfaces())
        incomplete[2] = ReviewSurfaceStatus(
            "inline_threads", "UNAVAILABLE", False, "GraphQL timeout"
        )
        canonical = build_canonical_review_evidence(
            repo=REPO,
            pr_number=255,
            head_sha=HEAD,
            reviews=[],
            issue_comments=[],
            review_threads_graphql=[],
            surfaces=tuple(incomplete),
            head_changed=True,
        )
        self.assertFalse(canonical.collection_complete)
        self.assertEqual("UNCERTAIN", canonical.verdict)
        self.assertIn("GraphQL timeout", canonical.errors)
        self.assertIn("HEAD_CHANGED_DURING_COLLECTION", canonical.errors)


if __name__ == "__main__":
    unittest.main()
