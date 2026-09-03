import unittest
from unittest.mock import patch

from agent_controller.codex_amplification import (
    analyze_codex_request_amplification,
    collect_codex_request_amplification,
    classify_codex_remediation_gap,
)


OWNER = "oimus1976"
CODEX = "chatgpt-codex-connector[bot]"


def issue_comment(body, login=OWNER):
    return {"id": 1, "user": {"login": login}, "body": body}


def review(body, login=OWNER, commit_id=None, review_id=1):
    return {
        "id": review_id,
        "user": {"login": login},
        "body": body,
        "commit_id": commit_id,
        "state": "COMMENTED",
    }


def review_request(sha):
    return (
        "@codex review\n\n"
        f"<!-- agent-controller:codex-review-request head={sha} -->"
    )


def remediation_request(sha):
    return (
        "@codex address that feedback\n\n"
        "<!-- agent-controller:codex-remediation-request "
        f"source_head={sha} -->"
    )


class CodexAmplificationTests(unittest.TestCase):
    def test_serial_multi_head_loop_is_amplification_not_duplicate_replay(self):
        heads = ["1111111111111111111111111111111111111111", "2222222222222222222222222222222222222222", "3333333333333333333333333333333333333333", "4444444444444444444444444444444444444444"]
        comments = [
            issue_comment(review_request(heads[0])),
            issue_comment(remediation_request(heads[0])),
            issue_comment(remediation_request(heads[1])),
            issue_comment(remediation_request(heads[2])),
        ]
        reviews = [
            review(review_request(heads[1]), review_id=10),
            review(review_request(heads[2]), review_id=11),
            review(review_request(heads[3]), review_id=12),
        ]
        reviews.extend(
            review(
                "Codex review",
                login=CODEX,
                commit_id=head,
                review_id=100 + index,
            )
            for index, head in enumerate(heads)
        )

        result = analyze_codex_request_amplification(
            issue_comments=comments,
            reviews=reviews,
            trusted_request_authors=(OWNER,),
        )

        self.assertEqual(result["status"], "OBSERVED")
        self.assertEqual(result["review_request_count"], 4)
        self.assertEqual(result["remediation_request_count"], 3)
        self.assertEqual(result["codex_review_submission_count"], 4)
        self.assertEqual(result["distinct_reviewed_head_count"], 4)
        self.assertEqual(result["distinct_loop_head_count"], 4)
        self.assertEqual(result["same_head_duplicate_review_request_count"], 0)
        self.assertEqual(result["same_head_duplicate_remediation_request_count"], 0)
        self.assertIsNone(result["provider_turn_count"])
        self.assertIsNone(result["token_fields"])
        self.assertIsNone(result["allowance_units"])

    def test_same_head_duplicates_are_reported_separately(self):
        head = "1111111111111111111111111111111111111111"
        result = analyze_codex_request_amplification(
            issue_comments=[
                issue_comment(review_request(head)),
                issue_comment(review_request(head)),
                issue_comment(remediation_request(head)),
                issue_comment(remediation_request(head)),
            ],
            reviews=[
                review("Codex review", login=CODEX, commit_id=head, review_id=1),
                review("Codex review", login=CODEX, commit_id=head, review_id=2),
            ],
            trusted_request_authors=(OWNER,),
        )

        self.assertEqual(result["review_request_count"], 2)
        self.assertEqual(result["remediation_request_count"], 2)
        self.assertEqual(result["codex_review_submission_count"], 2)
        self.assertEqual(result["distinct_loop_head_count"], 1)
        self.assertEqual(result["same_head_duplicate_review_request_count"], 1)
        self.assertEqual(result["same_head_duplicate_remediation_request_count"], 1)
        self.assertEqual(result["same_head_duplicate_codex_review_submission_count"], 1)

    def test_repeated_marker_inside_one_event_counts_once(self):
        head = "5555555555555555555555555555555555555555"
        marker = f"<!-- agent-controller:codex-review-request head={head} -->"
        result = analyze_codex_request_amplification(
            issue_comments=[issue_comment(f"@codex review\n\n{marker}\n{marker}")],
            reviews=[],
            trusted_request_authors=(OWNER,),
        )

        self.assertEqual(result["review_request_count"], 1)
        self.assertEqual(result["same_head_duplicate_review_request_count"], 0)

    def test_one_shot_review_iterable_is_materialized_once(self):
        head = "6666666666666666666666666666666666666666"
        reviews = (
            item
            for item in [
                review(review_request(head), review_id=1),
                review("Codex review", login=CODEX, commit_id=head, review_id=2),
            ]
        )
        result = analyze_codex_request_amplification(
            issue_comments=(),
            reviews=reviews,
            trusted_request_authors=(OWNER,),
        )

        self.assertEqual(result["review_request_count"], 1)
        self.assertEqual(result["codex_review_submission_count"], 1)

    def test_untrusted_marker_is_not_counted(self):
        head = "2222222222222222222222222222222222222222"
        result = analyze_codex_request_amplification(
            issue_comments=[issue_comment(review_request(head), login="mallory")],
            reviews=[],
            trusted_request_authors=(OWNER,),
        )

        self.assertEqual(result["status"], "OBSERVED")
        self.assertEqual(result["review_request_count"], 0)
        self.assertEqual(result["distinct_loop_head_count"], 0)

    def test_marker_without_command_is_uncertain_and_not_counted(self):
        head = "3333333333333333333333333333333333333333"
        result = analyze_codex_request_amplification(
            issue_comments=[
                issue_comment(
                    f"<!-- agent-controller:codex-review-request head={head} -->"
                )
            ],
            reviews=[],
            trusted_request_authors=(OWNER,),
        )

        self.assertEqual(result["status"], "UNCERTAIN")
        self.assertEqual(result["review_request_count"], 0)
        self.assertIn("REVIEW_MARKER_WITHOUT_COMMAND", result["uncertainties"][0])

    def test_codex_review_without_exact_commit_is_uncertain(self):
        result = analyze_codex_request_amplification(
            issue_comments=[],
            reviews=[review("Codex review", login=CODEX, commit_id=None)],
            trusted_request_authors=(OWNER,),
        )

        self.assertEqual(result["status"], "UNCERTAIN")
        self.assertEqual(result["codex_review_submission_count"], 0)
        self.assertIn(
            "CODEX_REVIEW_MISSING_EXACT_COMMIT", result["uncertainties"][0]
        )

    def test_empty_review_body_is_not_malformed(self):
        result = analyze_codex_request_amplification(
            issue_comments=[],
            reviews=[review(None, login="another-reviewer", commit_id="4444444444444444444444444444444444444444")],
            trusted_request_authors=(OWNER,),
        )

        self.assertEqual(result["status"], "OBSERVED")
        self.assertEqual(result["codex_review_submission_count"], 0)

    @patch("agent_controller.codex_amplification.get_pr_reviews")
    @patch("agent_controller.codex_amplification.get_pr_issue_comments")
    @patch("agent_controller.codex_amplification.load_policy")
    def test_collect_reads_each_github_surface_once(
        self, mock_policy, mock_comments, mock_reviews
    ):
        head = "7777777777777777777777777777777777777777"
        mock_policy.return_value = {"trusted_review_request_authors": [OWNER]}
        mock_comments.return_value = [issue_comment(review_request(head))]
        mock_reviews.return_value = [
            review("Codex review", login=CODEX, commit_id=head, review_id=99)
        ]

        result = collect_codex_request_amplification(
            owner="oimus1976",
            repo="agent-controller",
            pr_number=112,
            policy_path="policy.json",
        )

        self.assertEqual(result["status"], "OBSERVED")
        self.assertEqual(result["repo"], "oimus1976/agent-controller")
        self.assertEqual(result["pr"], 112)
        self.assertEqual(result["review_request_count"], 1)
        self.assertEqual(result["codex_review_submission_count"], 1)
        mock_comments.assert_called_once_with("oimus1976", "agent-controller", 112)
        mock_reviews.assert_called_once_with("oimus1976", "agent-controller", 112)

    @patch("agent_controller.codex_amplification.get_pr_reviews")
    @patch("agent_controller.codex_amplification.get_pr_issue_comments")
    @patch("agent_controller.codex_amplification.load_policy")
    def test_collect_malformed_top_level_evidence_is_uncertain(
        self, mock_policy, mock_comments, mock_reviews
    ):
        mock_policy.return_value = {"trusted_review_request_authors": [OWNER]}
        mock_comments.return_value = {}
        mock_reviews.return_value = []

        result = collect_codex_request_amplification(
            owner="oimus1976",
            repo="agent-controller",
            pr_number=112,
            policy_path="policy.json",
        )

        self.assertEqual(result["status"], "UNCERTAIN")
        self.assertEqual(result["reason"], "MALFORMED_GITHUB_EVIDENCE")

    @patch("agent_controller.codex_amplification.get_pr_issue_comments")
    @patch("agent_controller.codex_amplification.load_policy")
    def test_collect_github_read_failure_is_uncertain(self, mock_policy, mock_comments):
        mock_policy.return_value = {"trusted_review_request_authors": [OWNER]}
        mock_comments.side_effect = RuntimeError("offline")

        result = collect_codex_request_amplification(
            owner="oimus1976",
            repo="agent-controller",
            pr_number=112,
            policy_path="policy.json",
        )

        self.assertEqual(result["status"], "UNCERTAIN")
        self.assertIn("EVIDENCE_FETCH_FAILED", result["reason"])

    @patch("agent_controller.codex_amplification.get_pr_issue_comments")
    @patch("agent_controller.codex_amplification.load_policy")
    def test_collect_missing_policy_stops_before_github_reads(
        self, mock_policy, mock_comments
    ):
        mock_policy.return_value = None

        result = collect_codex_request_amplification(
            owner="oimus1976",
            repo="agent-controller",
            pr_number=112,
            policy_path="missing.json",
        )

        self.assertEqual(result["status"], "UNCERTAIN")
        self.assertEqual(result["reason"], "MISSING_OR_MALFORMED_POLICY")
        mock_comments.assert_not_called()


class CodexRemediationGapClassificationTests(unittest.TestCase):
    def test_absent_marker_is_observed(self):
        result = classify_codex_remediation_gap(
            issue_comments=[issue_comment("Just a regular comment")],
            reviews=[],
            trusted_request_authors=(OWNER,),
            current_pr_head="1111111111111111111111111111111111111111",
        )
        self.assertEqual(result["status"], "OBSERVED")
        self.assertEqual(result["reason"], "ABSENT_MARKER")

    def test_untrusted_marker_is_treated_as_absent(self):
        head = "2222222222222222222222222222222222222222"
        result = classify_codex_remediation_gap(
            issue_comments=[issue_comment(remediation_request(head), login="mallory")],
            reviews=[],
            trusted_request_authors=(OWNER,),
            current_pr_head=head,
        )
        self.assertEqual(result["status"], "OBSERVED")
        self.assertEqual(result["reason"], "ABSENT_MARKER")

    def test_malformed_head_is_uncertain(self):
        result = classify_codex_remediation_gap(
            issue_comments=[],
            reviews=[],
            trusted_request_authors=(OWNER,),
            current_pr_head="short",
        )
        self.assertEqual(result["status"], "UNCERTAIN")
        self.assertEqual(result["reason"], "MALFORMED_HEAD")

    def test_duplicate_trusted_marker_same_head_is_resolved(self):
        head = "3333333333333333333333333333333333333333"
        result = classify_codex_remediation_gap(
            issue_comments=[
                issue_comment(remediation_request(head)),
                issue_comment(remediation_request(head)),
            ],
            reviews=[],
            trusted_request_authors=(OWNER,),
            current_pr_head=head,
        )
        self.assertEqual(result["status"], "NEEDS_ATTENTION")
        self.assertEqual(result["provider_completion"], "UNKNOWN")

    def test_multiple_trusted_markers_different_heads_is_uncertain(self):
        head1 = "3333333333333333333333333333333333333333"
        head2 = "4444444444444444444444444444444444444444"
        result = classify_codex_remediation_gap(
            issue_comments=[
                issue_comment(remediation_request(head1)),
                issue_comment(remediation_request(head2)),
            ],
            reviews=[],
            trusted_request_authors=(OWNER,),
            current_pr_head=head1,
        )
        self.assertEqual(result["status"], "UNCERTAIN")
        self.assertEqual(result["reason"], "AMBIGUOUS_MULTIPLE_SOURCE_HEADS")

    def test_unchanged_head_needs_attention(self):
        head = "5555555555555555555555555555555555555555"
        result = classify_codex_remediation_gap(
            issue_comments=[issue_comment(remediation_request(head))],
            reviews=[],
            trusted_request_authors=(OWNER,),
            current_pr_head=head,
        )
        self.assertEqual(result["status"], "NEEDS_ATTENTION")
        self.assertEqual(result["provider_completion"], "UNKNOWN")
        self.assertIn("inspect the exact Codex task", result["operator_guidance"])

    def test_changed_head_is_new_untrusted(self):
        source_head = "6666666666666666666666666666666666666666"
        current_head = "7777777777777777777777777777777777777777"
        result = classify_codex_remediation_gap(
            issue_comments=[issue_comment(remediation_request(source_head))],
            reviews=[],
            trusted_request_authors=(OWNER,),
            current_pr_head=current_head,
        )
        self.assertEqual(result["status"], "NEW_UNTRUSTED_HEAD")
        self.assertEqual(
            result["requirements"],
            ["fresh objective scope", "exact-head CI", "exact-head review"],
        )

    def test_reviews_are_inspected(self):
        head = "8888888888888888888888888888888888888888"
        result = classify_codex_remediation_gap(
            issue_comments=[],
            reviews=[review(remediation_request(head))],
            trusted_request_authors=(OWNER,),
            current_pr_head=head,
        )
        self.assertEqual(result["status"], "NEEDS_ATTENTION")
        self.assertEqual(result["provider_completion"], "UNKNOWN")

    def test_marker_without_command_is_uncertain(self):
        head = "9999999999999999999999999999999999999999"
        result = classify_codex_remediation_gap(
            issue_comments=[
                issue_comment(
                    f"<!-- agent-controller:codex-remediation-request "
                    f"source_head={head} -->"
                )
            ],
            reviews=[],
            trusted_request_authors=(OWNER,),
            current_pr_head=head,
        )
        self.assertEqual(result["status"], "UNCERTAIN")
        self.assertEqual(
            result["reason"],
            "MALFORMED_REMEDIATION_EVIDENCE",
        )

    def test_malformed_trusted_author_entry_is_rejected(self):
        with self.assertRaisesRegex(
            ValueError,
            "trusted_request_authors must be a nonempty tuple",
        ):
            classify_codex_remediation_gap(
                issue_comments=[],
                reviews=[],
                trusted_request_authors=(OWNER, None),
                current_pr_head="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )

    def test_malformed_evidence_is_uncertain(self):
        result = classify_codex_remediation_gap(
            issue_comments=[None],
            reviews=[],
            trusted_request_authors=(OWNER,),
            current_pr_head="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        self.assertEqual(result["status"], "UNCERTAIN")
        self.assertEqual(
            result["reason"],
            "MALFORMED_REMEDIATION_EVIDENCE",
        )

    def test_missing_or_non_string_issue_comment_body_is_uncertain(self):
        head = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        malformed_comments = [
            {"id": 1, "user": {"login": OWNER}},
            {"id": 2, "user": {"login": OWNER}, "body": 123},
        ]
        for item in malformed_comments:
            with self.subTest(item=item):
                result = classify_codex_remediation_gap(
                    issue_comments=[item],
                    reviews=[],
                    trusted_request_authors=(OWNER,),
                    current_pr_head=head,
                )
                self.assertEqual(result["status"], "UNCERTAIN")
                self.assertEqual(
                    result["reason"],
                    "MALFORMED_REMEDIATION_EVIDENCE",
                )

    def test_empty_review_body_is_preserved_and_not_malformed(self):
        head = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        result = classify_codex_remediation_gap(
            issue_comments=[],
            reviews=[review(None, login=OWNER, commit_id=head)],
            trusted_request_authors=(OWNER,),
            current_pr_head=head,
        )
        self.assertEqual(result["status"], "OBSERVED")
        self.assertEqual(result["reason"], "ABSENT_MARKER")

    def test_non_string_review_body_is_uncertain(self):
        head = "dddddddddddddddddddddddddddddddddddddddd"
        for malformed_body in (123, [], {"unexpected": "object"}):
            with self.subTest(body=malformed_body):
                result = classify_codex_remediation_gap(
                    issue_comments=[],
                    reviews=[review(malformed_body, login=OWNER, commit_id=head)],
                    trusted_request_authors=(OWNER,),
                    current_pr_head=head,
                )
                self.assertEqual(result["status"], "UNCERTAIN")
                self.assertEqual(
                    result["reason"],
                    "MALFORMED_REMEDIATION_EVIDENCE",
                )

    def test_missing_review_body_field_is_uncertain(self):
        head = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
        result = classify_codex_remediation_gap(
            issue_comments=[],
            reviews=[
                {
                    "id": 1,
                    "user": {"login": OWNER},
                    "commit_id": head,
                    "state": "COMMENTED",
                }
            ],
            trusted_request_authors=(OWNER,),
            current_pr_head=head,
        )
        self.assertEqual(result["status"], "UNCERTAIN")
        self.assertEqual(
            result["reason"],
            "MALFORMED_REMEDIATION_EVIDENCE",
        )

    def test_malformed_marker_alongside_valid_marker_is_uncertain(self):
        head = "cccccccccccccccccccccccccccccccccccccccc"
        body = (
            remediation_request(head)
            + "\n<!-- agent-controller:codex-remediation-request source_head=short -->"
        )
        result = classify_codex_remediation_gap(
            issue_comments=[issue_comment(body)],
            reviews=[],
            trusted_request_authors=(OWNER,),
            current_pr_head=head,
        )
        self.assertEqual(result["status"], "UNCERTAIN")
        self.assertEqual(
            result["reason"],
            "MALFORMED_REMEDIATION_EVIDENCE",
        )


if __name__ == "__main__":
    unittest.main()
