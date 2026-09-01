import unittest
from dataclasses import replace

import test_jules_draft_publication as base


class JulesChangeSetFinalityRegressionTests(unittest.TestCase):
    def test_live_shape_one_completed_plus_repeated_in_progress_snapshots_passes(self):
        completed = base.evidence(activity="completed")
        snapshots = [
            replace(
                base.evidence(activity=f"snapshot-{index}"),
                session_completed=False,
                suggested_commit_message=None,
            )
            for index in range(5)
        ]
        result, github, _ = base.publish(
            github=base.FakeGitHub(),
            reader=base.Reader([*snapshots, completed]),
        )

        self.assertEqual(result.status, "PASS")
        self.assertEqual(result.activity_id, "completed")
        self.assertEqual(github.writes, ["commit", "branch", "pr"])

    def test_zero_completed_candidates_remains_ambiguous(self):
        snapshots = [
            replace(
                base.evidence(activity=f"snapshot-{index}"),
                session_completed=False,
                suggested_commit_message=None,
            )
            for index in range(2)
        ]
        result, github, _ = base.publish(
            github=base.FakeGitHub(),
            reader=base.Reader(snapshots),
        )

        self.assertEqual(result.status, "BLOCKED")
        self.assertEqual(result.reason, "CHANGESET_FINALITY_AMBIGUOUS")
        self.assertEqual(github.writes, [])

    def test_multiple_completed_candidates_remains_ambiguous(self):
        result, github, _ = base.publish(
            github=base.FakeGitHub(),
            reader=base.Reader(
                [base.evidence(activity="completed-a"), base.evidence(activity="completed-b")]
            ),
        )

        self.assertEqual(result.status, "BLOCKED")
        self.assertEqual(result.reason, "CHANGESET_FINALITY_AMBIGUOUS")
        self.assertEqual(github.writes, [])


if __name__ == "__main__":
    unittest.main()
