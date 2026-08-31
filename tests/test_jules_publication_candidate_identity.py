import unittest
from dataclasses import replace

from test_jules_draft_publication import FakeGitHub, Reader, evidence, publish


class JulesPublicationCandidateIdentityTests(unittest.TestCase):
    def test_activity_identity_must_match_exact_bound_session(self):
        item = replace(evidence(), activity_name="sessions/session-b/activities/act-1")
        result, github, _ = publish(reader=Reader([item]))
        self.assertEqual(result.status, "BLOCKED")
        self.assertEqual(result.reason, "CHANGESET_ACTIVITY_MISMATCH")
        self.assertEqual(github.writes, [])

    def test_candidate_must_be_session_completed(self):
        item = replace(evidence(), session_completed=False)
        result, github, _ = publish(reader=Reader([item]))
        self.assertEqual(result.status, "BLOCKED")
        self.assertEqual(result.reason, "CHANGESET_NOT_COMPLETED")
        self.assertEqual(github.writes, [])

    def test_malformed_suggested_commit_message_blocks_before_write(self):
        item = replace(evidence(), suggested_commit_message="")
        result, github, _ = publish(reader=Reader([item]))
        self.assertEqual(result.status, "BLOCKED")
        self.assertEqual(result.reason, "CHANGESET_COMMIT_MESSAGE_INVALID")
        self.assertEqual(github.writes, [])


if __name__ == "__main__":
    unittest.main()
