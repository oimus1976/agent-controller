import unittest
from dataclasses import replace

from test_jules_draft_publication import BASE, FakeGitHub, Reader, evidence, publish, task


class JulesPublicationHardeningTests(unittest.TestCase):
    def test_draft_pr_effect_must_be_explicitly_allowed(self):
        original = task()
        blocked = replace(original, allowed_effects=("SESSION_CREATE",))
        result, github, _ = publish(t=blocked)
        self.assertEqual(result.status, "BLOCKED")
        self.assertEqual(result.reason, "DRAFT_PR_EFFECT_NOT_ALLOWED")
        self.assertEqual(github.writes, [])

        forbidden = replace(original, forbidden_effects=("DRAFT_PR_CREATE",))
        result, github, _ = publish(t=forbidden)
        self.assertEqual(result.reason, "DRAFT_PR_EFFECT_NOT_ALLOWED")
        self.assertEqual(github.writes, [])

    def test_changeset_digest_is_recomputed_before_write(self):
        item = replace(evidence(), patch_sha256="0" * 64)
        result, github, _ = publish(reader=Reader([item]))
        self.assertEqual(result.status, "BLOCKED")
        self.assertEqual(result.reason, "CHANGESET_DIGEST_MISMATCH")
        self.assertEqual(github.writes, [])

    def test_base_drift_after_publication_never_returns_pass(self):
        github = FakeGitHub()
        github.base_sequence = [BASE, BASE, "9" * 40]
        result, github, _ = publish(github=github)
        self.assertEqual(result.status, "UNCERTAIN")
        self.assertEqual(result.reason, "BASE_POSTCONDITION_DRIFT")
        self.assertEqual(github.writes, ["commit", "branch", "pr"])


if __name__ == "__main__":
    unittest.main()
