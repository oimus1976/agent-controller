import unittest

from agent_controller.jules_patch import parse_and_apply_text_patch


class JulesPatchHardeningTests(unittest.TestCase):
    def test_hunk_counts_must_match_body(self):
        malformed = """diff --git a/a.txt b/a.txt
--- a/a.txt
+++ b/a.txt
@@ -1,2 +1,1 @@
-old
+new
"""
        with self.assertRaisesRegex(ValueError, "COUNT_MISMATCH"):
            parse_and_apply_text_patch(malformed, lambda _: "old\n")


if __name__ == "__main__":
    unittest.main()
