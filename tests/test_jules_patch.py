import unittest

from agent_controller.jules_patch import parse_and_apply_text_patch


class JulesPatchTests(unittest.TestCase):
    def test_add_update_delete(self):
        base = {"a.txt": "old\n", "delete.txt": "gone\n"}
        patch = """diff --git a/a.txt b/a.txt
--- a/a.txt
+++ b/a.txt
@@ -1 +1 @@
-old
+new
diff --git a/new.txt b/new.txt
new file mode 100644
--- /dev/null
+++ b/new.txt
@@ -0,0 +1 @@
+hello
diff --git a/delete.txt b/delete.txt
deleted file mode 100644
--- a/delete.txt
+++ /dev/null
@@ -1 +0,0 @@
-gone
"""
        changes = parse_and_apply_text_patch(patch, base.get)
        self.assertEqual(len(changes), 3)
        self.assertEqual(changes[0].new_text, "new\n")
        self.assertEqual(changes[1].new_text, "hello\n")
        self.assertIsNone(changes[2].new_text)

    def test_collision_and_no_newline_fail_closed(self):
        collision = """diff --git a/a.txt b/a.txt
--- a/a.txt
+++ b/a.txt
@@ -1 +1 @@
-x
+y
diff --git a/a.txt b/a.txt
--- a/a.txt
+++ b/a.txt
@@ -1 +1 @@
-x
+z
"""
        with self.assertRaisesRegex(ValueError, "COLLISION"):
            parse_and_apply_text_patch(collision, lambda _: "x\n")

        no_newline = """diff --git a/a.txt b/a.txt
--- a/a.txt
+++ b/a.txt
@@ -1 +1 @@
-old
+new
\\ No newline at end of file
"""
        with self.assertRaisesRegex(ValueError, "NO_NEWLINE"):
            parse_and_apply_text_patch(no_newline, lambda _: "old\n")

    def test_binary_mode_absolute_and_backslash_fail_closed(self):
        samples = (
            "diff --git a/a b/a\nGIT binary patch\n--- a/a\n+++ b/a\n@@ -0,0 +1 @@\n+x\n",
            "diff --git a/a b/a\nold mode 100644\nnew mode 100755\n--- a/a\n+++ b/a\n@@ -0,0 +1 @@\n+x\n",
            "diff --git a/a b/a\n--- /etc/passwd\n+++ b/a\n@@ -0,0 +1 @@\n+x\n",
            "diff --git a/a b/a\n--- a/a\\b\n+++ b/a\n@@ -0,0 +1 @@\n+x\n",
        )
        for sample in samples:
            with self.assertRaises(ValueError):
                parse_and_apply_text_patch(sample, lambda _: "")


if __name__ == "__main__":
    unittest.main()
