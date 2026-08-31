import base64
import unittest

from agent_controller.github_draft_publication import GitHubRestDraftPublicationBackend


BASE = "1" * 40
TREE = "2" * 40


class StubBackend(GitHubRestDraftPublicationBackend):
    def __init__(self, mode="100644", truncated=False):
        super().__init__(token="secret")
        self.mode = mode
        self.truncated = truncated
        self.calls = []

    def _request(self, method, path, body=None):
        self.calls.append((method, path, body))
        if "/git/commits/" in path:
            return {"tree": {"sha": TREE}}
        if "/git/trees/" in path:
            return {"truncated": self.truncated, "tree": [{"path": "app.txt", "mode": self.mode, "type": "blob"}]}
        if "/contents/app.txt" in path:
            return {"type": "file", "encoding": "base64", "content": base64.b64encode(b"hello\n").decode()}
        if path.endswith("/pulls") and method == "POST":
            return {"number": 3, "draft": body.get("draft")}
        raise AssertionError(path)


class GitHubDraftPublicationBackendTests(unittest.TestCase):
    def test_regular_100644_text_is_read(self):
        backend = StubBackend()
        self.assertEqual(backend.get_file_text("o/r", BASE, "app.txt"), "hello\n")

    def test_executable_or_other_mode_is_rejected_before_content_read(self):
        backend = StubBackend(mode="100755")
        with self.assertRaisesRegex(RuntimeError, "100644"):
            backend.get_file_text("o/r", BASE, "app.txt")
        self.assertFalse(any("/contents/" in path for _, path, _ in backend.calls))

    def test_truncated_tree_fails_closed(self):
        backend = StubBackend(truncated=True)
        with self.assertRaisesRegex(RuntimeError, "truncated"):
            backend.get_file_text("o/r", BASE, "app.txt")

    def test_create_pr_payload_is_always_draft(self):
        backend = StubBackend()
        result = backend.create_draft_pr(repo="o/r", head="controller/x", base="main", title="x", body="y")
        self.assertTrue(result["draft"])
        method, path, body = backend.calls[-1]
        self.assertEqual(method, "POST")
        self.assertTrue(body["draft"])
        self.assertNotIn("merge", body)
        self.assertNotIn("auto_merge", body)


if __name__ == "__main__":
    unittest.main()
