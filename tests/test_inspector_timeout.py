import inspect
import math
import unittest
from unittest.mock import patch

from agent_controller import inspector


class FakeResponse:
    def __init__(self, body=b"{}", link=None):
        self._body = body
        self.headers = {}
        if link is not None:
            self.headers["Link"] = link

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self):
        return self._body


class InspectorTimeoutTests(unittest.TestCase):
    def test_default_rest_timeout_is_explicit_and_finite(self):
        calls = []

        def fake_urlopen(req, **kwargs):
            calls.append(kwargs)
            return FakeResponse()

        with patch.object(inspector.urllib.request, "urlopen", side_effect=fake_urlopen):
            self.assertEqual(inspector._github_api_request("https://api.github.com/example"), {})

        self.assertEqual(len(calls), 1)
        timeout = calls[0].get("timeout")
        self.assertEqual(timeout, inspector.DEFAULT_GITHUB_REQUEST_TIMEOUT_SECONDS)
        self.assertTrue(math.isfinite(timeout))
        self.assertGreater(timeout, 0)

    def test_paginated_rest_forwards_timeout_on_every_page(self):
        calls = []
        responses = [
            FakeResponse(
                b"[]",
                '<https://api.github.com/example?page=2>; rel="next"',
            ),
            FakeResponse(b"[]"),
        ]

        def fake_urlopen(req, **kwargs):
            calls.append(kwargs)
            return responses.pop(0)

        with patch.object(inspector.urllib.request, "urlopen", side_effect=fake_urlopen):
            result = inspector._github_api_request_paginated(
                "https://api.github.com/example?page=1", timeout=7.5
            )

        self.assertEqual(result, [])
        self.assertEqual([call.get("timeout") for call in calls], [7.5, 7.5])

    def test_graphql_timeout_is_explicit_and_forwarded(self):
        calls = []

        def fake_urlopen(req, **kwargs):
            calls.append(kwargs)
            return FakeResponse(b'{"data": {}}')

        with patch.object(inspector.urllib.request, "urlopen", side_effect=fake_urlopen):
            result = inspector._github_graphql_request("query { viewer { login } }", timeout=4)

        self.assertEqual(result, {"data": {}})
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0].get("timeout"), 4.0)
        self.assertIn("data", calls[0])

    def test_invalid_timeout_fails_before_network_io(self):
        invalid = [True, False, None, 0, -1, float("nan"), float("inf"), float("-inf")]

        for value in invalid:
            with self.subTest(value=value):
                with patch.object(inspector.urllib.request, "urlopen") as urlopen:
                    with self.assertRaises(ValueError):
                        inspector._github_api_request(
                            "https://api.github.com/example", timeout=value
                        )
                    urlopen.assert_not_called()

                with patch.object(inspector.urllib.request, "urlopen") as urlopen:
                    with self.assertRaises(ValueError):
                        inspector._github_graphql_request("query { viewer { login } }", timeout=value)
                    urlopen.assert_not_called()

    def test_live_inspector_source_has_no_unbounded_urlopen_call(self):
        source = inspect.getsource(inspector)
        urlopen_lines = [line.strip() for line in source.splitlines() if "urlopen(" in line]
        self.assertEqual(len(urlopen_lines), 2)
        for line in urlopen_lines:
            self.assertIn("timeout=", line)

    def test_timeout_surface_exposes_no_retry_or_mutation(self):
        source = inspect.getsource(inspector._github_api_request_paginated)
        self.assertNotIn("sleep(", source)
        self.assertNotIn("retry", source.lower())
        self.assertNotIn("backoff", source.lower())


if __name__ == "__main__":
    unittest.main()
