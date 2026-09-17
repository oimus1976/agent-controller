import unittest

from agent_controller.private_ci_runner_readback import read_all_runner_items


def runner(runner_id):
    return {
        "id": runner_id,
        "name": f"runner-{runner_id}",
        "status": "offline",
        "busy": False,
        "labels": [],
    }


class RunnerReadbackTests(unittest.TestCase):
    def test_reads_later_pages(self):
        calls = []

        def fetch_page(page):
            calls.append(page)
            if page == 1:
                return {"runners": [runner(index) for index in range(1, 101)]}
            if page == 2:
                return {"runners": [runner(101)]}
            raise AssertionError(page)

        items = read_all_runner_items(fetch_page)
        self.assertEqual(len(items), 101)
        self.assertEqual(items[-1]["id"], 101)
        self.assertEqual(calls, [1, 2])

    def test_duplicate_id_across_pages_is_blocked(self):
        def fetch_page(page):
            if page == 1:
                return {"runners": [runner(index) for index in range(1, 101)]}
            return {"runners": [runner(100)]}

        with self.assertRaisesRegex(RuntimeError, "duplicate id"):
            read_all_runner_items(fetch_page)

    def test_invalid_runner_id_is_blocked(self):
        with self.assertRaisesRegex(RuntimeError, "runner id"):
            read_all_runner_items(lambda page: {"runners": [{"id": True}]})


if __name__ == "__main__":
    unittest.main()
