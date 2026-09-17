import unittest

from agent_controller.private_ci_live_registration import (
    FROZEN_RUNNER_LABEL,
    FROZEN_RUNNER_NAME,
)
from agent_controller.private_ci_runner_readback import read_all_runner_items


def runner(runner_id, *, name=None, labels=()):
    return {
        "id": runner_id,
        "name": name or f"runner-{runner_id}",
        "status": "offline",
        "busy": False,
        "labels": [{"name": label} for label in labels],
    }


class RunnerReadbackTests(unittest.TestCase):
    def test_reads_later_pages_twice_before_accepting(self):
        calls = []

        def fetch_page(page):
            calls.append(page)
            if page == 1:
                return {
                    "total_count": 101,
                    "runners": [runner(index) for index in range(1, 101)],
                }
            if page == 2:
                return {"total_count": 101, "runners": [runner(101)]}
            raise AssertionError(page)

        items = read_all_runner_items(fetch_page)
        self.assertEqual(len(items), 101)
        self.assertEqual(items[-1]["id"], 101)
        self.assertEqual(calls, [1, 2, 1, 2])

    def test_duplicate_id_across_pages_is_blocked(self):
        def fetch_page(page):
            if page == 1:
                return {
                    "total_count": 101,
                    "runners": [runner(index) for index in range(1, 101)],
                }
            return {"total_count": 101, "runners": [runner(100)]}

        with self.assertRaisesRegex(RuntimeError, "duplicate id"):
            read_all_runner_items(fetch_page)

    def test_invalid_runner_id_is_blocked(self):
        with self.assertRaisesRegex(RuntimeError, "runner id"):
            read_all_runner_items(
                lambda page: {
                    "total_count": 1,
                    "runners": [
                        {
                            "id": True,
                            "name": "bad",
                            "labels": [],
                        }
                    ],
                }
            )

    def test_malformed_or_duplicate_runner_labels_are_blocked(self):
        malformed_labels = (
            [FROZEN_RUNNER_LABEL],
            [{}],
            [{"name": ""}],
            [{"name": FROZEN_RUNNER_LABEL}, {"name": FROZEN_RUNNER_LABEL}],
        )
        for labels in malformed_labels:
            with self.subTest(labels=labels):
                with self.assertRaisesRegex(RuntimeError, "label"):
                    read_all_runner_items(
                        lambda page, labels=labels: {
                            "total_count": 1,
                            "runners": [
                                {
                                    "id": 7,
                                    "name": "other-runner",
                                    "status": "offline",
                                    "busy": False,
                                    "labels": labels,
                                }
                            ],
                        }
                    )

    def test_empty_runner_name_is_blocked(self):
        with self.assertRaisesRegex(RuntimeError, "runner name"):
            read_all_runner_items(
                lambda page: {
                    "total_count": 1,
                    "runners": [
                        {
                            "id": 7,
                            "name": "",
                            "status": "offline",
                            "busy": False,
                            "labels": [],
                        }
                    ],
                }
            )

    def test_bool_total_count_is_blocked(self):
        with self.assertRaisesRegex(RuntimeError, "total_count invalid"):
            read_all_runner_items(lambda page: {"total_count": True, "runners": []})

    def test_short_page_with_larger_total_count_is_blocked(self):
        with self.assertRaisesRegex(RuntimeError, "incomplete for total_count"):
            read_all_runner_items(
                lambda page: {
                    "total_count": 2,
                    "runners": [runner(1)],
                }
            )

    def test_total_count_change_across_pages_is_blocked(self):
        def fetch_page(page):
            if page == 1:
                return {
                    "total_count": 101,
                    "runners": [runner(index) for index in range(1, 101)],
                }
            return {"total_count": 102, "runners": [runner(101)]}

        with self.assertRaisesRegex(RuntimeError, "changed across pages"):
            read_all_runner_items(fetch_page)

    def test_accumulated_count_cannot_exceed_total_count(self):
        with self.assertRaisesRegex(RuntimeError, "exceeds total_count"):
            read_all_runner_items(
                lambda page: {
                    "total_count": 1,
                    "runners": [runner(1), runner(2)],
                }
            )

    def test_frozen_runner_name_without_frozen_label_is_blocked(self):
        with self.assertRaisesRegex(RuntimeError, "name/label collision"):
            read_all_runner_items(
                lambda page: {
                    "total_count": 1,
                    "runners": [runner(9, name=FROZEN_RUNNER_NAME, labels=())],
                }
            )

    def test_frozen_runner_name_with_frozen_label_is_readable(self):
        items = read_all_runner_items(
            lambda page: {
                "total_count": 1,
                "runners": [
                    runner(
                        9,
                        name=FROZEN_RUNNER_NAME,
                        labels=(FROZEN_RUNNER_LABEL,),
                    )
                ],
            }
        )
        self.assertEqual(len(items), 1)

    def test_same_total_count_but_shifted_runner_set_between_sweeps_is_blocked(self):
        calls = []

        def fetch_page(page):
            calls.append(page)
            sweep = 1 if len(calls) <= 2 else 2
            if page == 1:
                if sweep == 1:
                    ids = range(1, 101)
                else:
                    ids = range(2, 102)
                return {
                    "total_count": 101,
                    "runners": [runner(index) for index in ids],
                }
            if page == 2:
                last_id = 101 if sweep == 1 else 102
                return {"total_count": 101, "runners": [runner(last_id)]}
            raise AssertionError(page)

        with self.assertRaisesRegex(RuntimeError, "changed across sweeps"):
            read_all_runner_items(fetch_page)

    def test_order_only_change_between_sweeps_is_accepted(self):
        call_count = 0

        def fetch_page(page):
            nonlocal call_count
            self.assertEqual(page, 1)
            call_count += 1
            items = [runner(1), runner(2)]
            if call_count == 2:
                items.reverse()
            return {"total_count": 2, "runners": items}

        items = read_all_runner_items(fetch_page)
        self.assertEqual({item["id"] for item in items}, {1, 2})
        self.assertEqual(call_count, 2)


if __name__ == "__main__":
    unittest.main()
