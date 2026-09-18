"""A bounded search-hit read must not retain only text before the actual hit."""
import copy
import json
import unittest
from unittest.mock import patch

from vulngym_t2.pipeline import _ProductionSession
from vulngym_t2.prompt_evidence import bounded_navigation_result, display_record
from tests.test_t2_v2_navigation_context import long_read
from tests.test_t2_v2_pipeline import job
from tests.test_t2_v2_staged_pipeline import MemoryRepo


class NavigationAnchorTests(unittest.TestCase):
    def test_tight_interval_keeps_hit_and_exact_original_rows(self):
        original = long_read()["result"]
        saved = copy.deepcopy(original)
        bounded = bounded_navigation_result(original, 1500, anchor_line=185)
        self.assertLessEqual(bounded["start_line"], 185)
        self.assertGreaterEqual(bounded["end_line"], 185)
        self.assertGreater(bounded["start_line"], original["start_line"])
        self.assertEqual(bounded["lines"], [row for row in original["lines"]
            if bounded["start_line"] <= row["line"] <= bounded["end_line"]])
        self.assertEqual(bounded["text"], "\n".join(row["code"] for row in bounded["lines"]))
        shown = display_record({"result": bounded}, compact=True)["result"]
        self.assertLessEqual(len(json.dumps(shown, ensure_ascii=False, sort_keys=True, separators=(",", ":"))), 1500)
        self.assertEqual(original, saved)

    def test_unavailable_or_unaffordable_anchor_is_not_fabricated(self):
        value = long_read()["result"]
        for anchor in (99, 200, "185", True):
            self.assertEqual(bounded_navigation_result(value, 1500, anchor_line=anchor)["error_code"],
                             "navigation_anchor_unavailable")
        self.assertEqual(bounded_navigation_result(value, 20, anchor_line=185)["error_code"],
                         "navigation_display_limit")

    def test_controller_stores_only_the_same_anchored_interval_without_field_changes(self):
        class Client:
            response_mode = "staged_tool"
        repo = MemoryRepo()
        session = _ProductionSession(job(False), Client(), repo, 3, 24)
        session.prepare()
        fields = copy.deepcopy(session.result["fields"])
        value = long_read()["result"]
        with patch.object(repo, "call", return_value=value) as read:
            shown = session.read_tool("read_file", {"commit": value["commit"], "path": value["path"],
                "start_line": 100, "end_line": 199}, automatic=True,
                navigation_display_limit=1500, navigation_anchor_line=185)
        self.assertTrue(shown["success"])
        stored = session.evidence_by_id[shown["id"]]
        self.assertEqual(shown["result"]["start_line"], stored["result"]["start_line"])
        self.assertEqual(shown["result"]["end_line"], stored["result"]["end_line"])
        self.assertLessEqual(stored["result"]["start_line"], 185)
        self.assertGreaterEqual(stored["result"]["end_line"], 185)
        self.assertEqual(session.result["fields"], fields)
        self.assertEqual(session.result["model_calls"], 0)
        self.assertEqual(read.call_count, 1)
        self.assertNotIn("anchor_line", read.call_args.args[1])


if __name__ == "__main__":
    unittest.main()
