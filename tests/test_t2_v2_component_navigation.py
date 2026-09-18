"""Component-script navigation uses visible fixture bytes, not runtime claims."""
import copy
import unittest

from vulngym_t2.entry_navigation import entry_navigation_seed, navigate_entry, public_navigation_report
from tests.test_t2_v2_pipeline import VULNERABLE


def source(identity, path, lines, first=1):
    return {"id": identity, "tool": "read_file", "success": True, "result": {
        "commit": VULNERABLE, "path": path, "start_line": first,
        "end_line": first + len(lines) - 1, "text": "\n".join(lines)}}


def review_for(path, lines, selected, first=1):
    return {"draft_fields": {"commit": VULNERABLE}, "suggested_values": {
        "entry_point": {"evidence_ref": "E0001", "start_line": selected, "end_line": selected}},
        "field_reviews": {"entry_point": {"status": "uncertain", "evidence_refs": ["E0001"]}},
        "evidence": [source("E0001", path, lines, first)]}


class ComponentNavigationTests(unittest.TestCase):
    def test_component_script_and_partial_windows_supply_callback_names(self):
        lines = ["  const receiveEvent = async (event, cb) => {", "    consume(event.data);", "  };"]
        for suffix in ("svelte", "vue"):
            for first in (1, 300):
                with self.subTest(suffix=suffix, first=first):
                    review = review_for("src/View." + suffix, lines, first + 1, first)
                    before = copy.deepcopy(review)
                    self.assertEqual(entry_navigation_seed(review)["symbol"], "receiveEvent")
                    self.assertEqual(review, before)
        self.assertIsNone(entry_navigation_seed(review_for("docs/example.md", lines, 2)))

    def test_script_or_style_boundary_cannot_bind_a_previous_callback(self):
        for tag in ("</script>", "<script lang='ts'>", "<style>", "</STYLE>"):
            lines = ["const receiveEvent = (event) => {", tag, "  consume(event.data);"]
            with self.subTest(tag=tag):
                self.assertIsNone(entry_navigation_seed(review_for("src/View.svelte", lines, 3)))
        lines = ["<script lang='ts'>", "const receiveEvent = (event) => {", "  consume(event.data);", "}"]
        self.assertEqual(entry_navigation_seed(review_for("src/View.svelte", lines, 3))["symbol"], "receiveEvent")

    def test_registration_search_reads_actual_match_without_promoting_entry(self):
        review = review_for("src/View.svelte", [
            "const receiveEvent = (event) => {", "  consume(event.data);", "};"], 2)
        before = copy.deepcopy(review)
        calls = []

        def execute(tool, arguments):
            calls.append((tool, copy.deepcopy(arguments)))
            if tool == "search_code":
                return {"id": "E0002", "tool": tool, "success": True, "result": {
                    "commit": VULNERABLE, "query": "receiveEvent", "matches": [{
                        "file": "src/View.svelte", "line": 50,
                        "code": "bus.on('update', receiveEvent);"}]}}
            return source("E0003", "src/View.svelte", ["bus.on('update', receiveEvent);"], 50)

        result = navigate_entry(review, execute, lambda: len(calls) < 2)
        self.assertEqual([tool for tool, _ in calls], ["search_code", "read_file"])
        self.assertEqual(calls[0][1]["query"], "receiveEvent")
        self.assertLessEqual(calls[1][1]["start_line"], 50)
        self.assertGreaterEqual(calls[1][1]["end_line"], 50)
        self.assertEqual(result["version"], "entry-navigation-v20")
        self.assertFalse(result["semantic_approval"])
        self.assertEqual(review, before)
        result["version"] = "entry-navigation-v5"
        self.assertTrue(public_navigation_report(result))


if __name__ == "__main__":
    unittest.main()
