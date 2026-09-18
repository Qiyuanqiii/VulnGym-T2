"""Bookmark byte preservation and boundaries; no provider or real input score."""
import copy
import json
import unittest

from vulngym_t2.evidence_focus import source_bookmarks


SHA = "a" * 40


def receipt(identity, rows, *, first=1, sha=SHA, truncated=False):
    return {"id": identity, "tool": "read_file", "success": True,
            "arguments": {"start_line": first, "end_line": first + len(rows) + 50},
            "result": {"commit": sha, "path": "src/input.py", "start_line": first,
                       "end_line": first + len(rows) - 1, "truncated": truncated,
                       "lines": [{"line": first + index, "code": code} for index, code in enumerate(rows)],
                       "text": "\n".join(rows)}}


class EvidenceFocusTests(unittest.TestCase):
    def test_shown_prefix_survives_truncation_without_inventing_requested_tail(self):
        source = receipt("E0001", ['@router.get("/{item}")', 'async def read_item(item):',
                                   '    return lookup(item)'], first=80, truncated=True)
        before = copy.deepcopy(source)
        view = source_bookmarks([source])
        self.assertEqual(source, before)
        bookmark = view["bookmarks"][0]
        self.assertEqual((bookmark["visible_start"], bookmark["visible_end"]), (80, 82))
        self.assertEqual(bookmark["numbered_source"], '80: @router.get("/{item}")\n81: async def read_item(item):\n82:     return lookup(item)')
        self.assertNotIn("status", bookmark)

    def test_search_only_is_not_source_and_other_sha_queries_do_not_select_rows(self):
        search = {"id": "E0002", "tool": "search_code", "success": True,
                  "result": {"commit": "b" * 40, "query": "rare_marker", "matches": [{"line": 60}]}}
        self.assertEqual(source_bookmarks([search])["bookmarks"], [])
        source = receipt("E0003", ["# padding"] * 55 + ["rare_marker"] + ["# padding"] * 20)
        self.assertNotIn("rare_marker", json.dumps(source_bookmarks([search, source])))
        search["result"]["commit"] = SHA
        view = source_bookmarks([search, source])
        self.assertIn("56: rare_marker", view["bookmarks"][0]["numbered_source"])
        self.assertEqual(view["bookmarks"][0]["evidence_ref"], "E0003")

    def test_invalid_or_failed_reads_are_never_bookmarked(self):
        source = receipt("E0001", ["def example():", "    pass"])
        failed = copy.deepcopy(source)
        failed["success"] = False
        broken = copy.deepcopy(source)
        broken["result"]["lines"][1]["line"] = 10
        bad_sha = copy.deepcopy(source)
        bad_sha["result"]["commit"] = "HEAD"
        self.assertEqual(source_bookmarks([None, {}, failed, broken, bad_sha])["bookmarks"], [])

    def test_actual_serialized_budget_and_recent_reads_preferred(self):
        sources = [receipt(f"E{index:04}", ["def example():", "    " + "x" * 100], first=index * 20)
                   for index in range(1, 30)]
        for cap in (0, 500, 1000, 2000, 6000):
            view = source_bookmarks(sources, max_chars=cap)
            if view:
                self.assertLessEqual(len(json.dumps(view, ensure_ascii=False, sort_keys=True, separators=(",", ":"))), cap)
        view = source_bookmarks(sources, max_chars=2000)
        self.assertEqual(view["bookmarks"][0]["evidence_ref"], "E0029")
        self.assertGreater(view["omitted_excerpts"], 0)


if __name__ == "__main__":
    unittest.main()
