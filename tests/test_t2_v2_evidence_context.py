"""Prompt tables and synthetic controller read flows; no HTTP or target reads."""
import copy
import json
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from vulngym_t2.evidence_context import compact_record, expand_record
from vulngym_t2.pipeline import _ProductionSession
from vulngym_t2.prompt_evidence import display_record
from vulngym_t2.revision_navigation import initial_snapshot_probe_read


SHA = "a" * 40
OTHER_SHA = "b" * 40


def size(value):
    return len(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")))


def search(paths=None):
    paths = paths or ["packages/an/arbitrarily/long/component/source.py"] * 30
    return {"id": "E0042", "kind": "tool", "tool": "search_code", "success": True,
            "arguments": {"commit": SHA, "query": "literal needle", "paths": None},
            "result": {"commit": SHA, "query": "literal needle", "paths": None,
                       "matches": [{"file": path, "line": 20 + index,
                                    "code": f"  result_{index} = literal_needle('字符\\\"');"}
                                   for index, path in enumerate(paths)],
                       "truncated": True, "complete": False, "context_truncated": True,
                       "candidate_files": 17003, "scanned_files": 17003,
                       "skipped": ["missing fixture file"], "skipped_count": 1,
                       "search_scope": "bounded lexical navigation only",
                       "limits": {"matches": 100, "unknown_future_limit": {"count": 7}}}}


class EvidenceContextTests(unittest.TestCase):
    def assert_roundtrip(self, original):
        before = copy.deepcopy(original)
        packed = compact_record(original)
        self.assertEqual(original, before)
        self.assertEqual(expand_record(packed), original)
        self.assertLessEqual(size(packed), size(original))
        self.assertEqual(compact_record(packed), packed)
        return packed

    def test_all_search_code_and_metadata_survive_path_factoring(self):
        original = display_record(search(), compact=True)
        packed = self.assert_roundtrip(original)
        self.assertIn("consecutive_file_groups", packed["result"]["matches"])
        self.assertGreater(size(original) - size(packed), 1000)
        for key, value in original["result"].items():
            if key != "matches":
                self.assertEqual(packed["result"][key], value)
        self.assertEqual(packed["id"], "E0042")
        self.assertEqual(packed["result"]["commit"], SHA)
        self.assertEqual(packed["result"]["complete"], False)

    def test_nonconsecutive_same_path_is_not_sorted_or_coalesced(self):
        paths = ["long/path/first.py"] * 12 + ["long/path/second.py"] * 12 + ["long/path/first.py"] * 12
        packed = self.assert_roundtrip(search(paths))
        groups = packed["result"]["matches"]["consecutive_file_groups"]
        self.assertEqual([group["file"] for group in groups],
                         ["long/path/first.py", "long/path/second.py", "long/path/first.py"])

    def test_unique_paths_use_ordered_columns_without_code_omission(self):
        original = search([f"p{index}.py" for index in range(30)])
        packed = self.assert_roundtrip(original)
        self.assertEqual(packed["result"]["matches"]["columns"], ["file", "line", "code"])
        self.assertEqual(packed["result"]["matches"]["rows"],
                         [[row["file"], row["line"], row["code"]] for row in original["result"]["matches"]])

    def test_history_preserves_every_parent_subject_and_incomplete_flag(self):
        original = {"id": "E0007", "tool": "search_history", "success": True,
                    "result": {"commit": SHA, "query": "literal", "shallow": True,
                               "negative_result_conclusive": False, "has_more": True,
                               "matches": [{"commit": str(index) * 40, "parents": [SHA, OTHER_SHA],
                                            "subject": f"Uninterpreted title {index}", "subject_truncated": bool(index % 2)}
                                           for index in range(1, 10)],
                               "limits": {"matches": 20}, "future_unknown_metadata": ["retained"]}}
        packed = self.assert_roundtrip(original)
        self.assertIsInstance(packed["result"]["matches"], dict)
        self.assertEqual(packed["result"]["future_unknown_metadata"], ["retained"])
        self.assertFalse(packed["result"]["negative_result_conclusive"])

    def test_local_ref_table_preserves_null_and_full_object_identity(self):
        original = {"id": "E0004", "tool": "list_refs", "success": True,
                    "result": {"refs": [{"name": f"refs/tags/fixture-{index}", "kind": "tag",
                                         "object_type": "blob", "object_id": SHA, "commit": None}
                                        for index in range(10)],
                               "prefix": None, "truncated": True,
                               "evidence_scope": "identities only; no safety proof"}}
        packed = self.assert_roundtrip(original)
        self.assertIsInstance(packed["result"]["refs"], dict)
        self.assertEqual(packed["result"]["refs"]["rows"][0][-1], None)

    def test_empty_and_small_lists_are_not_expanded_by_table_headers(self):
        for rows in ([], [{"file": "x", "line": 1, "code": ""}]):
            original = search()
            original["result"]["matches"] = rows
            self.assertEqual(self.assert_roundtrip(original), original)

    def test_unknown_or_incomplete_hit_schema_is_retained_without_repair(self):
        variants = [None, "unrecognized", {"file": "x", "code": "x"},
                    {"file": "x", "line": 1, "code": "x", "future_limit": "unknown"}]
        for row in variants:
            with self.subTest(row=row):
                original = search()
                original["result"]["matches"].append(row)
                self.assertEqual(self.assert_roundtrip(original), original)

    def test_failed_receipts_and_error_codes_are_kept_in_full(self):
        for target, key, value in (("record", "success", False), ("record", "error", "failure"),
                                   ("result", "error", "failure"), ("result", "error_code", "bounded_read_failed"),
                                   ("result", "ok", False), ("result", "success", False)):
            with self.subTest(key=key, target=target):
                original = search()
                (original if target == "record" else original["result"])[key] = value
                self.assertEqual(self.assert_roundtrip(original), original)

    def test_source_diff_inspection_and_advisory_never_enter_compression(self):
        for tool in ("read_file", "read_diff", "inspect_commit", "unknown_future_tool", None, []):
            original = search()
            original["tool"] = tool
            original["result"].update(text="source bytes\n\t", diff="-old\n+new",
                                      message="Full commit message", path="actual/source.py",
                                      start_line=100, end_line=101, has_more=True)
            self.assertEqual(self.assert_roundtrip(original), original)
        advisory = {"id": "E0002", "kind": "advisory", "text": "Full untrusted advisory", "truncated": True}
        self.assertEqual(self.assert_roundtrip(advisory), advisory)

    def test_long_numbered_source_retains_every_line_at_each_sha(self):
        for sha in (SHA, OTHER_SHA):
            rows = [{"line": index, "code": f"  exact source {index}: 字符"} for index in range(40, 140)]
            original = {"id": "E0024", "tool": "read_file", "success": True,
                        "result": {"commit": sha, "path": "src/helper.py", "start_line": 40, "end_line": 139,
                                   "lines": rows, "text": "\n".join(row["code"] for row in rows),
                                   "has_more": True, "truncated": True}}
            displayed = display_record(original, compact=True)
            self.assertEqual(self.assert_roundtrip(displayed), displayed)
            self.assertIn("139:   exact source 139: 字符", displayed["result"]["numbered_source"])

    def test_return_values_do_not_alias_input_nested_metadata_or_rows(self):
        for original in (search(), {"tool": "read_file", "result": {"text": "exact", "limits": [1]}}):
            before = copy.deepcopy(original)
            packed = compact_record(original)
            packed["result"]["new_key"] = "new"
            if "matches" in packed["result"]:
                expanded = expand_record(packed)
                expanded["result"]["matches"][0]["code"] = "changed"
            self.assertEqual(original, before)

    def test_decoder_does_not_guess_malformed_or_unknown_table_shapes(self):
        variants = [{}, [], None, False, 37, "unrecognized",
                    {"columns": ["file", "line", "code"], "rows": [["x", 1]]},
                    {"columns": ["file", "code", "line"], "rows": [["x", "x", 1]]},
                    {"columns": ["file", "line", "code"], "rows": [["x", 1, "x"]], "unknown": True},
                    {"consecutive_file_groups": [{"file": "x", "matches": []}]},
                    {"consecutive_file_groups": [{"file": "x", "matches": {}}]},
                    {"consecutive_file_groups": [{"file": "x", "matches": "unrecognized"}]}]
        for value in variants:
            with self.subTest(value=value):
                original = search()
                original["result"]["matches"] = value
                self.assertEqual(expand_record(original), original)

    def test_general_large_search_and_history_evidence_saves_a_read_sized_window(self):
        # Arbitrary paths and literal hits; no project, version or expected answer.
        records = [search([f"a/long/arbitrary/component/{index}/source.py"] * 30) for index in range(4)]
        for index, record in enumerate(records):
            record["id"] = f"E{index + 1:04d}"
        packed = [self.assert_roundtrip(record) for record in records]
        self.assertGreater(size(records) - size(packed), 4096)
        self.assertEqual([record["id"] for record in packed], [record["id"] for record in records])


class EvidenceContextControllerTests(unittest.TestCase):
    @staticmethod
    def client():
        return SimpleNamespace(response_mode="staged_tool", annotation_format="assessed_tool",
                               complete=Mock(side_effect=AssertionError("No model call is allowed")))

    def test_read_tool_keeps_raw_search_and_ref_lists_while_showing_reversible_tables(self):
        refs = {"refs": [{"name": f"refs/tags/fixture-{index}", "kind": "tag",
                          "object_type": "commit", "object_id": SHA, "commit": SHA}
                         for index in range(8)], "prefix": None, "truncated": True,
                "evidence_scope": "local identities only", "limits": {"refs": 8}}
        cases = [("search_code", {"commit": SHA, "query": "literal needle", "paths": None},
                  search()["result"], "matches"),
                 ("list_refs", {"limit": 8}, refs, "refs")]
        for tool, arguments, source, list_key in cases:
            with self.subTest(tool=tool):
                original = copy.deepcopy(source)
                repo = SimpleNamespace(call=Mock(return_value=source))
                client = self.client()
                session = _ProductionSession({}, client, repo, 12, 24)
                displayed = session.read_tool(tool, arguments)
                saved = session.evidence_by_id[displayed["id"]]
                self.assertIs(saved, session.result["evidence"][-1])
                self.assertIsInstance(displayed["result"][list_key], dict)
                self.assertIsInstance(saved["result"][list_key], list)
                self.assertEqual(saved["result"], original)
                self.assertEqual(expand_record(displayed), display_record(saved, compact=True))
                self.assertEqual(source, original)
                self.assertEqual(saved["arguments"], arguments)
                self.assertLess(size(displayed), size(display_record(saved, compact=True)))
                reused = session.read_tool(tool, arguments)
                self.assertEqual(reused["reused_evidence_ref"], saved["id"])
                self.assertEqual(session.result["tool_calls"], 1)
                self.assertEqual(session.result["model_calls"], 0)
                self.assertEqual(session.result["fields"], {})
                repo.call.assert_called_once_with(tool, arguments)
                client.complete.assert_not_called()

    def test_snapshot_read_flow_navigates_raw_hits_after_both_searches_are_compacted(self):
        query, path = "RecordProcessor", "src/worker.py"
        mentions = [{"file": "src/adapter.py", "line": index + 1,
                     "code": f"result_{index} = RecordProcessor(value)"} for index in range(12)]
        declaration = {"file": path, "line": 120, "code": "class RecordProcessor(Base):"}

        def read(tool, arguments):
            if tool == "inspect_commit":
                return {"commit": OTHER_SHA, "parents": [], "message": "Uninterpreted fixture history"}
            if tool == "search_code":
                matches = copy.deepcopy(mentions)
                if arguments["commit"] == OTHER_SHA:
                    matches.append(copy.deepcopy(declaration))
                return {"commit": arguments["commit"], "query": query, "matches": matches,
                        "complete": True, "truncated": False, "limits": {"matches": 100}}
            self.assertEqual(tool, "read_file")
            self.assertEqual(arguments, {"commit": OTHER_SHA, "path": path,
                                         "start_line": 112, "end_line": 191})
            rows = [{"line": line, "code": declaration["code"] if line == 120 else f"# exact source {line}"}
                    for line in range(arguments["start_line"], arguments["end_line"] + 1)]
            return {**arguments, "total_lines": 250, "lines": rows,
                    "text": "\n".join(row["code"] for row in rows), "has_more": True, "truncated": False}

        repo, client = SimpleNamespace(call=Mock(side_effect=read)), self.client()
        session = _ProductionSession({}, client, repo, 12, 24)
        inspected = session.read_tool("inspect_commit", {"commit": OTHER_SHA})
        primary = session.read_tool("search_code", {"commit": SHA, "query": query})
        self.assertIsInstance(primary["result"]["matches"], dict)
        session.messages = [{"role": "user", "content": json.dumps({"tool_results": [inspected, primary]})}]

        with patch("vulngym_t2.revision_navigation.initial_snapshot_probe_read",
                   wraps=initial_snapshot_probe_read) as selector:
            session.probe_initial_snapshot()
        selector.assert_called_once()
        actual, seed = selector.call_args.args
        self.assertIs(actual, session.evidence_by_id[actual["id"]])
        self.assertIsInstance(actual["result"]["matches"], list)
        self.assertEqual(actual["result"]["matches"], mentions + [declaration])
        self.assertEqual(seed["arguments"], {"commit": OTHER_SHA, "query": query})

        model_rows = json.loads(session.messages[-1]["content"])["tool_results"]
        self.assertEqual([row["tool"] for row in model_rows], ["search_code", "read_file"])
        self.assertIsInstance(model_rows[0]["result"]["matches"], dict)
        for shown in model_rows:
            raw = session.evidence_by_id[shown["id"]]
            self.assertEqual(expand_record(shown), display_record(raw, compact=True))
        self.assertIn("120: class RecordProcessor(Base):", model_rows[1]["result"]["numbered_source"])
        self.assertEqual((model_rows[1]["result"]["start_line"], model_rows[1]["result"]["end_line"]),
                         (112, 191))
        self.assertEqual(session.result["fields"], {})
        self.assertEqual(session.result["model_calls"], 0)
        self.assertEqual(session.result["tool_calls"], 4)
        self.assertEqual(repo.call.call_count, 4)
        self.assertEqual([action["action"] for action in session.result["actions"]
                          if action["action"].startswith("initial_snapshot_")],
                         ["initial_snapshot_search", "initial_snapshot_source"])
        self.assertFalse(any(action.get("semantic_approval") is True for action in session.result["actions"]
                             if action["action"].startswith("initial_snapshot_")))
        session.probe_initial_snapshot()
        self.assertEqual(repo.call.call_count, 4)
        client.complete.assert_not_called()


if __name__ == "__main__":
    unittest.main()
