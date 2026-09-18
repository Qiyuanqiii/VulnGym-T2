"""Bounded literal-search recovery keeps real hits, not invented source."""
import copy
import json
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

from vulngym_t2.evidence_context import expand_record
from vulngym_t2.prompt_evidence import bounded_navigation_result
from vulngym_t2.pipeline import _MAX_RESULT_CHARS, _ProductionSession
from vulngym_t2.repository import MAX_MATCHES, MAX_SEARCH_BYTES, MAX_TEXT_CHARS, RepoReader
from vulngym_t2.revision_navigation import initial_snapshot_probe_read


SHA = "b" * 40
QUERY = "RecordProcessor"
DECLARATION = {"file": "src/worker.py", "line": 152, "code": "class RecordProcessor(Base):"}


def encoded_record(path, line, code):
    if isinstance(code, str):
        code = code.encode("utf-8")
    return f"{SHA}:{path}\0{line}\0".encode("utf-8") + code + b"\n"


def reader_for(records):
    reader = RepoReader.__new__(RepoReader)
    reader.resolve_commit = Mock(return_value=SHA)
    reader._files = Mock(return_value=["docs/index.json", "src/worker.py"])
    reader._git = SimpleNamespace(timeout_seconds=10, _run=Mock(return_value=SimpleNamespace(
        returncode=0, stderr=b"", stdout=b"".join(records))))
    return reader


def search_result(matches):
    return {"commit": SHA, "query": QUERY, "matches": matches, "complete": True,
            "truncated": False, "paths": None, "skipped": [], "skipped_count": 0}


def size(value):
    return len(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")))


class SearchOversizedLineTests(unittest.TestCase):
    def test_huge_matching_line_keeps_coordinate_and_later_complete_source_hit(self):
        huge = QUERY + "x" * MAX_TEXT_CHARS
        reader = reader_for([encoded_record("docs/index.json", 1, huge),
                             encoded_record(**{"path": DECLARATION["file"],
                                               "line": DECLARATION["line"], "code": DECLARATION["code"]})])
        result = reader.search_code(SHA, QUERY)
        self.assertEqual(result["matches"], [DECLARATION])
        self.assertEqual(result["skipped"], [{"path": "docs/index.json", "line": 1,
            "error": "matched_line_display_limit", "omitted_chars": len(huge)}])
        self.assertEqual(result["skipped_count"], 1)
        self.assertTrue(result["truncated"])
        self.assertFalse(result["complete"])
        self.assertNotIn("code", result["skipped"][0])
        self.assertNotIn(huge, json.dumps(result))
        self.assertEqual(reader._git._run.call_count, 1)
        args, options = reader._git._run.call_args
        self.assertIn("--max-count=100", args[0])
        self.assertEqual(options["max_stdout_bytes"], MAX_SEARCH_BYTES)

    def test_cumulative_text_limit_skips_nonfitting_line_without_expanding_text_budget(self):
        remaining = len(DECLARATION["code"])
        prefix = QUERY + "x" * (MAX_TEXT_CHARS - remaining - len(QUERY))
        reader = reader_for([encoded_record("docs/index.json", 1, prefix),
                             encoded_record("docs/index.json", 2, QUERY * 10),
                             encoded_record("src/worker.py", 152, DECLARATION["code"])])
        result = reader.search_code(SHA, QUERY)
        self.assertEqual(result["matches"][-1], DECLARATION)
        self.assertEqual(sum(len(hit["code"]) for hit in result["matches"]), MAX_TEXT_CHARS)
        self.assertEqual(result["skipped"][0]["line"], 2)
        self.assertFalse(result["complete"])

    def test_omitted_and_undecodable_hits_consume_original_match_processing_limit(self):
        for bad_code in (QUERY + "x" * MAX_TEXT_CHARS, b"RecordProcessor\xff"):
            with self.subTest(kind=type(bad_code).__name__):
                reader = reader_for([encoded_record("docs/index.json", n, bad_code)
                                     for n in range(1, MAX_MATCHES + 1)]
                                    + [encoded_record("src/worker.py", 152, DECLARATION["code"])])
                result = reader.search_code(SHA, QUERY)
                self.assertEqual(result["matches"], [])
                self.assertEqual(result["skipped_count"], MAX_MATCHES)
                self.assertEqual(len(result["skipped"]), 20)
                self.assertFalse(result["complete"])
                self.assertTrue(result["truncated"])

    def test_hundredth_actual_hit_is_retained_but_search_is_conservatively_incomplete(self):
        records = [encoded_record("docs/index.json", n, QUERY) for n in range(1, MAX_MATCHES)]
        records.append(encoded_record("src/worker.py", 152, DECLARATION["code"]))
        result = reader_for(records).search_code(SHA, QUERY)
        self.assertEqual(len(result["matches"]), MAX_MATCHES)
        self.assertEqual(result["matches"][-1], DECLARATION)
        self.assertFalse(result["complete"])
        self.assertTrue(result["truncated"])

    def test_ordinary_short_search_stays_complete_and_preserves_exact_code(self):
        code = "\tclass RecordProcessor(Base):  # 字节"
        result = reader_for([encoded_record("src/worker.py", 152, code + "\r")]).search_code(SHA, QUERY)
        self.assertEqual(result["matches"], [{**DECLARATION, "code": code}])
        self.assertTrue(result["complete"])
        self.assertFalse(result["truncated"])
        self.assertEqual(result["skipped"], [])


class SearchDeclarationDisplayTests(unittest.TestCase):
    def test_four_k_display_retains_complete_original_declaration_after_many_mentions(self):
        mentions = [{"file": "docs/examples.txt", "line": n,
                     "code": f'"{QUERY} example {n}"' + "x" * 90} for n in range(1, 73)]
        value = search_result(mentions + [copy.deepcopy(DECLARATION)])
        original = copy.deepcopy(value)
        shown = bounded_navigation_result(value, 4000)
        self.assertLessEqual(size(shown), 4000)
        self.assertEqual(shown["matches"][0], DECLARATION)
        self.assertEqual(shown["matches"][1:], mentions[:len(shown["matches"]) - 1])
        self.assertTrue(shown["truncated"])
        self.assertTrue(shown["context_truncated"])
        self.assertFalse(shown["complete"])
        self.assertEqual(value, original)

    def test_import_comment_string_return_type_and_different_name_do_not_get_priority(self):
        mentions = [{"file": "src/adapter.py", "line": n, "code": code} for n, code in enumerate((
            "from old import RecordProcessor", "# class RecordProcessor:", '"class RecordProcessor:"',
            "def load_record() -> RecordProcessor:", "class RecordProcessorExtra:",
            "    return RecordProcessor(value)"), 1)]
        filler = [{"file": "docs/examples.txt", "line": n, "code": QUERY + "x" * 90}
                  for n in range(10, 80)]
        shown = bounded_navigation_result(search_result(mentions + filler + [DECLARATION]), 1500)
        self.assertEqual(shown["matches"][0], DECLARATION)
        self.assertEqual(shown["matches"][1:1 + len(mentions)], mentions)

    def test_no_reordering_when_result_fits_and_no_fabricated_snippet_when_hit_cannot_fit(self):
        value = search_result([{"file": "docs/index.json", "line": 1, "code": QUERY}, DECLARATION])
        self.assertEqual(bounded_navigation_result(value, 4000), value)
        value = search_result([{**DECLARATION, "code": DECLARATION["code"] + "x" * 5000}])
        shown = bounded_navigation_result(value, 4000)
        self.assertEqual(shown["matches"], [])
        self.assertFalse(shown["complete"])

    def test_multiple_real_declarations_remain_multiple_and_truncated_is_never_unique(self):
        other = {**DECLARATION, "file": "src/other.py", "line": 25}
        value = search_result([{"file": "docs/index.json", "line": 1, "code": QUERY + "x" * 5000},
                               DECLARATION, other])
        shown = bounded_navigation_result(value, 4000)
        self.assertEqual(shown["matches"], [DECLARATION, other])
        seed = {"arguments": {"commit": SHA, "query": QUERY}, "evidence_refs": ["E0001", "E0002"]}
        receipt = {"id": "E0003", "tool": "search_code", "success": True, "result": shown}
        self.assertIsNone(initial_snapshot_probe_read(receipt, seed))

    def test_existing_failure_and_omission_metadata_survive_search_display(self):
        value = search_result([{"file": "docs/index.json", "line": 1, "code": QUERY + "x" * 5000}, DECLARATION])
        value.update(error="actual_reader_failure", success=False,
                     skipped=[{"path": "docs/index.json", "line": 2,
                               "error": "matched_line_display_limit", "omitted_chars": 9000}], skipped_count=1)
        shown = bounded_navigation_result(value, 4000)
        self.assertEqual(shown["error"], value["error"])
        self.assertIs(shown["success"], False)
        self.assertEqual(shown["skipped"], value["skipped"])
        self.assertFalse(shown["complete"])

    def test_reader_to_display_preserves_late_hit_and_omission_without_automatic_read(self):
        records = [encoded_record("docs/index.json", n, QUERY + "x" * 80) for n in range(1, 73)]
        records[2] = encoded_record("docs/index.json", 3, QUERY + "x" * MAX_TEXT_CHARS)
        records.append(encoded_record("src/worker.py", 152, DECLARATION["code"]))
        raw = reader_for(records).search_code(SHA, QUERY)
        shown = bounded_navigation_result(raw, 4000)
        self.assertEqual(shown["matches"][0], DECLARATION)
        self.assertEqual(shown["skipped"][0]["line"], 3)
        self.assertLessEqual(size(shown), 4000)
        self.assertFalse(shown["complete"])
        seed = {"arguments": {"commit": SHA, "query": QUERY}, "evidence_refs": ["E0001", "E0002"]}
        receipt = {"id": "E0003", "tool": "search_code", "success": True, "result": shown}
        self.assertIsNone(initial_snapshot_probe_read(receipt, seed))


class SearchControllerDisplayTests(unittest.TestCase):
    def test_real_reader_to_controller_keeps_late_declaration_at_ordinary_and_navigation_caps(self):
        for allowance in (None, 4000):
            with self.subTest(allowance=allowance):
                records = [encoded_record("docs/index.json", n, QUERY + "x" * 190)
                           for n in range(1, 101)]
                records[2] = encoded_record("docs/index.json", 3, QUERY + "x" * MAX_TEXT_CHARS)
                records[72] = encoded_record("src/worker.py", 152, DECLARATION["code"])
                reader = reader_for(records)
                raw = reader.search_code(SHA, QUERY)
                self.assertGreater(size(raw), _MAX_RESULT_CHARS)
                reader._git._run.reset_mock()
                client = SimpleNamespace(response_mode="staged_tool", annotation_format="assessed_tool")
                session = _ProductionSession({}, client, reader, 12, 24)
                options = {} if allowance is None else {"navigation_display_limit": allowance}
                arguments = {"commit": SHA, "query": QUERY}
                displayed = session.read_tool("search_code", arguments, automatic=allowance is not None, **options)
                saved = session.result["evidence"][-1]
                self.assertTrue(saved["success"])
                # The prompt factors repeated search structure, never the raw
                # reader receipt used by navigation and completeness checks.
                self.assertIsInstance(saved["result"]["matches"], list)
                self.assertIsInstance(displayed["result"]["matches"], dict)
                self.assertEqual(saved["result"], expand_record(displayed)["result"])
                self.assertEqual(saved["result"]["commit"], SHA)
                self.assertEqual(saved["result"]["query"], QUERY)
                self.assertEqual(saved["result"]["matches"][0], DECLARATION)
                self.assertLessEqual(size(saved["result"]), allowance or _MAX_RESULT_CHARS)
                self.assertTrue(saved["result"]["truncated"])
                self.assertFalse(saved["result"]["complete"])
                self.assertEqual(saved["result"]["skipped"][0]["line"], 3)
                self.assertEqual(session.result["tool_calls"], 1)
                self.assertEqual(session.result["model_calls"], 0)
                self.assertEqual(session.result["fields"], {})
                seed = {"arguments": arguments, "evidence_refs": ["E0008", "E0009"]}
                self.assertIsNone(initial_snapshot_probe_read(saved, seed))
                reused = session.read_tool("search_code", arguments, **options)
                self.assertEqual(reused["reused_evidence_ref"], saved["id"])
                self.assertEqual(session.result["tool_calls"], 1)
                self.assertEqual(reader._git._run.call_count, 1)

    def test_ordinary_search_failure_flag_survives_new_display_branch(self):
        value = search_result([{"file": "docs/index.json", "line": 1, "code": QUERY + "x" * 17000},
                               DECLARATION])
        value.update(error="real_failure", success=False)
        client = SimpleNamespace(response_mode="staged_tool", annotation_format="assessed_tool")
        session = _ProductionSession({}, client, SimpleNamespace(call=Mock(return_value=value)), 12, 24)
        displayed = session.read_tool("search_code", {"commit": SHA, "query": QUERY})
        self.assertIs(displayed["success"], False)
        self.assertEqual(displayed["result"]["error"], "real_failure")
        self.assertIs(displayed["result"]["success"], False)
        self.assertFalse(displayed["result"]["complete"])
        self.assertEqual(session.result["fields"], {})


if __name__ == "__main__":
    unittest.main()
