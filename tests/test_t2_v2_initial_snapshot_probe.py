"""First-source snapshot probes select real read directions, never annotations."""
import copy
import unittest

from vulngym_t2.revision_navigation import initial_snapshot_probe_read, initial_snapshot_probe_seed


PRIMARY, ALTERNATIVE, OTHER = "a" * 40, "b" * 40, "c" * 40
QUERY = "class RecordProcessor"
PATH = "src/worker.py"


def inspected(identity="E0002", commit=ALTERNATIVE):
    return {"id": identity, "tool": "inspect_commit", "success": True,
        "arguments": {"commit": commit}, "result": {"commit": commit, "parents": [OTHER],
            "message": "Unrelated maintenance summary", "truncated": True}}


def empty(identity="E0003", commit=PRIMARY, query=QUERY):
    return {"id": identity, "tool": "search_code", "success": True,
        "arguments": {"commit": commit, "query": query},
        "result": {"commit": commit, "query": query, "matches": [], "complete": True, "truncated": False}}


def receipts():
    return [{"id": "E0001", "kind": "repository", "result": {"head": None, "shallow": False}},
            inspected(), empty()]


def found():
    row = empty("E0004", ALTERNATIVE)
    row["result"]["matches"] = [{"file": PATH, "line": 120, "code": "class RecordProcessor(Base):"}]
    return row


class InitialSnapshotSeedTests(unittest.TestCase):
    def test_exact_observed_query_and_inspected_sha_without_parent_inference_or_mutation(self):
        value = receipts()
        original = copy.deepcopy(value)
        seed = initial_snapshot_probe_seed(value)
        self.assertEqual(seed, {"arguments": {"commit": ALTERNATIVE, "query": QUERY},
                                "evidence_refs": ["E0003", "E0002"]})
        self.assertEqual(value, original)
        self.assertNotEqual(seed["arguments"]["commit"], OTHER)

    def test_an_actual_source_read_at_any_immutable_sha_closes_the_first_source_aid(self):
        for sha in (PRIMARY, ALTERNATIVE, OTHER):
            for encoding in ("text", "lines"):
                with self.subTest(sha=sha, encoding=encoding):
                    value = receipts()
                    data = {"commit": sha, "path": PATH, "start_line": 1, "end_line": 1}
                    data[encoding] = "code" if encoding == "text" else [{"line": 1, "code": "code"}]
                    value.append({"id": "E0005", "tool": "read_file", "success": True, "result": data})
                    self.assertIsNone(initial_snapshot_probe_seed(value))

    def test_failed_or_empty_primary_source_is_not_successful_visible_source(self):
        for success, text in ((False, "code"), (True, "")):
            value = receipts()
            value.append({"id": "E0005", "tool": "read_file", "success": success,
                "arguments": {"commit": PRIMARY, "path": PATH},
                "result": {"commit": PRIMARY, "path": PATH, "start_line": 1, "end_line": 1, "text": text}})
            self.assertIsNotNone(initial_snapshot_probe_seed(value))

    def test_failed_partial_nonempty_or_mismatched_search_is_not_a_complete_empty_declaration_query(self):
        mutations = {
            "failed": lambda row: row.update(success=False),
            "outer error": lambda row: row.update(error="failed"),
            "inner error": lambda row: row["result"].update(error="failed"),
            "inner success": lambda row: row["result"].update(success=False),
            "inner ok": lambda row: row["result"].update(ok=False),
            "not complete": lambda row: row["result"].update(complete=False),
            "missing complete": lambda row: row["result"].pop("complete"),
            "truncated": lambda row: row["result"].update(truncated=True),
            "context truncated": lambda row: row["result"].update(context_truncated=True),
            "outer truncated": lambda row: row.update(truncated=True),
            "nonempty": lambda row: row["result"].update(matches=[{"code": "a mention"}]),
            "matches type": lambda row: row["result"].update(matches=None),
            "result sha": lambda row: row["result"].update(commit=OTHER),
            "result query": lambda row: row["result"].update(query="class OtherProcessor"),
            "alias": lambda row: row["arguments"].update(commit="HEAD"),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                value = receipts()
                mutate(value[-1])
                self.assertIsNone(initial_snapshot_probe_seed(value))

    def test_unknown_failed_or_same_primary_inspection_never_invents_an_alternative(self):
        for mutate in (lambda row: row.update(success=False), lambda row: row["result"].update(error="failed"),
                       lambda row: row["result"].update(commit="HEAD"),
                       lambda row: row["result"].update(commit=PRIMARY), lambda row: row.update(tool="list_refs")):
            value = receipts()
            mutate(value[1])
            self.assertIsNone(initial_snapshot_probe_seed(value))

    def test_any_attempt_at_the_alternative_prevents_repeating_that_snapshot(self):
        for tool in ("read_file", "search_code"):
            for side in ("arguments", "result"):
                with self.subTest(tool=tool, side=side):
                    value = receipts()
                    value.append({"id": "E0005", "tool": tool, "success": False, side: {"commit": ALTERNATIVE}})
                    self.assertIsNone(initial_snapshot_probe_seed(value))

    def test_only_declaration_or_simple_identifier_queries_are_reused_never_generated_from_prose(self):
        for query in ("worker.py", "class RecordProcessor: pass", "class RecordProcessor\nrun()",
                      "../worker", "class .*", "class ", "def " + "a" * 129,
                      " RecordProcessor", "RecordProcessor ", "RecordProcessor|Other", "RecordProcessor.*",
                      "RecordProcessor\x00", "RecordProcessor\n", '"RecordProcessor"', "process record",
                      "a" * 129):
            value = receipts()
            value[-1] = empty(query=query)
            self.assertIsNone(initial_snapshot_probe_seed(value))
        value = receipts()
        value[-1].update(tool="list_files", result={"commit": PRIMARY, "files": [], "total_files": 0})
        self.assertIsNone(initial_snapshot_probe_seed(value))

    def test_actual_empty_bare_identifier_is_replayed_verbatim_with_original_scope(self):
        for query in ("RecordProcessor", "process_record", "$processRecord", "a" * 128):
            with self.subTest(query=query):
                value = receipts()
                value[-1] = empty(query=query)
                value[-1]["arguments"]["paths"] = ["src/handlers"]
                value[-1]["result"]["paths"] = ["src/handlers"]
                original = copy.deepcopy(value)
                seed = initial_snapshot_probe_seed(value)
                self.assertEqual(seed, {"arguments": {"commit": ALTERNATIVE, "query": query,
                    "paths": ["src/handlers"]}, "evidence_refs": ["E0003", "E0002"]})
                seed["arguments"]["paths"].append("src/other.py")
                self.assertEqual(value, original)

    def test_bare_identifier_still_requires_complete_search_and_an_untried_snapshot(self):
        value = receipts()
        value[-1] = empty(query="process_record")
        for mutate in (
            lambda rows: rows[-1]["result"].update(complete=False,
                skipped=[{"path": "missing", "error": "source_path_unavailable"}], skipped_count=1),
            lambda rows: rows[-1]["result"].update(truncated=True),
            lambda rows: rows[-1]["result"].update(matches=[{"file": PATH, "line": 1, "code": "def process_record():"}]),
            lambda rows: rows.append({"id": "E0005", "tool": "search_code", "success": False,
                "arguments": {"commit": ALTERNATIVE}}),
            lambda rows: rows.append({"id": "E0005", "tool": "read_file", "success": True,
                "result": {"commit": PRIMARY, "path": PATH, "start_line": 1, "end_line": 1, "text": "code"}}),
        ):
            changed = copy.deepcopy(value)
            mutate(changed)
            self.assertIsNone(initial_snapshot_probe_seed(changed))

    def test_reference_only_bare_search_probes_without_declaring_definition_absent(self):
        value = receipts()
        value[-1] = empty(query="RecordProcessor")
        value[-1]["result"]["matches"] = [
            {"file": PATH, "line": index + 1, "code": code}
            for index, code in enumerate(("from old import RecordProcessor",
                '"RecordProcessor"', "def load_record() -> RecordProcessor:",
                "    return RecordProcessor(value)"))]
        original = copy.deepcopy(value)
        self.assertEqual(initial_snapshot_probe_seed(value), {
            "arguments": {"commit": ALTERNATIVE, "query": "RecordProcessor"},
            "evidence_refs": ["E0003", "E0002"]})
        self.assertEqual(value, original)

    def test_partial_malformed_or_out_of_scope_reference_sets_do_not_seed_probe(self):
        value = receipts()
        value[-1] = empty(query="RecordProcessor")
        value[-1]["arguments"]["paths"] = ["src"]
        value[-1]["result"]["matches"] = [{"file": PATH, "line": 1,
            "code": "from old import RecordProcessor"}]
        for update in ({"file": "../outside"}, {"file": "other/file.py"},
                       {"line": True}, {"line": 0}, {"code": None},
                       {"code": "RecordProcessor\nclass Other:"}, {"code_omitted": True},
                       {"truncated": True}):
            with self.subTest(update=update):
                changed = copy.deepcopy(value)
                changed[-1]["result"]["matches"][0].update(update)
                self.assertIsNone(initial_snapshot_probe_seed(changed))
        value[-1]["result"]["complete"] = False
        self.assertIsNone(initial_snapshot_probe_seed(value))

    def test_valid_query_whitespace_and_path_scope_are_preserved_without_input_aliasing(self):
        value = receipts()
        value[-1] = empty(query="async  def\tprocess_record")
        value[-1]["arguments"]["paths"] = ["src/handlers", "src/legacy.py"]
        value[-1]["result"]["paths"] = ["src/handlers", "src/legacy.py"]
        seed = initial_snapshot_probe_seed(value)
        self.assertEqual(seed["arguments"]["query"], value[-1]["arguments"]["query"])
        self.assertEqual(seed["arguments"]["paths"], ["src/handlers", "src/legacy.py"])
        seed["arguments"]["paths"].append("src/extra.py")
        self.assertEqual(value[-1]["arguments"]["paths"], ["src/handlers", "src/legacy.py"])
        value[-1]["arguments"]["paths"] = None
        value[-1]["result"]["paths"] = None
        self.assertIsNone(initial_snapshot_probe_seed(value)["arguments"]["paths"])

    def test_unsafe_scopes_malformed_or_ambiguous_receipts_are_rejected(self):
        for paths in (["../outside"], [":(glob)**"], ["src//file"], ["C:/outside"], [], "src", ["src"] * 9):
            value = receipts()
            value[-1]["arguments"]["paths"] = paths
            self.assertIsNone(initial_snapshot_probe_seed(value))
        for value in (None, {}, [{}], receipts() + [copy.deepcopy(receipts()[0])], receipts() * 100):
            self.assertIsNone(initial_snapshot_probe_seed(value))
        value = receipts()
        value[-1]["id"] = "not_a_receipt"
        self.assertIsNone(initial_snapshot_probe_seed(value))

    def test_candidate_order_is_observed_order_not_commit_message_or_parent_status(self):
        value = receipts()
        value.insert(1, inspected("E0006", OTHER))
        seed = initial_snapshot_probe_seed(value)
        self.assertEqual(seed["arguments"]["commit"], OTHER)
        self.assertEqual(seed["evidence_refs"], ["E0003", "E0006"])


class InitialSnapshotReadTests(unittest.TestCase):
    def test_bare_identifier_reads_only_a_unique_same_name_declaration_among_mentions(self):
        for query, code in (("RecordProcessor", "class RecordProcessor(Base):"),
                            ("process_record", "async def process_record(value):"),
                            ("processRecord", "export function processRecord(value) {"),
                            ("processRecord", "func processRecord(value string) {"),
                            ("processRecord", "const processRecord = (value) => value;")):
            with self.subTest(query=query):
                value = receipts()
                value[-1] = empty(query=query)
                seed = initial_snapshot_probe_seed(value)
                row = empty("E0004", ALTERNATIVE, query=query)
                row["result"]["matches"] = [
                    {"file": "src/adapter.py", "line": 10 + index, "code": mention}
                    for index, mention in enumerate((f"from old import {query}", f'"{query}"',
                        f"def load_record() -> {query}:", f"    return {query}(value)"))]
                row["result"]["matches"].append({"file": PATH, "line": 120, "code": code})
                self.assertEqual(initial_snapshot_probe_read(row, seed), {
                    "arguments": {"commit": ALTERNATIVE, "path": PATH, "start_line": 112, "end_line": 191},
                    "anchor_line": 120})

    def test_bare_identifier_usage_only_hits_leave_search_receipt_without_fabricating_source(self):
        value = receipts()
        value[-1] = empty(query="RecordProcessor")
        seed = initial_snapshot_probe_seed(value)
        row = empty("E0004", ALTERNATIVE, query="RecordProcessor")
        row["result"]["matches"] = [{"file": PATH, "line": 10 + index, "code": code}
            for index, code in enumerate(("from old import RecordProcessor", "# class RecordProcessor:",
                '"class RecordProcessor:"', '"""class RecordProcessor: example"""',
                "def load_record() -> RecordProcessor:", "    return RecordProcessor(value)",
                "class RecordProcessorExtra:", "RecordProcessor: Optional[type] = None"))]
        original = copy.deepcopy(row)
        self.assertIsNone(initial_snapshot_probe_read(row, seed))
        self.assertEqual(row, original)

    def test_multiple_same_name_bare_declarations_are_ambiguous_even_when_kinds_differ(self):
        value = receipts()
        value[-1] = empty(query="RecordProcessor")
        row = empty("E0004", ALTERNATIVE, query="RecordProcessor")
        row["result"]["matches"] = [
            {"file": PATH, "line": 10, "code": "class RecordProcessor(Base):"},
            {"file": "src/other.py", "line": 20, "code": "def RecordProcessor(value):"}]
        self.assertIsNone(initial_snapshot_probe_read(row, initial_snapshot_probe_seed(value)))

    def test_unique_real_declaration_produces_one_80_line_window_with_actual_anchor_and_no_mutation(self):
        seed, row = initial_snapshot_probe_seed(receipts()), found()
        original = copy.deepcopy((seed, row))
        self.assertEqual(initial_snapshot_probe_read(row, seed), {
            "arguments": {"commit": ALTERNATIVE, "path": PATH, "start_line": 112, "end_line": 191},
            "anchor_line": 120})
        self.assertEqual((seed, row), original)

    def test_python_async_javascript_and_go_declarations_keep_the_original_kind_and_name(self):
        for query, code in (("def process_record", "    def process_record(value):"),
                            ("async def process_record", "async def process_record(value):"),
                            ("function processRecord", "export function processRecord(value) {"),
                            ("func processRecord", "func processRecord(value string) {"),
                            (QUERY, "export class RecordProcessor extends Base {")):
            with self.subTest(query=query):
                values = receipts()
                values[-1] = empty(query=query)
                seed = initial_snapshot_probe_seed(values)
                row = found()
                row["arguments"]["query"] = row["result"]["query"] = query
                row["result"]["matches"][0]["code"] = code
                self.assertIsNotNone(initial_snapshot_probe_read(row, seed))

    def test_mentions_comments_strings_and_wrong_kind_are_not_declaration_hits(self):
        for code in ('"class RecordProcessor"', "# class RecordProcessor", "from old import RecordProcessor",
                     "def RecordProcessor():  # class RecordProcessor", "class RecordProcessorExtra:"):
            row = found()
            row["result"]["matches"][0]["code"] = code
            self.assertIsNone(initial_snapshot_probe_read(row, initial_snapshot_probe_seed(receipts())))

    def test_failed_truncated_or_other_sha_query_and_scope_results_do_not_create_reads(self):
        mutations = (lambda row: row.update(success=False), lambda row: row["result"].update(error="failed"),
                     lambda row: row["result"].update(commit=PRIMARY), lambda row: row["result"].update(query="class Other"),
                     lambda row: row["result"].update(complete=False), lambda row: row["result"].update(truncated=True),
                     lambda row: row["result"].update(context_truncated=True), lambda row: row["result"].update(paths=["other"]),
                     lambda row: row["result"].update(matches=[]), lambda row: row["result"].update(matches=[{}]))
        for mutate in mutations:
            row = found()
            mutate(row)
            self.assertIsNone(initial_snapshot_probe_read(row, initial_snapshot_probe_seed(receipts())))

    def test_multiple_declarations_or_conflicting_same_coordinate_bytes_are_ambiguous(self):
        for change in ({"file": "src/other.py"}, {"line": 140}, {"code": "class RecordProcessor(OtherBase):"}):
            row = found()
            row["result"]["matches"].append({**row["result"]["matches"][0], **change})
            self.assertIsNone(initial_snapshot_probe_read(row, initial_snapshot_probe_seed(receipts())))
        row = found()
        row["result"]["matches"].append(copy.deepcopy(row["result"]["matches"][0]))
        self.assertIsNotNone(initial_snapshot_probe_read(row, initial_snapshot_probe_seed(receipts())))

    def test_paths_lines_and_seed_coordinates_cannot_escape_or_expand_bounds(self):
        seed = initial_snapshot_probe_seed(receipts())
        for change in ({"file": "../outside.py"}, {"file": ":(glob)**"}, {"file": "C:/outside.py"},
                       {"line": 0}, {"line": True}, {"line": "120"}, {"line": 99_999_930},
                       {"code": "class RecordProcessor:\nexecute()"}):
            row = found()
            row["result"]["matches"][0].update(change)
            self.assertIsNone(initial_snapshot_probe_read(row, seed))
        for invalid in (None, {}, {"arguments": []}, {"arguments": seed["arguments"], "evidence_refs": ["E0002"]}):
            self.assertIsNone(initial_snapshot_probe_read(found(), invalid))
        for line, expected in ((1, (1, 72)), (99_999_929, (99_999_921, 100_000_000))):
            row = found()
            row["result"]["matches"][0]["line"] = line
            request = initial_snapshot_probe_read(row, seed)
            self.assertEqual((request["arguments"]["start_line"], request["arguments"]["end_line"]), expected)

    def test_original_explicit_scope_is_honored_for_both_search_and_read(self):
        value = receipts()
        value[-1]["arguments"]["paths"] = ["src"]
        seed = initial_snapshot_probe_seed(value)
        row = found()
        row["result"]["paths"] = ["src"]
        self.assertIsNotNone(initial_snapshot_probe_read(row, seed))
        row["result"]["matches"][0]["file"] = "other/worker.py"
        self.assertIsNone(initial_snapshot_probe_read(row, seed))


if __name__ == "__main__":
    unittest.main()
