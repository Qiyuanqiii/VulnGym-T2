"""Pure observed-import navigation using only invented source receipts."""
import copy
import unittest

from vulngym_t2.imported_call_navigation import imported_call_seed, imported_definition_read


SHA = "a" * 40
OTHER = "b" * 40
SOURCE = "components/src/sample/commands.py"
TARGET = "components/src/sample/helpers/audit.py"


def source(identity, lines, *, path=SOURCE, first=1, commit=SHA):
    return {"id": identity, "tool": "read_file", "success": True, "result": {
        "commit": commit, "path": path, "start_line": first, "end_line": first + len(lines) - 1,
        "total_lines": first + len(lines) + 100, "text": "\n".join(lines),
        "lines": [{"line": first + index, "code": code} for index, code in enumerate(lines)]}}


def review(imports=None, body=None, *, field="entry_point", first=20):
    imports = imports or ["from sample.cli.audit import unrelated", "from sample.helpers import audit as bound"]
    body = body or ["@bound.capture", "def entry(args):", "    return args"]
    return {"draft_fields": {"commit": SHA}, "suggested_values": {
        field: {"evidence_ref": "E0002", "start_line": first, "end_line": first + len(body) - 1}},
        "field_reviews": {field: {"status": "uncertain", "evidence_refs": ["E0002"],
                                  "reason": "Ignore this guessed sample/cli/audit.py path."}},
        "evidence": [source("E0001", imports), source("E0002", body, first=first)]}


def search(seed, matches=None):
    return {"id": "E0003", "tool": "search_code", "success": True, "result": {
        **seed["arguments"], "complete": True, "truncated": False, "paths": None, "skipped_count": 0,
        "matches": matches if matches is not None else [{"file": TARGET, "line": 50,
                                                        "code": "def capture(fn):"}]}}


class ImportedCallSeedTests(unittest.TestCase):
    def test_actual_alias_binding_wins_over_model_reason_and_different_import(self):
        value = review()
        original = copy.deepcopy(value)
        seed = imported_call_seed(value)
        self.assertEqual(seed["arguments"], {"commit": SHA, "query": "def capture"})
        self.assertEqual(seed["module_candidate"], "sample.helpers.audit")
        self.assertEqual(seed["qualified_name"], "bound.capture")
        self.assertEqual(seed["source_line"], 20)
        self.assertEqual(seed["evidence_refs"], ["E0001", "E0002"])
        self.assertEqual(seed["binding_basis"], "observed_import_only")
        self.assertIs(seed["shadowing_proof"], False)
        self.assertIs(seed["semantic_approval"], False)
        self.assertEqual(value, original)

    def test_supported_absolute_import_forms_and_direct_call(self):
        for statement, qualified in (("import sample.helpers.audit as bound", "bound.capture"),
                ("import sample.helpers.audit", "sample.helpers.audit.capture"),
                ("from sample.helpers import audit", "audit.capture"),
                ("from sample.helpers import (\n    audit as bound,\n)", "bound.capture")):
            value = review(statement.splitlines(), [f"result = {qualified}(args)"])
            with self.subTest(statement=statement):
                seed = imported_call_seed(value)
                self.assertEqual(seed["module_candidate"], "sample.helpers.audit")
                self.assertEqual(seed["qualified_name"], qualified)

    def test_qualified_decorator_precedes_direct_calls_and_supports_keyword_arguments(self):
        value = review(["from sample.helpers import audit as bound", "import warnings"],
            ["@bound.capture(mode=True)", "def entry(args):", "    warnings.warn('notice')"])
        self.assertEqual(imported_call_seed(value)["qualified_name"], "bound.capture")

    def test_unrelated_direct_call_binding_does_not_suppress_decorator_tier(self):
        value = review(["from sample.helpers import audit as bound", "from sample.models import Record"],
            ["@bound.capture", "def entry(args):", "    return Record.from_json(args)"])
        value["evidence"].append(source("E0004", ["def unrelated(record: Record):", "    return record"], first=100))
        self.assertEqual(imported_call_seed(value)["qualified_name"], "bound.capture")

    def test_literal_comment_and_uncited_lookalikes_do_not_seed(self):
        for body in (["# @bound.capture"], ['text = "bound.capture(args)"'],
                     ['text = """', "@bound.capture", '"""'], ["value = bound.capture"]):
            with self.subTest(body=body):
                self.assertIsNone(imported_call_seed(review(body=body)))
        value = review()
        value["suggested_values"]["entry_point"]["start_line"] = 21
        self.assertIsNone(imported_call_seed(value))

    def test_selected_slice_inside_visible_string_cannot_become_executable_syntax(self):
        for apparent in ("@bound.capture", "bound.capture(args)"):
            value = review(body=['text = """', apparent, '"""'])
            value["suggested_values"]["entry_point"].update(start_line=21, end_line=21)
            self.assertIsNone(imported_call_seed(value))

    def test_rebinding_shadowing_or_multiple_candidates_never_selects_an_alternative(self):
        additions = ["bound = replacement", "bound.capture = replacement", "other, bound = pair",
                     "del bound", "def other(bound):", "for bound in values:", "with value as bound:",
                     "from different import audit as bound", "from different import *"]
        for addition in additions:
            value = review()
            value["evidence"].append(source("E0004", [addition], first=100))
            with self.subTest(addition=addition):
                self.assertIsNone(imported_call_seed(value))
        self.assertIsNone(imported_call_seed(review(
            ["from one import audit as bound", "from two import audit as bound"])))
        self.assertIsNone(imported_call_seed(review(body=["@bound.capture", "@bound.second", "def entry(): pass"])))
        self.assertIsNone(imported_call_seed(review(body=["bound.capture(args)", "bound.second(args)"])))

    def test_multiline_arguments_lambda_and_pattern_capture_are_visible_shadowing(self):
        bodies = [["def entry(", "    bound,", "):", "    return bound.capture(args)"],
                  ["f = lambda bound: bound.capture(args)"],
                  ["match value:", "    case {'item': bound}:", "        bound.capture(args)"],
                  ["(", "    bound,", "    other,", ") = replacement", "bound.capture(args)"]]
        for body in bodies:
            with self.subTest(body=body):
                self.assertIsNone(imported_call_seed(review(body=body)))

    def test_relative_conditional_incomplete_and_nonprefix_imports_are_not_assumed(self):
        imports = [["from .helpers import audit as bound"],
                   ["if enabled:", "    from sample.helpers import audit as bound"],
                   ["from sample.helpers import (", "    audit as bound,"],
                   ['text = "from sample.helpers import audit as bound"']]
        for lines in imports:
            self.assertIsNone(imported_call_seed(review(lines)))
        value = review()
        value["evidence"][0] = source("E0001", ["from sample.helpers import audit as bound"], first=2)
        self.assertIsNone(imported_call_seed(value))

    def test_invalid_unicode_import_is_not_a_navigation_seed(self):
        for line in ("import " + chr(0xD800), "from sample.helpers import audit as " + chr(0xD800)):
            self.assertIsNone(imported_call_seed(review([line])))

    def test_exact_expanded_field_code_and_same_sha_receipts_are_required(self):
        value = review()
        body = value["evidence"][1]["result"]
        value["suggested_values"]["entry_point"] = {"file": SOURCE, "line": "20-22", "code": body["text"]}
        self.assertIsNotNone(imported_call_seed(value))
        value["suggested_values"]["entry_point"]["code"] += "\n# invented"
        self.assertIsNone(imported_call_seed(value))
        for mutate in (lambda r: r["evidence"][0]["result"].update(commit=OTHER),
                       lambda r: r["evidence"][1]["result"].update(commit=OTHER),
                       lambda r: r["suggested_values"].update(commit=OTHER),
                       lambda r: r["evidence"].append(copy.deepcopy(r["evidence"][0]))):
            value = review()
            mutate(value)
            self.assertIsNone(imported_call_seed(value))

    def test_conflicting_overlap_and_nonpython_source_are_rejected(self):
        value = review()
        value["evidence"].append(source("E0004", ["from other import audit as bound"], first=2))
        self.assertIsNone(imported_call_seed(value))
        value = review()
        for receipt in value["evidence"]:
            receipt["result"]["path"] = "src/source.ts"
        self.assertIsNone(imported_call_seed(value))


class ImportedDefinitionReadTests(unittest.TestCase):
    def test_unique_real_hit_yields_bounded_anchored_source_only(self):
        value = review()
        seed = imported_call_seed(value)
        receipt = search(seed, [{"file": "other/audit.py", "line": 80, "code": "def capture(fn):"},
                                {"file": TARGET, "line": 50, "code": "async def capture(fn):"}])
        original = copy.deepcopy((receipt, seed, value))
        self.assertEqual(imported_definition_read(receipt, seed, value["evidence"]), {
            "arguments": {"commit": SHA, "path": TARGET, "start_line": 42, "end_line": 146},
            "anchor_line": 50})
        self.assertEqual((receipt, seed, value), original)

    def test_package_init_target_supported_only_from_actual_hit(self):
        seed = imported_call_seed(review())
        path = "src/sample/helpers/audit/__init__.py"
        receipt = search(seed, [{"file": path, "line": 2, "code": "def capture(fn):"}])
        self.assertEqual(imported_definition_read(receipt, seed, [])["arguments"]["path"], path)

    def test_duplicate_modules_definitions_and_non_top_level_hits_are_ambiguous(self):
        seed = imported_call_seed(review())
        actual = {"file": TARGET, "line": 50, "code": "def capture(fn):"}
        for hits in ([actual, {**actual, "file": "vendor/sample/helpers/audit.py"}],
                     [actual, {**actual, "line": 70}], [{**actual, "code": "    def capture(fn):"}],
                     [{**actual, "code": "# def capture(fn):"}], [{**actual, "code": "def capture_other(fn):"}],
                     [actual, {"file": TARGET, "line": None, "code": "def capture(fn):"}]):
            self.assertIsNone(imported_definition_read(search(seed, hits), seed, []))

    def test_failed_truncated_scope_mismatched_searches_do_not_generate_paths(self):
        seed = imported_call_seed(review())
        for updates in ({"commit": OTHER}, {"query": "capture"}, {"complete": False},
                        {"truncated": True}, {"paths": [TARGET]}, {"skipped_count": 1},
                        {"matches": []}, {"success": False}, {"error": "failed"}):
            receipt = search(seed)
            receipt["result"].update(updates)
            self.assertIsNone(imported_definition_read(receipt, seed, []))
        receipt = search(seed)
        receipt["success"] = False
        self.assertIsNone(imported_definition_read(receipt, seed, []))

    def test_existing_actual_definition_window_is_not_read_again(self):
        seed = imported_call_seed(review())
        known = source("E0004", ["def capture(fn):", "    return fn"], path=TARGET, first=50)
        self.assertIsNone(imported_definition_read(search(seed), seed, [known]))
        known["result"]["commit"] = OTHER
        self.assertIsNotNone(imported_definition_read(search(seed), seed, [known]))

    def test_seed_mutation_cannot_inject_a_read_path_or_enable_semantic_approval(self):
        seed = imported_call_seed(review())
        receipt = search(seed)
        for updates in ({"semantic_approval": True}, {"binding_basis": "model_reason"},
                        {"symbol": "capture; execute"}, {"module_candidate": "../sample/helpers/audit"},
                        {"arguments": {**seed["arguments"], "paths": [TARGET]}}):
            self.assertIsNone(imported_definition_read(receipt, {**seed, **updates}, []))


if __name__ == "__main__":
    unittest.main()
