"""In-memory source-reference tests; no model, repository, or network reads."""
from copy import deepcopy
import unittest

from vulngym_t2.source_refs import resolve_location


COMMIT = "a" * 40


def fixture():
    reference = {"evidence_ref": "E0004", "start_line": 11, "end_line": 12, "desc": "Saved explanation."}
    evidence = [{"id": "E0001", "kind": "input", "result": {}},
                {"id": "E0004", "kind": "tool", "tool": "read_file", "success": True,
                 "arguments": {"commit": "HEAD", "path": "src/example.py", "start_line": 10, "end_line": 50},
                 "result": {"commit": COMMIT, "path": "src/example.py", "start_line": 10, "end_line": 13,
                            "lines": [{"line": 10, "code": "def example(value):"},
                                      {"line": 11, "code": "\ttext = '引号 \\\" | <tag>'  "},
                                      {"line": 12, "code": ""},
                                      {"line": 13, "code": "    return value"}],
                            "text": "NOT AUTHORITATIVE: omitted material cannot be used",
                            "truncated": True, "context_truncated": True}}]
    return reference, evidence


class SourceRefsTests(unittest.TestCase):
    def test_assembles_exact_displayed_lines_without_mutation_or_text_fallback(self):
        reference, evidence = fixture()
        before = deepcopy((reference, evidence))
        location = resolve_location(reference, evidence, COMMIT)
        self.assertEqual(location, {"file": "src/example.py", "line": "11-12",
                                    "code": evidence[1]["result"]["lines"][1]["code"] + "\n",
                                    "desc": "Saved explanation."})
        self.assertEqual((reference, evidence), before)
        self.assertNotIn("NOT AUTHORITATIVE", location["code"])

    def test_single_line_optional_description_and_blank_source_line(self):
        reference, evidence = fixture()
        reference.update(start_line=13, end_line=13, desc="")
        self.assertEqual(resolve_location(reference, evidence, COMMIT),
                         {"file": "src/example.py", "line": 13, "code": "    return value", "desc": ""})
        reference.pop("desc")
        reference.update(start_line=12, end_line=12)
        self.assertEqual(resolve_location(reference, evidence, COMMIT),
                         {"file": "src/example.py", "line": 12, "code": ""})

    def test_rejects_unknown_ambiguous_failed_and_nonread_receipts(self):
        cases = [
            ("unknown_evidence", lambda r, e: r.update(evidence_ref="E9999")),
            ("ambiguous_evidence", lambda r, e: e.append(deepcopy(e[1]))),
            ("failed_read", lambda r, e: e[1].update(success=False)),
            ("failed_read", lambda r, e: e[1].update(success=1)),
            ("failed_read", lambda r, e: e[1].pop("success")),
            ("failed_read", lambda r, e: e[1].update(error="failure")),
            ("failed_read", lambda r, e: e[1]["result"].update(error="failure")),
            ("failed_read", lambda r, e: e[1]["result"].update(ok=False)),
            ("commit_mismatch", lambda r, e: e[1]["result"].update(commit="b" * 40)),
            ("read_required", lambda r, e: e[1].update(tool="read_diff")),
            ("read_required", lambda r, e: e[1].update(tool="search_code")),
            ("read_required", lambda r, e: e[1].update(tool="inspect_commit")),
            ("source_missing", lambda r, e: e[1]["result"].pop("lines")),
            ("source_missing", lambda r, e: e[1]["result"].update(lines=[])),
        ]
        for code, mutate in cases:
            with self.subTest(code=code, mutate=cases.index((code, mutate))):
                reference, evidence = fixture()
                mutate(reference, evidence)
                with self.assertRaisesRegex(ValueError, "^source_ref_" + code + "$"):
                    resolve_location(reference, evidence, COMMIT)

    def test_refuses_out_of_bounds_and_noncontinuous_displayed_source(self):
        cases = [
            ("out_of_bounds", lambda r, e: r.update(start_line=9)),
            ("out_of_bounds", lambda r, e: r.update(end_line=14)),
            ("noncontiguous_source", lambda r, e: e[1]["result"]["lines"].pop(1)),
            ("noncontiguous_source", lambda r, e: e[1]["result"]["lines"].reverse()),
            ("noncontiguous_source", lambda r, e: e[1]["result"]["lines"].append({"line": 13, "code": "duplicate"})),
            ("noncontiguous_source", lambda r, e: e[1]["result"].update(end_line=50)),
            ("invalid_source_rows", lambda r, e: e[1]["result"]["lines"][1].update(code="two\nlines")),
            ("invalid_source_rows", lambda r, e: e[1]["result"]["lines"][1].update(code=None)),
            ("invalid_source_rows", lambda r, e: e[1]["result"]["lines"][1].update(line=True)),
            ("invalid_source_range", lambda r, e: e[1]["result"].update(start_line=True)),
        ]
        for code, mutate in cases:
            with self.subTest(code=code, mutate=cases.index((code, mutate))):
                reference, evidence = fixture()
                mutate(reference, evidence)
                with self.assertRaisesRegex(ValueError, "^source_ref_" + code + "$"):
                    resolve_location(reference, evidence, COMMIT)

    def test_refuses_nonrelative_or_invalid_paths(self):
        for path in (None, True, "", " ", ".", "../source.py", "src/../source.py", "/tmp/source.py",
                     "C:/source.py", "C:source.py", r"\\server\share\source.py", r"src\source.py", "src/\x00.py"):
            with self.subTest(path=path):
                reference, evidence = fixture()
                evidence[1]["result"]["path"] = path
                with self.assertRaisesRegex(ValueError, "^source_ref_invalid_path$"):
                    resolve_location(reference, evidence, COMMIT)

    def test_refuses_abnormal_reference_types_and_bool_lines(self):
        reference, evidence = fixture()
        for value in (None, [], "E0004", {**reference, "file": "override.py"}, {**reference, "code": "invented"}):
            with self.subTest(reference=value):
                with self.assertRaisesRegex(ValueError, "^source_ref_invalid_reference$"):
                    resolve_location(value, evidence, COMMIT)
        for key, values, code in (("evidence_ref", (None, True, 4, ""), "invalid_evidence_ref"),
                                  ("start_line", (None, True, "11", 11.0, 0, -1, 14), "invalid_range"),
                                  ("end_line", (None, True, "12", 12.0, 0, 10), "invalid_range"),
                                  ("desc", (None, False, [], 42), "invalid_description")):
            for value in values:
                with self.subTest(key=key, value=value):
                    with self.assertRaisesRegex(ValueError, "^source_ref_" + code + "$"):
                        resolve_location({**reference, key: value}, evidence, COMMIT)
        for commit in (None, False, 1, "HEAD", "a" * 39, "g" * 40):
            with self.subTest(commit=commit):
                with self.assertRaisesRegex(ValueError, "^source_ref_invalid_commit$"):
                    resolve_location(reference, evidence, commit)
        for value in (None, {}, (), [None]):
            with self.subTest(evidence=value):
                with self.assertRaisesRegex(ValueError, "^source_ref_invalid_evidence$"):
                    resolve_location(reference, value, COMMIT)

    def test_span_limit_is_inclusive_and_cannot_use_requested_but_unshown_lines(self):
        reference, evidence = fixture()
        reference.update(start_line=1, end_line=200)
        evidence[1]["result"].update(start_line=1, end_line=200,
                                      lines=[{"line": number, "code": "value"} for number in range(1, 201)])
        self.assertEqual(len(resolve_location(reference, evidence, COMMIT)["code"].split("\n")), 200)
        reference["end_line"] = 201
        with self.assertRaisesRegex(ValueError, "^source_ref_span_limit$"):
            resolve_location(reference, evidence, COMMIT)
        reference, evidence = fixture()
        reference.update(start_line=14, end_line=20)
        with self.assertRaisesRegex(ValueError, "^source_ref_out_of_bounds$"):
            resolve_location(reference, evidence, COMMIT)


if __name__ == "__main__":
    unittest.main()
