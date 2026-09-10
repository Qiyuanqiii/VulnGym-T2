import unittest
from vulngym_t2.output import _resolve_line_from_reads


class SourceCoordinateTests(unittest.TestCase):
    def evidence(self, lines):
        return {"E1": {"tool": "read_file", "success": True, "result": {
            "commit": "a" * 40, "path": "service.py", "start_line": 10,
            "end_line": 10 + len(lines) - 1, "text": "\n".join(lines)}}}

    def test_correct_unique_exact_quote_only(self):
        old = {"file": "service.py", "line": 10, "code": "    parse(data)"}
        new, receipt = _resolve_line_from_reads("a" * 40, old, ["E1"], self.evidence(["try:", "    parse(data)"]))
        self.assertEqual(new, {**old, "line": 11})
        self.assertEqual(receipt["from_line"], 10)
        self.assertEqual(old["line"], 10)

    def test_ambiguous_or_modified_quote_is_never_corrected(self):
        old = {"file": "service.py", "line": 10, "code": "    parse(data)"}
        for lines in [[old["code"], old["code"]], ["parse(data)"], ["    parse(other)"]]:
            new, receipt = _resolve_line_from_reads("a" * 40, old, ["E1"], self.evidence(lines))
            self.assertEqual(new, old)
            self.assertIsNone(receipt)


if __name__ == "__main__":
    unittest.main()
