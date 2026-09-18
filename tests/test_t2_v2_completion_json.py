"""Synthetic JSON tails only; a live Extra data error did not reveal its tail."""
import copy
import json
import unittest

from vulngym_t2 import completion_json, transport


class RecordingDecoder(json.JSONDecoder):
    def __init__(self):
        super().__init__(object_pairs_hook=transport._pairs,
                         parse_constant=transport._constant,
                         parse_float=transport._finite_float)
        self.errors = []
        self.values = []

    def decode(self, text):
        try:
            value = super().decode(text)
        except (ValueError, RecursionError) as error:
            self.errors.append(error)
            raise
        self.values.append(value)
        return value


class CompletionJSONTests(unittest.TestCase):
    def parse(self, text, *, allowed=True, decoder=None):
        return completion_json.parse_completion_json(
            text, decoder=decoder or RecordingDecoder(), allowed=allowed)

    def test_normal_json_is_unchanged_and_has_no_audit(self):
        for value in ({}, {"text": "literal } and {", "nested": [{"v": 1.25}],
                           "bool": True, "unknown": None}, [], "text", 1, None):
            with self.subTest(value=value):
                decoder = RecordingDecoder()
                text = " \r\n\t" + json.dumps(value, ensure_ascii=False) + " \n"
                parsed, audit = self.parse(text, decoder=decoder)
                self.assertEqual(parsed, value)
                self.assertIs(parsed, decoder.values[0])
                self.assertIsNone(audit)
                self.assertEqual(decoder.errors, [])

    def test_exactly_one_extra_close_after_complete_dict_is_audited_without_value_changes(self):
        expected = {"unicode": "中文", "text": "} { \\\"", "nested": {"items": [1, None, False]}}
        original = json.dumps(expected, ensure_ascii=False)
        for suffix in ("}", " } \n\t", "\r\n\t}\r\n"):
            decoder = RecordingDecoder()
            with self.subTest(suffix=suffix):
                parsed, audit = self.parse(" \t" + original + suffix, decoder=decoder)
                self.assertEqual(parsed, expected)
                self.assertIs(parsed, decoder.values[0])
                self.assertEqual(audit, {"code": "redundant_object_close_removed", "count": 1})
                self.assertEqual(len(decoder.errors), 1)
                self.assertEqual(decoder.errors[0].msg, "Extra data")

    def test_opt_in_is_explicit_and_truthy_values_do_not_enable_it(self):
        for allowed in (False, None, 1, "true"):
            decoder = RecordingDecoder()
            with self.subTest(allowed=allowed), self.assertRaises(json.JSONDecodeError) as caught:
                self.parse("{}}", allowed=allowed, decoder=decoder)
            self.assertIs(caught.exception, decoder.errors[0])
        with self.assertRaises(json.JSONDecodeError):
            completion_json.parse_completion_json("{}}", decoder=RecordingDecoder())

    def test_other_tails_truncation_and_malformed_objects_preserve_original_exception(self):
        values = ("{} }}", "{}{}", "{}[]", "{}true", "{} explanation", "{} // comment",
                  "{} } trailing", "{} ]", "{} }\u00a0", "{}\ufeff}", "\u00a0{}}",
                  '{"a":1', '{a:1}}', '{"a":"unterminated}}',
                  "```json\n{}}\n```", "", "{", "{")
        for text in values:
            decoder = RecordingDecoder()
            with self.subTest(text=text), self.assertRaises(json.JSONDecodeError) as caught:
                self.parse(text, decoder=decoder)
            self.assertIs(caught.exception, decoder.errors[0])

    def test_one_trailing_separator_removes_no_value_and_keeps_strict_hooks(self):
        for text, expected in ((r'{"a":1,}', {"a": 1}),
                               (r'{"a":[1,2, ]}', {"a": [1, 2]}),
                               (r'{"text":"literal ,} and ,]", "inner":{"a":null,}}',
                                {"text": "literal ,} and ,]", "inner": {"a": None}})):
            with self.subTest(text=text):
                result, audit = self.parse(text)
                self.assertEqual(result, expected)
                self.assertEqual(audit, {"code": "trailing_separator_removed", "count": 1})
                self.assertEqual(completion_json.public_normalizations([audit]), [audit])
                with self.assertRaises(json.JSONDecodeError):
                    self.parse(text, allowed=False)
        for text in ('{"a":,}', '{"a":[,]}', '{"a":[1,,]}', '{"a":[1,],}', '[1,]',
                     '{"a":1,}}', '{"a":1,"a":2,}', '{"a":NaN,}', '{"a":1e999,}',
                     '{"a":"unterminated,}', '{"a":1,} trailing'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                self.parse(text)

    def test_non_object_prefix_cannot_use_compatibility(self):
        for text in ("[]}", '"text"}', "1}", "true}", "null}"):
            decoder = RecordingDecoder()
            with self.subTest(text=text), self.assertRaises(json.JSONDecodeError) as caught:
                self.parse(text, decoder=decoder)
            self.assertIs(caught.exception, decoder.errors[0])
        # Normal non-object JSON remains available to the caller's old gate.
        value, audit = self.parse("[]")
        self.assertIsNone(audit)
        with self.assertRaises(transport.TransportError):
            transport._strict_object(json.dumps(value).encode("utf-8"))

    def test_strict_duplicate_nonfinite_hooks_are_not_bypassed(self):
        for body in ('{"a":1,"a":2}', '{"nested":{"a":1,"a":2}}',
                     '{"v":NaN}', '{"v":Infinity}', '{"v":-Infinity}', '{"v":1e999}'):
            for suffix in ("", "}"):
                decoder = RecordingDecoder()
                with self.subTest(body=body, suffix=suffix), self.assertRaises(ValueError) as caught:
                    self.parse(body + suffix, decoder=decoder)
                self.assertIs(caught.exception, decoder.errors[0])
                self.assertNotIsInstance(caught.exception, json.JSONDecodeError)

    def test_unchanged_bounded_domain_validation_still_rejects_decoded_object(self):
        nested = None
        for _ in range(18):
            nested = [nested]
        for source in ({"nested": nested}, {"x" * 257: 1}, {"v": [None] * 10_001}):
            with self.subTest(kind=next(iter(source))):
                value, audit = self.parse(json.dumps(source) + "}")
                self.assertEqual(value, source)
                self.assertEqual(audit["count"], 1)
                with self.assertRaises(ValueError):
                    transport._validate_bounded_json(value)

    def test_extra_data_diagnostics_expose_only_fixed_tail_category_and_length(self):
        for tail, expected in (("} \r\n", (1, "single_object_close")),
                               ("private explanation", (19, "other")),
                               ("{}", (2, "other")), ("}}", (2, "other"))):
            text = "{} " + tail
            try:
                RecordingDecoder().decode(text)
            except json.JSONDecodeError as error:
                diagnostic = completion_json.extra_data_diagnostics(text, error)
            self.assertEqual(diagnostic, {"tail_length": expected[0], "tail_kind": expected[1]})
            self.assertNotIn("private", json.dumps(diagnostic))
        self.assertEqual(completion_json.extra_data_diagnostics("{}", ValueError("private")), {})
        error = json.JSONDecodeError("Extra data", "{} private", 3)
        self.assertEqual(completion_json.extra_data_diagnostics("{} different", error), {})

    def test_public_normalizations_are_fixed_bounded_copied_and_reject_boolean_counts(self):
        valid = {"code": "redundant_object_close_removed", "count": 1}
        original = copy.deepcopy(valid)
        clean = completion_json.public_normalizations([valid])
        self.assertEqual(clean, [valid])
        clean[0]["count"] = 2
        self.assertEqual(valid, original)
        invalid = [None, {}, [], [valid, valid], [{**valid, "raw": "private"}],
                   [{**valid, "code": "private"}],
                   *[[{**valid, "count": count}] for count in (True, 1.0, 0, 2, "1")]]
        for value in invalid:
            with self.subTest(value=value):
                self.assertEqual(completion_json.public_normalizations(value), [])


if __name__ == "__main__":
    unittest.main()
