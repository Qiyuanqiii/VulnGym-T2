"""Synthetic extra-key observations, not reconstruction of unseen live output."""
import copy
import json
import unittest

from vulngym_t2 import protocol, staged_protocol as staged
from tests.test_t2_v2_staged_protocol import annotation, decision, location


def normalize(**updates):
    return staged.normalize_calls(annotation(**updates), "annotation")


def shape(field="critical_operation", suffix=".value", keys=None, unknown=0):
    return {"field": field, "code": "unexpected_properties",
            "path": "$[0].arguments." + field + suffix,
            "known_extra_keys": ["code"] if keys is None else keys,
            "unknown_extra_count": unknown}


class ErrorShapeDiagnosticTests(unittest.TestCase):
    def test_source_id_wire_does_not_report_its_valid_key_as_an_extra(self):
        from vulngym_t2.output import _saved_actions

        for field in ("entry_point", "critical_operation", "trace"):
            snapshot = staged.source_id_snapshot(staged.snapshot_from_state({}, {}))
            value = {"source_id": "E0001", "start_line": 1, "end_line": 1, "desc": "Observed row.",
                     "code": "hidden-source", "private_extra": "hidden-value"}
            snapshot[field]["value"] = [value] if field == "trace" else value
            result = staged.normalize_calls([{"tool": "submit_annotation", "arguments": snapshot}],
                                             "annotation", location_key="source_id")
            expected = {**shape(field, ".value[0]" if field == "trace" else ".value", ["code"], 1),
                        "location_reference_key": "source_id"}
            with self.subTest(field=field):
                self.assertEqual(result["annotation_error_shapes"], [expected])
                saved = _saved_actions([{"action": "annotation_error_shape", **expected}])
                self.assertEqual(saved, [{"action": "annotation_error_shape", **expected}])
                hint = staged.annotation_shape_feedback(result["annotation_errors"], location_key="source_id")[0]
                self.assertIn("source_id", hint["allowed_keys"])
                self.assertNotIn("evidence_ref", hint["allowed_keys"])
                self.assertNotIn("hidden-", json.dumps(result))
                invalid = {**expected, "known_extra_keys": ["source_id"]}
                self.assertEqual(staged.public_error_shapes([invalid]), [])

    def test_mixed_old_and_new_keys_reports_the_actual_extra_key(self):
        snapshot = staged.source_id_snapshot(staged.snapshot_from_state({}, {}))
        snapshot["entry_point"]["value"]["evidence_ref"] = "E0001"
        result = staged.normalize_calls([{"tool": "submit_annotation", "arguments": snapshot}],
                                         "annotation", location_key="source_id")
        self.assertEqual(result["annotation_error_shapes"], [
            {**shape("entry_point", keys=["evidence_ref"]), "location_reference_key": "source_id"}])
        self.assertNotIn("entry_point", result["field_reviews"])
        for invalid_key in (None, [], {}, "unknown"):
            invalid = {**result["annotation_error_shapes"][0], "location_reference_key": invalid_key}
            self.assertEqual(staged.public_error_shapes([invalid]), [])

    def test_location_error_observes_known_keys_and_unknown_count_without_values(self):
        bad = decision(location(file="hidden-file", line=999, code="hidden-code",
                                description="hidden-description", private_key={"secret": "hidden-value"},
                                another_private_key="hidden-value"))
        before = copy.deepcopy(bad)
        result = normalize(critical_operation=bad, vuln_title=decision("Valid sibling"))
        expected = shape(keys=["code", "description", "file", "line"], unknown=2)
        self.assertEqual(result["annotation_error_shapes"], [expected])
        self.assertEqual(result["annotation_errors"], [{key: expected[key] for key in ("field", "code", "path")}])
        self.assertNotIn("critical_operation", result["field_reviews"])
        self.assertEqual(result["fields"], {"vuln_title": "Valid sibling"})
        self.assertEqual(bad, before)
        for marker in ("hidden-", "private_key", '"secret"'):
            self.assertNotIn(marker, json.dumps(result))

    def test_only_the_reported_object_is_observed_not_unknown_nested_content(self):
        bad = decision(location(code="hidden-code"),
                       revision_basis="hidden-basis", private_container={"file": "hidden-file"})
        result = normalize(entry_point=bad)
        self.assertEqual(result["annotation_error_shapes"], [
            shape("entry_point", "", ["revision_basis"], 1)
        ])
        self.assertEqual(result["annotation_errors"][0]["path"], "$[0].arguments.entry_point")
        self.assertNotIn("hidden-", json.dumps(result))
        self.assertNotIn("private_container", json.dumps(result))

    def test_trace_error_paths_are_bound_to_actual_array_resource_limit(self):
        for index in (0, 31, 63):
            values = [location() for _ in range(index + 1)]
            values[index]["code"] = "hidden-code"
            with self.subTest(index=index):
                result = normalize(trace=decision(values))
                self.assertEqual(result["annotation_error_shapes"], [
                    shape("trace", f".value[{index}]")
                ])
                self.assertNotIn("trace", result["field_reviews"])
        with self.assertRaises(staged.ProtocolError):
            normalize(trace=decision([location(code="hidden-code") for _ in range(65)]))

    def test_valid_and_losslessly_normalized_decisions_do_not_get_error_shapes(self):
        good = decision(location())
        plain = normalize(entry_point=good)
        duplicate = copy.deepcopy(good)
        duplicate["value"]["reason"] = duplicate["reason"]
        adapted = normalize(entry_point=duplicate)
        self.assertNotIn("annotation_error_shapes", plain)
        self.assertNotIn("annotation_error_shapes", adapted)
        self.assertNotIn("annotation_errors", adapted)
        self.assertTrue(adapted.pop("annotation_normalizations"))
        self.assertEqual(adapted, plain)
        conflict = copy.deepcopy(good)
        conflict["value"]["reason"] = "hidden-qualification"
        rejected = normalize(entry_point=conflict)
        self.assertEqual(rejected["annotation_error_shapes"], [shape("entry_point", keys=["reason"])])
        self.assertNotIn("entry_point", rejected["field_reviews"])

    def test_other_errors_and_root_controls_do_not_invent_extra_key_diagnostics(self):
        missing = decision(location(code="hidden-code"))
        missing.pop("status")
        for bad in (missing, [], decision(location(end_line=9))):
            with self.subTest(bad=bad):
                result = normalize(entry_point=bad)
                self.assertNotIn("annotation_error_shapes", result)
                self.assertTrue(result["annotation_errors"])
        calls = annotation()
        calls[0]["arguments"]["private_root"] = "hidden-root"
        with self.assertRaises(staged.ProtocolError) as caught:
            staged.normalize_calls(calls, "annotation")
        self.assertEqual(caught.exception.diagnostic["protocol_path"], "$[0].arguments")
        self.assertNotIn("private_root", json.dumps(caught.exception.diagnostic))

    def test_public_filter_rejects_unbounded_or_misbound_records_and_prose(self):
        valid = shape(keys=["reason", "code"], unknown=2)
        invalid = [
            {**valid, "raw": "hidden-response"},
            {**valid, "field": []},
            {**valid, "code": "missing_property"},
            {**valid, "path": "$[0].arguments.entry_point.value"},
            {**valid, "path": "$[0].arguments.critical_operation.value.reason"},
            {**valid, "path": "$[0].arguments.critical_operation.private_key"},
            {**valid, "known_extra_keys": ["private_key"]},
            {**valid, "known_extra_keys": ["evidence_ref"]},
            {**valid, "known_extra_keys": ["code", "code"]},
            {**valid, "known_extra_keys": "code"},
            {**valid, "known_extra_keys": [True]},
            *[{**valid, "unknown_extra_count": value} for value in (-1, True, 1.0, 10_001, "2")],
            shape(keys=[], unknown=0),
            shape("trace", ".value[64]"),
        ]
        for item in invalid:
            with self.subTest(item=item):
                self.assertEqual(staged.public_error_shapes([item]), [])
        original = copy.deepcopy(valid)
        clean = staged.public_error_shapes([invalid[0], valid, invalid[6]])
        self.assertEqual(clean, [shape(keys=["code", "reason"], unknown=2)])
        self.assertEqual(valid, original)
        self.assertNotIn("hidden-", json.dumps(clean))
        self.assertEqual(staged.public_error_shapes([valid] * 9), [])
        self.assertEqual(staged.public_error_shapes(None), [])
        self.assertEqual(staged.public_error_shapes([shape(keys=[], unknown=10_000)]),
                         [shape(keys=[], unknown=10_000)])

    def test_each_failed_field_has_one_bounded_record_and_old_errors_stay_three_keys(self):
        snapshot = staged.snapshot_from_state({}, {})
        for item in snapshot.values():
            item["private_extra"] = "hidden-value"
        result = staged.normalize_calls([{"tool": "submit_annotation", "arguments": snapshot}], "annotation")
        self.assertEqual(len(result["annotation_error_shapes"]), 8)
        self.assertEqual(result["fields"], {})
        self.assertEqual(result["field_reviews"], {})
        self.assertTrue(all(set(error) == {"field", "code", "path"} for error in result["annotation_errors"]))
        for item in result["annotation_error_shapes"]:
            self.assertEqual(item["known_extra_keys"], [])
            self.assertEqual(item["unknown_extra_count"], 1)
        self.assertEqual(staged.public_error_shapes(result["annotation_error_shapes"]),
                         result["annotation_error_shapes"])
        self.assertLess(len(json.dumps(result["annotation_error_shapes"])), 4000)

    def test_prompt_changes_no_wire_schema_stage_or_permissions(self):
        self.assertEqual(staged.PROMPT_REVISION, "snapshot-guidance-v85")
        self.assertEqual(staged.STAGED_WIRE_VERSION, "snapshot-v2")
        self.assertEqual(staged.MULTI_STAGED_WIRE_VERSION, "candidate-serial-snapshot-v2")
        text = staged.instruction("annotation")
        self.assertIn("do not add extra properties, even duplicates", text)
        self.assertIn("unknown or conflicting extras remain errors", text)
        self.assertIn("at most one subsequent targeted field review", text)
        self.assertIn("within remaining shared budgets", text)
        self.assertIn("no extra reads or permissions", text)
        schema = staged.tool_definitions("annotation")[0]["function"]["parameters"]
        self.assertTrue(protocol._matches(staged.snapshot_from_state({}, {}), schema))
        self.assertFalse(schema["additionalProperties"])
        with self.assertRaisesRegex(ValueError, "staged_stage_invalid"):
            staged.tool_definitions("targeted_field_review")


if __name__ == "__main__":
    unittest.main()
