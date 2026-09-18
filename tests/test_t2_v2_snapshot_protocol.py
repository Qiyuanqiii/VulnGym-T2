"""Snapshot/candidate contracts: pure schema and state serialization tests."""
import copy
import json
import unittest

from vulngym_t2 import protocol, staged_protocol as staged
from tests.test_t2_v2_staged_protocol import annotation, decision, location, unknown_location


def normalize(arguments):
    return staged.normalize_calls([{"tool": "submit_annotation", "arguments": arguments}], "annotation")


def candidates(items):
    return staged.normalize_calls([{"tool": "propose_candidates", "arguments": {"candidates": items}}],
                                  "candidate_selection")


class SnapshotProtocolTests(unittest.TestCase):
    def test_schema_and_minimal_snapshot_are_eight_direct_decisions(self):
        schema = staged.tool_definitions("annotation")[0]["function"]["parameters"]
        self.assertEqual(staged.STAGED_WIRE_VERSION, "snapshot-v2")
        self.assertEqual(set(schema["required"]), set(staged.ANNOTATION_FIELDS))
        self.assertFalse(schema["additionalProperties"])
        for field, shape in schema["properties"].items():
            self.assertEqual(shape["type"], "object")
            self.assertEqual(set(shape["required"]), {"value", "status", "reason", "evidence_refs"}
                             | ({"revision_basis"} if field == "commit" else set()))
        for forbidden in ('"slot"', '"summary"', '"entry_id"', '"fields"', '"code"', '"anyOf"'):
            self.assertNotIn(forbidden, json.dumps(schema))
        snapshot = staged.snapshot_from_state({}, {})
        self.assertTrue(protocol._matches(snapshot, schema))
        result = normalize(snapshot)
        self.assertEqual(result["fields"], {})
        self.assertEqual(set(result["field_reviews"]), set(staged.ANNOTATION_FIELDS))
        self.assertTrue(all(review["status"] == "missing" for review in result["field_reviews"].values()))
        self.assertNotIn("annotation_errors", result)

    def test_schema_valid_direct_decisions_share_the_normalizer_shape(self):
        snapshot = annotation(commit=decision("a" * 40, revision_basis="behavior_at_revision"),
            vuln_title=decision("Shown defect"), vuln_category_l1=decision("Injection"),
            vuln_category_l2=decision("Specific candidate", "uncertain"),
            entry_point=decision(location()), critical_operation=decision(location(start_line=12, end_line=12)),
            trace=decision([]), vuln_ids=decision(["CVE-2026-12345"]))[0]["arguments"]
        schema = staged.tool_definitions("annotation")[0]["function"]["parameters"]
        self.assertTrue(protocol._matches(snapshot, schema))
        before = copy.deepcopy(snapshot)
        result = normalize(snapshot)
        self.assertNotIn("annotation_errors", result)
        self.assertEqual(len(result["field_reviews"]), 8)
        self.assertEqual(result["fields"]["entry_point"], location())
        self.assertEqual(result["field_reviews"]["commit"]["revision_basis"], "behavior_at_revision")
        self.assertNotIn("vuln_category_l2", result["fields"])
        self.assertEqual(result["field_reviews"]["vuln_category_l2"]["suggested_value"], "Specific candidate")
        self.assertEqual(snapshot, before)

    def test_decision_arrays_are_field_errors_not_first_item_or_no_update(self):
        for old in ([], [decision(location())], [decision(location()), decision(location())]):
            with self.subTest(length=len(old)):
                result = normalize(annotation(entry_point=old, vuln_title=decision("Valid sibling"))[0]["arguments"])
                self.assertEqual(result["fields"], {"vuln_title": "Valid sibling"})
                self.assertNotIn("entry_point", result["field_reviews"])
                self.assertEqual(result["annotation_errors"], [{"field": "entry_point", "code": "expected_object",
                    "path": "$[0].arguments.entry_point"}])
                self.assertNotIn("decision_limit", json.dumps(result))

    def test_snapshot_rejects_outer_controls_but_isolates_missing_decisions(self):
        for key in ("summary", "slot", "entry_id", "entries", "code", "private_unknown"):
            with self.subTest(key=key), self.assertRaises(staged.ProtocolError) as caught:
                normalize({**staged.snapshot_from_state({}, {}), key: "private-value"})
            self.assertEqual(caught.exception.diagnostic["protocol_path"], "$[0].arguments")
            self.assertNotIn("private", json.dumps(caught.exception.diagnostic))
        for field in staged.ANNOTATION_FIELDS:
            snapshot = staged.snapshot_from_state({}, {})
            del snapshot[field]
            with self.subTest(missing=field):
                result = normalize(snapshot)
                self.assertEqual(result["annotation_errors"], [{"field": field, "code": "missing_property",
                    "path": "$[0].arguments." + field}])
                self.assertEqual(set(result["field_reviews"]), set(staged.ANNOTATION_FIELDS) - {field})

    def test_unknown_location_and_range_semantics_still_hold_per_field(self):
        for value, code in ((unknown_location(), "supported_without_value"),
                            (unknown_location(evidence_ref="E0001"), "location_placeholder_invalid"),
                            (location(end_line=9), "location_range_invalid")):
            with self.subTest(code=code):
                result = normalize(annotation(entry_point=decision(value), critical_operation=decision(location()))[0]["arguments"])
                self.assertEqual(result["annotation_errors"][0]["code"], code)
                self.assertNotIn("entry_point", result["fields"])
                self.assertEqual(result["fields"]["critical_operation"], location())
        result = normalize(annotation(entry_point=decision(unknown_location(), "uncertain"))[0]["arguments"])
        self.assertEqual(result["field_reviews"]["entry_point"]["status"], "uncertain")
        self.assertNotIn("suggested_value", result["field_reviews"]["entry_point"])

    def test_real_omission_shapes_keep_supported_and_uncertain_siblings(self):
        for absent in ("entry_point", "vuln_title"):
            snapshot = annotation(commit=decision("a" * 40, revision_basis="behavior_at_revision"),
                vuln_title=decision("Saved title"), entry_point=decision(location()),
                critical_operation=decision(location(), "uncertain"))[0]["arguments"]
            del snapshot[absent]
            before = copy.deepcopy(snapshot)
            result = normalize(snapshot)
            with self.subTest(absent=absent):
                self.assertEqual(result["fields"]["commit"], "a" * 40)
                self.assertNotIn(absent, result["fields"])
                self.assertNotIn(absent, result["field_reviews"])
                self.assertEqual(result["field_reviews"]["critical_operation"]["suggested_value"], location())
                self.assertEqual(result["annotation_errors"], [{"field": absent, "code": "missing_property",
                    "path": "$[0].arguments." + absent}])
                self.assertEqual(snapshot, before)
                restored = staged.snapshot_from_state(result["fields"], result["field_reviews"])
                self.assertEqual(set(restored), set(staged.ANNOTATION_FIELDS))
                self.assertEqual(restored[absent]["status"], "missing")
                self.assertNotIn(absent, normalize(restored)["fields"])

    def test_empty_object_is_eight_explicit_errors_not_a_successful_unknown_snapshot(self):
        result = normalize({})
        self.assertEqual(result["fields"], {})
        self.assertEqual(result["field_reviews"], {})
        self.assertEqual(result["annotation_errors"], [
            {"field": field, "code": "missing_property", "path": "$[0].arguments." + field}
            for field in staged.ANNOTATION_FIELDS])
        for value in (None, [], "{}", 42):
            with self.subTest(value=value), self.assertRaises(staged.ProtocolError) as caught:
                normalize(value)
            self.assertEqual(caught.exception.diagnostic["protocol_reason"], "expected_object")

    def test_null_types_nested_extras_and_bad_refs_are_field_local(self):
        cases = [(None, "expected_object", ""), (1.5, "expected_object", ""),
                 (decision(None), "expected_object", ".value"),
                 (decision(location(start_line=1.5)), "expected_integer", ".value.start_line"),
                 (decision(location(start_line=True)), "expected_integer", ".value.start_line"),
                 (decision(location(evidence_ref="private-id")), "pattern_mismatch", ".value.evidence_ref"),
                 (decision(location(), evidence_refs=[None]), "expected_string", ".evidence_refs[0]"),
                 (decision(location(private_extra="private-value")), "unexpected_properties", ".value"),
                 (decision(location(), private_extra={"nested": "private-value"}), "unexpected_properties", "")]
        for malformed, code, suffix in cases:
            snapshot = annotation(entry_point=malformed, vuln_title=decision("Legal sibling"))[0]["arguments"]
            with self.subTest(code=code, suffix=suffix):
                result = normalize(snapshot)
                self.assertEqual(result["fields"], {"vuln_title": "Legal sibling"})
                self.assertNotIn("entry_point", result["field_reviews"])
                self.assertEqual(result["annotation_errors"], [{"field": "entry_point", "code": code,
                    "path": "$[0].arguments.entry_point" + suffix}])
                self.assertNotIn("private", json.dumps(result))

    def test_resource_boundaries_remain_global_even_with_legal_siblings(self):
        nested = "leaf"
        for _ in range(17):
            nested = {"value": nested}
        cases = [(decision("x" * 32001), "string_limit"),
                 (decision([None] * 65), "array_limit"),
                 (decision(nested), "json_depth_limit"),
                 (decision({"x" * 65: "value"}), "object_key_limit")]
        for malformed, reason in cases:
            with self.subTest(reason=reason), self.assertRaises(staged.ProtocolError) as caught:
                normalize(annotation(entry_point=malformed, vuln_title=decision("Legal sibling"))[0]["arguments"])
            self.assertEqual(caught.exception.diagnostic["protocol_reason"], reason)
        # Decision limits below the global resource ceiling still isolate a field.
        result = normalize(annotation(vuln_title=decision("bad reason", reason="x" * 2001),
            entry_point=decision(location()))[0]["arguments"])
        self.assertEqual(result["fields"], {"entry_point": location()})
        self.assertEqual(result["annotation_errors"][0]["code"], "reason_limit")

    def test_serializer_preserves_legal_compact_values_and_uncertain_suggestions(self):
        fields = {"commit": "a" * 40, "entry_point": location(), "vuln_title": "Kept title",
                  "entry_id": "controller-only", "code": "never copied"}
        reviews = {
            "commit": {"status": "supported", "reason": "Mechanism at this revision.", "evidence_refs": ["E0001"], "revision_basis": "behavior_at_revision"},
            "entry_point": {"status": "supported", "reason": "The shown entry.", "evidence_refs": ["E0001"]},
            "critical_operation": {"status": "conflicting", "reason": "Operation remains disputed.", "evidence_refs": ["E0002"], "suggested_value": location(evidence_ref="E0002")},
            "vuln_title": {"status": "supported", "reason": "Advisory title.", "evidence_refs": ["E0003"]},
        }
        before = copy.deepcopy((fields, reviews))
        snapshot = staged.snapshot_from_state(fields, reviews)
        self.assertEqual(snapshot["entry_point"]["value"], location())
        self.assertEqual(snapshot["critical_operation"]["value"], reviews["critical_operation"]["suggested_value"])
        self.assertEqual(snapshot["critical_operation"]["status"], "conflicting")
        self.assertEqual(snapshot["commit"]["revision_basis"], "behavior_at_revision")
        self.assertEqual(snapshot["vuln_title"]["reason"], "Advisory title.")
        self.assertEqual(set(snapshot), set(staged.ANNOTATION_FIELDS))
        self.assertNotIn("controller-only", json.dumps(snapshot))
        self.assertNotIn("never copied", json.dumps(snapshot))
        self.assertNotIn("annotation_errors", normalize(snapshot))
        self.assertEqual((fields, reviews), before)

    def test_serializer_never_completes_incomplete_or_expanded_source_provenance(self):
        fragment = {"file": "private/source.py", "line": 12, "code": "unproven bytes"}
        fields = {"entry_point": fragment, "trace": [fragment], "commit": "HEAD"}
        reviews = {field: {"status": "supported", "reason": "Original unsupported claim.", "evidence_refs": ["E0001"]}
                   for field in fields}
        reviews["critical_operation"] = {"status": "conflicting", "suggested_value": {"evidence_ref": "E0001", "start_line": 12},
                                         "reason": "Incomplete suggestion", "evidence_refs": ["E0001", "private-id"]}
        snapshot = staged.snapshot_from_state(fields, reviews)
        self.assertEqual(snapshot["entry_point"]["value"], unknown_location())
        self.assertEqual(snapshot["critical_operation"]["value"], unknown_location())
        self.assertEqual(snapshot["trace"]["value"], [])
        self.assertEqual(snapshot["commit"]["value"], "")
        self.assertTrue(all(snapshot[field]["status"] != "supported" for field in fields))
        self.assertEqual(snapshot["critical_operation"]["status"], "conflicting")
        self.assertEqual(snapshot["critical_operation"]["evidence_refs"], ["E0001"])
        self.assertNotIn("private", json.dumps(snapshot))
        self.assertNotIn("annotation_errors", normalize(snapshot))

    def test_serializer_sanitizes_only_expression_shape_and_stays_fresh(self):
        reviews = {"vuln_title": {"status": "not-a-status", "reason": 42, "evidence_refs": "not-a-list"},
                   "commit": {"status": "uncertain", "reason": "x" * 2500, "evidence_refs": ["E0001"] * 25,
                              "revision_basis": "not-a-basis", "suggested_value": "b" * 40}}
        snapshot = staged.snapshot_from_state({}, reviews)
        self.assertEqual(snapshot["vuln_title"]["status"], "missing")
        self.assertEqual(len(snapshot["commit"]["reason"]), 2000)
        self.assertEqual(snapshot["commit"]["evidence_refs"], ["E0001"])
        self.assertEqual(snapshot["commit"]["revision_basis"], "unknown")
        self.assertNotIn("annotation_errors", normalize(snapshot))
        snapshot["entry_point"]["value"]["desc"] = "mutated"
        self.assertEqual(staged.snapshot_from_state({}, {})["entry_point"]["value"], unknown_location())


class CandidateProtocolTests(unittest.TestCase):
    def test_candidates_have_no_model_owned_identity_or_entry_fields(self):
        definitions = staged.tool_definitions("candidate_selection")
        self.assertEqual([item["function"]["name"] for item in definitions], ["propose_candidates"])
        schema = definitions[0]["function"]["parameters"]
        self.assertEqual(schema["required"], ["candidates"])
        self.assertEqual(set(schema["properties"]["candidates"]["items"]["required"]), {"scope", "evidence_refs"})
        self.assertEqual(staged.MULTI_STAGED_WIRE_VERSION, "candidate-serial-snapshot-v2")
        self.assertEqual(candidates([]), {"action": "candidates", "candidates": []})
        for count in (1, 5, 64):
            values = [{"scope": "Candidate " + str(i), "evidence_refs": ["E0001"]} for i in range(count)]
            before = copy.deepcopy(values)
            self.assertEqual(candidates(values), {"action": "candidates", "candidates": values})
            self.assertEqual(values, before)

    def test_candidate_control_fields_and_invalid_references_are_not_salvaged(self):
        for extra in ("slot", "entry_id", "fields", "summary", "code", "private_unknown"):
            with self.subTest(extra=extra), self.assertRaises(staged.ProtocolError) as caught:
                candidates([{"scope": "A scope", "evidence_refs": ["E0001"], extra: "private-value"}])
            self.assertEqual(caught.exception.diagnostic["protocol_path"], "$[0].arguments.candidates[0]")
            self.assertNotIn("private", json.dumps(caught.exception.diagnostic))
        with self.assertRaises(staged.ProtocolError) as caught:
            candidates([{"scope": "A scope", "evidence_refs": ["private-id"]}])
        self.assertEqual(caught.exception.diagnostic["protocol_path"], "$[0].arguments.candidates[0].evidence_refs[0]")
        with self.assertRaises(staged.ProtocolError):
            staged.normalize_calls([{"tool": "propose_candidates", "arguments": {"candidates": [], "slot": 1}}], "candidate_selection")

    def test_old_multi_wire_is_unsupported_and_read_control_remains_strict(self):
        for operation in (lambda: staged.tool_definitions("annotation_multi"),
                          lambda: staged.instruction("annotation_multi"),
                          lambda: staged.normalize_calls([], "annotation_multi")):
            with self.assertRaisesRegex(ValueError, "staged_annotation_multi_unsupported"):
                operation()
        read = {"tool": "inspect_commit", "arguments": {"commit": "a" * 40}}
        proposal = {"tool": "propose_candidates", "arguments": {"candidates": []}}
        self.assertEqual(len(staged.normalize_calls([read, read], "read")["calls"]), 2)
        for calls, stage in (([proposal, proposal], "candidate_selection"), ([read], "candidate_selection"),
                             ([proposal], "annotation"), ([proposal], "read"), ([read, read], "followup")):
            with self.subTest(stage=stage), self.assertRaises(staged.ProtocolError):
                staged.normalize_calls(calls, stage)
        self.assertEqual(len(staged.tool_definitions("read")), 8)


if __name__ == "__main__":
    unittest.main()
