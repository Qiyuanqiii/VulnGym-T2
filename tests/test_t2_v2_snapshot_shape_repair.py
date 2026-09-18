"""Bounded duplicate-property adaptation, not a replay of unseen provider extras.

The public failure records identify only decision/location error paths. These
synthetic cases establish the allowed transformation, not real-model efficacy.
"""
import copy
import json
import unittest

from vulngym_t2 import protocol, staged_protocol as staged, transport
from tests.test_t2_v2_protocol import tool_envelope
from tests.test_t2_v2_staged_protocol import annotation, decision, location, unknown_location


def normalize(snapshot):
    return staged.normalize_calls([{"tool": "submit_annotation", "arguments": snapshot}], "annotation")


def snapshot(**updates):
    return annotation(**updates)[0]["arguments"]


class SnapshotShapeRepairTests(unittest.TestCase):
    def assert_redundant_only(self, original, with_extras):
        expected = normalize(original)
        before = copy.deepcopy(with_extras)
        actual = normalize(with_extras)
        audit = actual.pop("annotation_normalizations")
        self.assertEqual(actual, expected)
        self.assertEqual(with_extras, before)
        self.assertTrue(audit)
        self.assertEqual(staged.public_normalizations(audit), audit)
        return audit

    def test_only_exact_outer_field_identity_name_is_redundant(self):
        for status in protocol.STATUSES:
            original = snapshot(vuln_title=decision("Synthetic title", status))
            with_extras = copy.deepcopy(original)
            with_extras["vuln_title"]["name"] = "vuln_title"
            with self.subTest(status=status):
                audit = self.assert_redundant_only(original, with_extras)
                self.assertEqual(audit, [{"field": "vuln_title", "code": "redundant_properties_removed",
                    "path": "$[0].arguments.vuln_title", "removed_keys": ["name"]}])
        for name in ("entry_point", "VULN_TITLE", None, ["vuln_title"]):
            result = normalize(snapshot(vuln_title=decision("Synthetic title", name=name)))
            self.assertEqual(result["annotation_errors"][0]["code"], "unexpected_properties")
            self.assertNotIn("annotation_normalizations", result)
            self.assertNotIn("vuln_title", result["fields"])

    def test_complete_location_and_decision_duplicates_leave_values_and_status_unchanged(self):
        for field in ("entry_point", "critical_operation"):
            for status in ("supported", "uncertain"):
                original = snapshot(**{field: decision(location(), status, evidence_refs=["E0001", "E0002"])})
                with_extras = copy.deepcopy(original)
                current = with_extras[field]
                current.update(copy.deepcopy(original[field]["value"]))
                current["value"].update({key: copy.deepcopy(current[key]) for key in ("status", "reason", "evidence_refs")})
                with self.subTest(field=field, status=status):
                    audit = self.assert_redundant_only(original, with_extras)
                    self.assertEqual([item["path"] for item in audit],
                                     [f"$[0].arguments.{field}", f"$[0].arguments.{field}.value"])
                    self.assertEqual(audit[0]["removed_keys"], ["desc", "end_line", "evidence_ref", "start_line"])
                    self.assertEqual(audit[1]["removed_keys"], ["evidence_refs", "reason", "status"])

    def test_conflicting_or_differently_typed_duplicates_discard_only_the_bad_field(self):
        cases = [("decision", "start_line", True), ("decision", "start_line", 10.0),
                 ("decision", "evidence_ref", "E9999"), ("decision", "desc", "different claim"),
                 ("location", "status", "uncertain"), ("location", "reason", "different limitation"),
                 ("location", "evidence_refs", ["E0002", "E0001"])]
        for where, key, value in cases:
            bad = decision(location(), evidence_refs=["E0001", "E0002"])
            target = bad if where == "decision" else bad["value"]
            target[key] = value
            with self.subTest(where=where, key=key, value=value):
                result = normalize(snapshot(entry_point=bad, vuln_title=decision("Legal sibling")))
                self.assertEqual(result["fields"], {"vuln_title": "Legal sibling"})
                self.assertNotIn("entry_point", result["field_reviews"])
                self.assertEqual(result["annotation_errors"][0]["code"], "unexpected_properties")
                self.assertNotIn("annotation_normalizations", result)

    def test_unknown_extras_are_not_ignored_even_when_empty_or_mixed_with_valid_duplicates(self):
        for extra in (None, "", {}, [], False, "private qualification"):
            for where in ("decision", "location"):
                bad = decision(location(), name="entry_point")
                target = bad if where == "decision" else bad["value"]
                target["private_unknown_key"] = extra
                with self.subTest(where=where, extra=extra):
                    result = normalize(snapshot(entry_point=bad))
                    self.assertNotIn("entry_point", result["field_reviews"])
                    self.assertNotIn("annotation_normalizations", result)
                    self.assertEqual(result["annotation_errors"][0]["code"], "unexpected_properties")
                    self.assertNotIn("private", json.dumps(result))
        # A basis on another field could qualify its meaning; do not drop it.
        result = normalize(snapshot(vuln_title=decision("Title", revision_basis="unknown")))
        self.assertEqual(result["annotation_errors"][0]["code"], "unexpected_properties")

    def test_required_properties_are_never_filled_from_extras_or_invented(self):
        for key in ("value", "status", "reason", "evidence_refs"):
            bad = decision(location(), name="entry_point")
            bad.pop(key)
            result = normalize(snapshot(entry_point=bad))
            self.assertNotIn("entry_point", result["field_reviews"])
            self.assertNotIn("annotation_normalizations", result)
        bad = decision(location(), desc="could look like a relocated value")
        bad["value"].pop("desc")
        result = normalize(snapshot(entry_point=bad))
        self.assertNotIn("entry_point", result["field_reviews"])
        self.assertNotIn("annotation_normalizations", result)
        for malformed in (decision("a" * 40, name="commit"),
                          decision("a" * 40, revision_basis="not-a-basis", name="commit")):
            result = normalize(snapshot(commit=malformed))
            self.assertNotIn("commit", result["field_reviews"])
            self.assertNotIn("annotation_normalizations", result)

    def test_all_existing_semantic_and_resource_bounds_still_apply_to_the_core(self):
        bad = [decision(unknown_location(), name="entry_point"),
               decision(unknown_location(desc="not empty"), "uncertain", name="entry_point"),
               decision(location(start_line=0), "uncertain", name="entry_point"),
               decision(location(end_line=9), name="entry_point"),
               decision(location(), reason="x" * 2001, name="entry_point"),
               decision([location()], name="entry_point")]
        for current in bad:
            with self.subTest(current=current):
                result = normalize(snapshot(entry_point=current, vuln_title=decision("Legal sibling")))
                self.assertEqual(result["fields"], {"vuln_title": "Legal sibling"})
                self.assertNotIn("annotation_normalizations", result)
        for value in ([location()] * 33, [location()] * 65):
            current = snapshot(trace=decision(value, name="trace"))
            if len(value) == 65:
                with self.assertRaises(staged.ProtocolError):
                    normalize(current)
            else:
                result = normalize(current)
                self.assertNotIn("trace", result["field_reviews"])
                self.assertNotIn("annotation_normalizations", result)

    def test_unknown_placeholder_stays_unknown_after_exact_duplicate_removal(self):
        for status in ("uncertain", "missing", "conflicting"):
            original = snapshot(entry_point=decision(unknown_location(), status))
            extra = copy.deepcopy(original)
            extra["entry_point"]["value"]["status"] = status
            self.assert_redundant_only(original, extra)
            result = normalize(extra)
            self.assertNotIn("entry_point", result["fields"])
            self.assertNotIn("suggested_value", result["field_reviews"]["entry_point"])
            self.assertEqual(result["field_reviews"]["entry_point"]["status"], status)

    def test_all_42_allowed_object_events_are_kept_without_truncation(self):
        original = staged.snapshot_from_state({}, {})
        original["trace"] = decision([location()] * 32, "uncertain")
        extra = copy.deepcopy(original)
        for field in staged.ANNOTATION_FIELDS:
            extra[field]["name"] = field
        for field in ("entry_point", "critical_operation"):
            extra[field]["value"]["status"] = extra[field]["status"]
        for item in extra["trace"]["value"]:
            item["status"] = extra["trace"]["status"]
        audit = self.assert_redundant_only(original, extra)
        self.assertEqual(len(audit), 42)
        self.assertEqual(len(staged.public_normalizations(audit)), 42)
        self.assertEqual(audit[-2]["path"], "$[0].arguments.trace.value[31]")

    def test_public_audit_filter_rejects_unknown_shapes_without_retaining_prose(self):
        valid = {"field": "entry_point", "code": "redundant_properties_removed",
                 "path": "$[0].arguments.entry_point.value", "removed_keys": ["status"]}
        invalid = [{**valid, "raw": "private-value"}, {**valid, "code": "private-code"},
                   {**valid, "path": "$[0].arguments.commit.value"},
                   {**valid, "path": "$[0].arguments.entry_point.value.status"},
                   {**valid, "removed_keys": ["private-key"]}, {**valid, "removed_keys": ["name"]},
                   {**valid, "removed_keys": ["status", "status"]}, {**valid, "field": []},
                   {**valid, "removed_keys": [True]}, {**valid, "removed_keys": "status"}]
        before = copy.deepcopy([valid, *invalid])
        self.assertEqual(staged.public_normalizations(before), [valid])
        self.assertEqual(before, [valid, *invalid])
        self.assertNotIn("private", json.dumps(staged.public_normalizations(before)))
        self.assertEqual(staged.public_normalizations([valid] * 43), [])
        self.assertEqual(staged.public_normalizations(None), [])

    def test_shape_feedback_identifies_decision_and_location_allowed_keys(self):
        bad = snapshot(vuln_title=decision("Title", private_unknown="private value"),
                       critical_operation=decision(location(private_unknown="private value")))
        errors = normalize(bad)["annotation_errors"]
        before = copy.deepcopy(errors)
        feedback = staged.annotation_shape_feedback(errors)
        self.assertEqual(errors, before)
        self.assertEqual([item["field"] for item in feedback], ["vuln_title", "critical_operation"])
        self.assertEqual(feedback[0]["allowed_keys"], ["value", "status", "reason", "evidence_refs"])
        self.assertEqual(feedback[1]["allowed_keys"], ["evidence_ref", "start_line", "end_line", "desc"])
        self.assertEqual(feedback[1]["path"], "$[0].arguments.critical_operation.value")
        self.assertEqual(feedback[0]["expected_shape"],
                         staged.tool_definitions("annotation")[0]["function"]["parameters"]["properties"]["vuln_title"])
        self.assertNotIn("private", json.dumps(feedback))
        feedback[0]["allowed_keys"].append("caller mutation")
        self.assertNotIn("caller mutation", json.dumps(staged.annotation_shape_feedback(errors)))

    def test_shape_feedback_is_bounded_and_only_derives_from_safe_schema_paths(self):
        errors = normalize({})["annotation_errors"]
        feedback = staged.annotation_shape_feedback(errors)
        self.assertEqual(len(feedback), 8)
        self.assertLessEqual(len(json.dumps(feedback, ensure_ascii=False, separators=(",", ":"))), 12000)
        for hint in feedback:
            self.assertLessEqual(len(json.dumps(hint, ensure_ascii=False, separators=(",", ":"))), 1400)
            self.assertEqual(set(hint["expected_shape"]["required"]), set(hint["allowed_keys"]))
        invalid = [{"field": "private-key", "code": "unexpected_properties", "path": "$"},
                   {"field": "entry_point", "code": "private-code", "path": "$[0].arguments.entry_point"},
                   {"field": "entry_point", "code": "unexpected_properties", "path": "$[0].arguments.commit"},
                   {"field": "entry_point", "code": "unexpected_properties", "path": "$[0].arguments.entry_point.value.calls"}]
        self.assertEqual(staged.annotation_shape_feedback(invalid), [])
        self.assertEqual(staged.annotation_shape_feedback(None), [])

    def test_root_controls_read_tools_and_unparsed_json_remain_strict(self):
        for extra in ("summary", "slot", "private_root"):
            with self.subTest(extra=extra), self.assertRaises(staged.ProtocolError):
                normalize({**snapshot(), extra: ""})
        with self.assertRaises(staged.ProtocolError):
            staged.normalize_calls([{"tool": "inspect_commit", "arguments": {"commit": "a" * 40, "name": "inspect_commit"}}], "read")
        with self.assertRaises(staged.ProtocolError):
            staged.normalize_calls([{"tool": "propose_candidates", "arguments": {"candidates": [], "name": "propose_candidates"}}], "candidate_selection")
        for arguments in ('{"vuln_title":', '{"vuln_title":{},"vuln_title":{}}'):
            body = json.loads(tool_envelope(arguments=arguments))
            body["choices"][0]["message"]["tool_calls"][0]["function"]["name"] = "submit_annotation"
            with self.assertRaises(transport._CompletionJSONBlocked):
                transport.parse_chat_response(json.dumps(body).encode(), response_mode="staged_tool", stage="annotation")

    def test_strict_sent_schema_and_versions_are_not_relaxed(self):
        self.assertEqual(staged.PROMPT_REVISION, "snapshot-guidance-v85")
        self.assertEqual(staged.STAGED_WIRE_VERSION, "snapshot-v2")
        self.assertEqual(staged.MULTI_STAGED_WIRE_VERSION, "candidate-serial-snapshot-v2")
        definition = staged.tool_definitions("annotation")[0]["function"]
        self.assertIs(definition["strict"], True)
        with_extras = snapshot(vuln_title=decision("Title", name="vuln_title"))
        self.assertFalse(protocol._matches(with_extras, definition["parameters"]))
        self.assertTrue(protocol._matches(snapshot(vuln_title=decision("Title")), definition["parameters"]))
        self.assertIn("unknown or conflicting extras remain errors", staged.instruction("annotation"))


if __name__ == "__main__":
    unittest.main()
