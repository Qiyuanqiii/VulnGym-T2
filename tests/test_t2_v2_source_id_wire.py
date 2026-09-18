"""An explicit wire name distinguishes one location ID from reason citations."""
import copy
import json
import unittest

from vulngym_t2 import staged_protocol as staged, transport
from tests.test_t2_v2_snapshot_json import envelope


class SourceIdWireTests(unittest.TestCase):
    def snapshot(self):
        value = staged.snapshot_from_state({}, {})
        location = {"evidence_ref": "E0001", "start_line": 3, "end_line": 4, "desc": "Synthetic source location."}
        for field in ("entry_point", "critical_operation"):
            value[field] = {"value": dict(location), "status": "uncertain", "reason": "Premise unresolved.", "evidence_refs": ["E0001"]}
        value["trace"] = {"value": [dict(location)], "status": "uncertain", "reason": "Connection unverified.", "evidence_refs": ["E0001"]}
        return value

    def test_schema_and_template_use_one_source_id_but_plural_citations(self):
        tool = staged.tool_definitions("annotation", location_key="source_id")[0]["function"]
        for field in ("entry_point", "critical_operation", "trace"):
            schema = tool["parameters"]["properties"][field]
            self.assertIn("evidence_refs", schema["properties"])
            location = schema["properties"]["value"]
            if field == "trace":
                location = location["items"]
            self.assertIn("source_id", location["properties"])
            self.assertIn("source_id", location["required"])
            self.assertNotIn("evidence_ref", location["properties"])
        text = staged.instruction("annotation", location_key="source_id")
        self.assertIn('"source_id": ""', text)
        self.assertNotIn('"evidence_ref":', text)
        self.assertIn("evidence_refs", text)

    def test_lossless_roundtrip_never_changes_source_ids_locations_or_statuses(self):
        original = self.snapshot()
        saved = copy.deepcopy(original)
        encoded = staged.source_id_snapshot(original)
        legacy = staged.normalize_calls([{"tool": "submit_annotation", "arguments": original}], "annotation")
        actual = staged.normalize_calls([{"tool": "submit_annotation", "arguments": encoded}], "annotation", location_key="source_id")
        self.assertEqual(actual, legacy)
        self.assertEqual(original, saved)
        for field in ("entry_point", "critical_operation", "trace"):
            self.assertEqual(actual["field_reviews"][field]["status"], "uncertain")

    def test_old_key_or_both_keys_rejects_field_instead_of_picking_one(self):
        for variant in ("old_only", "both_equal", "both_conflicting", "array"):
            value = staged.source_id_snapshot(self.snapshot())
            location = value["entry_point"]["value"]
            if variant == "old_only":
                location["evidence_ref"] = location.pop("source_id")
            elif variant.startswith("both"):
                location["evidence_ref"] = "E0001" if variant == "both_equal" else "E9999"
            else:
                location["source_id"] = ["E0001"]
            with self.subTest(variant=variant):
                result = staged.normalize_calls([{"tool": "submit_annotation", "arguments": value}], "annotation", location_key="source_id")
                self.assertNotIn("entry_point", result["field_reviews"])
                self.assertIn("critical_operation", result["field_reviews"])
                self.assertEqual([row["field"] for row in result["annotation_errors"]], ["entry_point"])

    def test_duplicate_actual_keys_are_strictly_rejected_before_any_conversion(self):
        raw = json.loads(envelope(call=("submit_annotation", staged.source_id_snapshot(self.snapshot()))))
        function = raw["choices"][0]["message"]["tool_calls"][0]["function"]
        function["arguments"] = function["arguments"].replace('"source_id": "E0001"', '"source_id": "E0001", "source_id": "E9999"', 1)
        with self.assertRaises(transport.TransportError) as caught:
            transport._parse_completion_json(function["arguments"], unwrap_fence=False)
        diagnostic = transport.public_failure_diagnostics(caught.exception.diagnostic)
        self.assertEqual(diagnostic["duplicate_key_name"], "source_id")
        self.assertNotIn("E9999", json.dumps(diagnostic))
        rejected = transport.parse_chat_response(json.dumps(raw).encode(), response_mode="staged_tool",
                                                  stage="annotation", location_key="source_id")
        self.assertEqual(rejected, {"action": "annotation_snapshot_rejected", "code": "duplicate_location_key",
            "path": "$[0].arguments", "duplicate_fields": ["entry_point"],
            "known_duplicate_keys": ["source_id"], "duplicate_key_count": 1})
        self.assertNotIn("fields", rejected)
        self.assertNotIn("field_reviews", rejected)
        self.assertNotIn("E9999", json.dumps(rejected))

    def test_legacy_wire_not_silently_changed(self):
        original = self.snapshot()
        encoded = staged.source_id_snapshot(original)
        result = staged.normalize_calls([{"tool": "submit_annotation", "arguments": encoded}], "annotation")
        self.assertEqual({row["field"] for row in result["annotation_errors"]}, {"entry_point", "critical_operation", "trace"})
        self.assertIn('"evidence_ref": ""', staged.annotation_template_json())
        self.assertEqual(staged.STAGED_WIRE_VERSION, "snapshot-v2")

    def test_new_key_cannot_be_selected_for_read_tools_or_plain_assessment(self):
        with self.assertRaises(ValueError):
            staged.tool_definitions("read", location_key="source_id")
        with self.assertRaises(ValueError):
            transport.parse_chat_response(envelope(content="note"), response_mode="assessment_text", location_key="source_id")


if __name__ == "__main__":
    unittest.main()
