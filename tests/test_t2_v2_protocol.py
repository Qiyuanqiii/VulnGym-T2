"""Offline typed-container checks; no provider or repository operations."""
import copy
import json
import unittest

from vulngym_t2 import protocol
from vulngym_t2.pipeline import ENTRY_FIELDS, READ_TOOLS


def record(name="commit", value="a" * 40, *, status="supported", has_value=True,
           revision_basis="behavior_at_revision"):
    return {"name": name, "has_value": has_value, "value": value, "status": status,
            "reason": "Brief cited mechanism, not human verification.", "evidence_refs": ["E0001"],
            "revision_basis": revision_basis if name == "commit" else "unknown"}


def step(records=None, *, calls=None):
    return {"action": "tools" if calls is not None else "draft",
            "plan": "Read source." if calls is not None else "", "calls": calls or [],
            "records": [] if records is None else records, "summary": ""}


def location_ref(*, evidence_ref="E0001", start_line=1, end_line=2, desc=""):
    return {"evidence_ref": evidence_ref, "start_line": start_line, "end_line": end_line, "desc": desc}


def tool_envelope(value=None, *, arguments=None, model="deepseek-v4-pro"):
    return json.dumps({"object": "chat.completion", "model": model, "choices": [{
        "index": 0, "finish_reason": "tool_calls", "message": {
            "role": "assistant", "content": None, "reasoning_content": "private hidden reasoning",
            "tool_calls": [{"id": "call_synthetic", "type": "function", "function": {
                "name": "submit_step", "arguments": arguments if arguments is not None else json.dumps(value or step())}}]}}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30}}).encode()


class ProtocolTests(unittest.TestCase):
    def test_read_batch_rejects_a_bad_later_range_or_blank_path_before_returning_calls(self):
        valid = {"tool": "inspect_commit", "arguments": {"commit": "a" * 40}}
        for path, start, end, reason, suffix in (("", 1, 0, "blank_argument", "path"),
                (" ", 1, 2, "blank_argument", "path"),
                ("handler.py", 3, 2, "numeric_range", "end_line")):
            value = step(calls=[valid, {"tool": "read_file", "arguments": {
                "commit": "a" * 40, "path": path, "start_line": start, "end_line": end}}])
            with self.subTest(suffix=suffix), self.assertRaises(protocol.ProtocolError) as caught:
                protocol.normalize_step(value)
            self.assertEqual(caught.exception.diagnostic["protocol_reason"], reason)
            self.assertEqual(caught.exception.diagnostic["protocol_path"], "$.calls[1].arguments." + suffix)
        default = step(calls=[{"tool": "read_file", "arguments": {
            "commit": "a" * 40, "path": "handler.py", "start_line": 3, "end_line": 0}}])
        self.assertNotIn("end_line", protocol.normalize_step(default)["calls"][0]["arguments"])

    def test_bounded_scalar_opt_in_does_not_change_legacy_schema_or_leak_encode_errors(self):
        for scalar in (None, 1.5):
            with self.subTest(scalar=scalar):
                protocol._bounded({"value": scalar}, allow_json_scalars=True)
                with self.assertRaises(protocol.ProtocolError):
                    protocol._bounded({"value": scalar})
        for scalar in (float("nan"), float("inf"), "\ud800", 10 ** 5000):
            with self.subTest(kind=type(scalar).__name__), self.assertRaises(protocol.ProtocolError) as caught:
                protocol._bounded({"value": scalar}, allow_json_scalars=True)
            self.assertEqual(caught.exception.diagnostic["protocol_reason"], "unsupported_value_type")

    def test_revision_basis_schema_matches_local_semantics_with_and_without_values(self):
        schema = protocol.strict_tool_definition()["function"]["parameters"]
        values = {name: "value" for name in ENTRY_FIELDS}
        values.update(commit="a" * 40, vuln_ids=[], entry_point=location_ref(),
                      critical_operation=location_ref(), trace=[], verify=0)
        for name in ENTRY_FIELDS:
            for has_value in (False, True):
                for basis in protocol.REVISION_BASES:
                    item = record(name, values[name] if has_value else "", has_value=has_value, status="missing")
                    item["revision_basis"] = basis
                    value = step([item])
                    accepted = name == "commit" or basis == "unknown"
                    with self.subTest(name=name, has_value=has_value, basis=basis):
                        self.assertEqual(protocol._matches(value, schema), accepted)
                        if accepted:
                            normalized = protocol.normalize_step(value)
                            self.assertEqual(normalized["field_reviews"][name]["status"], "missing")
                        else:
                            with self.assertRaises(protocol.ProtocolError):
                                protocol.normalize_step(value)

    def test_structural_diagnostics_select_known_branches_without_model_text(self):
        private = "PRIVATE_MODEL_TEXT"
        missing = step([record()])
        del missing["records"][0]["value"]
        wrong_line = step([record("entry_point", location_ref(end_line="private-line"))])
        unexpected = step(calls=[{"tool": "inspect_commit", "arguments": {"commit": "a" * 40, private: private}}])
        cases = [
            (missing, "missing_property", "$.records[0].value"),
            (wrong_line, "expected_integer", "$.records[0].value.end_line"),
            (unexpected, "unexpected_properties", "$.calls[0].arguments"),
            (step([record(private, private)]), "enum_mismatch", "$.records[0].name"),
            (step(calls=[{"tool": private, "arguments": {}}]), "enum_mismatch", "$.calls[0].tool"),
            (step([record("entry_point", location_ref(evidence_ref=private))]), "pattern_mismatch", "$.records[0].value.evidence_ref"),
        ]
        for value, reason, path in cases:
            with self.subTest(reason=reason, path=path), self.assertRaises(protocol.ProtocolError) as caught:
                protocol.normalize_step(value)
            self.assertEqual(caught.exception.diagnostic, {"phase": "validate_submit_step",
                             "protocol_reason": reason, "protocol_path": path})
            self.assertEqual(str(caught.exception), "deepseek_strict_protocol_invalid")
            self.assertNotIn(private, json.dumps(caught.exception.diagnostic))
            self.assertNotIn("private-line", json.dumps(caught.exception.diagnostic))

    def test_bounds_and_semantic_diagnostics_are_fixed_codes_and_index_paths(self):
        invalid_ref = step([record()])
        invalid_ref["records"][0]["evidence_refs"] = ["PRIVATE_VALUE"]
        long_reason = step([record()])
        long_reason["records"][0]["reason"] = "PRIVATE_VALUE" * 200
        cases = [
            (step([record(), record()]), "duplicate_record", "$.records[1].name"),
            (step([record("trace", [location_ref(start_line=3, end_line=2)])]),
             "location_range_invalid", "$.records[0].value[0].end_line"),
            (step([record("commit", "", has_value=False)]), "supported_without_value", "$.records[0].has_value"),
            (step(calls=[{"tool": "inspect_commit", "arguments": {"commit": " "}}]),
             "blank_argument", "$.calls[0].arguments.commit"),
            (invalid_ref, "evidence_ref_invalid", "$.records[0].evidence_refs[0]"),
            (long_reason, "reason_limit", "$.records[0].reason"),
            (step([record("vuln_title", "PRIVATE_VALUE" * 3000)]), "string_limit", "$"),
            (step(calls=[]), "tools_calls_required", "$.calls"),
        ]
        for value, reason, path in cases:
            with self.subTest(reason=reason), self.assertRaises(protocol.ProtocolError) as caught:
                protocol.normalize_step(value)
            self.assertEqual(caught.exception.diagnostic["protocol_reason"], reason)
            self.assertEqual(caught.exception.diagnostic["protocol_path"], path)
            self.assertNotIn("PRIVATE_VALUE", json.dumps(caught.exception.diagnostic))

    def test_diagnostic_inputs_are_sanitized_and_schema_explanation_does_not_validate(self):
        error = protocol.ProtocolError("PRIVATE_REASON", "$.records[0].PRIVATE_PROPERTY")
        self.assertEqual(error.diagnostic, {"phase": "validate_submit_step", "protocol_reason": "schema_mismatch", "protocol_path": "$"})
        self.assertFalse(protocol.is_safe_diagnostic_item("protocol_reason", "PRIVATE_REASON"))
        self.assertFalse(protocol.is_safe_diagnostic_item("protocol_path", "$.PRIVATE_PROPERTY"))
        self.assertTrue(protocol.is_safe_diagnostic_item("protocol_path", "$.records[0].value[1].end_line"))
        schema = protocol.strict_tool_definition()["function"]["parameters"]
        valid = step([record("entry_point", location_ref()), record()])
        self.assertIsNone(protocol._schema_error(valid, schema))
        self.assertTrue(protocol._matches(valid, schema))
        self.assertEqual(protocol.normalize_step(valid)["fields"]["entry_point"], location_ref())

    def test_schema_is_fresh_strict_and_uses_only_supported_vocabulary(self):
        definition = protocol.strict_tool_definition()
        self.assertEqual(definition["function"]["name"], "submit_step")
        self.assertIs(definition["function"]["strict"], True)
        seen_tools, seen_fields, seen_locations = set(), set(), []

        def visit(value):
            if isinstance(value, dict):
                self.assertFalse(set(value) & {"minLength", "maxLength", "minItems", "maxItems", "oneOf"})
                if value.get("type") == "object":
                    self.assertEqual(set(value["required"]), set(value["properties"]))
                    self.assertIs(value["additionalProperties"], False)
                    if "tool" in value["properties"]:
                        name = value["properties"]["tool"]["enum"][0]
                        seen_tools.add(name)
                        self.assertEqual(set(value["properties"]["arguments"]["properties"]), set(READ_TOOLS[name]))
                    if "has_value" in value["properties"]:
                        seen_fields.update(value["properties"]["name"]["enum"])
                    if "evidence_ref" in value["properties"]:
                        seen_locations.append(value)
                        self.assertEqual(set(value["properties"]), {"evidence_ref", "start_line", "end_line", "desc"})
                        self.assertFalse(set(value["properties"]) & {"file", "line", "code"})
                for child in value.values():
                    visit(child)
            elif isinstance(value, list):
                for child in value:
                    visit(child)
        visit(definition)
        self.assertEqual(seen_tools, set(READ_TOOLS))
        self.assertEqual(seen_fields, set(ENTRY_FIELDS))
        self.assertEqual(len(seen_locations), 2)
        definition["function"]["parameters"]["properties"].clear()
        self.assertTrue(protocol.strict_tool_definition()["function"]["parameters"]["properties"])

    def test_all_fifteen_fields_preserve_native_types_and_commit_basis(self):
        location = location_ref()
        values = {name: name + " value" for name in ENTRY_FIELDS}
        values.update(commit="a" * 40, vuln_ids=["GHSA-AAAA-BBBB-CCCC"],
                      entry_point=location, critical_operation={**location, "end_line": 1}, trace=[location], verify=0)
        result = protocol.normalize_step(step([record(name, value) for name, value in values.items()]))
        self.assertEqual(result["fields"], values)
        self.assertEqual(result["field_reviews"]["commit"]["revision_basis"], "behavior_at_revision")
        self.assertNotIn("revision_basis", result["field_reviews"]["entry_point"])

    def test_location_references_survive_normalization_for_fields_and_suggestions(self):
        for status in ("supported", "uncertain", "missing", "conflicting"):
            value = step([record("entry_point", location_ref(), status=status),
                          record("critical_operation", location_ref(start_line=3, end_line=4), status=status),
                          record("trace", [location_ref(), location_ref(start_line=3, end_line=4)], status=status)])
            original = copy.deepcopy(value)
            result = protocol.normalize_step(value)
            self.assertEqual(value, original)
            for item in value["records"]:
                if status == "supported":
                    normalized = result["fields"][item["name"]]
                else:
                    self.assertNotIn(item["name"], result["fields"])
                    normalized = result["field_reviews"][item["name"]]["suggested_value"]
                self.assertEqual(normalized, item["value"])
                self.assertIsNot(normalized, item["value"])

    def test_unknown_locations_stay_unknown_without_creating_references(self):
        result = protocol.normalize_step(step([record(name, "", has_value=False, status="missing")
                                               for name in ("entry_point", "critical_operation", "trace")]))
        self.assertEqual(result["fields"], {})
        for review in result["field_reviews"].values():
            self.assertNotIn("suggested_value", review)

    def test_location_reference_shape_and_ranges_are_checked_without_source_repair(self):
        invalid = [location_ref(evidence_ref=value) for value in ("", "E1", "E123456789", "e0001", "E0001\n", "advisory-1")]
        invalid.extend(location_ref(start_line=value) for value in (0, -1, True, "1", 1.0, 100_000_001))
        invalid.extend(location_ref(end_line=value) for value in (0, -1, False, "2", 2.0, 100_000_001))
        invalid.extend([location_ref(start_line=3, end_line=2),
                        {**location_ref(), "code": "must not be transcribed"},
                        {"file": "src/a.py", "line": 1, "code": "legacy public shape", "desc": ""},
                        {key: value for key, value in location_ref().items() if key != "desc"}])
        for location in invalid:
            for name in ("entry_point", "critical_operation", "trace"):
                value = [location] if name == "trace" else location
                with self.subTest(name=name, location=location), self.assertRaises(protocol.ProtocolError):
                    protocol.normalize_step(step([record(name, value)]))

    def test_unknown_placeholder_is_omitted_and_non_supported_values_are_suggestions(self):
        result = protocol.normalize_step(step([
            record("commit", "", has_value=False, status="missing", revision_basis="unknown"),
            record("vuln_title", "candidate", status="uncertain"),
            record("vuln_category_l1", "candidate", status="missing"),
            record("vuln_category_l2", "candidate", status="conflicting"),
        ]))
        self.assertEqual(result["fields"], {})
        self.assertNotIn("suggested_value", result["field_reviews"]["commit"])
        for name in ("vuln_title", "vuln_category_l1", "vuln_category_l2"):
            self.assertEqual(result["field_reviews"][name]["suggested_value"], "candidate")

    def test_read_argument_sentinels_normalize_without_inventing_commits(self):
        calls = [
            {"tool": "list_refs", "arguments": {"prefix": "", "limit": 30}},
            {"tool": "search_history", "arguments": {"query": "patch", "commit": "a" * 40, "path": "", "limit": 20}},
            {"tool": "read_file", "arguments": {"commit": "a" * 40, "path": "src/a.py", "start_line": 1, "end_line": 0}},
            {"tool": "search_code", "arguments": {"commit": "a" * 40, "query": "handler", "paths": []}},
        ]
        original = copy.deepcopy(calls)
        result = protocol.normalize_step(step(calls=calls))
        self.assertEqual(calls, original)
        self.assertNotIn("prefix", result["calls"][0]["arguments"])
        self.assertEqual(result["calls"][1]["arguments"]["commit"], "a" * 40)
        self.assertNotIn("path", result["calls"][1]["arguments"])
        self.assertNotIn("end_line", result["calls"][2]["arguments"])
        self.assertNotIn("paths", result["calls"][3]["arguments"])

    def test_duplicate_unknown_fields_wrong_types_and_json_string_values_are_rejected(self):
        invalid = [step([record(), record()]), step([record("unexpected")]),
                   step([record("entry_point", '{"file":"a.py","line":1}')]),
                   step([record("verify", True)]), step([record("verify", 1)]),
                   step([record("vuln_ids", "[]")]), step([record("commit", "", has_value=False)]),
                   step([record("commit", "guessed", has_value=False, status="missing")])]
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(protocol.ProtocolError):
                protocol.normalize_step(value)
        value = step([record("vuln_title", "title")])
        value["records"][0]["revision_basis"] = "inspected_only"
        with self.assertRaises(protocol.ProtocolError):
            protocol.normalize_step(value)

    def test_extra_missing_properties_unrecognized_tools_and_mixed_actions_rejected(self):
        invalid = [step(calls=[{"tool": "shell", "arguments": {"command": "noop"}}]),
                   step(calls=[]), step([record()], calls=[{"tool": "inspect_commit", "arguments": {"commit": "abc"}}])]
        for mutate in (lambda value: value.update(extra=True), lambda value: value.pop("records"),
                       lambda value: value["records"][0].update(extra=True),
                       lambda value: value["records"][0].pop("value")):
            value = step([record()])
            mutate(value)
            invalid.append(value)
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(protocol.ProtocolError):
                protocol.normalize_step(value)

    def test_local_bounds_remain_enforced_without_unsupported_schema_keywords(self):
        invalid = [step(calls=[{"tool": "inspect_commit", "arguments": {"commit": "a" * 40}}] * 7),
                   step([record()] * 16), step([record("trace", [location_ref()] * 33)]),
                   step([record("vuln_title", "x" * 32_001)])]
        value = step([record()])
        value["records"][0]["evidence_refs"] = ["E0001"] * 25
        invalid.append(value)
        for value in invalid:
            with self.subTest(shape=value["action"]), self.assertRaises(protocol.ProtocolError):
                protocol.normalize_step(value)


if __name__ == "__main__":
    unittest.main()
