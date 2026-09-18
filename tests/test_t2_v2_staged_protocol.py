"""Pure staged-wire checks; no model, target repository, credentials or files."""
from copy import deepcopy
import json
import unittest

from vulngym_t2 import staged_protocol as staged


def annotation(**updates):
    value = staged.snapshot_from_state({}, {})
    value.update(updates)
    return [{"tool": "submit_annotation", "arguments": value}]


def decision(value, status="supported", **updates):
    result = {"value": value, "status": status, "reason": "Existing evidence supports this decision.",
              "evidence_refs": ["E0001"]}
    result.update(updates)
    return result


def location(**updates):
    return {"evidence_ref": "E0001", "start_line": 10, "end_line": 11, "desc": "", **updates}


def unknown_location(**updates):
    return {"evidence_ref": "", "start_line": 0, "end_line": 0, "desc": "", **updates}


class StagedProtocolTests(unittest.TestCase):
    def isolated_error(self, calls, field):
        result = staged.normalize_calls(calls, "annotation")
        self.assertNotIn(field, result["fields"])
        self.assertNotIn(field, result["field_reviews"])
        errors = [error for error in result["annotation_errors"] if error["field"] == field]
        self.assertEqual(len(errors), 1)
        self.assertEqual(set(errors[0]), {"field", "code", "path"})
        return errors[0]

    def test_native_definitions_are_stage_specific_and_have_no_union_or_metadata(self):
        read = staged.tool_definitions("read")
        followup = staged.tool_definitions("followup")
        final = staged.tool_definitions("annotation")
        self.assertEqual(len(read), 8)
        self.assertEqual({item["function"]["name"] for item in followup},
                         {"read_file", "search_code", "inspect_commit", "search_history", "read_diff", "finish_reading"})
        self.assertEqual([item["function"]["name"] for item in final], ["submit_annotation"])
        schema = final[0]["function"]["parameters"]
        self.assertEqual(set(schema["properties"]), set(staged.ANNOTATION_FIELDS))
        self.assertNotIn("summary", schema["properties"])
        for field in ("entry_point", "critical_operation"):
            value_schema = schema["properties"][field]["properties"]["value"]
            self.assertEqual(value_schema["type"], "object")
            self.assertEqual(set(value_schema["required"]), {"evidence_ref", "start_line", "end_line", "desc"})
            self.assertFalse(value_schema["additionalProperties"])
        self.assertEqual(schema["properties"]["trace"]["properties"]["value"]["type"], "array")
        encoded = json.dumps([read, followup, final])
        for forbidden in ('"anyOf"', '"has_value"', '"records"', '"entry_id"', '"verify"'):
            self.assertNotIn(forbidden, encoded)
        final[0]["function"]["parameters"]["properties"].clear()
        self.assertEqual(len(staged.tool_definitions("annotation")[0]["function"]["parameters"]["properties"]), 8)

    def test_one_read_normalizes_only_documented_optional_arguments(self):
        calls = [{"tool": "read_file", "arguments": {
            "commit": "a" * 40, "path": "src/file.py", "start_line": 1, "end_line": 0}}]
        before = deepcopy(calls)
        result = staged.normalize_calls(calls, "read")
        self.assertEqual(result, {"action": "tools", "plan": "", "calls": [{
            "tool": "read_file", "arguments": {"commit": "a" * 40, "path": "src/file.py", "start_line": 1}}]})
        self.assertEqual(calls, before)
        result = staged.normalize_calls([{"tool": "list_refs", "arguments": {"prefix": "", "limit": 30}}], "read")
        self.assertEqual(result["calls"][0]["arguments"], {"limit": 30})

    def test_native_descriptions_preserve_navigation_and_local_limit_guidance(self):
        descriptions = {item["function"]["name"]: item["function"]["description"]
                        for item in staged.tool_definitions("read")}
        self.assertIn("literal text in local commit messages", descriptions["search_history"])
        self.assertIn("list_refs first when HEAD is unavailable", descriptions["search_history"])
        self.assertIn("read_file", descriptions["search_code"])
        instruction = staged.instruction("annotation")
        self.assertEqual(staged.STAGED_WIRE_VERSION, "snapshot-v2")
        self.assertIn(staged.STAGED_WIRE_VERSION, instruction)
        self.assertIn("Do not supply summary", instruction)
        self.assertIn("entire snapshot", instruction)
        self.assertIn("each field's reason", instruction)
        self.assertIn("never an array", instruction)
        self.assertIn("desc may be empty", instruction)
        self.assertIn("Other malformed field decisions are discarded as a whole", instruction)
        self.assertIn("unknown or conflicting extras remain errors", instruction)
        self.assertIn("original single self-review", instruction)
        for limit in ("reason <=2000", "evidence_refs <=24", "trace <=32"):
            self.assertIn(limit, instruction)

    def test_annotation_has_no_summary_and_keeps_field_reasons_and_unknowns(self):
        reason = "The cited lines establish this source location."
        unknown_reason = "The operation is not established from the supplied evidence."
        calls = annotation(entry_point=decision(location(), reason=reason),
                           critical_operation=decision(unknown_location(), "uncertain", reason=unknown_reason))
        result = staged.normalize_calls(calls, "annotation")
        self.assertEqual(result["summary"], "")
        self.assertEqual(result["fields"], {"entry_point": location()})
        self.assertEqual(result["field_reviews"]["entry_point"]["reason"], reason)
        self.assertEqual(result["field_reviews"]["critical_operation"]["status"], "uncertain")
        self.assertEqual(result["field_reviews"]["critical_operation"]["reason"], unknown_reason)
        self.assertNotIn("suggested_value", result["field_reviews"]["critical_operation"])
        self.assertEqual(result["field_reviews"]["vuln_title"]["status"], "missing")
        for summary in ("", "short", " ", "x" * 1001, [], {}):
            with self.subTest(summary=type(summary).__name__), self.assertRaises(staged.ProtocolError) as caught:
                staged.normalize_calls(annotation(summary=summary), "annotation")
            self.assertEqual(caught.exception.diagnostic, {"phase": "validate_staged_step",
                "protocol_reason": "unexpected_properties", "protocol_path": "$[0].arguments"})

    def test_finish_reading_never_executes_or_changes_fields(self):
        self.assertEqual(staged.FINISH_REASONS,
                         ("enough_evidence", "no_further_useful_read", "reserve_annotation_budget"))
        for stage in ("read", "followup"):
            finish = next(item["function"] for item in staged.tool_definitions(stage)
                          if item["function"]["name"] == "finish_reading")
            self.assertEqual(finish["parameters"]["properties"]["reason"],
                             {"type": "string", "enum": list(staged.FINISH_REASONS)})
            for reason in staged.FINISH_REASONS:
                with self.subTest(stage=stage, reason=reason):
                    self.assertEqual(staged.normalize_calls([{"tool": "finish_reading", "arguments": {"reason": reason}}], stage),
                                     {"action": "finish_reading", "reason": reason})
                    self.assertIn(reason, finish["description"])
                    self.assertIn(reason, staged.instruction(stage))

    def test_finish_reading_free_form_and_long_reasons_are_schema_rejected(self):
        for stage in ("read", "followup"):
            for reason in ("", "Enough evidence.", "enough_evidence ", "x" * 501, "x" * 4096):
                with self.subTest(stage=stage, length=len(reason)), self.assertRaises(staged.ProtocolError) as caught:
                    staged.normalize_calls([{"tool": "finish_reading", "arguments": {"reason": reason}}], stage)
                self.assertEqual(caught.exception.diagnostic, {"phase": "validate_staged_step",
                    "protocol_reason": "enum_mismatch", "protocol_path": "$[0].arguments.reason"})

    def test_native_call_limits_and_stage_boundaries_are_enforced(self):
        read = {"tool": "inspect_commit", "arguments": {"commit": "a" * 40}}
        finish = {"tool": "finish_reading", "arguments": {"reason": "enough_evidence"}}
        cases = [(None, "read"), ([], "read"), ([read] * 5, "read"), ([read, read], "followup"), ([read, finish], "followup"),
                 ([read], "annotation"), ([finish], "annotation"), (annotation(), "read"),
                 ([{"tool": "list_refs", "arguments": {"prefix": "", "limit": 30}}], "followup")]
        for calls, stage in cases:
            with self.subTest(calls=calls, stage=stage), self.assertRaises(staged.ProtocolError):
                staged.normalize_calls(calls, stage)

    def test_annotation_reuses_existing_normal_form_and_keeps_locations_as_references(self):
        calls = annotation(commit=decision("a" * 40, revision_basis="behavior_at_revision"),
                           entry_point=decision(location()), critical_operation=decision(location(start_line=12, end_line=12)),
                           trace=decision([]), vuln_ids=decision([]), vuln_category_l1=decision("Injection"))
        before = deepcopy(calls)
        result = staged.normalize_calls(calls, "annotation")
        self.assertEqual(result["action"], "draft")
        self.assertEqual(result["fields"]["commit"], "a" * 40)
        self.assertEqual(result["fields"]["entry_point"], location())
        self.assertEqual(result["fields"]["trace"], [])
        self.assertEqual(result["fields"]["vuln_ids"], [])
        self.assertEqual(result["field_reviews"]["commit"]["revision_basis"], "behavior_at_revision")
        self.assertNotIn("file", result["fields"]["entry_point"])
        self.assertNotIn("code", result["fields"]["entry_point"])
        self.assertNotIn("revision_basis", result["field_reviews"]["entry_point"])
        self.assertEqual(calls, before)

    def test_unknown_decision_is_not_no_update_or_an_empty_official_fact(self):
        empty = staged.normalize_calls(annotation(), "annotation")
        self.assertEqual(empty["fields"], {})
        self.assertEqual(set(empty["field_reviews"]), set(staged.ANNOTATION_FIELDS))
        self.assertTrue(all(review["status"] == "missing" for review in empty["field_reviews"].values()))
        unknown = staged.normalize_calls(annotation(commit=decision("", "missing", revision_basis="unknown"),
                                                    entry_point=decision(unknown_location(), "uncertain"),
                                                    vuln_title=decision("", "conflicting")), "annotation")
        self.assertEqual(unknown["fields"], {})
        self.assertEqual(unknown["field_reviews"]["commit"]["status"], "missing")
        self.assertEqual(unknown["field_reviews"]["entry_point"]["status"], "uncertain")
        self.assertTrue(all("suggested_value" not in unknown["field_reviews"][field]
                            for field in ("commit", "entry_point", "vuln_title")))
        for field, value in (("commit", ""), ("vuln_title", ""), ("entry_point", unknown_location()), ("critical_operation", unknown_location())):
            with self.subTest(field=field):
                error = self.isolated_error(annotation(**{field: decision(value, **({"revision_basis": "unknown"} if field == "commit" else {}))}), field)
            self.assertEqual(error["code"], "supported_without_value")
            self.assertEqual(error["path"], "$[0].arguments." + field + ".value")

    def test_non_supported_candidates_remain_suggestions(self):
        result = staged.normalize_calls(annotation(commit=decision("a" * 40, "uncertain", revision_basis="inspected_only"),
                                                   entry_point=decision(location(), "conflicting")), "annotation")
        self.assertEqual(result["fields"], {})
        self.assertEqual(result["field_reviews"]["commit"]["suggested_value"], "a" * 40)
        self.assertEqual(result["field_reviews"]["entry_point"]["suggested_value"], location())

    def test_decision_cardinality_types_and_no_unknown_extra_fields(self):
        cases = [("entry_point", annotation(entry_point=decision([location(), location()]))),
                 ("vuln_title", annotation(vuln_title=[decision("one"), decision("two")])),
                 ("entry_point", annotation(entry_point=decision({"file": "src/file.py", "line": 1, "code": "invented"}))),
                 ("commit", annotation(commit=decision("HEAD", revision_basis="behavior_at_revision"))),
                 ("commit", annotation(commit=decision("a" * 40))),
                 ("vuln_title", annotation(vuln_title=decision("x", revision_basis="unknown"))),
                 ("vuln_ids", annotation(vuln_ids=decision("[]")))]
        for field, calls in cases:
            with self.subTest(field=field):
                self.isolated_error(calls, field)
        missing = annotation()
        del missing[0]["arguments"]["trace"]
        self.assertEqual(self.isolated_error(missing, "trace"), {"field": "trace", "code": "missing_property",
            "path": "$[0].arguments.trace"})
        with self.assertRaises(staged.ProtocolError):
            staged.normalize_calls(annotation(verify=decision(0)), "annotation")

    def test_existing_reference_and_range_limits_keep_precise_safe_paths(self):
        cases = [(annotation(entry_point=decision(location(end_line=9))), "location_range_invalid", "$[0].arguments.entry_point.value.end_line"),
                 (annotation(vuln_title=decision("x", evidence_refs=["unsafe-secret"])), "pattern_mismatch", "$[0].arguments.vuln_title.evidence_refs[0]"),
                 (annotation(trace=decision([location()] * 33)), "trace_limit", "$[0].arguments.trace.value"),
                 (annotation(vuln_title=decision("x", reason="x" * 2001)), "reason_limit", "$[0].arguments.vuln_title.reason")]
        for calls, reason, path in cases:
            field = path.split(".")[2].split("[")[0]
            with self.subTest(reason=reason):
                error = self.isolated_error(calls, field)
            self.assertEqual(error, {"field": field, "code": reason, "path": path})
            self.assertTrue(staged.is_safe_diagnostic_item("protocol_path", path))
            self.assertNotIn("unsafe-secret", str(error))

    def test_exact_unknown_placeholders_preserve_status_without_empty_facts(self):
        for field in ("entry_point", "critical_operation"):
            for status in ("uncertain", "missing", "conflicting"):
                with self.subTest(field=field, status=status):
                    result = staged.normalize_calls(annotation(**{field: decision(unknown_location(), status)}), "annotation")
                    self.assertNotIn(field, result["fields"])
                    self.assertEqual(result["field_reviews"][field]["status"], status)
                    self.assertNotIn("suggested_value", result["field_reviews"][field])

    def test_partial_placeholders_and_legacy_arrays_are_rejected_not_repaired(self):
        partial = [unknown_location(evidence_ref="E0001"), unknown_location(start_line=1),
                   unknown_location(end_line=1), unknown_location(desc="not empty"),
                   unknown_location(desc=" "), location(evidence_ref=""),
                   location(start_line=0), location(end_line=0)]
        for field in ("entry_point", "critical_operation"):
            for value in partial + [[], [location()], [location(), location()]]:
                with self.subTest(field=field, value=value):
                    error = self.isolated_error(annotation(**{field: decision(value, "uncertain")}), field)
                self.assertEqual(error["code"],
                                 "expected_object" if isinstance(value, list) else "location_placeholder_invalid")
                self.assertEqual(error["path"], "$[0].arguments." + field + ".value")
            for key in unknown_location():
                value = unknown_location()
                del value[key]
                with self.subTest(field=field, missing=key):
                    error = self.isolated_error(annotation(**{field: decision(value, "missing")}), field)
                self.assertEqual(error["code"], "missing_property")
                self.assertEqual(error["path"], "$[0].arguments." + field + ".value." + key)

    def test_bad_field_is_discarded_without_losing_or_promoting_siblings(self):
        calls = annotation(commit=decision("a" * 40, revision_basis="behavior_at_revision"),
                           entry_point=decision(location()),
                           critical_operation=decision(location(), private_unknown_key="private-field-value"),
                           vuln_title=decision("candidate only", "uncertain"), trace=decision([]))
        before = deepcopy(calls)
        result = staged.normalize_calls(calls, "annotation")
        self.assertEqual(result["fields"], {"commit": "a" * 40, "entry_point": location(), "trace": []})
        self.assertEqual(result["field_reviews"]["vuln_title"]["status"], "uncertain")
        self.assertEqual(result["field_reviews"]["vuln_title"]["suggested_value"], "candidate only")
        self.assertNotIn("critical_operation", result["field_reviews"])
        self.assertEqual(result["annotation_errors"], [{"field": "critical_operation",
            "code": "unexpected_properties", "path": "$[0].arguments.critical_operation"}])
        self.assertNotIn("private", json.dumps(result))
        self.assertEqual(calls, before)

    def test_all_invalid_fields_return_explicit_empty_draft_and_safe_errors(self):
        for invalid in (None, 1.5, {}, "private-invalid-field"):
            with self.subTest(invalid=type(invalid).__name__):
                result = staged.normalize_calls(annotation(**{field: invalid for field in staged.ANNOTATION_FIELDS}), "annotation")
                self.assertEqual(result["action"], "draft")
                self.assertEqual(result["fields"], {})
                self.assertEqual(result["field_reviews"], {})
                self.assertEqual(len(result["annotation_errors"]), 8)
                self.assertEqual({error["field"] for error in result["annotation_errors"]}, set(staged.ANNOTATION_FIELDS))
                self.assertNotIn("private", json.dumps(result))
                self.assertTrue(all(staged.is_safe_diagnostic_item("protocol_reason", error["code"])
                                    and staged.is_safe_diagnostic_item("protocol_path", error["path"])
                                    for error in result["annotation_errors"]))

    def test_isolation_requires_a_valid_native_envelope_and_parsed_json(self):
        from vulngym_t2 import transport
        from tests.test_t2_v2_protocol import tool_envelope

        arguments = annotation(vuln_title=decision("supported sibling"), entry_point=None)[0]["arguments"]
        body = json.loads(tool_envelope(arguments=json.dumps(arguments)))
        function = body["choices"][0]["message"]["tool_calls"][0]["function"]
        function["name"] = "submit_annotation"
        result = transport.parse_chat_response(json.dumps(body).encode(), response_mode="staged_tool", stage="annotation")
        self.assertEqual(result["fields"], {"vuln_title": "supported sibling"})
        self.assertEqual(result["annotation_errors"][0]["field"], "entry_point")
        for malformed in ('{"vuln_title":', json.dumps({**arguments, "private_root_key": "private-value"})):
            function["arguments"] = malformed
            with self.subTest(malformed=len(malformed)), self.assertRaises(transport.TransportError):
                transport.parse_chat_response(json.dumps(body).encode(), response_mode="staged_tool", stage="annotation")
        function["arguments"] = json.dumps(arguments)
        body["choices"][0]["message"]["tool_calls"] *= 2
        with self.assertRaisesRegex(transport.TransportError, "deepseek_strict_tool_call_invalid"):
            transport.parse_chat_response(json.dumps(body).encode(), response_mode="staged_tool", stage="annotation")

    def test_bounds_and_diagnostics_do_not_copy_untrusted_values(self):
        calls = [{"tool": "read_file", "arguments": {"commit": "a" * 40, "path": "", "start_line": 1, "end_line": 0}}]
        with self.assertRaises(staged.ProtocolError) as caught:
            staged.normalize_calls(calls, "read")
        self.assertEqual(caught.exception.diagnostic["protocol_path"], "$[0].arguments.path")
        error = staged.ProtocolError("secret text", "$[0].arguments.private_payload")
        self.assertEqual(error.diagnostic["protocol_reason"], "schema_mismatch")
        self.assertEqual(error.diagnostic["protocol_path"], "$")
        with self.assertRaises(staged.ProtocolError):
            staged.normalize_calls(annotation(summary="x" * 1001), "annotation")
        for stage in ("unknown", None, []):
            with self.assertRaisesRegex(ValueError, "staged_stage_invalid"):
                staged.tool_definitions(stage)


if __name__ == "__main__":
    unittest.main()
