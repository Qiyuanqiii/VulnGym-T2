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


def tool_envelope(value=None, *, arguments=None, model="deepseek-v4-pro"):
    return json.dumps({"object": "chat.completion", "model": model, "choices": [{
        "index": 0, "finish_reason": "tool_calls", "message": {
            "role": "assistant", "content": None, "reasoning_content": "private hidden reasoning",
            "tool_calls": [{"id": "call_synthetic", "type": "function", "function": {
                "name": "submit_step", "arguments": arguments if arguments is not None else json.dumps(value or step())}}]}}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30}}).encode()


class ProtocolTests(unittest.TestCase):
    def test_schema_is_fresh_strict_and_uses_only_supported_vocabulary(self):
        definition = protocol.strict_tool_definition()
        self.assertEqual(definition["function"]["name"], "submit_step")
        self.assertIs(definition["function"]["strict"], True)
        seen_tools, seen_fields = set(), set()

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
                for child in value.values():
                    visit(child)
            elif isinstance(value, list):
                for child in value:
                    visit(child)
        visit(definition)
        self.assertEqual(seen_tools, set(READ_TOOLS))
        self.assertEqual(seen_fields, set(ENTRY_FIELDS))
        definition["function"]["parameters"]["properties"].clear()
        self.assertTrue(protocol.strict_tool_definition()["function"]["parameters"]["properties"])

    def test_all_fifteen_fields_preserve_native_types_and_commit_basis(self):
        location = {"file": "src/a.py", "line": "1-2", "code": "x = 1\nprint(x)", "desc": ""}
        values = {name: name + " value" for name in ENTRY_FIELDS}
        values.update(commit="a" * 40, vuln_ids=["GHSA-AAAA-BBBB-CCCC"],
                      entry_point=location, critical_operation={**location, "line": 1}, trace=[location], verify=0)
        result = protocol.normalize_step(step([record(name, value) for name, value in values.items()]))
        self.assertEqual(result["fields"], values)
        self.assertEqual(result["field_reviews"]["commit"]["revision_basis"], "behavior_at_revision")
        self.assertNotIn("revision_basis", result["field_reviews"]["entry_point"])

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
                   step([record()] * 16), step([record("trace", [{"file": "a", "line": 1, "code": "x", "desc": ""}] * 33)]),
                   step([record("vuln_title", "x" * 32_001)])]
        value = step([record()])
        value["records"][0]["evidence_refs"] = ["E0001"] * 25
        invalid.append(value)
        for value in invalid:
            with self.subTest(shape=value["action"]), self.assertRaises(protocol.ProtocolError):
                protocol.normalize_step(value)


if __name__ == "__main__":
    unittest.main()
