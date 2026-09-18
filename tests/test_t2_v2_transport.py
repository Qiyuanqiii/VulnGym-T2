"""Offline-only transport checks: HTTPS and timers are replaced by test doubles."""

import ast
import json
from pathlib import Path
import unittest
from unittest.mock import MagicMock, patch

from vulngym_t2 import transport
from tests.test_t2_v2_protocol import record, step, tool_envelope
from tests.test_t2_v2_staged_protocol import annotation, decision, location, unknown_location


def envelope(content='{"action":"draft"}', *, finish="stop", model=None):
    return json.dumps({
        "object": "chat.completion", "model": model or transport.MODEL_ID,
        "choices": [{"index": 0, "finish_reason": finish, "message": {
            "role": "assistant", "content": content,
            "reasoning_content": "private reasoning must never enter returned fields"}}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30},
    }).encode()


class FakeResponse:
    def __init__(self, body=b"{}", *, status=200, headers=None):
        self.body, self.status = body, status
        self.headers = {} if headers is None else headers
        self.position = 0
        self.closed = False

    def getheader(self, name, default=None):
        return self.headers.get(name, default)

    def isclosed(self):
        return self.position >= len(self.body)

    def read1(self, limit):
        chunk = self.body[self.position:self.position + limit]
        self.position += len(chunk)
        return chunk

    def close(self):
        self.closed = True


class TransportTests(unittest.TestCase):
    def staged_envelope(self, calls):
        body = json.loads(tool_envelope(arguments=json.dumps(calls[0]["arguments"])))
        body["choices"][0]["message"]["tool_calls"][0]["function"]["name"] = "submit_annotation"
        return json.dumps(body).encode()

    def test_staged_single_location_object_and_exact_unknown_normalize_from_native_call(self):
        body = self.staged_envelope(annotation(entry_point=decision(location()),
            critical_operation=decision(unknown_location(), "uncertain"), trace=decision([location()])))
        result = transport.parse_chat_response(body, response_mode="staged_tool", stage="annotation")
        self.assertEqual(result["fields"]["entry_point"], location())
        self.assertEqual(result["fields"]["trace"], [location()])
        self.assertNotIn("critical_operation", result["fields"])
        self.assertEqual(result["field_reviews"]["critical_operation"]["status"], "uncertain")
        self.assertNotIn("suggested_value", result["field_reviews"]["critical_operation"])
        self.assertNotIn("private hidden reasoning", json.dumps(result))

    def test_staged_location_wire_failures_preserve_only_new_schema_paths(self):
        cases = [([], "uncertain", "expected_object", ".value"),
                 ([location()], "supported", "expected_object", ".value"),
                 ([location(), location()], "supported", "expected_object", ".value"),
                 (unknown_location(), "supported", "supported_without_value", ".value"),
                 (unknown_location(desc="private placeholder detail"), "missing", "location_placeholder_invalid", ".value"),
                 (location(end_line="private line"), "uncertain", "expected_integer", ".value.end_line")]
        for value, status, reason, suffix in cases:
            with self.subTest(reason=reason, value=value):
                result = transport.parse_chat_response(self.staged_envelope(annotation(
                    entry_point=decision(location()), critical_operation=decision(value, status))),
                    response_mode="staged_tool", stage="annotation")
                self.assertEqual(result["annotation_errors"], [{"field": "critical_operation",
                    "code": reason, "path": "$[0].arguments.critical_operation" + suffix}])
                self.assertEqual(result["fields"]["entry_point"], location())
                self.assertNotIn("critical_operation", result["fields"])
                self.assertNotIn("critical_operation", result["field_reviews"])
                self.assertNotIn("private", json.dumps(result))

    def test_staged_old_decision_arrays_are_isolated_but_outer_controls_are_rejected(self):
        result = transport.parse_chat_response(self.staged_envelope(annotation(
            entry_point=decision(location()), critical_operation=[decision(location())])),
            response_mode="staged_tool", stage="annotation")
        self.assertEqual(result["fields"]["entry_point"], location())
        self.assertEqual(result["annotation_errors"], [{"field": "critical_operation",
            "code": "expected_object", "path": "$[0].arguments.critical_operation"}])
        for control in ("summary", "slot", "entries", "private_control"):
            calls = annotation()
            calls[0]["arguments"][control] = "private response value"
            with self.subTest(control=control), self.assertRaises(transport.TransportError) as caught:
                transport.parse_chat_response(self.staged_envelope(calls),
                                              response_mode="staged_tool", stage="annotation")
            self.assertEqual(caught.exception.error_code, "deepseek_staged_protocol_invalid")
            self.assertNotIsInstance(caught.exception, transport._CompletionJSONBlocked)
            self.assertNotIn("private", json.dumps(caught.exception.diagnostic))

    def test_staged_snapshot_argument_json_remains_strict_without_repair(self):
        for arguments in ('{"unfinished":', '{"commit":{},"commit":{}}', '[]',
                          '```json\n{}\n```', '{} trailing'):
            body = json.loads(tool_envelope(arguments=arguments))
            body["choices"][0]["message"]["tool_calls"][0]["function"]["name"] = "submit_annotation"
            with self.subTest(arguments=arguments), self.assertRaises(transport._CompletionJSONBlocked) as caught:
                transport.parse_chat_response(json.dumps(body).encode(),
                                              response_mode="staged_tool", stage="annotation")
            self.assertEqual(caught.exception.diagnostic["phase"], "parse_completion_json")
            self.assertFalse(caught.exception.diagnostic["outer_code_fence_unwrapped"])

    def test_staged_omission_and_empty_objects_cross_transport_as_explicit_field_errors(self):
        calls = annotation(vuln_title=decision("Legal sibling"))
        del calls[0]["arguments"]["entry_point"]
        result = transport.parse_chat_response(self.staged_envelope(calls), response_mode="staged_tool", stage="annotation")
        self.assertEqual(result["fields"], {"vuln_title": "Legal sibling"})
        self.assertEqual(result["annotation_errors"], [{"field": "entry_point", "code": "missing_property",
            "path": "$[0].arguments.entry_point"}])
        result = transport.parse_chat_response(self.staged_envelope([{"arguments": {}}]),
                                               response_mode="staged_tool", stage="annotation")
        self.assertEqual(len(result["annotation_errors"]), 8)
        self.assertEqual((result["fields"], result["field_reviews"]), ({}, {}))

    def test_staged_resource_exhaustion_remains_global_not_partial_recovery(self):
        oversized = annotation(vuln_title=decision("Legal sibling"), entry_point=decision([None] * 65))
        with self.assertRaises(transport._FormatBlocked) as caught:
            transport.parse_chat_response(self.staged_envelope(oversized), response_mode="staged_tool", stage="annotation")
        self.assertEqual(caught.exception.diagnostic["protocol_reason"], "array_limit")
        self.assertNotIsInstance(caught.exception, transport._CompletionJSONBlocked)

    def test_strict_function_answer_normalizes_typed_fields_without_hidden_reasoning(self):
        value = step([record(), record("vuln_title", "unconfirmed", status="uncertain")])
        envelope_value = json.loads(tool_envelope(value))
        envelope_value["choices"][0]["message"]["content"] = "ancillary prose must not become an answer"
        result = transport.parse_chat_response(json.dumps(envelope_value).encode(), response_mode="strict_tool")
        self.assertEqual(result["fields"], {"commit": "a" * 40})
        self.assertEqual(result["field_reviews"]["commit"]["revision_basis"], "behavior_at_revision")
        self.assertEqual(result["field_reviews"]["vuln_title"]["suggested_value"], "unconfirmed")
        self.assertNotIn("private hidden reasoning", json.dumps(result))
        self.assertNotIn("ancillary prose", json.dumps(result))
        self.assertNotIn("tool_calls", result)

    def test_strict_mode_rejects_text_fallback_multiple_wrong_or_malformed_functions(self):
        with self.assertRaises(transport.TransportError):
            transport.parse_chat_response(envelope(), response_mode="strict_tool")
        mutations = [
            lambda message: message["tool_calls"].append(message["tool_calls"][0]),
            lambda message: message["tool_calls"][0]["function"].update(name="execute_shell"),
            lambda message: message["tool_calls"][0]["function"].update(arguments={}),
            lambda message: message["tool_calls"][0]["function"].update(extra="not allowed"),
            lambda message: message["tool_calls"][0].update(type="shell"),
            lambda message: message["tool_calls"][0].pop("id"),
            lambda message: message.update(content={"malformed": "content"}),
            lambda message: message.update(role="user"),
            lambda message: message.update(refusal="cannot comply"),
        ]
        for mutate in mutations:
            body = json.loads(tool_envelope())
            mutate(body["choices"][0]["message"])
            with self.subTest(mutation=mutations.index(mutate)), self.assertRaises(transport.TransportError) as caught:
                transport.parse_chat_response(json.dumps(body).encode(), response_mode="strict_tool")
            self.assertNotIsInstance(caught.exception, transport._CompletionJSONBlocked)

    def test_tool_shape_diagnostics_keep_only_counts_and_whitelisted_names(self):
        body = json.loads(tool_envelope())
        message = body["choices"][0]["message"]
        message["tool_calls"].extend([
            {"function": {"name": "private-unknown-tool", "arguments": "private-arguments"}},
            {"function": {"name": "read_file", "arguments": "private-source"}},
            {"function": {"name": ["private-malformed-name"]}},
        ])
        with self.assertRaises(transport.TransportError) as caught:
            transport.parse_chat_response(json.dumps(body).encode(), response_mode="strict_tool")
        self.assertEqual(caught.exception.error_code, "deepseek_strict_tool_call_invalid")
        self.assertEqual(caught.exception.diagnostic, {"tool_call_count": 4,
            "tool_names": ["read_file", "submit_step"], "unknown_tool_count": 2})
        self.assertNotIn("private", json.dumps(caught.exception.diagnostic))
        self.assertEqual(transport._tool_call_diagnostics({"tool_calls": "private-not-an-array"}),
                         {"tool_call_count": None, "tool_names": [], "unknown_tool_count": None})
        self.assertEqual(transport._tool_call_diagnostics({"tool_calls": []}),
                         {"tool_call_count": 0, "tool_names": [], "unknown_tool_count": 0})
        self.assertEqual(transport._safe_tool_diagnostics({"tool_call_count": True,
            "unknown_tool_count": -1, "tool_names": ["read_file", "private-name"], "arguments": "private"}), {})

    def test_strict_arguments_do_not_unwrap_repair_or_skip_schema_validation(self):
        for arguments in ('{"bad":', '{} {}', '[]', '```json\n{}\n```', '{"a":1,"a":2}'):
            with self.subTest(arguments=arguments), self.assertRaises(transport._CompletionJSONBlocked) as caught:
                transport.parse_chat_response(tool_envelope(arguments=arguments), response_mode="strict_tool")
            self.assertEqual(caught.exception.diagnostic["phase"], "parse_completion_json")
            self.assertFalse(caught.exception.diagnostic["outer_code_fence_unwrapped"])
        with self.assertRaisesRegex(transport.TransportError, "deepseek_strict_protocol_invalid") as caught:
            transport.parse_chat_response(tool_envelope(arguments='{"action":"draft"}'), response_mode="strict_tool")
        self.assertNotIsInstance(caught.exception, transport._CompletionJSONBlocked)

    def test_protocol_failure_preserves_only_structural_diagnostics(self):
        value = step()
        value["unexpected_private_key"] = "private response value"
        with self.assertRaises(transport.TransportError) as caught:
            transport.parse_chat_response(tool_envelope(value), response_mode="strict_tool")
        error = caught.exception
        self.assertEqual(error.error_code, "deepseek_strict_protocol_invalid")
        self.assertNotIsInstance(error, transport._CompletionJSONBlocked)
        self.assertEqual(error.diagnostic["phase"], "validate_submit_step")
        self.assertEqual(set(error.diagnostic), {"phase", "protocol_reason", "protocol_path"})
        self.assertNotIn("private", json.dumps(error.diagnostic))

    def test_format_isolation_marker_requires_completed_valid_envelope(self):
        for mutation in (lambda body: body.update(model="other"),
                         lambda body: body.update(object="wrong"),
                         lambda body: body["choices"][0].update(finish_reason="length"),
                         lambda body: body["choices"][0]["message"].update(refusal="refused")):
            body = json.loads(envelope('{"bad":'))
            mutation(body)
            with self.assertRaises(transport.TransportError) as caught:
                transport.parse_chat_response(json.dumps(body).encode())
            self.assertNotIsInstance(caught.exception, transport._CompletionJSONBlocked)
        with self.assertRaises(transport.TransportError) as caught:
            transport.parse_chat_response(b'{"bad":')
        self.assertNotIsInstance(caught.exception, transport._CompletionJSONBlocked)

    def test_strict_beta_endpoint_is_one_post_same_host_and_rejects_other_paths(self):
        connection = MagicMock()
        connection.getresponse.return_value = FakeResponse(b"{}")
        with patch.object(transport.http.client, "HTTPSConnection", return_value=connection) as factory, patch.object(transport, "Timer"):
            self.assertEqual(transport._post_official_strict(b"{}", "unit-test-key", 5), b"{}")
        factory.assert_called_once_with("api.deepseek.com", timeout=5)
        self.assertEqual(connection.request.call_args.args, ("POST", "/beta/chat/completions"))
        self.assertEqual(connection.request.call_count, 1)
        with patch.object(transport.http.client, "HTTPSConnection") as factory:
            with self.assertRaisesRegex(transport.TransportError, "deepseek_api_path_invalid"):
                transport._post_official(b"{}", "unit-test-key", 5, api_path="https://elsewhere.invalid")
        factory.assert_not_called()

    def test_standalone_imports_and_structured_answer_only(self):
        source = Path(transport.__file__).read_text(encoding="utf-8")
        imports = [node.module for node in ast.walk(ast.parse(source)) if isinstance(node, ast.ImportFrom)]
        self.assertFalse(any(name and name.startswith("vulngym_agent") for name in imports))
        self.assertEqual(transport.parse_chat_response(envelope()), {"action": "draft"})
        self.assertNotIn("private reasoning", json.dumps(transport.parse_chat_response(envelope())))

    def test_strict_json_rejects_duplicates_nonfinite_arrays_and_oversize(self):
        for raw in (b'{"a":1,"a":2}', b'{"v":NaN}', b'{"v":1e999}', b'[]', b'\xff'):
            with self.subTest(raw=raw), self.assertRaises(transport.TransportError):
                transport._strict_object(raw)
        with patch.object(transport, "MAX_RESPONSE_BYTES", 2):
            with self.assertRaisesRegex(transport.TransportError, "deepseek_response_too_large"):
                transport._strict_object(b'{"a":1}')

    def test_bounded_json_depth_nodes_strings_and_object_keys(self):
        nested = None
        for _ in range(18):
            nested = [nested]
        values = [{"v": nested}, {"v": [None] * 10_001}, {"v": "x" * 262_145}, {"x" * 257: 1}]
        for value in values:
            with self.subTest(shape=type(value)), self.assertRaisesRegex(transport.TransportError, "deepseek_response_invalid_json"):
                transport.parse_chat_response(envelope(json.dumps(value)))

    def test_truncation_retains_safe_usage_counters_not_response_text(self):
        with self.assertRaises(transport.TransportError) as caught:
            transport.parse_chat_response(envelope("private answer", finish="length"))
        error = caught.exception
        self.assertEqual(error.error_code, "deepseek_output_truncated")
        self.assertEqual(error.diagnostic["total_tokens"], 30)
        self.assertTrue(error.diagnostic["usage_consistent"])
        self.assertEqual(error.diagnostic["answer_characters"], len("private answer"))
        self.assertNotIn("private answer", json.dumps(error.diagnostic))
        self.assertNotIn("private reasoning", json.dumps(error.diagnostic))

    def test_model_envelope_tool_calls_and_incomplete_completion_rejected(self):
        with self.assertRaisesRegex(transport.TransportError, "deepseek_response_model_mismatch"):
            transport.parse_chat_response(envelope(model="another-model"))
        body = json.loads(envelope())
        body["choices"][0]["message"]["tool_calls"] = [{"function": {"name": "shell"}}]
        with self.assertRaisesRegex(transport.TransportError, "deepseek_response_invalid"):
            transport.parse_chat_response(json.dumps(body).encode())
        for reason, code in (("content_filter", "deepseek_content_filtered"),
                             ("insufficient_system_resource", "deepseek_resource_unavailable"),
                             (None, "deepseek_completion_incomplete")):
            with self.subTest(reason=reason), self.assertRaisesRegex(transport.TransportError, code):
                transport.parse_chat_response(envelope(finish=reason))

    def test_explicit_refusal_is_not_misclassified_as_empty_or_accepted(self):
        for content in ("   ", '{"action":"draft"}'):
            body = json.loads(envelope(content))
            body["choices"][0]["message"]["refusal"] = "provider refusal text is not logged"
            with self.assertRaisesRegex(transport.TransportError, "deepseek_refusal"):
                transport.parse_chat_response(json.dumps(body).encode())

    def test_one_full_json_or_unlabelled_fence_is_unwrapped_without_json_changes(self):
        payload = '{"action":"draft","fields":{"code":"literal ``` and \\\\n stay literal"}}'
        for wrapped in ("```json\n" + payload + "\n```", "```\n" + payload + "\n```",
                        " \r\n```json\r\n" + payload + "\r\n```\r\n "):
            with self.subTest(wrapped=wrapped[:12]):
                normalized, unwrapped = transport._unwrap_json_fence(wrapped)
                self.assertTrue(unwrapped)
                self.assertEqual(normalized, payload)
                self.assertEqual(transport.parse_chat_response(envelope(wrapped)), json.loads(payload))
        # Envelope JSON is never unwrapped; only a completion's text may be.
        with self.assertRaises(transport.TransportError):
            transport._strict_object(b'```json\n{}\n```')

    def test_prefixed_trailing_multiple_and_other_language_fences_remain_invalid(self):
        cases = [
            'Here is the answer:\n```json\n{}\n```',
            '```json\n{}\n```\nExtra trailing text',
            '```json\n{}\n```\n```json\n{}\n```',
            '```javascript\n{}\n```',
            '```json\n{}\n{}\n```',
            '```json\n{"a":1,}\n```',
            '```json\n{"a":1,"a":2}\n```',
            '```json\n{"a":NaN}\n```',
            '{} trailing private text',
        ]
        for content in cases:
            with self.subTest(shape=content[:20]), self.assertRaises(transport.TransportError) as caught:
                transport.parse_chat_response(envelope(content))
            self.assertEqual(caught.exception.error_code, "deepseek_response_invalid_json")
        with self.assertRaises(transport.TransportError) as caught:
            transport.parse_chat_response(envelope('```json\n{"a":1,"a":2}\n```'))
        self.assertEqual(caught.exception.diagnostic["json_error_kind"], "duplicate_key")

    def test_invalid_json_diagnostic_contains_parser_coordinates_but_no_answer(self):
        content = '{\n  "private_secret_marker": [1 2]\n}'
        with self.assertRaises(transport.TransportError) as caught:
            transport.parse_chat_response(envelope(content))
        diagnostic = caught.exception.diagnostic
        self.assertEqual(diagnostic["phase"], "parse_completion_json")
        self.assertEqual(diagnostic["json_decode_message"], "Expecting ',' delimiter")
        self.assertEqual(diagnostic["json_decode_line"], 2)
        self.assertEqual(diagnostic["json_decode_column"], 31)
        self.assertEqual(diagnostic["first_nonspace_category"], "object_start")
        self.assertFalse(diagnostic["answer_contains_code_fence"])
        self.assertFalse(diagnostic["outer_code_fence_unwrapped"])
        self.assertEqual(diagnostic["answer_characters"], len(content))
        serialized = json.dumps(diagnostic)
        self.assertNotIn("private_secret_marker", serialized)
        self.assertNotIn("private reasoning", serialized)
        self.assertLess(len(serialized), 1000)
        self.assertEqual(str(caught.exception), "deepseek_response_invalid_json")

    def test_fenced_failure_diagnostics_do_not_override_refusal_or_truncation(self):
        content = '```json\n{"private_secret_marker": }\n```'
        with self.assertRaises(transport.TransportError) as caught:
            transport.parse_chat_response(envelope(content))
        diagnostic = caught.exception.diagnostic
        self.assertTrue(diagnostic["answer_contains_code_fence"])
        self.assertTrue(diagnostic["outer_code_fence_unwrapped"])
        self.assertEqual(diagnostic["answer_first_nonspace_category"], "backtick")
        self.assertEqual(diagnostic["first_nonspace_category"], "object_start")
        self.assertEqual(diagnostic["json_decode_line"], 1)
        self.assertNotIn("private_secret_marker", json.dumps(diagnostic))
        for finish, code in (("content_filter", "deepseek_content_filtered"),
                             ("length", "deepseek_output_truncated")):
            with self.subTest(finish=finish), patch.object(transport, "_unwrap_json_fence") as unwrap:
                with self.assertRaisesRegex(transport.TransportError, code):
                    transport.parse_chat_response(envelope('```json\n{}\n```', finish=finish))
            unwrap.assert_not_called()

    def test_one_post_to_fixed_official_endpoint_with_timer_cleanup(self):
        response = FakeResponse(b'{"ok":true}', headers={"Content-Length": "11"})
        connection = MagicMock()
        connection.getresponse.return_value = response
        with patch.object(transport.http.client, "HTTPSConnection", return_value=connection) as factory, patch.object(transport, "Timer") as timer:
            result = transport._post_official(b"{}", "unit-test-key", 5)
        self.assertEqual(result, b'{"ok":true}')
        factory.assert_called_once_with("api.deepseek.com", timeout=5)
        connection.request.assert_called_once_with("POST", "/chat/completions", body=b"{}", headers={
            "Authorization": "Bearer unit-test-key", "Content-Type": "application/json",
            "Accept": "application/json", "Accept-Encoding": "identity"})
        timer.return_value.start.assert_called_once()
        timer.return_value.cancel.assert_called_once()
        connection.close.assert_called_once()
        self.assertTrue(response.closed)

    def test_interrupted_read_still_closes_response_connection_and_timer(self):
        response = FakeResponse(b"{}")
        connection = MagicMock()
        connection.getresponse.return_value = response
        with patch.object(transport.http.client, "HTTPSConnection", return_value=connection), \
                patch.object(transport, "Timer") as timer, \
                patch.object(response, "read1", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                transport._post_official(b"{}", "synthetic-key", 5)
        self.assertTrue(response.closed)
        connection.request.assert_called_once()
        connection.close.assert_called_once()
        timer.return_value.cancel.assert_called_once()

    def test_connection_cleanup_survives_response_close_failure(self):
        response = FakeResponse(b"{}")
        connection = MagicMock()
        connection.getresponse.return_value = response
        with patch.object(transport.http.client, "HTTPSConnection", return_value=connection), \
                patch.object(transport, "Timer") as timer, \
                patch.object(response, "close", side_effect=OSError("synthetic close error")):
            with self.assertRaises(OSError):
                transport._post_official(b"{}", "synthetic-key", 5)
        connection.close.assert_called_once()
        timer.return_value.cancel.assert_called_once()

    def test_http_denials_and_redirects_never_retry_or_follow_location(self):
        for status, code in ((301, "deepseek_redirect_rejected"), (401, "deepseek_authentication_failed"),
                             (402, "deepseek_balance_insufficient"), (403, "deepseek_access_denied"),
                             (429, "deepseek_rate_limited"), (503, "deepseek_server_error")):
            response = FakeResponse(b"private server message", status=status, headers={"Location": "https://elsewhere.invalid"})
            connection = MagicMock()
            connection.getresponse.return_value = response
            with self.subTest(status=status), patch.object(transport.http.client, "HTTPSConnection", return_value=connection) as factory, patch.object(transport, "Timer"):
                with self.assertRaisesRegex(transport.TransportError, code) as caught:
                    transport._post_official(b"{}", "unit-test-key", 5)
            factory.assert_called_once()
            connection.request.assert_called_once()
            connection.close.assert_called_once()
            self.assertEqual(caught.exception.error_code, code)
            self.assertFalse(caught.exception.diagnostic["usage_and_billing_known"])
            self.assertNotIn("private server", json.dumps(caught.exception.diagnostic))

    def test_response_bounds_timeout_and_preflight_rejection_without_network(self):
        checks = [
            (FakeResponse(b"{}", headers={"Content-Encoding": "gzip"}), "deepseek_response_encoding_unsupported"),
            (FakeResponse(b"{}", headers={"Content-Length": "xx"}), "deepseek_response_invalid"),
            (FakeResponse(b"{}", headers={"Content-Length": "3"}), "deepseek_response_incomplete"),
            (FakeResponse(b"{}", headers={"Content-Length": "3000000"}), "deepseek_response_too_large"),
        ]
        for response, code in checks:
            connection = MagicMock()
            connection.getresponse.return_value = response
            with self.subTest(code=code), patch.object(transport.http.client, "HTTPSConnection", return_value=connection), patch.object(transport, "Timer"):
                with self.assertRaisesRegex(transport.TransportError, code):
                    transport._post_official(b"{}", "unit-test-key", 5)
        connection = MagicMock()
        connection.connect.side_effect = TimeoutError("private underlying failure")
        with patch.object(transport.http.client, "HTTPSConnection", return_value=connection), patch.object(transport, "Timer"):
            with self.assertRaisesRegex(transport.TransportError, "deepseek_timeout") as caught:
                transport._post_official(b"{}", "unit-test-key", 5)
        connection.request.assert_not_called()
        self.assertNotIn("private underlying", str(caught.exception))
        with patch.object(transport.http.client, "HTTPSConnection") as factory:
            for key, timeout in (("line\nbreak", 5), ("unit-test-key", float("inf")), ("unit-test-key", True)):
                with self.assertRaises(transport.TransportError):
                    transport._post_official(b"{}", key, timeout)
            with patch.object(transport, "MAX_REQUEST_BYTES", 1):
                with self.assertRaisesRegex(transport.TransportError, "deepseek_request_too_large"):
                    transport._post_official(b"{}", "unit-test-key", 5)
        factory.assert_not_called()


if __name__ == "__main__":
    unittest.main()
