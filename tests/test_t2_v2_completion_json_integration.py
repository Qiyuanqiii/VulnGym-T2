"""Synthetic parser boundary tests; no replay of discarded real response text."""
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from vulngym_t2 import staged_protocol, transport
from tests.test_t2_v2_protocol import tool_envelope
from tests import test_t2_v2_staged_pipeline as fixture
from tests.test_t2_v2_staged_pipeline import READ, full_annotation


AUDIT = [{"code": "redundant_object_close_removed", "count": 1}]


def envelope(tool, arguments, **message_updates):
    body = json.loads(tool_envelope(arguments=arguments))
    message = body["choices"][0]["message"]
    message["tool_calls"][0]["function"]["name"] = tool
    message.update(message_updates)
    return json.dumps(body).encode()


class CompletionJSONBoundaryTests(unittest.TestCase):
    def test_selection_and_snapshot_allow_only_one_redundant_close_with_audit(self):
        for stage, tool, value in (
            ("candidate_selection", "propose_candidates", {"candidates": []}),
            ("annotation", "submit_annotation", staged_protocol.snapshot_from_state({}, {})),
        ):
            with self.subTest(stage=stage):
                ordinary = transport.parse_chat_response(envelope(tool, json.dumps(value)),
                    response_mode="staged_tool", stage=stage)
                adjusted = transport.parse_chat_response(envelope(tool, json.dumps(value) + "} \n"),
                    response_mode="staged_tool", stage=stage)
                self.assertEqual(adjusted.pop("completion_json_normalizations"), AUDIT)
                self.assertEqual(adjusted, ordinary)

    def test_read_arguments_and_provider_envelope_remain_strict(self):
        with self.assertRaises(transport.TransportError):
            transport.parse_chat_response(envelope(READ[0], json.dumps(READ[1]) + "}"),
                response_mode="staged_tool", stage="read")
        with self.assertRaises(transport.TransportError):
            transport.parse_chat_response(envelope("propose_candidates", '{"candidates":[]}') + b'}',
                response_mode="staged_tool", stage="candidate_selection")

    def test_schema_failures_still_fail_and_bad_fields_are_not_promoted(self):
        with self.assertRaises(transport.TransportError):
            transport.parse_chat_response(envelope("propose_candidates", '{"candidates":"bad"}}'),
                response_mode="staged_tool", stage="candidate_selection")
        snapshot = staged_protocol.snapshot_from_state({}, {})
        snapshot["critical_operation"]["value"]["code"] = "unverified data"
        result = transport.parse_chat_response(envelope("submit_annotation", json.dumps(snapshot) + "}"),
            response_mode="staged_tool", stage="annotation")
        self.assertEqual(result["completion_json_normalizations"], AUDIT)
        self.assertEqual(result["annotation_errors"][0]["field"], "critical_operation")
        self.assertNotIn("critical_operation", result["field_reviews"])
        self.assertNotIn("unverified data", json.dumps(result))

    def test_refusal_truncation_and_model_mismatch_stop_before_compatibility(self):
        for mutation, code in (
            (lambda b: b["choices"][0]["message"].update(refusal="refused"), "deepseek_refusal"),
            (lambda b: b["choices"][0].update(finish_reason="length"), "deepseek_output_truncated"),
            (lambda b: b.update(model="wrong-model"), "deepseek_response_model_mismatch"),
        ):
            body = json.loads(envelope("propose_candidates", '{"candidates":[]}}'))
            mutation(body)
            with self.subTest(code=code), self.assertRaisesRegex(transport.TransportError, code):
                transport.parse_chat_response(json.dumps(body).encode(),
                    response_mode="staged_tool", stage="candidate_selection")

    def test_other_extra_data_stays_an_error_and_only_finite_diagnostics_survive(self):
        for suffix in ('{"extra":"private-tail"}', 'private-tail', ']', '}}'):
            with self.subTest(suffix=suffix), self.assertRaises(transport.TransportError) as caught:
                transport.parse_chat_response(envelope("propose_candidates", '{"candidates":[]}' + suffix),
                    response_mode="staged_tool", stage="candidate_selection")
            public = transport.public_failure_diagnostics(caught.exception.diagnostic)
            self.assertEqual(public["tail_kind"], "other")
            self.assertEqual(public["tail_length"], len(suffix))
            self.assertNotIn("private-tail", json.dumps(public))


class CompletionJSONAuditTests(unittest.TestCase):
    setUp = fixture.StagedPipelineTests.setUp
    run_script = fixture.StagedPipelineTests.run_script

    def test_zero_extra_http_and_audit_in_ledger_pipeline_and_public_review(self):
        original_parse = transport.parse_chat_response

        def extra_close(raw, **kwargs):
            body = json.loads(raw)
            for call in body["choices"][0]["message"]["tool_calls"]:
                if call["function"]["name"] == "submit_annotation":
                    call["function"]["arguments"] += "}"
            return original_parse(json.dumps(body).encode(), **kwargs)

        with patch.object(transport, "parse_chat_response", side_effect=extra_close):
            result, final, client, _, _ = self.run_script(
                [READ, full_annotation, full_annotation], max_calls=3, max_tool_calls=1)
        self.assertIsNone(client.halted)
        self.assertEqual((result["model_calls"], result["tool_calls"]), (3, 1))
        self.assertEqual(final["entry"]["verify"], 0)
        saved = [a for a in final["review"]["actions"] if a["action"] == "completion_json_normalized"]
        self.assertEqual([a["stage"] for a in saved], ["draft", "self_review"])
        self.assertTrue(all(a["normalizations"] == AUDIT for a in saved))
        self.assertEqual([e["diagnostics"]["completion_json_normalizations"] for e in client.events
                          if e.get("diagnostics", {}).get("completion_json_normalizations")], [AUDIT, AUDIT])
        ledger_file = next(Path(self.temp.name).glob("ledger-*.jsonl"))
        ledger = [json.loads(line) for line in ledger_file.read_text().splitlines()]
        self.assertEqual(sum(bool(e.get("diagnostics", {}).get("completion_json_normalizations"))
                             for e in ledger), 2)
        self.assertEqual(client.summary()["automatic_retries"], 0)


if __name__ == "__main__":
    unittest.main()
