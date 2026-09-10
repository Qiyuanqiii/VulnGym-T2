"""Small synthetic integration checks; no provider or target execution."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

from test_t2_v2_pipeline import (SOURCE, VULNERABLE, StubClient, StubRepo,
                                choose_source, evidence_from, job, retain_review,
                                source_draft)
from test_t2_v2_protocol import location_ref, record, step, tool_envelope
from vulngym_t2.llm import DeepSeekClient, RequestLedger
from vulngym_t2.pipeline import ENTRY_FIELDS, produce
from vulngym_t2.protocol import strict_tool_definition
from vulngym_t2.output import finalize_result


class StrictClient(StubClient):
    response_mode = "strict_tool"


class CheckedRepo(StubRepo):
    def validate_location(self, commit, location):
        return {"valid": commit == VULNERABLE, "commit": commit}


def referenced_draft(messages):
    reply = source_draft(messages)
    read = next(row for row in evidence_from(messages) if row.get("tool") == "read_file" and row["success"])
    for name in ("entry_point", "critical_operation"):
        line = reply["fields"][name]["line"]
        reply["fields"][name] = {"evidence_ref": read["id"], "start_line": line, "end_line": line, "desc": ""}
    return reply


class ReferencePipelineTests(unittest.TestCase):
    def test_native_strict_wire_expands_references_and_applies_incremental_self_review(self):
        payloads, wire_steps = [], []
        revised_title = "Unrestricted expression input reaches execution"

        def synthetic_send(body, _key, _timeout):
            payload = json.loads(body)
            payloads.append(payload)
            self.assertEqual(payload["tools"], [strict_tool_definition()])
            self.assertEqual(payload["tool_choice"], "required")
            self.assertEqual(payload["thinking"], {"type": "disabled"})
            if len(payloads) == 1:
                wire = step(calls=[{"tool": "read_file", "arguments": {
                    "commit": VULNERABLE, "path": "service/handler.py", "start_line": 1, "end_line": 2}}])
            elif len(payloads) == 2:
                draft = referenced_draft(payload["messages"])
                read_ref = draft["fields"]["entry_point"]["evidence_ref"]
                draft["fields"]["trace"] = [location_ref(evidence_ref=read_ref)]
                draft["field_reviews"]["trace"] = {
                    "status": "supported", "reason": "The two shown lines connect input and execution.",
                    "evidence_refs": [read_ref]}
                records = []
                for name, value in draft["fields"].items():
                    review = draft["field_reviews"][name]
                    item = record(name, 0 if name == "verify" else value,
                                  revision_basis=review.get("revision_basis", "unknown"))
                    item.update(reason=review["reason"], evidence_refs=review["evidence_refs"])
                    records.append(item)
                wire = step(records)
            elif len(payloads) == 3:
                advisory = next(row for row in evidence_from(payload["messages"]) if row["kind"] == "advisory")
                change = record("vuln_title", revised_title)
                change.update(evidence_refs=[advisory["id"]], reason="Narrow the title to the shown input/execution mechanism.")
                wire = step([change])
            else:
                self.fail("Unexpected extra synthetic sender call")
            wire_steps.append(copy.deepcopy(wire))
            # The real client parses this native envelope and calls normalize_step.
            return tool_envelope(wire)

        with tempfile.TemporaryDirectory(prefix="t2-native-ref-") as temp:
            ledger = RequestLedger(Path(temp).resolve() / "requests.jsonl", limit=3)
            client = DeepSeekClient("dummy-not-a-real-key", ledger, run_id="synthetic-native-reference",
                                    max_requests=3, response_mode="strict_tool", thinking="disabled", send=synthetic_send)
            repo = CheckedRepo()
            try:
                client.start_next_case(job(False)["report_id"])
                result = produce(job(False), client, repo, max_calls=3, max_tool_calls=1)
                final = finalize_result(job(False), result, repo)
                self.assertEqual((client.calls, ledger.started, len(payloads)), (3, 3, 3))
                self.assertIsNone(client.halted)
            finally:
                client.close()
                ledger.close()

        self.assertEqual(len(repo.calls), 1)
        self.assertEqual(result["self_review_status"], "completed")
        self.assertEqual(sum(item.get("stage") == "self_review" for item in result["actions"]), 1)
        self.assertEqual([item["name"] for item in wire_steps[-1]["records"]], ["vuln_title"])
        short_draft = next(json.loads(message["content"]) for message in payloads[-1]["messages"]
                           if message["role"] == "assistant" and json.loads(message["content"]).get("action") == "draft")
        self.assertEqual(set(short_draft["fields"]["entry_point"]), {"evidence_ref", "start_line", "end_line", "desc"})
        self.assertNotIn("code", short_draft["fields"]["trace"][0])
        self.assertIsNotNone(final["entry"])
        self.assertEqual(set(final["entry"]), set(ENTRY_FIELDS))
        self.assertEqual(len(final["entry"]), 15)
        self.assertEqual(final["entry"]["vuln_title"], revised_title)
        self.assertEqual(final["entry"]["commit"], VULNERABLE)
        self.assertEqual(final["entry"]["entry_point"]["code"], SOURCE[0])
        self.assertEqual(final["entry"]["critical_operation"]["code"], SOURCE[1])
        self.assertEqual(final["entry"]["trace"][0]["code"], "\n".join(SOURCE))
        self.assertEqual(final["entry"]["verify"], 0)
        self.assertNotIn("evidence_ref", json.dumps(final["entry"]))
        self.assertNotIn("source_ref", json.dumps(final["entry"]))

    def test_references_expand_but_prompt_does_not_echo_source(self):
        client = StrictClient(choose_source, referenced_draft, retain_review)
        result = produce(job(False), client, CheckedRepo(), max_calls=3)
        final = finalize_result(job(False), result, CheckedRepo())
        self.assertIsNotNone(final["entry"])
        self.assertEqual(final["entry"]["entry_point"]["code"], SOURCE[0])
        self.assertEqual(final["entry"]["critical_operation"]["code"], SOURCE[1])
        self.assertNotIn("evidence_ref", final["entry"]["entry_point"])
        self.assertNotIn("Reply with ONE JSON object", client.messages[0][0]["content"])
        for record in evidence_from(client.messages[-1]):
            if record.get("tool") == "read_file":
                self.assertNotIn("text", record["result"])
                self.assertTrue(record["result"]["lines"])
        saved = next(row for row in result["evidence"] if row.get("tool") == "read_file")
        self.assertEqual(saved["result"]["text"], "\n".join(SOURCE))
        draft = next(json.loads(message["content"]) for message in client.messages[-1]
                     if message["role"] == "assistant" and json.loads(message["content"]).get("action") == "draft")
        self.assertIn("evidence_ref", draft["fields"]["entry_point"])
        self.assertNotIn("code", draft["fields"]["entry_point"])
        self.assertEqual(result["evidence_followup_status"], "not_requested")

    def test_invalid_reference_never_inherits_a_supported_location(self):
        for change in ({"evidence_ref": "E9999"}, {"start_line": 999, "end_line": 999}, {"end_line": True}):
            with self.subTest(change=change):
                def invalid(messages):
                    reply = referenced_draft(messages)
                    reply["fields"]["entry_point"].update(change)
                    return reply
                result = produce(job(False), StrictClient(choose_source, invalid, retain_review), CheckedRepo(), max_calls=3)
                self.assertNotIn("entry_point", result["fields"])
                self.assertEqual(result["field_reviews"]["entry_point"]["status"], "uncertain")
                self.assertIn("evidence_ref", result["field_reviews"]["entry_point"]["suggested_value"])
                self.assertIsNone(finalize_result(job(False), result, CheckedRepo())["entry"])

    def test_candidate_revision_can_expand_uncertain_suggestion_without_promoting_it(self):
        def uncertain(messages):
            reply = referenced_draft(messages)
            commit = reply["fields"].pop("commit")
            reply["field_reviews"]["commit"].update(status="uncertain", revision_basis="inspected_only", suggested_value=commit)
            reference = reply["fields"].pop("entry_point")
            reply["field_reviews"]["entry_point"].update(status="uncertain", suggested_value=reference)
            return reply
        result = produce(job(False), StrictClient(choose_source, uncertain, retain_review), CheckedRepo(), max_calls=3)
        suggestion = result["field_reviews"]["entry_point"]["suggested_value"]
        self.assertEqual(suggestion["code"], SOURCE[0])
        self.assertNotIn("entry_point", result["fields"])
        self.assertEqual(result["field_reviews"]["commit"]["status"], "uncertain")

    def test_followup_reuses_shown_source_and_final_review_can_downgrade_entry(self):
        def read_gap(_messages):
            return {"action": "tools", "plan": "Check enclosing function.", "calls": [{
                "tool": "read_file", "arguments": {"commit": VULNERABLE, "path": "service/handler.py", "start_line": 1, "end_line": 1}}]}
        def downgrade(messages):
            reference = referenced_draft(messages)["fields"]["entry_point"]
            return {"action": "draft", "fields": {}, "field_reviews": {"entry_point": {
                "status": "uncertain", "reason": "The source does not establish external registration.",
                "suggested_value": reference, "evidence_refs": [reference["evidence_ref"]]}}, "summary": "Keep the entry premise uncertain."}
        repo = CheckedRepo()
        client = StrictClient(choose_source, referenced_draft, read_gap, downgrade)
        result = produce(job(False), client, repo, max_calls=5, max_tool_calls=4)
        self.assertEqual(len(repo.calls), 1)
        self.assertEqual(result["model_calls"], 4)
        self.assertEqual(result["tool_calls"], 1)
        self.assertEqual(result["evidence_followup_status"], "completed")
        self.assertEqual(result["self_review_status"], "completed")
        self.assertTrue(any(row["action"] == "source_read_reused" for row in result["actions"]))
        self.assertIsNone(finalize_result(job(False), result, repo)["entry"])

    def test_followup_can_read_new_evidence_inside_existing_budgets(self):
        def read_gap(_messages):
            return {"action": "tools", "plan": "Read supplied caller.", "calls": [{
                "tool": "read_file", "arguments": {"commit": VULNERABLE, "path": "service/caller.py", "start_line": 1, "end_line": 2}}]}
        repo = CheckedRepo()
        result = produce(job(False), StrictClient(choose_source, referenced_draft, read_gap, retain_review), repo, max_calls=4, max_tool_calls=2)
        self.assertEqual(result["tool_calls"], 2)
        self.assertEqual(result["model_calls"], 4)
        self.assertEqual(result["evidence_followup_status"], "completed")
        self.assertEqual(result["self_review_status"], "completed")

    def test_followup_failure_preserves_draft_and_blocks_complete_export(self):
        malformed = {"action": "tools", "calls": [{"tool": "list_files", "arguments": {"commit": VULNERABLE}}]}
        for failure in (RuntimeError("synthetic failure"), malformed):
            with self.subTest(failure=type(failure).__name__):
                repo = CheckedRepo()
                result = produce(job(False), StrictClient(choose_source, referenced_draft, failure), repo, max_calls=5)
                self.assertEqual(result["evidence_followup_status"], "failed")
                self.assertEqual(result["self_review_status"], "not_requested")
                self.assertEqual(result["fields"]["entry_point"]["code"], SOURCE[0])
                finalized = finalize_result(job(False), result, repo)
                self.assertIsNone(finalized["entry"])
                self.assertIn("evidence_followup_incomplete", [row["code"] for row in finalized["review"]["errors"]])
                self.assertEqual(len(repo.calls), 1)

    def test_zero_change_followup_retains_draft_for_the_existing_self_review(self):
        result = produce(job(False), StrictClient(choose_source, referenced_draft, retain_review, retain_review), CheckedRepo(), max_calls=5)
        self.assertEqual(result["evidence_followup_status"], "completed")
        self.assertEqual(result["self_review_status"], "completed")
        self.assertEqual(result["model_calls"], 4)
        self.assertIsNotNone(finalize_result(job(False), result, CheckedRepo())["entry"])


if __name__ == "__main__":
    unittest.main()
