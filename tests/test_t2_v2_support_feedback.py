"""Offline support-hold integration; fixture acceptance is not semantic approval.

Only in-memory repository bytes and scripted model decisions are used. The
observed self-disclaimer is supplied as test data, not an exact response replay.
"""
import copy
from html import unescape
import json
import os
from pathlib import Path
import tempfile
import unittest

from vulngym_t2 import staged_protocol
from vulngym_t2.output import BatchWriter, finalize_result
from vulngym_t2.pipeline import produce
from vulngym_t2.report import build_assessment
from vulngym_t2.review_export import export_review
from vulngym_t2.support_consistency import basis_changed, check_support, public_checks
from tests.test_t2_v2_retest_failures import UnknownClient, MemoryRepo, full_annotation
from tests.test_t2_v2_pipeline import VULNERABLE, evidence_from, job
from tests.test_t2_v2_staged_pipeline import READ, CALLER
from tests.test_t2_v2_support_consistency import OPENCLAW_EP_REASON


CLEAN_REASON = "The selected fixture location was read; this is a synthetic assessment, not semantic approval."


class FeedbackClient(UnknownClient):
    def __init__(self, correction):
        super().__init__()
        self.correction = correction
        self.stages = []

    def complete(self, messages, *, stage):
        self.messages.append(copy.deepcopy(messages))
        self.stages.append(stage)
        number = len(self.messages)
        if number == 1:
            reads = [READ, CALLER] if self.correction in ("selection", "new_source_ref") else [READ]
            return staged_protocol.normalize_calls([
                {"tool": name, "arguments": arguments} for name, arguments in reads], stage)
        if number not in (2, 3):
            raise AssertionError("The three-call script must not gain a retry or follow-up")
        name, arguments = full_annotation({"messages": messages})
        entry = arguments["entry_point"]
        entry["reason"] = OPENCLAW_EP_REASON if number == 2 else CLEAN_REASON
        if number == 3:
            if self.correction == "description":
                entry["value"]["desc"] = "Reworded description only."
            elif self.correction == "ref_order":
                entry["evidence_refs"].reverse()
            elif self.correction == "uncertain":
                entry.update(status="uncertain", reason=OPENCLAW_EP_REASON)
            elif self.correction in ("selection", "new_source_ref"):
                extra = next(item for item in evidence_from(messages)
                             if item.get("tool") == "read_file"
                             and item.get("result", {}).get("path") == CALLER[1]["path"])
                entry["evidence_refs"].append(extra["id"])
                if self.correction == "selection":
                    entry["value"] = {"evidence_ref": extra["id"], "start_line": 1,
                                      "end_line": 1, "desc": "Changed synthetic selection; requires human role review."}
            elif self.correction == "invalid_selection":
                entry["value"].update(start_line=99, end_line=99)
        return staged_protocol.normalize_calls([{"tool": name, "arguments": arguments}], stage)


class SupportFeedbackTests(unittest.TestCase):
    def run_script(self, correction):
        client, repo, supplied = FeedbackClient(correction), MemoryRepo(), job(False)
        result = produce(supplied, client, repo, max_calls=3, max_tool_calls=2)
        self.assertEqual(client.stages, ["read", "annotation", "annotation"])
        self.assertEqual(result["model_calls"], 3)
        self.assertEqual(result["self_review_status"], "completed")
        self.assertEqual(result["evidence_followup_status"], "not_requested")
        self.assertEqual(result["tool_calls"], 2 if correction in ("selection", "new_source_ref") else 1)
        feedback = next(item for item in result["actions"] if item["action"] == "draft_validation")
        checks = feedback["support_consistency_checks"]
        self.assertEqual(set(checks), {"entry_point"})
        self.assertEqual(checks["entry_point"]["issues"], [{"code": "supported_reason_conflict",
            "prerequisite": "external_entry_role", "rule": "factory_dispatch_inferred"}])
        packets = []
        for message in client.messages[-1]:
            try:
                packet = json.loads(message["content"])
            except json.JSONDecodeError:
                continue
            if isinstance(packet, dict) and "draft_validation" in packet:
                packets.append(packet)
        self.assertEqual(len(packets), 1)
        self.assertEqual(packets[0]["draft_validation"]["support_consistency_checks"], checks)
        self.assertNotIn(OPENCLAW_EP_REASON, json.dumps(checks))
        final = finalize_result(supplied, result, repo)
        self.assertEqual(final["review"]["model_errors"], [])
        self.assertEqual(final["review"]["annotation_errors"], [])
        return supplied, result, final

    def test_reason_description_and_reference_reordering_do_not_clear_the_hold(self):
        for correction in ("reason_only", "description", "ref_order"):
            with self.subTest(correction=correction):
                _, result, final = self.run_script(correction)
                assessment = result["field_reviews"]["entry_point"]
                self.assertIn("pending_support_conflict", assessment)
                self.assertIsNone(final["entry"])
                review = final["review"]
                self.assertEqual(review["status"], "draft")
                self.assertEqual(review["field_reviews"]["entry_point"]["status"], "uncertain")
                self.assertEqual(review["field_reviews"]["entry_point"]["pre_check_status"], "supported")
                self.assertEqual(review["field_reviews"]["entry_point"]["reason"], CLEAN_REASON)
                self.assertEqual(review["suggested_values"]["entry_point"], result["fields"]["entry_point"])
                self.assertIsNotNone(review["draft_fields"]["critical_operation"])
                holds = [item for item in review["actions"] if item["action"] == "support_consistency_hold"]
                self.assertEqual(len(holds), 1)
                self.assertEqual(holds[0]["reason"], OPENCLAW_EP_REASON)
                self.assertIn("supported_reason_conflict", review["field_reviews"]["entry_point"]["validation_errors"])

    def test_explicit_uncertainty_preserves_the_suggestion_without_an_added_hold(self):
        _, result, final = self.run_script("uncertain")
        self.assertNotIn("pending_support_conflict", result["field_reviews"]["entry_point"])
        self.assertIsNone(final["entry"])
        self.assertEqual(final["review"]["field_reviews"]["entry_point"]["status"], "uncertain")
        self.assertEqual(final["review"]["field_reviews"]["entry_point"]["reason"], OPENCLAW_EP_REASON)
        self.assertEqual(final["review"]["suggested_values"]["entry_point"],
                         result["field_reviews"]["entry_point"]["suggested_value"])
        self.assertFalse(any(item["action"] == "support_consistency_hold" for item in result["actions"]))

    def test_changed_selection_or_new_same_sha_source_can_be_rechecked_without_extra_calls(self):
        for correction in ("selection", "new_source_ref"):
            with self.subTest(correction=correction):
                _, result, final = self.run_script(correction)
                self.assertNotIn("pending_support_conflict", result["field_reviews"]["entry_point"])
                self.assertIsNotNone(final["entry"])
                self.assertEqual(final["entry"]["verify"], 0)
                self.assertTrue(final["review"]["location_checks"])
                self.assertTrue(all(row["valid"] for row in final["review"]["location_checks"]))
                self.assertIn("not independent human proof", final["review"]["verification"])
                self.assertFalse(final["review"]["support_consistency_checks"])

    def test_changed_but_unread_selection_still_fails_normal_source_checks(self):
        _, _, final = self.run_script("invalid_selection")
        self.assertIsNone(final["entry"])
        self.assertEqual(final["review"]["field_reviews"]["entry_point"]["status"], "uncertain")
        self.assertIsNone(final["review"]["draft_fields"]["entry_point"])

    def test_public_checks_drop_arbitrary_fields_prose_and_unknown_rule_values(self):
        clean = check_support("entry_point", {"status": "supported", "reason": OPENCLAW_EP_REASON})
        dirty = copy.deepcopy(clean)
        dirty.update(reason="private-prose", source="private-source", arbitrary="private-value")
        dirty["issues"][0].update(reason="private-prose", arbitrary="private-value")
        incoming = {"entry_point": dirty, "private-field": dirty,
                    "commit": {"version": "private-version", "issues": dirty["issues"]},
                    "critical_operation": {"version": clean["version"], "issues": [{
                        "code": "private-code", "prerequisite": "operation_behavior", "rule": "operation_behavior_disclaimed"}]}}
        before = copy.deepcopy(incoming)
        public = public_checks(incoming)
        self.assertEqual(public, {"entry_point": clean})
        self.assertEqual(public_checks(public), public)
        self.assertEqual(incoming, before)
        self.assertNotIn("private", json.dumps(public))

    def test_basis_change_needs_a_new_successful_same_sha_source_not_prose(self):
        location = {"file": "service/handler.py", "line": 1, "code": "synthetic", "desc": "old"}
        before = {"status": "supported", "reason": OPENCLAW_EP_REASON, "evidence_refs": ["E0001", "E0002"]}
        after = {**before, "reason": CLEAN_REASON, "evidence_refs": ["E0002", "E0001"]}
        self.assertFalse(basis_changed("entry_point", location, before, {**location, "desc": "new"}, after, [],
                                       selected_commit=VULNERABLE))
        after["evidence_refs"] = ["E0001", "E0002", "E0003"]
        valid = {"id": "E0003", "tool": "read_file", "success": True,
                 "result": {"commit": VULNERABLE, "path": "service/routes.py", "start_line": 1, "end_line": 1,
                            "lines": [{"line": 1, "code": "synthetic direct caller"}], "text": "synthetic direct caller"}}
        self.assertTrue(basis_changed("entry_point", location, before, location, after, [valid], selected_commit=VULNERABLE))
        for change in ("different_sha", "failed", "error", "not_read_file", "no_selected_commit"):
            receipt = copy.deepcopy(valid)
            selected = VULNERABLE
            if change == "different_sha":
                receipt["result"]["commit"] = "b" * 40
            elif change == "failed":
                receipt["success"] = False
            elif change == "error":
                receipt["result"]["error"] = "synthetic failure"
            elif change == "not_read_file":
                receipt["tool"] = "inspect_commit"
            else:
                selected = None
            with self.subTest(change=change):
                self.assertFalse(basis_changed("entry_point", location, before, location, after, [receipt], selected_commit=selected))

    def test_held_field_exports_with_original_reason_and_zero_technical_error_counts(self):
        supplied, _, final = self.run_script("reason_only")
        temp_root = "D:/VulnGym-bv2-runtime/tmp" if os.name == "nt" else None
        with tempfile.TemporaryDirectory(prefix="t2-support-feedback-", dir=temp_root) as temporary:
            root = Path(temporary)
            writer = BatchWriter(root / "run")
            writer.record(supplied, final)
            summary = writer.finish({"status": "completed", "format_failure_count": 0,
                                     "requested_input_count": 1, "unprocessed_input_count": 0})
            self.assertEqual((summary["entry_count"], summary["draft_count"]), (0, 1))
            for key in ("model_error_count", "annotation_error_count", "format_failure_count"):
                self.assertEqual(summary[key], 0)
            saved = json.loads((writer.directory / "review.jsonl").read_text(encoding="utf-8"))
            self.assertEqual(saved["suggested_values"], final["review"]["suggested_values"])
            self.assertEqual(saved["support_consistency_checks"], final["review"]["support_consistency_checks"])
            actions = [json.loads(line)["action"] for line in
                       (writer.directory / "actions.jsonl").read_text(encoding="utf-8").splitlines()]
            self.assertTrue(any(item.get("reason") == OPENCLAW_EP_REASON for item in actions))
            export_review(writer.directory, root / "review.md")
            report = build_assessment(writer.directory)
            for path in (root / "review.md", report):
                text = unescape(path.read_text(encoding="utf-8")).replace("\\_", "_")
                self.assertIn("supported_reason_conflict", text)
                self.assertIn("external_entry_role", text)
                self.assertIn("不是 API/格式故障", text)
                self.assertIn("未命中不代表语义正确", text)


if __name__ == "__main__":
    unittest.main()
