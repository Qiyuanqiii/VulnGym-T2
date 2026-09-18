"""Synthetic citation coverage, not semantic source approval or target reads."""
from copy import deepcopy
from html import unescape
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from vulngym_t2 import source_refs
from vulngym_t2.output import BatchWriter, finalize_job, finalize_result
from vulngym_t2.report import build_assessment
from vulngym_t2.review_export import export_review
from test_t2_v2_output import COMMIT, StubRepoReader, fixture


def receipt(identity="E0010", start=500, end=565, **updates):
    return {"id": identity, "tool": "read_file", "success": True,
            "arguments": {"start_line": 1, "end_line": 900},
            "result": {"commit": COMMIT, "path": "src/example.py",
                       "start_line": start, "end_line": end,
                       "lines": [{"line": n, "code": "line"} for n in range(start, end + 1)],
                       "text": "\n".join("line" for _ in range(start, end + 1)),
                       "truncated": True}, **updates}


class ReasonCitationTests(unittest.TestCase):
    def check(self, reason, evidence=None, commit=COMMIT):
        return source_refs.reason_citations(reason, evidence if evidence is not None else [receipt()], commit)

    def test_explicit_out_of_window_blocks_only_its_field_and_keeps_reason(self):
        job, result = fixture()
        reason = "E0010:564-576"
        result["evidence"].append(receipt())
        result["field_reviews"]["entry_point"]["reason"] = reason
        before = deepcopy(result)
        checked = finalize_result(job, result, StubRepoReader())
        self.assertIsNone(checked["entry"])
        review = checked["review"]
        self.assertEqual(review["field_reviews"]["entry_point"]["reason"], reason)
        self.assertEqual(review["field_reviews"]["entry_point"]["status"], "uncertain")
        self.assertEqual(review["suggested_values"]["entry_point"], result["fields"]["entry_point"])
        self.assertIsNotNone(review["draft_fields"]["critical_operation"])
        issue = review["field_reviews"]["entry_point"]["reason_citations"]["citations"][0]
        self.assertEqual((issue["code"], issue["severity"], issue["visible_end_line"]),
                         ("reason_citation_out_of_bounds", "error", 565))
        self.assertIn("reason_citation_out_of_bounds", review["field_reviews"]["entry_point"]["validation_errors"])
        self.assertEqual(result, before)
        with tempfile.TemporaryDirectory() as temporary:
            writer = BatchWriter(Path(temporary) / "run")
            writer.record(job, checked)
            summary = writer.finish({"status": "completed"})
            saved = json.loads((writer.directory / "review.jsonl").read_text(encoding="utf-8"))
            self.assertEqual(saved["field_reviews"]["entry_point"]["reason_citations"]["citations"][0], issue)
            self.assertEqual((summary["entry_count"], summary["draft_count"], summary["model_error_count"]), (0, 1, 0))

    def test_unresolved_error_and_warning_survive_both_report_exports(self):
        for reason, severity in (("E0010:564-576", "error"), ("E0010:564-576 was not read.", "warning")):
            with self.subTest(severity=severity), tempfile.TemporaryDirectory() as temporary:
                job, result = fixture()
                result["evidence"].append(receipt())
                result["field_reviews"]["entry_point"]["reason"] = reason
                final = finalize_result(job, result, StubRepoReader())
                root = Path(temporary)
                writer = BatchWriter(root / "run")
                writer.record(job, final)
                writer.finish({"status": "completed"})
                originals = {path: path.read_bytes() for path in writer.directory.iterdir() if path.is_file()}
                outcome = export_review(writer.directory, root / "review.md")
                self.assertEqual(outcome["http_attempts"], 0)
                self.assertEqual(outcome["entry_count"], int(severity == "warning"))
                for markdown in ((root / "review.md").read_text(encoding="utf-8"),
                                 build_assessment(writer.directory).read_text(encoding="utf-8")):
                    text = unescape(markdown).replace("\\_", "_")
                    self.assertIn("reason_citation_out_of_bounds", text)
                    self.assertIn(severity, text)
                    self.assertIn("564", text)
                    self.assertIn("576", text)
                for path, original in originals.items():
                    self.assertEqual(path.read_bytes(), original)

    def test_precise_formats_and_inclusive_visible_bounds(self):
        for text in ("E0010:564-576", "E0010 (lines 564–576)", "E0010 的第564至576行"):
            with self.subTest(text=text):
                row = self.check(text)["citations"][0]
                self.assertEqual((row["start_line"], row["end_line"], row["severity"]), (564, 576, "error"))
        for text in ("E0010:500-565", "E0010 (line 565)", "E0010 的第500行"):
            self.assertEqual(self.check(text)["citations"][0]["code"], "covered")
        for text in ("E0010:0", "E0010:576-564"):
            self.assertEqual(self.check(text)["citations"][0]["code"], "reason_citation_invalid_range")

    def test_labeled_compact_citations_check_the_exact_reference_without_backtracking(self):
        for text in ("function declared E0010 498)", "call E0010 564-576,", "defined at E0010 499"):
            with self.subTest(text=text):
                row = self.check(text)["citations"][0]
                self.assertEqual((row["binding"], row["code"], row["severity"]),
                                 ("explicit", "reason_citation_out_of_bounds", "error"))
        self.assertEqual(self.check("function declared E0010 500)")["citations"][0]["code"], "covered")
        row = self.check("call E0010 500-9999999999)")["citations"][0]
        self.assertEqual(row["code"], "reason_citation_invalid_range")
        self.assertIsNone(row["end_line"])
        for text in ("call E0010 500-", "call E0010 500-501-999", "call E0010 500 to unknown"):
            self.assertEqual(self.check(text)["citations"], [])

    def test_unlabeled_compact_numbers_are_visible_but_only_warn_when_not_covered(self):
        row = self.check("(E0010 498)")["citations"][0]
        self.assertEqual((row["binding"], row["code"], row["severity"]),
                         ("compact", "reason_citation_out_of_bounds", "warning"))
        rows = self.check("(E0010 550, function declared E0010 498)")["citations"]
        self.assertEqual(len(rows), 2)
        self.assertEqual([row["severity"] for row in rows], ["info", "error"])
        self.assertEqual(self.check("E0010 2026 release notes")["citations"], [])
        self.assertEqual(self.check("declared E0010 498 was not read")["citations"], [])
        self.assertEqual(self.check("not read: declared E0010 498)")["citations"][0]["severity"], "warning")

    def test_labeled_bad_reference_blocks_supported_output_without_changing_source_or_claim(self):
        job, result = fixture()
        result["evidence"].append(receipt())
        reason = "This function is declared E0010 498)"
        result["field_reviews"]["entry_point"]["reason"] = reason
        before = deepcopy(result)
        checked = finalize_result(job, result, StubRepoReader())
        self.assertIsNone(checked["entry"])
        self.assertEqual(result, before)
        self.assertEqual(checked["review"]["field_reviews"]["entry_point"]["reason"], reason)
        self.assertIn("reason_citation_out_of_bounds", {row["code"] for row in checked["review"]["errors"]})

    def test_oversized_or_incomplete_range_never_falls_back_to_covered_first_line(self):
        for separator in ("-", " - ", " to ", "至", "—"):
            with self.subTest(separator=separator):
                row = self.check("E0010:500" + separator + "9999999999")["citations"][0]
                self.assertEqual(row["code"], "reason_citation_invalid_range")
                self.assertEqual(row["start_line"], 500)
                self.assertIsNone(row["end_line"])
        for text in ("E0010:9999999999", "E0010 (lines 500 to " + "9" * 1800 + ")"):
            self.assertEqual(self.check(text)["citations"][0]["code"], "reason_citation_invalid_range")
        for text in ("E0010:500 - ", "E0010:500 to unknown", "E0010:500-501-900"):
            self.assertEqual(self.check(text)["citations"], [])

    def test_actual_style_prose_is_a_warning_not_a_semantic_downgrade(self):
        text = ("E0010 shows the external handler entry receiving the component interaction, resolving component data "
                "and interaction context including rawGuildId, and then dispatching to ensureGuildComponentMemberAllowed "
                "at lines 564-576. This is the actual ingress, not a changed helper fragment.")
        row = self.check(text)["citations"][0]
        self.assertEqual((row["binding"], row["code"], row["severity"]),
                         ("same_sentence", "reason_citation_out_of_bounds", "warning"))
        job, result = fixture()
        result["evidence"].append(receipt())
        result["field_reviews"]["entry_point"]["reason"] = text
        self.assertIsNotNone(finalize_result(job, result, StubRepoReader())["entry"])

    def test_no_cross_sentence_or_multiple_identity_guessing(self):
        for text in ("E0010 was read. The call is at lines 564-576.",
                     "E0010 and E0011 show the call at lines 564-576.",
                     "E0010 was read; lines 564-576 concern something else.",
                     "E0010 was read\nlines 564-576 concern something else.",
                     "E0010 gives context without line numbers.", "No citations."):
            self.assertEqual(self.check(text)["citations"], [], text)
        rows = self.check("E0010:500-501; E0011:9-10", [receipt(), receipt("E0011", 9, 10)])["citations"]
        self.assertEqual([row["code"] for row in rows], ["covered", "covered"])

    def test_negative_or_uncertain_coverage_mentions_are_only_warnings(self):
        for text in ("E0010:564-576 was not read.", "No evidence supports E0010 (lines 564-576).",
                     "E0010 doesn't show lines 564-576.", "E0010 的第564至576行未读取。"):
            self.assertEqual(self.check(text)["citations"][0]["severity"], "warning", text)

    def test_receipt_identity_success_and_visible_data_are_authoritative(self):
        cases = []
        cases.append(([], "unknown_evidence"))
        cases.append(([receipt(), receipt()], "ambiguous_evidence"))
        for tool in ("read_diff", "search_code", "inspect_commit", None):
            cases.append(([receipt(tool=tool)], "read_required"))
        for success in (False, None, 1):
            cases.append(([receipt(success=success)], "failed_read"))
        item = receipt(); item["result"].update(error="failed")
        cases.append(([item], "failed_read"))
        item = receipt(); item["result"].pop("lines"); item["result"].pop("text")
        cases.append(([item], "source_missing"))
        item = receipt(); item["result"]["lines"][0]["line"] = True
        cases.append(([item], "invalid_source_rows"))
        item = receipt(); item["result"]["lines"].pop(1)
        cases.append(([item], "invalid_source_rows"))
        for evidence, code in cases:
            with self.subTest(code=code):
                self.assertEqual(self.check("E0010:500", evidence)["citations"][0]["code"], "reason_citation_" + code)

    def test_truncation_uses_returned_complete_lines_not_requested_or_declared_end(self):
        for mode in ("lines", "text", "clipped_text"):
            item = receipt()
            item["result"]["end_line"] = 900
            if mode != "lines":
                item["result"].pop("lines")
            if mode == "clipped_text":
                item["result"]["text"] += "<truncated>"
            row = self.check("E0010:565-576", [item])["citations"][0]
            self.assertEqual(row["visible_end_line"], 564 if mode == "clipped_text" else 565)
            self.assertEqual(row["code"], "reason_citation_out_of_bounds")

    def test_revision_comparison_is_context_not_a_new_gate(self):
        item = receipt(); item["result"]["commit"] = "b" * 40
        for commit, expected in ((COMMIT, False), (None, None)):
            row = self.check("E0010:500-565", [item], commit)["citations"][0]
            self.assertEqual(row["code"], "covered")
            self.assertEqual(row["matches_selected_commit"], expected)

    def test_explicit_bad_trace_cannot_bypass_as_empty_but_unknown_suggestion_is_not_promoted(self):
        for status in ("supported", "uncertain"):
            job, result = fixture()
            result["evidence"].append(receipt())
            result["field_reviews"]["trace"].update(status=status, reason="E0010:564-576",
                                                    suggested_value=[deepcopy(result["fields"]["entry_point"])])
            checked = finalize_result(job, result, StubRepoReader())
            self.assertEqual(checked["entry"] is None, status == "supported")
            review = checked["review"]
            self.assertEqual(review["draft_fields"]["trace"], [])
            self.assertEqual(review["field_reviews"]["trace"]["omitted_assessment"]["status"], status)
            self.assertEqual(review["suggested_values"]["trace"], result["field_reviews"]["trace"]["suggested_value"])

    def test_warning_and_prior_truncation_stay_visible_without_changing_suggestions(self):
        job, result = fixture()
        result["evidence"].append(receipt())
        result["field_reviews"]["entry_point"].update(reason="E0010:564-576 was not read.", reason_truncated=True)
        checked = finalize_result(job, result, StubRepoReader())
        self.assertIsNotNone(checked["entry"])
        packet = checked["review"]["reason_citation_checks"]["entry_point"]
        self.assertTrue(packet["truncated"])
        self.assertEqual(packet["citations"][0]["severity"], "warning")

    def test_only_corrected_current_reason_clears_a_prior_coverage_error(self):
        job, result = fixture()
        result["evidence"].append(receipt())
        result["field_reviews"]["entry_point"]["reason"] = "E0010:564-576"
        self.assertIsNone(finalize_result(job, result, StubRepoReader())["entry"])
        result["field_reviews"]["entry_point"]["reason"] = "E0010:500-565"
        corrected = finalize_result(job, result, StubRepoReader())
        self.assertIsNotNone(corrected["entry"])
        self.assertEqual(corrected["review"]["reason_citation_checks"]["entry_point"]["citations"][0]["code"], "covered")

    def test_child_error_does_not_broadcast_and_budget_is_shared_once(self):
        job, result = fixture()
        result["evidence"].append(receipt())
        rows = [{"slot": i, "fields": deepcopy(result["fields"]), "field_reviews": deepcopy(result["field_reviews"]),
                 "self_review_status": "completed"} for i in (1, 2)]
        rows[1]["field_reviews"]["entry_point"]["reason"] = "E0010:564-576"
        result.update(annotation_mode="snapshot", entry_results=rows)
        checked = finalize_job(job, result, StubRepoReader(), entry_ids={1: job["entry_id"], 2: "entry-00002"})
        self.assertEqual(checked["status"], "partial")
        self.assertIsNotNone(checked["items"][0]["entry"])
        self.assertIsNone(checked["items"][1]["entry"])
        self.assertEqual(sum(item["review"]["model_calls"] for item in checked["items"]), result["model_calls"])

    def test_bounded_pure_helper_never_copies_source_or_mutates_inputs(self):
        evidence = [receipt()]
        before = deepcopy(evidence)
        with patch("builtins.open", side_effect=AssertionError("No reads")):
            packet = self.check("E0010:500 " * 1000, evidence)
        self.assertTrue(packet["truncated"])
        self.assertLessEqual(len(packet["citations"]), 16)
        self.assertLess(len(json.dumps(packet)), 12000)
        self.assertNotIn('"code": "line"', json.dumps(packet))
        self.assertEqual(evidence, before)
        self.assertEqual(self.check(None)["citations"], [])


if __name__ == "__main__":
    unittest.main()
