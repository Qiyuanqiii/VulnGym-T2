"""Partial-state boundaries: saved evidence must not turn failures into facts."""
import unittest

from vulngym_t2.pipeline import produce
from vulngym_t2.output import finalize_result
from tests.test_t2_v2_pipeline import (
    StubClient, StubRepo, choose_source, job, source_draft, retain_review,
)
from tests.test_t2_v2_staged_pipeline import MemoryRepo
from tests.test_t2_v2_revision_feedback import fixture
from vulngym_t2.source_refs import revision_consistency, review_locations


class PipelineResilienceTests(unittest.TestCase):
    def test_oversized_error_result_never_becomes_successful_source(self):
        for flag in ({"error": "fixture-read-failed"}, {"ok": False}, {"success": False}):
            with self.subTest(flag=flag):
                class FailedRepo(StubRepo):
                    def call(self, tool, arguments):
                        return {**super().call(tool, arguments), "padding": "x" * 20000, **flag}
                result = produce(job(False), StubClient(choose_source, retain_review, retain_review),
                                 FailedRepo(), max_calls=3)
                receipt = next(item for item in result["evidence"] if item.get("tool") == "read_file")
                self.assertIs(receipt["success"], False)
                self.assertTrue(receipt["result"]["context_truncated"])
                self.assertTrue(receipt["result"]["error"])
                self.assertTrue(result["errors"])

    def test_legacy_reason_limit_is_explicit_and_propagates_to_output(self):
        reason = "Evidence-based explanation. " * 100
        def draft(messages):
            reply = source_draft(messages)
            reply["field_reviews"]["commit"]["reason"] = reason
            return reply
        supplied, repo = job(False), MemoryRepo()
        result = produce(supplied, StubClient(choose_source, draft, retain_review), repo, max_calls=3)
        review = result["field_reviews"]["commit"]
        self.assertEqual(review["reason"], reason[:2000])
        self.assertIs(review["reason_truncated"], True)
        saved = finalize_result(supplied, result, repo)["review"]["field_reviews"]["commit"]
        self.assertEqual(saved["reason"], review["reason"])
        self.assertIs(saved["reason_truncated"], True)

    def test_revision_preview_counts_initial_truncation_not_only_budget_trim(self):
        review = fixture()
        review["field_reviews"]["commit"]["reason"] = "r" * 1900
        packet = revision_consistency(review)
        self.assertEqual(len(packet["commit_reason"]), 800)
        self.assertEqual(packet["omitted"]["commit_reason_chars"], 1100)
        self.assertTrue(packet["truncated"])
        small = revision_consistency(review, max_chars=1024)
        self.assertEqual(len(small["commit_reason"]) + small["omitted"]["commit_reason_chars"], 1900)

    def test_location_preview_keeps_upstream_truncation_warning(self):
        review = fixture()
        review["field_reviews"]["entry_point"].update(reason="short saved prefix", reason_truncated=True)
        row = review_locations(review)["locations"][0]
        self.assertIn("reason", row["truncated"])


if __name__ == "__main__":
    unittest.main()
