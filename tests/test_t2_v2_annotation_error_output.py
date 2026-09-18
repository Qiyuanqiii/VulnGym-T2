"""Offline field-protocol diagnostics through finalization and public consumers."""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest

from tests.test_t2_v2_output import fixture, StubRepoReader
from tests.test_t2_v2_multi_entry import multi_fixture
from vulngym_t2.multi_entry import allocate_entry_ids
from vulngym_t2.output import BatchWriter, finalize_job, finalize_result
from vulngym_t2.report import _assessment, _entry_diagnostic
from vulngym_t2.review_export import ExportError, render_packet


def field_error(field="trace", *, slot=None):
    prefix = "$[0].arguments" + (f".entries[{slot - 1}]" if slot else "")
    return {"field": field, "code": "unexpected_properties", "path": prefix + "." + field + "[0]"}


class AnnotationErrorOutputTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="t2-annotation-output-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def save(self, job, finalized, name="run", *, multi=False):
        writer = BatchWriter(self.root / name, multi_entry=multi)
        (writer.record_job if multi else writer.record)(job, finalized)
        summary = writer.finish({"status": "completed", "requested_input_count": 1,
                                 "unprocessed_input_count": 0})
        def rows(filename):
            return [json.loads(line) for line in (writer.directory / filename).read_text(encoding="utf-8").splitlines()]
        return summary, rows("entries.jsonl"), rows("review.jsonl")

    def test_unresolved_optional_trace_cannot_hide_behind_empty_default(self):
        job, result = fixture()
        result.update(annotation_errors=[field_error()], initial_draft_status="partial")
        original = deepcopy(result)
        finalized = finalize_result(job, result, StubRepoReader())
        review = finalized["review"]
        self.assertIsNone(finalized["entry"])
        self.assertEqual(review["status"], "draft")
        self.assertEqual(review["annotation_errors"], [field_error()])
        self.assertEqual(review["field_reviews"]["trace"]["status"], "uncertain")
        self.assertEqual(review["draft_fields"]["trace"], [])
        self.assertEqual(review["field_reviews"]["entry_point"]["status"], "supported")
        self.assertEqual(review["initial_draft_status"], "partial")
        self.assertEqual(review["model_errors"], [])
        self.assertEqual(result, original)

    def test_recovered_history_is_retained_without_permanent_demotion(self):
        job, result = fixture()
        result.update(annotation_errors=[], initial_draft_status="partial", self_review_status="completed")
        result["actions"] = [{"action": action, "slot": 1, **field_error()}
                             for action in ("annotation_field_rejected", "annotation_field_recovered")]
        finalized = finalize_result(job, result, StubRepoReader())
        self.assertIsNotNone(finalized["entry"])
        self.assertEqual(len(finalized["entry"]), 15)
        self.assertEqual(finalized["entry"]["verify"], 0)
        self.assertEqual(finalized["review"]["actions"], result["actions"])
        self.assertEqual(finalized["review"]["annotation_errors"], [])
        summary, _, _ = self.save(job, finalized)
        self.assertEqual((summary["annotation_error_count"], summary["jobs_with_annotation_errors"]), (0, 0))

    def test_multi_errors_are_local_counts_are_per_field_and_per_input(self):
        for slots in ((1,), (1, 2)):
            with self.subTest(slots=slots):
                job, result = multi_fixture()
                # Even a parent copy must not broadcast an error to clean slots.
                result["annotation_errors"] = [field_error()]
                for slot in slots:
                    result["entry_results"][slot - 1]["annotation_errors"] = [field_error(slot=slot)]
                finalized = finalize_job(job, result, StubRepoReader(), entry_ids=allocate_entry_ids([job])[0])
                self.assertEqual(finalized["status"], "partial" if len(slots) == 1 else "draft")
                second = finalized["items"][1]
                self.assertEqual(second["entry"] is None, 2 in slots)
                self.assertEqual(bool(second["review"]["annotation_errors"]), 2 in slots)
                summary, entries, reviews = self.save(job, finalized, str(len(slots)), multi=True)
                self.assertEqual((summary["annotation_error_count"], summary["jobs_with_annotation_errors"]), (len(slots), 1))
                self.assertEqual((summary["model_calls"], summary["tool_calls"], summary["model_error_count"]), (3, 1, 0))
                self.assertEqual(sum(review["model_calls"] for review in reviews), 3)
                self.assertEqual(len(entries), 2 - len(slots))
                render_packet(summary, entries, reviews)

    def test_consumers_show_field_location_without_whole_request_failure_claim(self):
        job, result = fixture()
        result.update(annotation_errors=[field_error()], initial_draft_status="no_valid_updates")
        summary, entries, reviews = self.save(job, finalize_result(job, result, StubRepoReader()))
        before = deepcopy((summary, entries, reviews))
        diagnostic = _entry_diagnostic(reviews[0])
        self.assertEqual(diagnostic["category"], "draft_with_technical_anomaly")
        self.assertIn("不等于模型整体请求失败", diagnostic["detail"])
        for text in (_assessment(summary, reviews), render_packet(summary, entries, reviews)):
            self.assertIn("可恢复", text)
            self.assertIn("非纯证据不足", text)
            self.assertIn("field | code | path", text)
            self.assertIn("trace", text)
            self.assertIn("no_valid_updates 不代表收到有效初稿", text)
        self.assertEqual((summary, entries, reviews), before)
        with self.assertRaisesRegex(ExportError, "summary_count_mismatch"):
            render_packet(dict(summary, annotation_error_count=0), entries, reviews)

    def test_legacy_inputs_still_complete_and_old_summaries_stay_unrecorded(self):
        job, result = fixture()
        finalized = finalize_result(job, result, StubRepoReader())
        self.assertIsNotNone(finalized["entry"])
        self.assertNotIn("initial_draft_status", finalized["review"])
        self.assertEqual(finalized["review"]["annotation_errors"], [])
        summary, entries, reviews = self.save(job, finalized)
        self.assertEqual((summary["annotation_error_count"], summary["jobs_with_annotation_errors"]), (0, 0))
        summary.pop("annotation_error_count")
        summary.pop("jobs_with_annotation_errors")
        reviews[0].pop("annotation_errors")
        before = deepcopy((summary, reviews))
        self.assertIn("annotation_errors：旧记录未声明", render_packet(summary, entries, reviews))
        self.assertIn("| 未解决字段协议异常项数 / 涉及输入数 | 未记录 / 未记录 |", _assessment(summary, reviews))
        self.assertEqual((summary, reviews), before)


if __name__ == "__main__":
    unittest.main()
