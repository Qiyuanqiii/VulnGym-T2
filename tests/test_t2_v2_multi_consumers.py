"""Synthetic offline input-review-v2 consumer checks; no target or provider."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from scripts import package_t2_v2
from vulngym_t2 import pending, report, review_export


URL = "https://github.com/advisories/GHSA-2222-3333-4444"
REPORT = "GHSA-2222-3333-4444"


def fixture(groups=(("complete", "complete"),), *, requested=None):
    reviews, entries, mappings = [], [], []
    for index, statuses in enumerate(groups, 1):
        input_id = f"entry-{index * 10:05d}"
        rows = []
        for slot, status in enumerate(statuses, 1):
            identity = f"entry-{index * 10 + slot - 1:05d}"
            fields = {key: None for key in report._FIELDS}
            fields.update(entry_id=identity, report_id=REPORT, source_link=URL,
                          project="Synthetic project", vuln_title="Supplied title", verify=0, trace=[])
            row = dict(entry_id=identity, report_id=REPORT, source_link=URL,
                       input_id=input_id, slot=slot, process_metadata_scope="shared_input",
                       status=status, draft_fields=fields, suggested_values={}, field_reviews={},
                       evidence=[], actions=[], errors=[], model_errors=[], tool_errors=[], pipeline_errors=[],
                       self_review_status="not_requested", evidence_followup_status="not_requested",
                       model_calls=3 if slot == 1 else 0, tool_calls=2 if slot == 1 else 0)
            rows.append(row)
            if status == "complete":
                entries.append(deepcopy(fields))
        status = ("input_failure" if statuses == ("input_failure",) else
                  "complete" if all(value == "complete" for value in statuses) else
                  "partial" if "complete" in statuses else "draft")
        mappings.append(dict(input_id=input_id, report_id=REPORT, source_link=URL, status=status,
                             review_entry_ids=[row["entry_id"] for row in rows],
                             entry_ids=[row["entry_id"] for row in rows if row["status"] == "complete"],
                             model_calls=3, tool_calls=2))
        reviews.extend(rows)
    requested = len(groups) if requested is None else requested
    summary = dict(counting_version="input-review-v2", input_reviews=mappings,
                   status="completed" if requested == len(groups) else "provider_stopped",
                   input_count=len(groups), requested_input_count=requested,
                   unprocessed_input_count=requested - len(groups), review_count=len(reviews),
                   entry_count=len(entries), candidate_count=len(entries), schema_entry_count=len(entries),
                   draft_count=sum(row["status"] == "draft" for row in reviews),
                   input_failure_count=sum(row["status"] == "input_failure" for row in reviews),
                   report_count=int(bool(entries)), report_conflict_count=0, report_linkage_complete=True,
                   model_calls=3 * len(groups), tool_calls=2 * len(groups),
                   model_error_count=0, tool_error_count=0, pipeline_error_count=0, jobs_with_model_errors=0,
                   format_failure_count=0)
    for status in ("complete", "partial", "draft"):
        summary[status + "_input_count"] = sum(row["status"] == status for row in mappings)
    return summary, entries, reviews


class MultiConsumerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="t2-multi-consumer-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.run = self.root / "run"
        self.run.mkdir()
        self.summary, self.entries, self.reviews = fixture()

    def save(self):
        (self.run / "summary.json").write_text(json.dumps(self.summary), encoding="utf-8")
        for name, rows in (("entries.jsonl", self.entries), ("review.jsonl", self.reviews),
                           ("reports.jsonl", [{"report_id": REPORT, "entry_ids": [row["entry_id"] for row in self.entries]}] if self.entries else []),
                           ("actions.jsonl", [])):
            (self.run / name).write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
        self.urls = self.root / "urls.txt"
        self.urls.write_text((URL + "\n") * self.summary["requested_input_count"], encoding="utf-8")

    def template(self):
        path = self.root / "template.json"
        report.build_review_template(self.run, path)
        return json.loads(path.read_text(encoding="utf-8"))

    def package(self, name="package.zip"):
        for path in ("README_T2_V2.md", "SCHEMA.md", "LICENSE"):
            (self.root / path).write_text("Synthetic fixture.\n", encoding="utf-8")
        with patch.multiple(package_t2_v2, ROOT=self.root, MODULES=(), VENDOR=(), DOCS=(), PUBLIC_INPUT_FILES=()):
            return package_t2_v2.build(self.root / name, [self.run])

    def test_two_complete_candidates_keep_two_denominators_and_snapshot_forms(self):
        self.save()
        original = {path.name: path.read_bytes() for path in self.run.iterdir()}
        with patch("socket.socket", side_effect=AssertionError("network forbidden")):
            automatic = report._assessment(self.summary, self.reviews)
            packet = review_export.render_packet(self.summary, self.entries, self.reviews)
            document = self.template()
        for text in (automatic, packet):
            self.assertIn("输入分母：1 个已处理输入；候选复核分母：2 条 review", text)
            self.assertNotIn("计数不一致", text)
        self.assertEqual(len(document["entries"]), 2)
        self.assertEqual([row["source_snapshot"] for row in document["entries"]], self.reviews)
        for row, decision in zip(document["entries"], ("supported", "reasonable_alternative")):
            row["overall"].update(decision=decision, reviewer="External reviewer", reason="Supplied judgment")
        reviewed = report._validate_human_review(document, self.reviews)
        human = report._human_assessment(self.summary, self.reviews, reviewed)
        self.assertIn("| 支持 | 1 / 2 |", human)
        self.assertIn("| 合理替代 | 1 / 2 |", human)
        self.assertIn("输入分母：1 个已处理输入", human)
        self.assertTrue(all(len(row) == 15 and row["verify"] == 0 for row in self.entries))
        self.assertEqual(original, {path.name: path.read_bytes() for path in self.run.iterdir()})

    def test_partial_draft_inherits_shared_error_signals_without_double_usage(self):
        self.summary, self.entries, self.reviews = fixture((("complete", "draft"),))
        self.reviews[0].update(model_errors=["Recorded failure", "Retained draft"],
                               pipeline_errors=["Recorded failure", "Retained draft"])
        self.summary.update(model_error_count=2, pipeline_error_count=2, jobs_with_model_errors=1)
        self.save()
        packet = review_export.render_packet(self.summary, self.entries, self.reviews)
        document = self.template()
        counts = document["diagnostic_summary_display"]["counts_by_category"]
        self.assertEqual(counts["draft_with_technical_anomaly"], 1)
        self.assertEqual(counts["draft_without_recorded_technical_anomaly"], 0)
        self.assertIn("Recorded failure", packet.split("## 逐条复核 ")[2])
        self.assertEqual(self.summary["model_calls"], 3)
        self.assertEqual(self.summary["partial_input_count"], 1)
        self.assertEqual(self.summary["complete_input_count"], 0)
        self.assertEqual(self.reviews[1]["model_errors"], [])

    def test_shared_error_two_drafts_count_candidates_not_errors_or_inputs(self):
        self.summary, self.entries, self.reviews = fixture((("draft", "draft"),))
        self.reviews[0]["model_errors"] = ["one", "two"]
        self.summary.update(model_error_count=2, jobs_with_model_errors=1)
        review_export.render_packet(self.summary, self.entries, self.reviews)
        self.assertEqual(report._diagnostic_counts(self.reviews)["draft_with_technical_anomaly"], 2)
        self.assertEqual(self.summary["draft_input_count"], 1)
        self.assertEqual(self.summary["draft_count"], 2)

    def test_pending_preserves_repeated_advisory_inputs_and_uses_input_prefix(self):
        self.summary, self.entries, self.reviews = fixture((("complete", "complete"), ("draft",)), requested=3)
        self.save()
        with patch("socket.socket", side_effect=AssertionError("network forbidden")):
            result = pending.export_pending(self.urls, self.run, self.root / "pending.txt")
        self.assertEqual(result["processed_input_count"], 2)
        self.assertEqual(result["review_count"], 3)
        self.assertEqual(result["pending_input_count"], 1)
        self.assertEqual(result["pending"][0]["input_index"], 3)
        self.assertEqual((self.root / "pending.txt").read_text(encoding="utf-8"), URL + "\n")

    def test_bad_v2_mapping_is_rejected_by_all_consumers(self):
        mutations = (
            lambda s, r: s.update(counting_version="unknown"),
            lambda s, r: s.update(input_count=2),
            lambda s, r: s["input_reviews"][0].update(status="partial"),
            lambda s, r: s["input_reviews"][0].update(review_entry_ids=[r[0]["entry_id"]]),
            lambda s, r: s["input_reviews"].append(deepcopy(s["input_reviews"][0])),
            lambda s, r: r[1].update(slot=1),
            lambda s, r: r[1].update(input_id="entry-99999"),
            lambda s, r: r[1].update(tool_calls=2),
            lambda s, r: r[1].update(model_errors=["duplicate shared signal"]),
            lambda s, r: s["input_reviews"][0].update(source_link="https://example.test/other"),
        )
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                self.summary, self.entries, self.reviews = fixture()
                mutate(self.summary, self.reviews)
                self.save()
                for call in (lambda: report._assessment(self.summary, self.reviews),
                             lambda: review_export.render_packet(self.summary, self.entries, self.reviews),
                             lambda: pending.plan_pending(self.urls, self.run),
                             lambda: self.package()):
                    with self.assertRaises(ValueError):
                        call()
                self.assertFalse((self.root / "package.zip").exists())

    def test_new_archives_accept_complete_and_partial_and_keep_public_rows(self):
        for index, statuses in enumerate((("complete", "complete"), ("complete", "draft"))):
            self.summary, self.entries, self.reviews = fixture((statuses,))
            self.save()
            self.package(f"new-{index}.zip")
            with zipfile.ZipFile(self.root / f"new-{index}.zip") as archive:
                self.assertEqual(archive.read("examples/run-01/review.jsonl"), (self.run / "review.jsonl").read_bytes())

    def test_old_counting_is_not_silently_reinterpreted_as_multiple_candidates(self):
        self.summary.pop("counting_version")
        self.summary.pop("input_reviews")
        self.save()
        for call in (lambda: report._assessment(self.summary, self.reviews),
                     lambda: review_export.render_packet(self.summary, self.entries, self.reviews),
                     lambda: pending.plan_pending(self.urls, self.run), lambda: self.package()):
            with self.assertRaises(ValueError):
                call()

    def test_changed_shared_snapshot_invalidates_old_form_for_all_candidates(self):
        self.save()
        document = self.template()
        self.reviews[0]["pipeline_errors"] = ["Different saved process"]
        with self.assertRaisesRegex(ValueError, "human_review_source_snapshot_mismatch"):
            report._validate_human_review(document, self.reviews)

    def test_input_failure_and_draft_placeholders_still_count_one_input_each(self):
        self.summary, self.entries, self.reviews = fixture((("input_failure",), ("draft",)))
        self.save()
        review_export.render_packet(self.summary, self.entries, self.reviews)
        result = pending.plan_pending(self.urls, self.run)
        self.assertEqual(result["processed_input_count"], 2)
        self.assertEqual(result["processed_by_status"]["input_failure"], 1)
        self.assertEqual(result["processed_by_status"]["draft"], 1)
        self.assertEqual(result["pending_input_count"], 0)

    def test_new_input_failure_template_preserves_missing_report_identity(self):
        self.summary, self.entries, self.reviews = fixture((("input_failure",),))
        self.summary["input_reviews"][0].update(report_id=None, source_link=None)
        self.reviews[0].update(report_id=None, source_link=None)
        self.reviews[0]["draft_fields"].update(report_id=None, source_link=None)
        self.save()
        document = self.template()
        self.assertIsNone(document["entries"][0]["report_id"])
        self.assertEqual(document["entries"][0]["source_snapshot"], self.reviews[0])
        reviewed = report._validate_human_review(document, self.reviews)
        self.assertIn("| 未评 | 1 / 1 |", report._human_assessment(self.summary, self.reviews, reviewed))
        # A legacy null report binding remains invalid; no identity is invented.
        self.reviews[0].pop("process_metadata_scope")
        with self.assertRaisesRegex(ValueError, "review_binding_ids_required"):
            report._review_bindings(self.reviews)

    def test_conflict_warning_does_not_imply_missing_canonical_report_link(self):
        self.summary.update(report_conflict_count=1, report_conflict_entry_count=2, report_linkage_complete=True)
        packet = review_export.render_packet(self.summary, self.entries, self.reviews)
        self.assertIn("冲突不等于关联缺失", packet)
        self.assertIn("canonical report", report._assessment(self.summary, self.reviews))

    def test_real_public_writer_shape_is_accepted_without_running_target_code(self):
        from tests.test_t2_v2_multi_entry import multi_fixture
        from tests.test_t2_v2_output import StubRepoReader
        from vulngym_t2.multi_entry import allocate_entry_ids
        from vulngym_t2.output import BatchWriter, finalize_job
        for index, partial in enumerate((False, True)):
            job, result = multi_fixture()
            if partial:
                result["entry_results"][1]["field_reviews"]["critical_operation"]["status"] = "uncertain"
            finalized = finalize_job(job, result, StubRepoReader(), entry_ids=allocate_entry_ids([job])[0])
            writer = BatchWriter(self.root / f"written-{index}")
            writer.record_job(job, finalized)
            summary = writer.finish({"status": "completed", "requested_input_count": 1, "unprocessed_input_count": 0})
            reviews = review_export._rows((writer.directory / "review.jsonl").read_text(encoding="utf-8"))
            entries = review_export._rows((writer.directory / "entries.jsonl").read_text(encoding="utf-8"))
            review_export.render_packet(summary, entries, reviews)
            report._assessment(summary, reviews)
            self.assertEqual(summary["partial_input_count"], int(partial))
            self.assertEqual(len(reviews), 2)

    def test_new_record_bound_expands_only_for_explicit_counting_version(self):
        self.summary, self.entries, self.reviews = fixture(tuple(("complete", "complete") for _ in range(251)))
        self.save()
        result = review_export.export_review(self.run, self.root / "many.md")
        self.assertEqual(result["review_count"], 502)
        text = (self.run / "review.jsonl").read_text(encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "record_limit_exceeded"):
            review_export._rows(text)
        self.assertIn("multi_entry", package_t2_v2.MODULES)


if __name__ == "__main__":
    unittest.main()
