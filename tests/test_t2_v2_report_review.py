"""Offline report checks using only small synthetic public run files."""
from __future__ import annotations

import contextlib
from copy import deepcopy
import io
import json
from pathlib import Path
import tempfile
import unittest

from vulngym_t2.report import (
    _entry_diagnostic, build_assessment, build_human_assessment, build_review_template, main,
)


class T2V2ReportReviewTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="t2-report-review-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.run = self.root / "public-run"
        self.run.mkdir()
        self.summary = {
            "status": "partial", "requested_input_count": 6, "input_count": 5,
            "unprocessed_input_count": 1, "candidate_count": 1,
            "draft_count": 2, "input_failure_count": 1,
        }
        self.reviews = [
            {"entry_id": f"entry-{index:05d}", "report_id": "GHSA-AAAA-BBBB-CCCC",
             "status": status, "source_link": "https://github.com/advisories/GHSA-AAAA-BBBB-CCCC",
             "draft_fields": {"project": "sample", "vuln_title": "Supplied advisory",
                              "commit": "a" * 40, "verify": 0,
                              "entry_point": {"file": "src/api.py", "line": 3},
                              "critical_operation": None},
             "field_reviews": {"critical_operation": {"status": "uncertain", "reason": "Missing evidence"}}}
            for index, status in enumerate(("draft", "unknown", "complete", "input_failure", "draft"), 1)
        ]
        self._write_public()
        self.original = {path.name: path.read_bytes() for path in self.run.iterdir()}
        self.template_path = self.root / "review-template.json"

    def _write_public(self):
        (self.run / "summary.json").write_text(json.dumps(self.summary), encoding="utf-8")
        (self.run / "review.jsonl").write_text(
            "\n".join(json.dumps(item) for item in self.reviews) + "\n", encoding="utf-8")

    def _template(self):
        build_review_template(self.run, self.template_path)
        return json.loads(self.template_path.read_text(encoding="utf-8"))

    def _write_form(self, document, name="filled.json"):
        path = self.root / name
        path.write_text(json.dumps(document, ensure_ascii=False), encoding="utf-8")
        return path

    def _assert_public_unchanged(self):
        for name, original in self.original.items():
            self.assertEqual((self.run / name).read_bytes(), original)

    def test_template_keeps_real_entry_bindings_and_every_judgment_unreviewed(self):
        document = self._template()
        self.assertEqual(len(document["entries"]), 5)
        self.assertEqual(document["entries"][0]["entry_id"], "entry-00001")
        self.assertEqual({entry["report_id"] for entry in document["entries"]}, {"GHSA-AAAA-BBBB-CCCC"})
        expected_checks = {"project_source", "title_source", "affected_version", "entry_point_role",
                           "critical_operation", "entry_operation_link", "classification"}
        for entry in document["entries"]:
            self.assertEqual(set(entry["checks"]), expected_checks)
            for judgment in [entry["overall"], *entry["checks"].values()]:
                self.assertEqual(judgment, {"reviewer": "", "decision": "not_reviewed", "reason": "", "evidence_refs": []})
        self.assertEqual(document["entries"][0]["source_snapshot"], self.reviews[0])
        self.assertEqual(document["entries"][0]["source_context_display"]["status"], "draft")
        self.assertEqual(document["entries"][1]["source_context_display"]["status"], "unknown")
        self.assertEqual(document["entries"][0]["source_context_display"]["verify"], "0")
        self.assertFalse((self.run / "assessment.md").exists())
        self._assert_public_unchanged()

    def test_human_counts_keep_alternatives_uncertainty_and_unreviewed_in_denominator(self):
        document = self._template()
        decisions = ("supported", "reasonable_alternative", "contradicted", "uncertain", "not_reviewed")
        for entry, decision in zip(document["entries"], decisions):
            if decision != "not_reviewed":
                entry["overall"].update(reviewer="导师 A", decision=decision,
                                        reason="保留合理的另一调用点；[文字] <script> Bearer secretvalue D:\\private\\source",
                                        evidence_refs=["E0002", "public-note:section-3"])
        document["entries"][0]["checks"]["classification"].update(
            reviewer="导师 B", decision="reasonable_alternative", reason="另一个类别同样符合机制", evidence_refs=[])
        # Editable display context cannot alter the run status used in the report.
        document["entries"][0]["source_context_display"].update(status="complete", verify="1")
        output = self.root / "human.md"
        build_human_assessment(self.run, self._write_form(document), output)
        markdown = output.read_text(encoding="utf-8")
        for label in ("支持", "合理替代", "反证", "不确定", "未评"):
            self.assertIn(f"| {label} | 1 / 5 |", markdown)
        self.assertIn("分类是否符合实际缺陷机制 | 0 | 1 | 0 | 0 | 4 | 5 |", markdown)
        self.assertIn("原状态：draft；原 verify：0", markdown)
        self.assertIn("原状态：unknown；原 verify：0", markdown)
        self.assertIn("不计算或宣称 accuracy", markdown)
        self.assertIn("未处理输入：1", markdown)
        self.assertNotIn("secretvalue", markdown)
        self.assertNotIn("D:\\private", markdown)
        self.assertNotIn("<script>", markdown)
        self.assertIn(r"\[文字\]", markdown)
        self._assert_public_unchanged()

    def test_incomplete_mismatched_or_illegal_forms_fail_before_output_creation(self):
        template = self._template()
        cases = {
            "wrong_report": lambda form: form["entries"][0].update(report_id="GHSA-WRONG-WRONG-WRONG"),
            "missing_entry": lambda form: form["entries"].pop(),
            "duplicate_entry": lambda form: form["entries"].append(deepcopy(form["entries"][0])),
            "missing_check": lambda form: form["entries"][0]["checks"].pop("affected_version"),
            "invalid_decision": lambda form: form["entries"][0]["overall"].update(decision="correct"),
            "missing_reviewer": lambda form: form["entries"][0]["overall"].update(decision="supported", reason="Evidence"),
            "missing_reason": lambda form: form["entries"][0]["overall"].update(decision="uncertain", reviewer="Reviewer", reason="  "),
            "check_missing_reviewer": lambda form: form["entries"][0]["checks"]["entry_point_role"].update(decision="contradicted", reason="Evidence"),
            "invalid_refs": lambda form: form["entries"][0]["overall"].update(evidence_refs=[{}]),
            "wrong_schema": lambda form: form.update(schema_version=True),
            "missing_snapshot": lambda form: form["entries"][0].pop("source_snapshot"),
        }
        for name, mutate in cases.items():
            with self.subTest(name=name):
                document = deepcopy(template)
                mutate(document)
                output = self.root / f"{name}.md"
                with self.assertRaises(ValueError):
                    build_human_assessment(self.run, self._write_form(document, f"{name}.json"), output)
                self.assertFalse(output.exists())
        self._assert_public_unchanged()

    def test_same_ids_with_changed_candidate_reason_refs_or_suggestions_reject_old_review(self):
        document = self._template()
        document["entries"][0]["overall"].update(
            reviewer="Reviewer", decision="supported", reason="Reviewed the original content", evidence_refs=["E0001"])
        form = self._write_form(document)
        originals = deepcopy(self.reviews)
        changes = {
            "candidate": lambda review: review["draft_fields"].update(commit="b" * 40),
            "reason": lambda review: review["field_reviews"]["critical_operation"].update(reason="Changed source rationale"),
            "references": lambda review: review["field_reviews"]["critical_operation"].update(evidence_refs=["E9999"]),
            "suggestion": lambda review: review.update(suggested_values={"critical_operation": {"file": "src/other.py", "line": 8}}),
            "evidence_content": lambda review: review.update(evidence=[{"id": "E0001", "text": "New source text"}]),
        }
        try:
            for name, change in changes.items():
                with self.subTest(name=name):
                    self.reviews = deepcopy(originals)
                    change(self.reviews[0])
                    self._write_public()
                    output = self.root / f"stale-{name}.md"
                    with self.assertRaisesRegex(ValueError, "human_review_source_snapshot_mismatch"):
                        build_human_assessment(self.run, form, output)
                    self.assertFalse(output.exists())
        finally:
            self.reviews = originals
            self._write_public()
        self._assert_public_unchanged()

    def test_cli_modes_are_exclusive_and_all_outputs_refuse_overwrite(self):
        base = ["--run-dir", str(self.run)]
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(base + ["--review-template", str(self.template_path)]), 0)
            self.assertEqual(main(base + ["--review-template", str(self.template_path)]), 2)
            human_output = self.root / "human.md"
            self.assertEqual(main(base + ["--human-review", str(self.template_path), "--output", str(human_output)]), 0)
            self.assertEqual(main(base + ["--human-review", str(self.template_path), "--output", str(human_output)]), 2)
            self.assertEqual(main(base), 0)
            self.assertEqual(main(base), 2)
        for flags in (["--review-template", str(self.template_path), "--human-review", str(self.template_path)],
                      ["--human-review", str(self.template_path)], ["--output", str(self.root / "bad.md")]):
            with self.subTest(flags=flags), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                main(base + flags)
            self.assertEqual(error.exception.code, 2)
        self._assert_public_unchanged()

    def test_default_assessment_keeps_conflict_counts_unknown_for_older_runs(self):
        markdown = build_assessment(self.run).read_text(encoding="utf-8")
        self.assertIn("| 报告聚合冲突 / 涉及条目 | 未记录 / 未记录 |", markdown)
        self.assertIn("未识别的 review 状态", markdown)
        self._assert_public_unchanged()
        second = self.root / "conflicting-run"
        second.mkdir()
        summary = dict(self.summary, report_conflict_count=2, report_conflict_entry_count=4)
        (second / "summary.json").write_text(json.dumps(summary), encoding="utf-8")
        (second / "review.jsonl").write_bytes((self.run / "review.jsonl").read_bytes())
        markdown = build_assessment(second).read_text(encoding="utf-8")
        self.assertIn("| 报告聚合冲突 / 涉及条目 | 2 / 4 |", markdown)
        self.assertIn("保留 canonical report 与完整 entry", markdown)

    def test_draft_diagnostics_distinguish_recorded_signals_from_missing_old_fields(self):
        clean = {"status": "draft", "model_errors": [], "tool_errors": [], "pipeline_errors": [],
                 "self_review_status": "not_requested", "evidence_followup_status": "completed"}
        cases = [
            (clean, "draft_without_recorded_technical_anomaly"),
            (dict(clean, model_errors=["first error", "second error"]), "draft_with_technical_anomaly"),
            (dict(clean, tool_errors=["read failed"]), "draft_with_technical_anomaly"),
            (dict(clean, pipeline_errors=["pipeline failed"]), "draft_with_technical_anomaly"),
            (dict(clean, self_review_status="failed"), "draft_with_technical_anomaly"),
            (dict(clean, evidence_followup_status="failed"), "draft_with_technical_anomaly"),
            ({"status": "draft"}, "draft_diagnostic_insufficient"),
            (dict(clean, model_errors=None), "draft_diagnostic_insufficient"),
            ({key: value for key, value in clean.items() if key != "self_review_status"}, "draft_diagnostic_insufficient"),
            ({"status": "draft", "self_review_status": "failed"}, "draft_with_technical_anomaly"),
            (dict(clean, status="complete", model_errors=["error"]), "complete"),
            (dict(clean, status="input_failure"), "input_failure"),
        ]
        for review, expected in cases:
            with self.subTest(review=review):
                before = deepcopy(review)
                diagnostic = _entry_diagnostic(review)
                self.assertEqual(diagnostic["category"], expected)
                self.assertEqual(review, before)
        self.assertIn("诊断不足", _entry_diagnostic({"status": "draft", "self_review_status": "failed"})["detail"])

    def test_diagnostic_counts_match_template_auto_and_human_reports_per_entry(self):
        for review, status in zip(self.reviews, ("draft", "draft", "draft", "complete", "input_failure")):
            review.update(status=status, model_errors=[], tool_errors=[], pipeline_errors=[],
                          self_review_status="not_requested", evidence_followup_status="not_requested")
        self.reviews[1]["model_errors"] = ["Model request failed during draft: ProviderError", "No model draft obtained"]
        self.reviews[1]["pipeline_errors"] = list(self.reviews[1]["model_errors"])
        del self.reviews[2]["tool_errors"]
        self.summary.update(draft_count=3, format_failure_count=0)
        self._write_public()
        self.original = {path.name: path.read_bytes() for path in self.run.iterdir()}
        document = self._template()
        expected = {"complete": 1, "input_failure": 1, "draft_with_technical_anomaly": 1,
                    "draft_without_recorded_technical_anomaly": 1, "draft_diagnostic_insufficient": 1,
                    "unrecognized_status": 0}
        self.assertEqual(document["diagnostic_summary_display"]["counts_by_category"], expected)
        self.assertEqual(document["entries"][1]["source_context_display"]["diagnostic"]["category"], "draft_with_technical_anomaly")
        auto = build_assessment(self.run).read_text(encoding="utf-8")
        # Display fields are not trusted to override actual per-entry diagnosis.
        document["diagnostic_summary_display"]["counts_by_category"]["draft_with_technical_anomaly"] = 99
        human = build_human_assessment(self.run, self._write_form(document), self.root / "diagnostics.md").read_text(encoding="utf-8")
        for markdown in (auto, human):
            self.assertIn("| 伴技术异常的草稿 | 1 |", markdown)
            self.assertIn("| 未记录技术异常的草稿（仍需核对证据缺口） | 1 |", markdown)
            self.assertIn("| 草稿诊断不足（诊断字段缺失或无效） | 1 |", markdown)
            self.assertIn("同一条有多条错误仍只计一次", markdown)
            self.assertIn("不推断唯一根因", markdown)
        self.assertIn("| 格式失败输入数 | 0 |", auto)
        self._assert_public_unchanged()


if __name__ == "__main__":
    unittest.main()
