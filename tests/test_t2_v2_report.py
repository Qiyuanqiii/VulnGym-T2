"""Offline rendering checks on synthetic public records, without target/provider access."""

from copy import deepcopy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from vulngym_t2.report import _assessment, build_assessment


def fixture():
    summary = {"status": "completed", "input_count": 1, "requested_input_count": 1,
               "unprocessed_input_count": 0, "candidate_count": 0, "draft_count": 1,
               "input_failure_count": 0, "format_failure_count": 0, "provider": {}}
    review = {"entry_id": "entry-synthetic", "report_id": "REPORT-synthetic", "status": "draft",
              "source_link": "https://example.test/synthetic", "draft_fields": {"commit": "a" * 40, "verify": 0},
              "suggested_values": {}, "field_reviews": {"commit": {
                  "status": "supported", "reason": "Saved machine statement", "evidence_refs": ["E1"],
              }}, "model_calls": 0, "tool_calls": 0, "errors": [], "pipeline_errors": [],
              "model_errors": [], "tool_errors": []}
    return summary, [review]


class ReportTests(unittest.TestCase):
    def test_four_revision_bases_are_explained_without_changing_machine_status(self):
        labels = {"behavior_at_revision": "源码机制依据", "affected_range_and_source": "影响范围+源码",
                  "inspected_only": "仅检查过", "unknown": "未建立"}
        for basis, label in labels.items():
            with self.subTest(basis=basis):
                summary, reviews = fixture()
                reviews[0]["field_reviews"]["commit"]["revision_basis"] = basis
                before = deepcopy((summary, reviews))
                content = _assessment(summary, reviews)
                self.assertIn("版本判断依据（已记录机器声明）：" + label, content)
                self.assertIn("机器声明不等于人工审核", content)
                self.assertIn("| `commit` | 已支持（模型/控制器） |", content)
                self.assertEqual((summary, reviews), before)
                self.assertEqual(reviews[0]["draft_fields"]["verify"], 0)

    def test_old_revision_basis_remains_undeclared_without_downgrading_saved_status(self):
        summary, reviews = fixture()
        before = deepcopy((summary, reviews))
        content = _assessment(summary, reviews)
        self.assertIn("版本判断依据（已记录机器声明）：旧记录未声明", content)
        self.assertIn("| `commit` | 已支持（模型/控制器） |", content)
        self.assertEqual((summary, reviews), before)
        self.assertNotIn("revision_basis", reviews[0]["field_reviews"]["commit"])

    def test_invalid_basis_is_unrecognized_not_invented_or_rendered_as_markup(self):
        for basis in ("<script>invented</script>", ["behavior_at_revision"], None):
            with self.subTest(basis=basis):
                summary, reviews = fixture()
                reviews[0]["field_reviews"]["commit"]["revision_basis"] = basis
                content = _assessment(summary, reviews)
                self.assertIn("版本判断依据（已记录机器声明）：未识别声明", content)
                self.assertNotIn("<script>", content)
                self.assertNotIn("版本判断依据（已记录机器声明）：源码机制依据", content)

    def test_self_review_status_is_explicit_and_missing_old_fields_are_not_inferred(self):
        labels = {"not_requested": "未请求（不是失败）", "completed": "已完成机器自查",
                  "failed": "机器自查失败", None: "旧记录未声明"}
        for status, label in labels.items():
            with self.subTest(status=status):
                summary, reviews = fixture()
                if status is not None:
                    reviews[0]["self_review_status"] = status
                before = deepcopy((summary, reviews))
                content = _assessment(summary, reviews)
                self.assertIn("机器自查状态：" + label, content)
                self.assertIn("机器自查不等于独立人工审核", content)
                self.assertEqual((summary, reviews), before)
                self.assertEqual(reviews[0]["status"], "draft")

    def test_evidence_followup_status_is_adjacent_to_self_review_and_not_human_verification(self):
        cases = [("not_requested", "未请求（不是失败）"), ("completed", "已完成聚焦补证"),
                 ("failed", "聚焦补证失败"), (None, "旧记录未声明"),
                 (["completed"], "未识别声明"), ("<script>unknown</script>", "未识别声明")]
        for status, label in cases:
            with self.subTest(status=status):
                summary, reviews = fixture()
                reviews[0]["self_review_status"] = "not_requested"
                if status is not None:
                    reviews[0]["evidence_followup_status"] = status
                before = deepcopy((summary, reviews))
                content = _assessment(summary, reviews)
                lines = content.splitlines()
                index = next(i for i, line in enumerate(lines) if line.startswith("- 聚焦补证状态："))
                self.assertIn("聚焦补证状态：" + label, lines[index])
                self.assertTrue(lines[index + 1].startswith("- 机器自查状态：未请求（不是失败）"))
                self.assertIn("预算内只读补证，实际次数见动作记录", lines[index])
                self.assertIn("非人工验收，不保证语义正确", lines[index])
                self.assertNotIn("<script>", content)
                self.assertEqual((summary, reviews), before)
                self.assertEqual(reviews[0]["status"], "draft")
                self.assertEqual(reviews[0]["draft_fields"]["verify"], 0)

    def test_completed_with_errors_preserves_draft_and_exposes_case_failures(self):
        summary, reviews = fixture()
        summary.update(status="completed_with_errors", format_failure_count=1,
                       case_failures=[{"report_id": "REPORT-synthetic", "code": "model_format_failure",
                                       "continued": True}])
        before = deepcopy((summary, reviews))
        content = _assessment(summary, reviews)
        self.assertIn("批次已处理完但含格式错误", content)
        self.assertIn("不是全成功", content)
        self.assertIn("失败输入仍是草稿", content)
        self.assertIn("| 格式失败输入数 | 1 |", content)
        self.assertIn("model\\_format\\_failure", content)
        self.assertEqual((summary, reviews), before)
        self.assertEqual(reviews[0]["status"], "draft")

    def test_both_completed_states_reject_unprocessed_or_inconsistent_input_counts(self):
        for status in ("completed", "completed_with_errors"):
            for changes in ({"unprocessed_input_count": 1, "requested_input_count": 2},
                            {"requested_input_count": 2}, {"unprocessed_input_count": False}):
                with self.subTest(status=status, changes=changes):
                    summary, reviews = fixture()
                    summary.update(status=status, format_failure_count=1, **changes)
                    with self.assertRaises(ValueError):
                        _assessment(summary, reviews)

    def test_completed_with_errors_requires_actual_format_failures(self):
        for count in (0, True, None, -1):
            with self.subTest(count=count):
                summary, reviews = fixture()
                summary.update(status="completed_with_errors", format_failure_count=count)
                with self.assertRaisesRegex(ValueError, "format_failure_count_invalid"):
                    _assessment(summary, reviews)

    def test_legacy_completed_summary_without_optional_input_counts_remains_readable(self):
        summary, reviews = fixture()
        del summary["requested_input_count"]
        del summary["unprocessed_input_count"]
        del summary["format_failure_count"]
        content = _assessment(summary, reviews)
        self.assertIn("旧记录未声明", content)
        self.assertIn("| 格式失败输入数 | 未记录 |", content)

    def test_file_export_reads_only_public_records_and_preserves_json_sources(self):
        temp_root = Path("D:/VulnGym-bv2-runtime/tmp") if os.name == "nt" else None
        if temp_root is not None:
            temp_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="t2-report-", dir=temp_root) as directory:
            run = Path(directory)
            summary, reviews = fixture()
            summary.update(status="completed_with_errors", format_failure_count=1,
                           case_failures=[{"report_id": "REPORT-synthetic", "code": "model_format_failure",
                                           "continued": True}])
            reviews[0]["field_reviews"]["commit"]["revision_basis"] = "inspected_only"
            reviews[0]["evidence_followup_status"] = "completed"
            (run / "summary.json").write_text(json.dumps(summary), encoding="utf-8")
            (run / "review.jsonl").write_text(json.dumps(reviews[0]) + "\n", encoding="utf-8")
            before = {path.name: path.read_bytes() for path in run.iterdir()}
            with patch("socket.socket", side_effect=AssertionError("network forbidden")):
                destination = build_assessment(run)
            self.assertEqual(destination, run / "assessment.md")
            content = destination.read_text(encoding="utf-8")
            self.assertIn("版本判断依据（已记录机器声明）：仅检查过", content)
            self.assertIn("聚焦补证状态：已完成聚焦补证", content)
            self.assertIn("不是全成功", content)
            self.assertEqual(before, {name: (run / name).read_bytes() for name in before})
            self.assertEqual({path.name for path in run.iterdir()}, set(before) | {"assessment.md"})


if __name__ == "__main__":
    unittest.main()
