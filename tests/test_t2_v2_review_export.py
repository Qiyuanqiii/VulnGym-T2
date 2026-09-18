from __future__ import annotations

from contextlib import redirect_stdout
from copy import deepcopy
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from vulngym_t2.review_export import ExportError, export_review, main, render_packet


def fixture():
    reviews, entries = [], []
    for identity, status in (("entry-second", "draft"), ("entry-first", "complete"), ("entry-third", "input_failure")):
        fields = {"entry_id": identity, "report_id": "REPORT-" + identity, "source_link": "https://example.test/" + identity,
                  "vuln_title": "Title for " + identity, "verify": 0, "entry_point": {"file": "src/api.py", "line": 7, "code": "run(value)"}}
        review = {key: fields[key] for key in ("entry_id", "report_id", "source_link")}
        review.update(status=status, draft_fields=deepcopy(fields), suggested_values={"project": "unverified suggestion"},
                      field_reviews={"vuln_title": {"status": "supported", "reason": "Recorded reason", "evidence_refs": ["E1", "controller:title", "missing"]}},
                      evidence=[{"id": "E1", "kind": "input", "result": {"body": "RAW INPUT NOT EXPORTED"}},
                                {"id": "E2", "kind": "advisory", "name": "sample.md", "text": "RAW ADVISORY NOT EXPORTED"},
                                {"id": "E3", "kind": "tool", "tool": "read_file", "success": True,
                                 "arguments": {"path": "src/api.py", "commit": "a" * 40, "start_line": 7, "body": "RAW ARGUMENT NOT EXPORTED"},
                                 "result": {"text": "RAW SOURCE NOT EXPORTED", "truncated": True}}],
                      errors=[{"code": "input_failure", "message": "synthetic failure"}] if status == "input_failure" else [],
                      model_errors=[], tool_errors=[], pipeline_errors=[], model_calls=0, tool_calls=0,
                      verification="Machine annotation only")
        if status == "complete":
            entries.append(fields)
            review["draft_fields"]["vuln_title"] = "STALE DRAFT NOT EXPORTED"
        reviews.append(review)
    summary = {"status": "provider_stopped", "input_count": 3, "requested_input_count": 5,
               "unprocessed_input_count": 2, "entry_count": 1, "schema_entry_count": 1, "candidate_count": 1,
               "draft_count": 1, "input_failure_count": 1, "report_count": 1, "human_verified_count": 0,
               "provider": {"halted": "synthetic_stop", "http_attempts": 9}}
    return summary, entries, reviews


class ReviewExportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="t2-review-export-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.run = self.root / "run"
        self.run.mkdir()
        self.summary, self.entries, self.reviews = fixture()
        self.save()

    def save(self):
        (self.run / "summary.json").write_text(json.dumps(self.summary), encoding="utf-8")
        for name, rows in (("entries.jsonl", self.entries), ("review.jsonl", self.reviews)):
            (self.run / name).write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")

    def test_offline_packet_joins_ids_and_preserves_all_sources(self):
        before = {path.name: path.read_bytes() for path in self.run.iterdir()}
        with patch("socket.socket", side_effect=AssertionError("network forbidden")):
            result = export_review(self.run, self.root / "packet.md")
        self.assertEqual(result["http_attempts"], 0)
        packet = (self.root / "packet.md").read_text(encoding="utf-8")
        self.assertEqual(packet.count("## 逐条复核 "), 3)
        sections = packet.split("## 逐条复核 ")[1:]
        self.assertIn("草稿字段", sections[0])
        self.assertIn("unverified suggestion", sections[0])
        self.assertIn("完整字段", sections[1])
        self.assertIn("Title for entry&#45;first", sections[1])
        self.assertNotIn("STALE DRAFT", packet)
        self.assertIn("输入失败：该输入未导出完整条目", sections[2])
        self.assertIn("提供方已停止", packet)
        self.assertIn("人工复核状态：未知", packet)
        self.assertIn("unresolved&#95;evidence&#95;refs", packet)
        self.assertIn("read&#95;file", packet)
        self.assertIn("not applicable / not recorded".replace("/", "&#47;"), packet)
        self.assertNotIn("RAW ", packet)
        self.assertNotIn("- [x]", packet)
        self.assertEqual(before, {path.name: path.read_bytes() for path in self.run.iterdir()})

    def test_reversed_complete_entries_are_joined_by_id_not_position(self):
        entry, review = deepcopy(self.entries[0]), deepcopy(self.reviews[1])
        identity = {"entry_id": "entry-fourth", "report_id": "REPORT-fourth", "source_link": "https://example.test/fourth"}
        entry.update(identity, vuln_title="Distinct fourth title")
        review.update(identity)
        review["draft_fields"].update(identity)
        self.entries.insert(0, entry)
        self.reviews.append(review)
        self.summary.update(input_count=4, requested_input_count=6, entry_count=2, schema_entry_count=2,
                            candidate_count=2, report_count=2)
        packet = render_packet(self.summary, self.entries, self.reviews)
        sections = packet.split("## 逐条复核 ")[1:]
        self.assertIn("Title for entry&#45;first", sections[1])
        self.assertNotIn("Distinct fourth title", sections[1])
        self.assertIn("Distinct fourth title", sections[3])
        self.assertNotIn("Title for entry&#45;first", sections[3])

    def test_markdown_html_newlines_and_long_values_are_inert(self):
        payload = '<script>alert(1)</script>\n| [click](javascript:boom) `code` **yes** &lt;img&gt;\r\t'
        self.reviews[0]["draft_fields"]["payload"] = payload
        self.reviews[0]["field_reviews"]["bad|field"] = {"status": "uncertain", "reason": payload, "evidence_refs": []}
        self.reviews[0]["suggested_values"]["long"] = "z" * 8_001
        packet = render_packet(self.summary, self.entries, self.reviews)
        self.assertNotIn("<script>", packet)
        self.assertNotIn("[click]", packet)
        self.assertNotIn("`code`", packet)
        self.assertNotIn("**yes**", packet)
        self.assertNotIn("&lt;img", packet)
        self.assertIn("&#60;script&#62;", packet)
        self.assertIn("&#92;n&#124;", packet)
        self.assertIn("truncated", packet)
        self.assertIn("1 characters omitted", packet)

    def test_secret_tokens_and_absolute_local_paths_are_redacted(self):
        self.reviews[0]["draft_fields"]["notes"] = r"D:\private\target.py /home/person/private sk-syntheticsecret123 Bearer syntheticsecret"
        packet = render_packet(self.summary, self.entries, self.reviews)
        for private in ("target.py", "person", "syntheticsecret"):
            self.assertNotIn(private, packet)
        self.assertIn("local path redacted", packet)
        self.assertIn("secret redacted", packet)

    def test_rejects_inconsistent_ids_counts_and_shapes(self):
        mutations = [
            lambda s, e, r: e.append(deepcopy(e[0])),
            lambda s, e, r: r.append(deepcopy(r[0])),
            lambda s, e, r: e[0].update(entry_id="unmatched"),
            lambda s, e, r: r[1].update(status="draft"),
            lambda s, e, r: r[1].update(report_id="wrong"),
            lambda s, e, r: r[0]["draft_fields"].update(entry_id="wrong"),
            lambda s, e, r: r[0]["suggested_values"].update(entry_id="wrong"),
            lambda s, e, r: s.update(candidate_count=2),
            lambda s, e, r: s.update(requested_input_count=6),
            lambda s, e, r: s.update(input_count=True),
            lambda s, e, r: s.update(model_error_count=1),
            lambda s, e, r: s.update(status="running"),
            lambda s, e, r: s.update(status="pending"),
            lambda s, e, r: s.update(status="unknown"),
            lambda s, e, r: s.update(status="completed"),
            lambda s, e, r: r[0]["evidence"].append(deepcopy(r[0]["evidence"][0])),
            lambda s, e, r: r[0]["field_reviews"]["vuln_title"].update(evidence_refs="E1"),
            lambda s, e, r: r[0].update(errors="not a list"),
            lambda s, e, r: r[0].update(status=[]),
            lambda s, e, r: e[0].update(report_id={}),
        ]
        for mutation in mutations:
            with self.subTest(mutation=mutations.index(mutation)):
                summary, entries, reviews = fixture()
                mutation(summary, entries, reviews)
                with self.assertRaises(ExportError):
                    render_packet(summary, entries, reviews)

    def test_invalid_json_duplicate_keys_blank_lines_and_size_refused(self):
        for value in ('{"status":', '{"status":"completed","status":"oops"}', '{"n":NaN}', '{"n":1e999}', '[]'):
            with self.subTest(value=value):
                (self.run / "summary.json").write_text(value, encoding="utf-8")
                with self.assertRaises(ExportError):
                    export_review(self.run, self.root / "packet.md")
                self.assertFalse((self.root / "packet.md").exists())
        self.save()
        with patch("vulngym_t2.review_export.MAX_FILE_BYTES", 8):
            with self.assertRaisesRegex(ExportError, "source_file_too_large"):
                export_review(self.run, self.root / "packet.md")
        (self.run / "entries.jsonl").write_text("\n", encoding="utf-8")
        with self.assertRaisesRegex(ExportError, "blank_jsonl_record"):
            export_review(self.run, self.root / "packet.md")

    def test_output_must_be_new_and_outside_run_and_local(self):
        existing = self.root / "existing.md"
        existing.write_text("keep", encoding="utf-8")
        for output in (existing, self.run / "packet.md", self.run / "nested" / "packet.md"):
            with self.subTest(output=output):
                with self.assertRaises(ExportError):
                    export_review(self.run, output)
        self.assertEqual(existing.read_text(encoding="utf-8"), "keep")
        for path in (r"\\server\share\run", "https://example.test/run"):
            with self.assertRaisesRegex(ExportError, "local_path_required"):
                export_review(path, self.root / "packet.md")

    def test_source_symlink_and_output_alias_inside_run_refused(self):
        link = self.root / "run-alias"
        try:
            link.symlink_to(self.run, target_is_directory=True)
        except OSError:
            self.skipTest("symlink creation unavailable")
        with self.assertRaisesRegex(ExportError, "output_must_be_outside_run"):
            export_review(self.run, link / "packet.md")
        source = self.run / "entries.jsonl"
        moved = self.root / "entries-copy.jsonl"
        source.rename(moved)
        source.symlink_to(moved)
        with self.assertRaisesRegex(ExportError, "source_file_unavailable"):
            export_review(self.run, self.root / "packet.md")

    def test_empty_finished_run_has_no_implied_review(self):
        summary = {"status": "completed", "input_count": 0, "entry_count": 0, "schema_entry_count": 0,
                   "candidate_count": 0, "draft_count": 0, "input_failure_count": 0}
        packet = render_packet(summary, [], [])
        self.assertIn("没有已处理的复核记录", packet)
        self.assertNotIn("## 逐条复核 ", packet)

    def test_revision_basis_labels_are_machine_claims_without_rewriting_records(self):
        labels = {"behavior_at_revision": "源码机制依据", "affected_range_and_source": "影响范围+源码",
                  "inspected_only": "仅检查过", "unknown": "未建立"}
        for basis, label in labels.items():
            with self.subTest(basis=basis):
                self.reviews[1]["field_reviews"]["commit"] = {
                    "status": "supported", "reason": "Saved machine claim", "evidence_refs": ["E3"],
                    "revision_basis": basis,
                }
                before = deepcopy((self.summary, self.entries, self.reviews))
                packet = render_packet(self.summary, self.entries, self.reviews)
                self.assertIn("版本判断依据（已记录机器声明）：" + label, packet)
                self.assertIn("机器声明不等于人工审核", packet)
                self.assertEqual((self.summary, self.entries, self.reviews), before)
                self.assertEqual(self.entries[0]["verify"], 0)
                self.assertEqual(self.reviews[1]["status"], "complete")

    def test_legacy_revision_basis_is_undeclared_not_reclassified(self):
        self.reviews[1]["field_reviews"]["commit"] = {
            "status": "supported", "reason": "Legacy assessment", "evidence_refs": ["E3"],
        }
        before = deepcopy((self.summary, self.entries, self.reviews))
        packet = render_packet(self.summary, self.entries, self.reviews)
        section = packet.split("## 逐条复核 ")[2]
        self.assertIn("版本判断依据（已记录机器声明）：旧记录未声明", section)
        self.assertIn("| commit | supported | Legacy assessment |", section)
        self.assertEqual((self.summary, self.entries, self.reviews), before)
        self.assertNotIn("revision_basis", self.reviews[1]["field_reviews"]["commit"])

    def test_self_review_status_is_shown_without_inference_or_reclassification(self):
        labels = {"not_requested": "未请求（不是失败）", "completed": "已完成机器自查",
                  "failed": "机器自查失败", None: "旧记录未声明"}
        for status, label in labels.items():
            with self.subTest(status=status):
                if status is None:
                    self.reviews[0].pop("self_review_status", None)
                else:
                    self.reviews[0]["self_review_status"] = status
                before = deepcopy((self.summary, self.entries, self.reviews))
                packet = render_packet(self.summary, self.entries, self.reviews)
                section = packet.split("## 逐条复核 ")[1]
                self.assertIn("机器自查状态：" + label, section)
                self.assertIn("机器自查不等于独立人工审核", section)
                self.assertEqual((self.summary, self.entries, self.reviews), before)
                self.assertEqual(self.reviews[0]["status"], "draft")

    def test_evidence_followup_status_is_adjacent_to_self_review_without_mutation(self):
        cases = [("not_requested", "未请求（不是失败）"), ("completed", "已完成聚焦补证"),
                 ("failed", "聚焦补证失败"), (None, "旧记录未声明"),
                 (["completed"], "未识别声明"), ("<script>unknown</script>", "未识别声明")]
        for status, label in cases:
            with self.subTest(status=status):
                self.reviews[0]["self_review_status"] = "not_requested"
                if status is None:
                    self.reviews[0].pop("evidence_followup_status", None)
                else:
                    self.reviews[0]["evidence_followup_status"] = status
                before = deepcopy((self.summary, self.entries, self.reviews))
                packet = render_packet(self.summary, self.entries, self.reviews)
                section = packet.split("## 逐条复核 ")[1]
                lines = section.splitlines()
                index = next(i for i, line in enumerate(lines) if line.startswith("聚焦补证状态："))
                self.assertIn("聚焦补证状态：" + label, lines[index])
                self.assertEqual(lines[index + 1], "")
                self.assertTrue(lines[index + 2].startswith("机器自查状态：未请求（不是失败）"))
                self.assertIn("预算内只读补证，实际次数见动作记录", lines[index])
                self.assertIn("非人工验收，不保证语义正确", lines[index])
                self.assertNotIn("<script>", section)
                self.assertEqual((self.summary, self.entries, self.reviews), before)
                self.assertEqual(self.reviews[0]["status"], "draft")
                self.assertEqual(self.reviews[0]["draft_fields"]["verify"], 0)

    def test_completed_with_errors_is_finished_but_not_all_successful(self):
        self.summary.update(status="completed_with_errors", requested_input_count=3,
                            unprocessed_input_count=0, format_failure_count=1, provider={},
                            case_failures=[{"report_id": self.reviews[0]["report_id"],
                                            "code": "model_format_failure", "continued": True}])
        self.save()
        before = {path.name: path.read_bytes() for path in self.run.iterdir()}
        with patch("socket.socket", side_effect=AssertionError("network forbidden")):
            export_review(self.run, self.root / "with-errors.md")
        packet = (self.root / "with-errors.md").read_text(encoding="utf-8")
        self.assertIn("批次已处理完但含格式错误", packet)
        self.assertIn("不是全成功", packet)
        self.assertIn("format&#95;failure&#95;count", packet)
        self.assertIn("model&#95;format&#95;failure", packet)
        self.assertIn("失败输入仍是草稿", packet)
        self.assertEqual(self.reviews[0]["status"], "draft")
        self.assertEqual(before, {path.name: path.read_bytes() for path in self.run.iterdir()})
        for changes in ({"unprocessed_input_count": 1, "requested_input_count": 4},
                        {"format_failure_count": 0}, {"format_failure_count": True},
                        {"requested_input_count": 4}):
            with self.subTest(changes=changes):
                summary = deepcopy(self.summary)
                summary.update(changes)
                with self.assertRaises(ExportError):
                    render_packet(summary, self.entries, self.reviews)

    def test_not_received_candidate_renders_placeholder_draft_section(self):
        self.reviews[0]["initial_draft_status"] = "not_received"
        self.reviews[0]["actions"] = [{"action": "annotation_snapshot_reencoding", "stage": "draft",
                                       "summary": "budget_unavailable"}]
        before = deepcopy((self.summary, self.entries, self.reviews))
        packet = render_packet(self.summary, self.entries, self.reviews)
        section = packet.split("## 逐条复核 ")[1]
        self.assertIn("### 初稿未接收说明", section)
        self.assertLess(section.index("### 初稿未接收说明"), section.index("### 字段判断"))
        self.assertIn("本候选的结构化初稿未接收或未恢复", section)
        self.assertIn("仅有输入元数据与已收集证据", section)
        self.assertIn("initial&#95;draft&#95;status", section)
        self.assertIn("not&#95;received", section)
        self.assertIn("budget&#95;unavailable", section)
        self.assertIn("已保留证据条数", section)
        self.assertIn("| 3 | E1, E2, E3 |", section)
        self.assertIn("本工具不自动填充任何字段", section)
        self.assertIn("被拒收对象的字段值从未被应用", section)
        self.assertNotIn("RAW ", section)
        self.assertEqual((self.summary, self.entries, self.reviews), before)
        self.save()
        with patch("socket.socket", side_effect=AssertionError("network forbidden")):
            export_review(self.run, self.root / "gap.md")
        exported = (self.root / "gap.md").read_text(encoding="utf-8")
        self.assertIn("### 初稿未接收说明", exported)
        self.assertIn("| 3 | E1, E2, E3 |", exported)

    def test_accepted_and_partial_drafts_do_not_render_the_placeholder_section(self):
        self.reviews[0]["initial_draft_status"] = "accepted"
        self.reviews[1]["initial_draft_status"] = "accepted"
        self.reviews[2]["initial_draft_status"] = "accepted"
        packet = render_packet(self.summary, self.entries, self.reviews)
        self.assertNotIn("初稿未接收说明", packet)
        # "partial" received a draft with recoverable field errors; its row can
        # hold real merged values, so it must not be called a placeholder.
        self.reviews[0]["initial_draft_status"] = "partial"
        self.reviews[0]["actions"] = [{"action": "annotation_snapshot_reencoding", "stage": "draft",
                                       "summary": "recovered"}]
        packet = render_packet(self.summary, self.entries, self.reviews)
        self.assertNotIn("初稿未接收说明", packet)

    def test_received_initial_draft_survives_a_failed_self_review_encoding(self):
        # NLTK v80 shape: accepted initial fields remain even when the later
        # self-review encoding cannot be corrected. A failed review is not a
        # missing initial draft; neither accepted nor partial values are lost.
        for status in ("accepted", "partial"):
            for stage in ("self_review", "draft"):
                with self.subTest(status=status, stage=stage):
                    self.reviews[0]["initial_draft_status"] = status
                    self.reviews[0]["self_review_status"] = "failed"
                    self.reviews[0]["actions"] = [
                        {"action": "annotation_snapshot_reencoding", "stage": stage,
                         "summary": "budget_unavailable"}]
                    before = deepcopy((self.summary, self.entries, self.reviews))
                    packet = render_packet(self.summary, self.entries, self.reviews)
                    self.assertNotIn("初稿未接收说明", packet)
                    self.assertEqual((self.summary, self.entries, self.reviews), before)

    def test_legacy_reencoding_failure_requires_an_explicit_draft_stage(self):
        for review in self.reviews:
            review.pop("initial_draft_status", None)
        for stage in ("self_review", "field_recovery", None):
            with self.subTest(stage=stage):
                action = {"action": "annotation_snapshot_reencoding", "summary": "failed"}
                if stage is not None:
                    action["stage"] = stage
                self.reviews[0]["actions"] = [action]
                before = deepcopy((self.summary, self.entries, self.reviews))
                packet = render_packet(self.summary, self.entries, self.reviews)
                self.assertNotIn("初稿未接收说明", packet)
                self.assertEqual((self.summary, self.entries, self.reviews), before)

    def test_explicit_missing_initial_status_needs_no_reencoding_action(self):
        for status in ("not_received", "no_valid_updates"):
            with self.subTest(status=status):
                self.reviews[0]["initial_draft_status"] = status
                self.reviews[0]["actions"] = []
                packet = render_packet(self.summary, self.entries, self.reviews)
                section = packet.split("## 逐条复核 ")[1]
                self.assertIn("### 初稿未接收说明", section)
                self.assertIn(status.replace("_", "&#95;"), section)

    def test_legacy_records_without_initial_draft_status_render_unchanged(self):
        for review in self.reviews:
            review.pop("initial_draft_status", None)
        before = deepcopy((self.summary, self.entries, self.reviews))
        packet = render_packet(self.summary, self.entries, self.reviews)
        self.assertNotIn("初稿未接收说明", packet)
        self.assertIn("### 字段判断", packet)
        self.assertEqual((self.summary, self.entries, self.reviews), before)
        # A legacy row without the field still shows the section when its own
        # actions record an unrecovered snapshot re-encoding.
        self.reviews[0]["actions"] = [{"action": "annotation_snapshot_rejected", "code": "missing_root_fields"},
                                      {"action": "annotation_snapshot_reencoding", "stage": "draft",
                                       "summary": "budget_unavailable"}]
        section = render_packet(self.summary, self.entries, self.reviews).split("## 逐条复核 ")[1]
        self.assertIn("### 初稿未接收说明", section)
        self.assertIn("| 3 | E1, E2, E3 |", section)
        self.assertLess(section.index("### 初稿未接收说明"), section.index("### 字段判断"))

    def test_cli_emits_compact_json_on_success_and_failure(self):
        output = self.root / "packet.md"
        process = subprocess.run([sys.executable, "-B", "-m", "vulngym_t2.review_export", "--run-dir", str(self.run),
                                  "--output", str(output)], cwd=Path(__file__).resolve().parents[1],
                                 capture_output=True, text=True, check=False)
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(json.loads(process.stdout)["http_attempts"], 0)
        self.assertEqual(len(process.stdout.splitlines()), 1)
        captured = io.StringIO()
        with redirect_stdout(captured):
            code = main(["--run-dir", str(self.run), "--output", str(output)])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(captured.getvalue()), {"status": "error", "code": "output_exists", "http_attempts": 0})


if __name__ == "__main__":
    unittest.main()
