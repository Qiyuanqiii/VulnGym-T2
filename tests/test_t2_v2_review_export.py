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
