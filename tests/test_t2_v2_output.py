from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest

from vulngym_t2._vendor.schema_adapter import ENTRY_FIELDS, ORIGIN, SchemaAdapter
from vulngym_t2.output import BatchWriter, finalize_result


COMMIT = "a" * 40
REPORT = "GHSA-AAAA-BBBB-CCCC"
SOURCE = "https://github.com/advisories/" + REPORT
ROOT = Path(__file__).resolve().parents[1]


class StubRepoReader:
    """Synthetic source data only: tests do not open target repositories."""

    def __init__(self, *, refuse_sink: bool = False):
        self.calls = []
        self.refuse_sink = refuse_sink
        self.source = {"src/api.py": {3: "    payload = request.body", 4: "    execute(payload)"}}

    def validate_location(self, commit, location):
        self.calls.append((commit, deepcopy(location)))
        valid = (commit == COMMIT and self.source.get(location["file"], {}).get(location["line"]) == location["code"]
                 and not (self.refuse_sink and location["line"] == 4))
        return {"valid": valid, "commit": commit, "reason": "verbatim_match" if valid else "code_not_verbatim_at_commit"}


def fixture(entry_id="entry-00001"):
    job = {"entry_id": entry_id, "report_id": REPORT, "source_link": SOURCE,
           "repo_url": "https://github.com/example/sample", "repo_path": r"D:\private\target-repo"}
    fields = {
        "entry_id": "entry-99999", "report_id": "GHSA-FAKE-FAKE-FAKE",
        "source_link": "https://github.com/advisories/GHSA-FAKE-FAKE-FAKE",
        "origin": "model-created", "verify": 1,
        "project": "sample", "repo_url": "https://github.com/model/wrong",
        "commit": COMMIT, "vuln_title": "Command injection - api.py",
        "vuln_category_l1": "Command injection", "vuln_category_l2": "Untrusted command",
        "vuln_ids": [REPORT.lower(), "cve-2026-12345", REPORT],
        "entry_point": {"file": "src/api.py", "line": 3, "code": "    payload = request.body", "desc": "External request body enters the handler."},
        "critical_operation": {"file": "src/api.py", "line": 4, "code": "    execute(payload)", "desc": "The untrusted value reaches the operation."},
        "trace": [],
    }
    evidence = [
        {"id": "E0001", "kind": "input", "result": {key: val for key, val in job.items() if key != "repo_path"}},
        {"id": "E0002", "kind": "advisory", "name": "sample-advisory.md", "text": "Sample command-injection advisory CVE-2026-12345."},
        {"id": "E0003", "kind": "tool", "tool": "read_file", "success": True,
         "arguments": {"commit": COMMIT, "path": "src/api.py", "start_line": 3, "end_line": 4},
         "result": {"commit": COMMIT, "path": "src/api.py", "start_line": 3, "end_line": 4,
                    "text": "    payload = request.body\n    execute(payload)",
                    "lines": [{"line": 3, "code": "    payload = request.body"}, {"line": 4, "code": "    execute(payload)"}], "truncated": False}},
    ]
    reviews = {field: {"status": "supported", "reason": "Supported by supplied advisory and source context.",
                       "evidence_refs": ["E0003" if field in {"entry_point", "critical_operation", "commit"} else "E0002"]}
               for field in fields}
    result = {"fields": fields, "field_reviews": reviews, "evidence": evidence,
              "actions": [{"action": "tools", "tool": "read_file", "evidence_id": "E0003"}],
              "model_calls": 3, "tool_calls": 1, "errors": []}
    return job, result


class T2V2OutputTests(unittest.TestCase):
    def test_complete_entry_has_only_official_fields_and_controller_provenance(self):
        job, result = fixture()
        repo = StubRepoReader()
        finalized = finalize_result(job, result, repo)
        entry = finalized["entry"]
        self.assertIsNotNone(entry, finalized["review"])
        self.assertEqual(set(entry), set(ENTRY_FIELDS))
        self.assertEqual(len(entry), 15)
        self.assertTrue(SchemaAdapter().validate(entry, formal_t2=True).valid)
        self.assertEqual((entry["entry_id"], entry["report_id"], entry["source_link"]), (job["entry_id"], REPORT, SOURCE))
        self.assertEqual(entry["repo_url"], job["repo_url"])
        self.assertEqual(entry["origin"], ORIGIN)
        self.assertEqual(entry["verify"], 0)
        self.assertEqual(entry["trace"], [])
        self.assertEqual(entry["vuln_ids"], ["CVE-2026-12345", REPORT])
        self.assertEqual(len(repo.calls), 2)
        self.assertIn("not independent human proof", finalized["review"]["verification"])

    def test_advisory_only_or_wrong_commit_receipts_cannot_support_unread_code(self):
        for mode in ("advisory_only", "wrong_commit", "metadata_without_bytes"):
            with self.subTest(mode=mode):
                job, result = fixture()
                if mode == "advisory_only":
                    result["field_reviews"]["entry_point"]["evidence_refs"] = ["E0002"]
                elif mode == "wrong_commit":
                    result["evidence"][2]["result"]["commit"] = "b" * 40
                else:
                    result["evidence"][2]["result"].pop("lines")
                    result["evidence"][2]["result"].pop("text")
                finalized = finalize_result(job, result, StubRepoReader())
                self.assertIsNone(finalized["entry"])
                review = finalized["review"]
                self.assertIsNone(review["draft_fields"]["entry_point"])
                self.assertEqual(review["draft_fields"]["vuln_title"], result["fields"]["vuln_title"])
                self.assertIn("source_not_read", review["field_reviews"]["entry_point"]["validation_errors"])

    def test_exact_repository_check_is_required_even_after_a_real_read(self):
        job, result = fixture()
        repo = StubRepoReader(refuse_sink=True)
        finalized = finalize_result(job, result, repo)
        self.assertIsNone(finalized["entry"])
        review = finalized["review"]
        self.assertEqual(len(repo.calls), 2)
        self.assertIsNotNone(review["draft_fields"]["entry_point"])
        self.assertIsNone(review["draft_fields"]["critical_operation"])
        self.assertEqual(review["location_checks"][1]["valid"], False)
        self.assertIn("location_validation_failed", review["field_reviews"]["critical_operation"]["validation_errors"])

    def test_made_up_location_and_line_zero_never_become_schema_entries(self):
        for line in (99, 0):
            with self.subTest(line=line):
                job, result = fixture()
                result["fields"]["critical_operation"]["line"] = line
                finalized = finalize_result(job, result, StubRepoReader())
                self.assertIsNone(finalized["entry"])
                self.assertIsNone(finalized["review"]["draft_fields"]["critical_operation"])
                self.assertEqual(finalized["review"]["suggested_values"]["critical_operation"]["line"], line)
                self.assertEqual(finalized["review"]["draft_fields"]["commit"], COMMIT)

    def test_uncertain_missing_conflicting_fields_are_empty_with_suggestions(self):
        for status in ("uncertain", "missing", "conflicting"):
            with self.subTest(status=status):
                job, result = fixture()
                title = result["fields"].pop("vuln_title")
                result["field_reviews"]["vuln_title"] = {"status": status, "reason": "Title needs comparison with full advisory.", "evidence_refs": ["E0002"], "suggested_value": title}
                finalized = finalize_result(job, result, StubRepoReader())
                review = finalized["review"]
                self.assertIsNone(finalized["entry"])
                self.assertIsNone(review["draft_fields"]["vuln_title"])
                self.assertEqual(review["suggested_values"]["vuln_title"], title)
                self.assertEqual(review["field_reviews"]["vuln_title"]["status"], status)
                self.assertTrue(any(error["field"] == "vuln_title" for error in review["errors"]))
                self.assertEqual(review["draft_fields"]["project"], "sample")

    def test_supported_label_without_successful_evidence_is_not_support(self):
        for mode in ("no_review", "no_refs", "unknown_ref", "failed_ref"):
            with self.subTest(mode=mode):
                job, result = fixture()
                if mode == "no_review":
                    result["field_reviews"].pop("vuln_category_l2")
                elif mode == "no_refs":
                    result["field_reviews"]["vuln_category_l2"]["evidence_refs"] = []
                elif mode == "unknown_ref":
                    result["field_reviews"]["vuln_category_l2"]["evidence_refs"] = ["invented"]
                else:
                    result["evidence"].append({"id": "E0004", "kind": "tool", "tool": "read_file", "success": False, "result": {"error": "read_failed"}})
                    result["field_reviews"]["vuln_category_l2"]["evidence_refs"] = ["E0004"]
                finalized = finalize_result(job, result, StubRepoReader())
                self.assertIsNone(finalized["entry"])
                review = finalized["review"]
                self.assertIsNone(review["draft_fields"]["vuln_category_l2"])
                self.assertEqual(review["draft_fields"]["vuln_title"], result["fields"]["vuln_title"])
                self.assertEqual(review["field_reviews"]["vuln_category_l2"]["status"], "uncertain")

    def test_batch_counts_only_complete_entries_groups_reports_and_redacts_sidecars(self):
        with tempfile.TemporaryDirectory(prefix="t2-output-", dir=ROOT.parent) as temp:
            writer = BatchWriter(Path(temp) / "new-output")
            for entry_id in ("entry-00002", "entry-00001"):
                job, result = fixture(entry_id)
                if entry_id == "entry-00002":
                    result["fields"]["vuln_title"] = "Command injection - handler.py"
                    result["fields"]["vuln_ids"].append("CVE-2026-54321")
                writer.record(job, finalize_result(job, result, StubRepoReader()))
            job, result = fixture("entry-00003")
            result["field_reviews"]["vuln_title"]["status"] = "uncertain"
            result["errors"] = ["Provider error at D:\\private\\target-repo using sk-test-secret123456"]
            result["actions"].append({"action": "draft", "reasoning": "hidden raw thought", "summary": r"Read D:\private\target-repo\src\api.py", "api_key": "secret"})
            writer.record(job, finalize_result(job, result, StubRepoReader()))
            failure = {"entry_id": "entry-00004", "report_id": REPORT, "source_link": SOURCE, "input_error": "advisory_unavailable"}
            writer.record(failure, finalize_result(failure, {}, None))
            summary = writer.finish({"candidate_count": 900, "provider": {"http_attempts": 3, "api_key": "private-key"}})
            self.assertEqual({key: summary[key] for key in ("input_count", "candidate_count", "draft_count", "input_failure_count", "model_error_count")},
                             {"input_count": 4, "candidate_count": 2, "draft_count": 1, "input_failure_count": 1, "model_error_count": 1})
            output = writer.directory
            entries = [json.loads(line) for line in (output / "entries.jsonl").read_text(encoding="utf-8").splitlines()]
            report = json.loads((output / "reports.jsonl").read_text(encoding="utf-8"))
            self.assertEqual([entry["entry_id"] for entry in entries], ["entry-00001", "entry-00002"])
            self.assertEqual(report["entry_ids"], ["entry-00001", "entry-00002"])
            self.assertEqual(report["vuln_title"], "Command injection")
            self.assertEqual(report["num_entries"], 2)
            self.assertEqual(report["vuln_ids"], ["CVE-2026-12345", "CVE-2026-54321", REPORT])
            self.assertEqual(len((output / "review.jsonl").read_text(encoding="utf-8").splitlines()), 4)
            all_text = "\n".join(path.read_text(encoding="utf-8") for path in output.iterdir())
            for private in ("sk-test-secret123456", "private-key", "hidden raw thought", "D:\\\\private", "repo_path"):
                self.assertNotIn(private, all_text)
            self.assertFalse(any("manifest" in path.name or "hash" in path.name for path in output.iterdir()))

    def test_existing_output_refused_and_missing_trusted_identity_not_model_filled(self):
        with tempfile.TemporaryDirectory(prefix="t2-output-", dir=ROOT.parent) as temp:
            sentinel = Path(temp) / "keep.txt"
            sentinel.write_text("unchanged", encoding="utf-8")
            with self.assertRaises(FileExistsError):
                BatchWriter(temp)
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "unchanged")
        job, result = fixture()
        job.pop("entry_id")
        finalized = finalize_result(job, result, StubRepoReader())
        self.assertIsNone(finalized["entry"])
        self.assertIsNone(finalized["review"]["draft_fields"]["entry_id"])

    def test_draft_validation_feedback_is_preserved_in_public_actions(self):
        job, result = fixture()
        result["actions"].append({"action": "draft_validation", "errors": [{"field": "entry_point", "code": "source_not_read"}],
                                  "location_corrections": [], "note": "Mechanical checks only."})
        actions = finalize_result(job, result, StubRepoReader())["review"]["actions"]
        feedback = next(action for action in actions if action["action"] == "draft_validation")
        self.assertEqual(feedback["errors"][0]["code"], "source_not_read")
        self.assertEqual(feedback["note"], "Mechanical checks only.")


if __name__ == "__main__":
    unittest.main()
