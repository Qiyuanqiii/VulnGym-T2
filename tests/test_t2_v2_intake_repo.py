"""Focused synthetic checks; never execute code from an inspected repository."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from vulngym_t2.intake import MAX_DOCUMENT_CHARS, load_jobs
from vulngym_t2.repository import RepoReader, safe_error_code
from vulngym_t2._vendor.schema_adapter import validate_entry


class IntakeRepoTests(unittest.TestCase):
    def test_repository_error_codes_are_an_exact_allowlist(self):
        self.assertEqual(safe_error_code(ValueError("commit_unavailable")), "commit_unavailable")
        for error in (ValueError("synthetic_private_string"), ValueError("path D:/private/example"),
                      RuntimeError("commit_unavailable"), ValueError("commit_unavailable", "extra")):
            self.assertEqual(safe_error_code(error), "repository_read_failed")

    @classmethod
    def setUpClass(cls):
        temp_root = Path("D:/Temp") if os.name == "nt" else None
        cls.temp = tempfile.TemporaryDirectory(prefix="vulngym-t2-intake-", dir=temp_root)
        cls.root = Path(cls.temp.name)
        cls.repo = cls.root / "repo"
        cls.repo.mkdir()
        cls.git_executable = shutil.which("git")
        cls.git("init", "--quiet")
        (cls.repo / "nested").mkdir()
        (cls.repo / "nested" / "handler.py").write_text(
            "def handle(value):\n    return unsafe(value)\n", encoding="utf-8")
        (cls.repo / "other.txt").write_text("ordinary fixture\n", encoding="utf-8")
        cls.git("add", "--", "nested/handler.py", "other.txt")
        cls.git("-c", "user.name=Synthetic Fixture", "-c", "user.email=fixture@example.invalid",
                "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "before")
        cls.before = cls.git("rev-parse", "HEAD")
        (cls.repo / "nested" / "handler.py").write_text(
            "def handle(value):\n    return safe(value)\n", encoding="utf-8")
        cls.git("add", "--", "nested/handler.py")
        cls.git("-c", "user.name=Synthetic Fixture", "-c", "user.email=fixture@example.invalid",
                "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "fix input")
        cls.after = cls.git("rev-parse", "HEAD")
        cls.git("config", "--local", "remote.origin.url", "https://github.com/example/fixture.git")

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    @classmethod
    def git(cls, *args):
        env = {key: value for key, value in os.environ.items() if not key.upper().startswith("GIT_")}
        env.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_SYSTEM": os.devnull,
                    "GIT_CONFIG_GLOBAL": os.devnull, "GIT_TERMINAL_PROMPT": "0"})
        return subprocess.run(
            [cls.git_executable, "-c", f"core.hooksPath={os.devnull}", "-C", str(cls.repo), *args],
            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=10, env=env, text=True,
        ).stdout.strip()

    def test_local_advisory_infers_only_same_repository_fix_and_stable_ids(self):
        advisory = self.root / "advisory.md"
        advisory.write_text(
            "GHSA-2345-6789-cfgh\nInput issue.\n"
            f"https://github.com/example/fixture/commit/{self.after}\n"
            f"https://github.com/unrelated/dependency/commit/{'a' * 40}\n"
            f"Unclassified hash {'b' * 40}\n", encoding="utf-8")
        first = load_jobs(advisory=advisory, repo=self.repo)[0]
        second = load_jobs(advisory=advisory, repo=self.repo)[0]
        self.assertEqual(first["fix_commits"], [self.after])
        self.assertEqual(first["entry_id"], second["entry_id"])
        self.assertEqual(first["report_id"], "GHSA-2345-6789-CFGH")
        self.assertEqual(first["repo_url"], "https://github.com/example/fixture")
        self.assertNotIn("input_error", first)
        self.assertNotIn("source_paths", first)
        location = {"file": "nested/handler.py", "line": 2, "code": "    return unsafe(value)"}
        entry = {"entry_id": first["entry_id"], "report_id": first["report_id"],
                 "source_link": first["source_link"], "repo_url": first["repo_url"],
                 "commit": self.before, "vuln_ids": [first["report_id"]],
                 "origin": "GitHub Advisory Database (reviewed)", "project": "fixture",
                 "vuln_title": "Synthetic fixture", "vuln_category_l1": "Injection",
                 "vuln_category_l2": "Input injection", "entry_point": location,
                 "critical_operation": location, "trace": [], "verify": 0}
        checked = validate_entry(entry)
        self.assertTrue(checked.valid, checked.issues)

    def test_duplicate_batch_ids_are_schema_shaped_and_explicitly_distinct(self):
        batch = self.root / "duplicate-batch.jsonl"
        row = {"description": "same material", "repo_path": "repo",
               "repo_url": "https://github.com/example/fixture"}
        batch.write_text((json.dumps(row) + "\n") * 2, encoding="utf-8")
        jobs = load_jobs(input_path=batch)
        self.assertNotEqual(jobs[0]["entry_id"], jobs[1]["entry_id"])
        for job in jobs:
            self.assertRegex(job["entry_id"], r"^entry-[0-9]{5}$")
        self.assertIn("entry_id_collision_resolved_within_batch", jobs[1]["input_warnings"])

    def test_jsonl_preserves_missing_and_invalid_jobs_and_bounds_documents(self):
        batch = self.root / "batch.jsonl"
        row = {"description": "x" * (MAX_DOCUMENT_CHARS + 20), "repo_path": "repo",
               "repo_url": "https://github.com/example/fixture"}
        batch.write_text(json.dumps(row) + '\n{"bad":\n' +
                         json.dumps({"description": "missing repo"}) + "\n", encoding="utf-8")
        jobs = load_jobs(input_path=batch)
        self.assertEqual(len(jobs), 3)
        self.assertEqual(len(jobs[0]["documents"][0]["text"]), MAX_DOCUMENT_CHARS)
        self.assertTrue(jobs[0]["documents"][0]["truncated"])
        self.assertIn("invalid_json_record", jobs[1]["input_error"])
        self.assertIn("repository_path_missing", jobs[2]["input_error"])

    def test_malformed_json_or_url_rows_do_not_drop_later_input(self):
        batch = self.root / "edge-rows.jsonl"
        rows = [
            '{"nested":' + '[' * 1500 + '0' + ']' * 1500 + '}',
            'https://[invalid/GHSA-2345-6789-cfgh',
            '{"description":"first","description":"contradictory"}',
            '{"description":"\\ud800"}',
            '{"unused":NaN}',
            json.dumps({"description": "Valid final input", "repo_path": "repo",
                        "repo_url": "https://github.com/example/fixture"}),
        ]
        batch.write_text("\n".join(rows) + "\n", encoding="utf-8")
        jobs = load_jobs(input_path=batch)
        self.assertEqual(len(jobs), len(rows))
        for item in jobs[:-1]:
            self.assertIn("input_error", item)
        self.assertNotIn("input_error", jobs[-1])

    def test_duplicate_primary_json_identity_is_not_promoted_to_metadata(self):
        document = self.root / "duplicate-primary.json"
        document.write_text('{"ghsa_id":"GHSA-2345-6789-cfgh","ghsa_id":"GHSA-2345-6789-jmpq",'
                            '"summary":"Synthetic","description":"Ambiguous primary identity"}', encoding="utf-8")
        loaded = load_jobs(advisory=document, repo=self.repo)[0]
        self.assertTrue(loaded["documents"][0]["json_parse_error"])
        self.assertNotIn("advisory_metadata", loaded)

    def test_cached_url_list_with_map_and_missing_cache(self):
        cache = self.root / "cache"
        cache.mkdir(exist_ok=True)
        cached_advisory = {"ghsa_id": "GHSA-2345-6789-cfgh", "summary": "Cached public advisory",
                           "description": "Unclassified prose hash: " + "f" * 40,
                           "fix_commits": [self.after,
                                           f"https://github.com/example/fixture/commit/{self.before}",
                                           f"https://github.com/unrelated/dependency/commit/{'c' * 40}",
                                           "--not-a-commit", {"commit": "d" * 40}]}
        (cache / "ghsa-2345-6789-cfgh.json").write_text(
            json.dumps(cached_advisory), encoding="utf-8")
        links = self.root / "urls.txt"
        links.write_text("https://github.com/advisories/GHSA-2345-6789-cfgh\n"
                         "https://github.com/advisories/GHSA-2345-6789-jmpq\n", encoding="utf-8")
        mapping = self.root / "repos.json"
        mapping.write_text(json.dumps({"GHSA-2345-6789-CFGH": {
            "repo_path": "repo", "repo_url": "https://github.com/example/fixture"}}), encoding="utf-8")
        jobs = load_jobs(input_path=links, cache_dir=cache, repo_map=mapping)
        self.assertEqual(jobs[0]["repo_path"], str(self.repo.resolve()))
        self.assertEqual(jobs[0]["documents"][0]["kind"], "cached_advisory")
        self.assertEqual(jobs[0]["fix_commits"], [self.after, self.before])
        self.assertEqual(len(jobs[0]["documents"][0]["fix_commits"]), 3)
        self.assertIn("invalid_advisory_fix_commit_ignored", jobs[0]["input_warnings"])
        self.assertIn("advisory_fix_commit_repository_mismatch_or_unknown", jobs[0]["input_warnings"])
        self.assertNotIn("vulnerable_commit", jobs[0])
        self.assertIn("cached_advisory_missing", jobs[1]["input_error"])
        # A wrongly named cached file must not attach this advisory's explicit
        # SHA or URL candidates to a different report, even with the same repo.
        (cache / "ghsa-2345-6789-jmpq.json").write_text(json.dumps(cached_advisory), encoding="utf-8")
        mismatched = load_jobs(input_path=links, cache_dir=cache, repo=self.repo)[1]
        self.assertEqual(mismatched["fix_commits"], [])
        self.assertIn("advisory_metadata_report_mismatch", mismatched["input_warnings"])
        self.assertIn("primary_advisory_report_mismatch", mismatched["input_error"])
        self.assertEqual(mismatched["input_conflicts"][0]["expected_report_id"], "GHSA-2345-6789-JMPQ")
        self.assertEqual(mismatched["input_conflicts"][0]["actual_report_id"], "GHSA-2345-6789-CFGH")
        self.assertEqual(mismatched["documents"][0]["role"], "primary")

    def test_native_advisory_json_is_readable_bounded_input_not_an_answer(self):
        advisory = self.root / "native-ghsa.json"
        body = "## Impact\nQuoted \\" + '"' + " details and real newlines.\nNo source paths supplied."
        raw = {"ghsa_id": "GHSA-2345-6789-cfgh", "summary": "Synthetic advisory",
               "description": body, "identifiers": [{"type": "CVE", "value": "CVE-2026-12345"},
                                                        {"type": "CVE", "value": "cve-2026-12345"}],
               "cve_id": "CVE-2026-67890",
               "references": [f"https://github.com/example/fixture/commit/{self.after}"],
               "vulnerabilities": [{"package": {"ecosystem": "pip", "name": "fixture"},
                                     "vulnerable_version_range": "< 1.2.3", "first_patched_version": "1.2.3"}],
               "repository_metadata": "irrelevant metadata " * 1800,
               "entry_point": {"file": "not-trusted.py", "line": 123, "code": "unread"}}
        advisory.write_text(json.dumps(raw), encoding="utf-8")
        job = load_jobs(advisory=advisory, repo=self.repo)[0]
        document = job["documents"][0]
        self.assertEqual(document["input_format"], "github_advisory_json")
        self.assertIn(body, document["text"])
        self.assertIn("CVE-2026-12345", document["text"])
        self.assertIn("< 1.2.3", document["text"])
        self.assertNotIn("irrelevant metadata", document["text"])
        self.assertNotIn("not-trusted.py", document["text"])
        self.assertIn("repository_metadata", document["omitted_metadata_fields"])
        self.assertFalse(document["truncated"])
        self.assertEqual(job["fix_commits"], [self.after])
        expected_metadata = {"ghsa_id": "GHSA-2345-6789-CFGH", "title": "Synthetic advisory",
                             "vuln_ids": ["CVE-2026-12345", "CVE-2026-67890", "GHSA-2345-6789-CFGH"]}
        self.assertEqual(document["advisory_metadata"], expected_metadata)
        self.assertEqual(job["advisory_metadata"], expected_metadata)
        self.assertEqual(job["title"], "Synthetic advisory")
        self.assertEqual(job["vuln_ids"], expected_metadata["vuln_ids"])
        mismatched = load_jobs(advisory=advisory, repo=self.repo,
                               source_link="https://github.com/advisories/GHSA-2345-6789-jmpq")[0]
        self.assertNotIn("advisory_metadata", mismatched)
        self.assertNotIn("vuln_ids", mismatched)
        self.assertIn("advisory_metadata_report_mismatch", mismatched["input_warnings"])
        self.assertIn("primary_advisory_report_mismatch", mismatched["input_error"])
        raw["description"] = "long body " * 3000 + f"https://github.com/example/fixture/commit/{self.before}"
        advisory.write_text(json.dumps(raw), encoding="utf-8")
        long_job = load_jobs(advisory=advisory, repo=self.repo)[0]
        self.assertLessEqual(len(long_job["documents"][0]["text"]), MAX_DOCUMENT_CHARS)
        self.assertIn("description", long_job["documents"][0]["truncated_fields"])
        self.assertIn(self.before, long_job["fix_commits"])
        self.assertEqual(long_job["advisory_metadata"], expected_metadata)
        advisory.write_text(json.dumps(raw)[:-5], encoding="utf-8")
        malformed = load_jobs(advisory=advisory, repo=self.repo)[0]["documents"][0]
        self.assertTrue(malformed["json_parse_error"])
        self.assertNotIn("input_format", malformed)
        self.assertNotIn("advisory_metadata", malformed)

    def test_other_ghsa_references_and_supporting_advisories_are_not_primary_conflicts(self):
        primary = self.root / "primary-with-reference.json"
        primary.write_text(json.dumps({
            "ghsa_id": "GHSA-2345-6789-cfgh", "summary": "Primary advisory",
            "description": "Related issue: GHSA-2345-6789-jmpq",
            "references": ["https://github.com/advisories/GHSA-2345-6789-jmpq"],
        }), encoding="utf-8")
        supporting = self.root / "supporting-other-advisory.json"
        supporting.write_text(json.dumps({
            "ghsa_id": "GHSA-2345-6789-jmpq", "summary": "Related advisory",
            "description": "Supplementary context, not this report's identity.",
        }), encoding="utf-8")
        batch = self.root / "primary-and-supporting.jsonl"
        batch.write_text(json.dumps({
            "source_link": "https://github.com/advisories/GHSA-2345-6789-cfgh",
            "repo_path": "repo", "repo_url": "https://github.com/example/fixture",
            "advisory": primary.name,
            "documents": [{"name": "related", "path": supporting.name, "kind": "supporting"}],
        }) + "\n", encoding="utf-8")
        loaded = load_jobs(input_path=batch)[0]
        self.assertNotIn("input_error", loaded)
        self.assertEqual(loaded["input_conflicts"], [])
        self.assertEqual(loaded["advisory_metadata"]["ghsa_id"], "GHSA-2345-6789-CFGH")
        self.assertEqual(loaded["title"], "Primary advisory")
        self.assertEqual(len(loaded["documents"]), 2)

    def test_reader_discovers_files_resolves_history_and_reads_fix_diff(self):
        reader = RepoReader(self.repo)
        details = reader.call("inspect_commit", {"commit": "HEAD"})
        self.assertEqual(details["parents"], [self.before])
        self.assertEqual(details["changed_paths"], ["nested/handler.py"])
        files = reader.call("list_files", {"commit": self.before, "limit": 1})
        self.assertTrue(files["truncated"])
        self.assertEqual(files["next_offset"], 1)
        self.assertEqual(reader.resolve_commit("HEAD^"), self.before)
        diff = reader.read_diff(self.before, "HEAD", "nested/handler.py")
        self.assertIn("-    return unsafe(value)", diff["diff"])
        self.assertIn("+    return safe(value)", diff["diff"])
        self.assertEqual(reader.info()["head"], self.after)

    def test_search_and_verbatim_validation_are_commit_specific(self):
        reader = RepoReader(self.repo)
        result = reader.search_code(self.before, "unsafe")
        self.assertEqual(result["matches"], [{"file": "nested/handler.py", "line": 2,
                                               "code": "    return unsafe(value)"}])
        location = result["matches"][0]
        self.assertTrue(reader.validate_location(self.before, location)["valid"])
        self.assertFalse(reader.validate_location(self.after, location)["valid"])
        self.assertFalse(reader.validate_location(self.before, {**location, "line": 0})["valid"])
        self.assertFalse(reader.validate_location(self.before, {
            **location, "code": "return unsafe(value)"})["valid"])
        source = reader.read_file(self.before, "nested/handler.py", 2, 2)
        self.assertEqual(source["text"], location["code"])
        self.assertEqual(source["commit"], self.before)
        self.assertFalse(source["truncated"])

    def test_search_accepts_directories_exact_files_and_literal_needles(self):
        reader = RepoReader(self.repo)
        expected = [{"file": "nested/handler.py", "line": 2, "code": "    return unsafe(value)"}]
        for paths in (["nested"], ["nested/"], ["nested/handler.py"], ["nested", "nested/handler.py"]):
            with self.subTest(paths=paths):
                result = reader.search_code(self.before, "unsafe(", paths=paths)
                self.assertEqual(result["matches"], expected)
                self.assertEqual(result["candidate_files"], 1)
                self.assertTrue(result["complete"])
        missing = reader.search_code(self.before, "unsafe(", paths=["missing"])
        self.assertEqual(missing["matches"], [])
        self.assertFalse(missing["complete"])
        self.assertEqual(missing["skipped"][0]["error"], "source_path_unavailable")
        self.assertEqual(reader.search_code(self.before, "unsafe(", paths=[])["matches"], [])
        self.assertEqual(reader.search_code(self.after, "unsafe(", paths=["nested"])["matches"], [])

    def test_tool_and_path_boundary_rejects_unexposed_actions(self):
        reader = RepoReader(self.repo)
        for name, args in [("run", {"cmd": "echo unwanted"}),
                           ("read_file", {"commit": "HEAD", "path": "../outside"}),
                           ("inspect_commit", {"commit": "--output=oops"}),
                           ("list_files", {"commit": "HEAD", "limit": 100000}),
                           ("read_file", {"commit": "HEAD", "path": "nested/handler.py", "shell": True})]:
            with self.subTest(name=name, args=args), self.assertRaises(ValueError):
                reader.call(name, args)
        self.assertEqual(self.git("rev-parse", "HEAD"), self.after)
        self.assertEqual(self.git("status", "--porcelain"), "")


if __name__ == "__main__":
    unittest.main()
