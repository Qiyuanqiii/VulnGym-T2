"""Ordinary history browsing on fresh synthetic Git data, without target execution."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from vulngym_t2.repository import (
    MAX_HISTORY_BYTES, MAX_HISTORY_SUBJECT_CHARS, MAX_TEXT_CHARS, RepoReader,
)
from vulngym_t2._vendor.git_repository import GitOutputTooLarge, GitTimeoutError


class HistoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temp_root = Path(tempfile.gettempdir()) if os.name == "nt" else None
        if temp_root is not None:
            temp_root.mkdir(parents=True, exist_ok=True)
        cls.temp = tempfile.TemporaryDirectory(prefix="t2-history-", dir=temp_root)
        cls.root = Path(cls.temp.name)
        cls.repo = cls.root / "repo"
        cls.repo.mkdir()
        cls.git_executable = shutil.which("git")
        cls.git("init", "--quiet", "--initial-branch=main")
        (cls.repo / "src").mkdir()
        (cls.repo / "src" / "handler.txt").write_text("first\n", encoding="utf-8")
        (cls.repo / "elsewhere.txt").write_text("first\n", encoding="utf-8")
        cls.git("add", "--", "src/handler.txt", "elsewhere.txt")
        cls.before = cls.make_commit("Initialize synthetic source")
        cls.git("tag", "v1.0", cls.before)
        cls.git("tag", "v1/child", cls.before)
        cls.git("tag", "v1.2/path/deep", cls.before)
        (cls.repo / "src" / "handler.txt").write_text("second\n", encoding="utf-8")
        cls.git("add", "--", "src/handler.txt")
        cls.fix = cls.make_commit("Handle literal [input].* safely", "Synthetic body token: GHSA-fixture")
        cls.git("tag", "--annotate", "v1.1", "--message", "Synthetic release", cls.fix)
        cls.git("tag", "--annotate", "nested-v1.1", "--message", "Nested synthetic tag", "v1.1")
        cls.git("branch", "release/1", cls.fix)
        cls.git("update-ref", "refs/remotes/origin/main", cls.fix)
        cls.git("update-ref", "refs/custom/snapshot", cls.before)
        blob = cls.git("rev-parse", cls.before + ":elsewhere.txt")
        cls.git("tag", "blob-only", blob)
        cls.git("tag", "--annotate", "annotated-blob", "--message", "Not a commit", blob)
        (cls.repo / "elsewhere.txt").write_text("second\n", encoding="utf-8")
        cls.git("add", "--", "elsewhere.txt")
        cls.other = cls.make_commit("Other literal [input].* adjustment")
        cls.head = cls.make_commit("Newest ordinary commit", allow_empty=True)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    @classmethod
    def git(cls, *args):
        env = {key: value for key, value in os.environ.items()
               if not key.upper().startswith("GIT_")}
        env.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_SYSTEM": os.devnull,
                    "GIT_CONFIG_GLOBAL": os.devnull, "GIT_TERMINAL_PROMPT": "0"})
        return subprocess.run(
            [cls.git_executable, "-c", f"core.hooksPath={os.devnull}",
             "-c", "user.name=Synthetic Fixture", "-c", "user.email=fixture@example.invalid",
             "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false",
             "-C", str(cls.repo), *args],
            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=10, env=env, text=True, encoding="utf-8",
        ).stdout.strip()

    @classmethod
    def make_commit(cls, subject, body=None, allow_empty=False):
        args = ["commit", "--quiet", "-m", subject]
        if body is not None:
            args.extend(["-m", body])
        if allow_empty:
            args.append("--allow-empty")
        cls.git(*args)
        return cls.git("rev-parse", "HEAD")

    def test_refs_expose_only_local_identities_and_peel_tags(self):
        reader = RepoReader(self.repo)
        result = reader.call("list_refs", {})
        refs = {item["name"]: item for item in result["refs"]}
        self.assertEqual(refs["refs/heads/main"]["commit"], self.head)
        self.assertEqual(refs["refs/heads/release/1"]["kind"], "branch")
        self.assertEqual(refs["refs/tags/v1.0"]["commit"], self.before)
        self.assertEqual(refs["refs/tags/v1.1"]["commit"], self.fix)
        self.assertEqual(refs["refs/tags/nested-v1.1"]["commit"], self.fix)
        self.assertEqual(refs["refs/remotes/origin/main"]["kind"], "remote")
        self.assertEqual(refs["refs/custom/snapshot"]["kind"], "ref")
        self.assertIsNone(refs["refs/tags/blob-only"]["commit"])
        self.assertIsNone(refs["refs/tags/annotated-blob"]["commit"])
        self.assertFalse(result["truncated"])
        self.assertEqual(result["limits"]["refs"], 30)
        self.assertIn("not proof", result["evidence_scope"])
        self.assertNotIn("vulnerable_commit", result)
        self.assertNotIn("fix_commits", result)

    def test_ref_prefix_and_limit_are_explicit(self):
        reader = RepoReader(self.repo)
        result = reader.call("list_refs", {"prefix": "refs/tags/v1", "limit": 1})
        self.assertEqual([item["name"] for item in result["refs"]], ["refs/tags/v1.0"])
        self.assertTrue(result["truncated"])
        tags = reader.list_refs("refs/tags/", 100)
        self.assertTrue(all(item["kind"] == "tag" for item in tags["refs"]))
        version_refs = reader.list_refs("refs/tags/v1")
        self.assertIn("refs/tags/v1/child", [item["name"] for item in version_refs["refs"]])
        self.assertIn("refs/tags/v1.2/path/deep", [item["name"] for item in version_refs["refs"]])
        missing = reader.list_refs("refs/tags/missing")
        self.assertEqual(missing["refs"], [])
        self.assertFalse(missing["truncated"])

    def test_search_finds_unknown_commit_from_message_or_body(self):
        reader = RepoReader(self.repo)
        result = reader.call("search_history", {"query": "GHSA-fixture"})
        self.assertEqual(result["commit"], self.head)
        self.assertEqual(result["matches"], [{
            "commit": self.fix, "parents": [self.before],
            "subject": "Handle literal [input].* safely", "subject_truncated": False,
        }])
        self.assertFalse(result["truncated"])
        self.assertFalse(result["shallow"])
        self.assertFalse(result["negative_result_conclusive"])
        self.assertEqual(result["limits"]["matches"], 20)
        root = reader.search_history("Initialize", commit="v1.0")
        self.assertEqual(root["matches"][0]["parents"], [])

    def test_unresolvable_head_requires_an_explicit_discovered_commit(self):
        original_head = self.git("symbolic-ref", "HEAD")
        original_refs = self.git("show-ref")
        missing_branch = "refs/heads/not-created"
        try:
            self.git("symbolic-ref", "HEAD", missing_branch)
            reader = RepoReader(self.repo)
            self.assertIsNone(reader.info()["head"])
            refs = reader.call("list_refs", {})
            selected = next(item["commit"] for item in refs["refs"]
                            if item["name"] == "refs/heads/main")
            self.assertEqual(selected, self.head)
            with self.assertRaisesRegex(ValueError, "^commit_unavailable$"):
                reader.call("search_history", {"query": "GHSA-fixture"})
            result = reader.call("search_history", {
                "query": "GHSA-fixture", "commit": selected,
            })
            self.assertEqual(result["commit"], selected)
            self.assertEqual([item["commit"] for item in result["matches"]], [self.fix])
            self.assertNotIn("vulnerable_commit", result)
            self.assertNotIn("fix_commits", result)
            self.assertEqual(self.git("symbolic-ref", "HEAD"), missing_branch)
            self.assertEqual(self.git("show-ref"), original_refs)
        finally:
            self.git("symbolic-ref", "HEAD", original_head)

    def test_literal_search_path_scope_and_selected_revision(self):
        reader = RepoReader(self.repo)
        result = reader.search_history("[input].*", path="src/handler.txt")
        self.assertEqual([item["commit"] for item in result["matches"]], [self.fix])
        scoped = reader.search_history("[input].*", commit="v1.1")
        self.assertEqual([item["commit"] for item in scoped["matches"]], [self.fix])
        for query, path in [("[INPUT].*", None), ("literal.*adjustment", None),
                            ("[input].*", "src/*"), ("absent token", None), ("--all", None)]:
            with self.subTest(query=query, path=path):
                missing = reader.search_history(query, path=path)
                self.assertEqual(missing["matches"], [])
                self.assertFalse(missing["negative_result_conclusive"])

    def test_search_limit_reports_extra_match_without_inventing_a_total(self):
        reader = RepoReader(self.repo)
        result = reader.search_history("[input].*", limit=1)
        self.assertEqual([item["commit"] for item in result["matches"]], [self.other])
        self.assertTrue(result["truncated"])
        self.assertTrue(result["has_more"])
        exact = reader.search_history("[input].*", limit=2)
        self.assertEqual(len(exact["matches"]), 2)
        self.assertFalse(exact["truncated"])
        self.assertNotIn("total_matches", exact)

    def test_argument_boundaries_reject_options_paths_and_excess(self):
        reader = RepoReader(self.repo)
        cases = [("list_refs", {"prefix": value}) for value in
                 ("--all", "refs/*", "refs/../heads", "refs//heads", "refs/~", "", 1)]
        cases += [("search_history", {"query": value}) for value in
                  ("", "  ", "x\ny", "x\ry", "x\0y", "x" * 257, None)]
        cases += [("search_history", {"query": "literal", "path": value}) for value in
                  ("../outside", "/absolute", "--output=oops", ":(glob)*", "D:/elsewhere")]
        cases += [("search_history", {"query": "literal", "commit": "--all"}),
                  ("search_history", {"query": "literal", "limit": 51}),
                  ("search_history", {"query": "literal", "limit": True}),
                  ("search_history", {"query": "literal", "limit": 0}),
                  ("search_history", {"query": "literal", "shell": True}),
                  ("list_refs", {"limit": 101}), ("list_refs", {"limit": False}),
                  ("list_refs", {"limit": 0}), ("list_refs", {"remote": True})]
        for name, arguments in cases:
            with self.subTest(name=name, arguments=arguments), self.assertRaises(ValueError):
                reader.call(name, arguments)

    def test_history_transport_timeout_and_output_limit_are_preserved(self):
        reader = RepoReader(self.repo)
        for error, code in [(GitTimeoutError("bounded fixture"), "git_timeout"),
                            (GitOutputTooLarge("bounded fixture"), "git_output_limit")]:
            for name, arguments in [("list_refs", {}), ("search_history", {"query": "literal"})]:
                with self.subTest(error=code, name=name), \
                        patch.object(reader, "resolve_commit", return_value=self.head), \
                        patch.object(reader._git, "_run", side_effect=error) as run, \
                        self.assertRaisesRegex(ValueError, "^" + code + "$"):
                    reader.call(name, arguments)
                self.assertEqual(run.call_count, 1)
                self.assertEqual(run.call_args.kwargs["max_stdout_bytes"], MAX_HISTORY_BYTES)
                self.assertEqual(run.call_args.kwargs["max_stderr_bytes"], 4096)

    def test_long_subject_is_presented_with_explicit_truncation(self):
        reader = RepoReader(self.repo)
        subject = b"a" * (MAX_HISTORY_SUBJECT_CHARS + 1)
        raw = self.fix.encode() + b"\0" + self.before.encode() + b"\0" + subject + b"\0"
        with patch.object(reader, "resolve_commit", return_value=self.head), \
                patch.object(reader, "_run", return_value=raw):
            result = reader.search_history("a")
        self.assertTrue(result["truncated"])
        self.assertFalse(result["has_more"])
        self.assertTrue(result["matches"][0]["subject_truncated"])
        self.assertEqual(len(result["matches"][0]["subject"]), MAX_HISTORY_SUBJECT_CHARS)
        self.assertLessEqual(len(result["matches"][0]["subject"]), MAX_TEXT_CHARS)

    def test_shallow_marker_keeps_negative_history_inconclusive(self):
        reader = RepoReader(self.repo)
        with patch.object(reader._git, "history_is_shallow", return_value=True):
            result = reader.search_history("absent token")
        self.assertTrue(result["shallow"])
        self.assertFalse(result["negative_result_conclusive"])

    def test_malformed_history_records_are_not_accepted_as_git_facts(self):
        reader = RepoReader(self.repo)
        for raw in (b"missing terminator", b"not-a-sha\0\0subject\0",
                    self.fix.encode() + b"\0not-a-parent\0subject\0",
                    self.fix.encode() + b"\0\0subject\0embedded\0"):
            with self.subTest(raw=raw), \
                    patch.object(reader, "resolve_commit", return_value=self.head), \
                    patch.object(reader, "_run", return_value=raw), \
                    self.assertRaisesRegex(ValueError, "^git_history_response_invalid$"):
                reader.search_history("subject")

    def test_malformed_ref_records_are_not_accepted_as_git_facts(self):
        reader = RepoReader(self.repo)
        for raw in (b"missing terminator", b"refs/tags/bad\0commit\0not-a-sha\0\0\n",
                    b"refs/tags/bad\0mystery\0" + self.fix.encode() + b"\0\0\n"):
            with self.subTest(raw=raw), patch.object(reader, "_run", return_value=raw), \
                    self.assertRaisesRegex(ValueError, "^git_refs_response_invalid$"):
                reader.list_refs()

    def test_tools_leave_checkout_and_git_refs_unchanged(self):
        before = self.git("show-ref", "--head")
        reader = RepoReader(self.repo)
        reader.list_refs()
        reader.search_history("[input].*")
        self.assertEqual(self.git("show-ref", "--head"), before)
        self.assertEqual(self.git("status", "--porcelain"), "")


if __name__ == "__main__":
    unittest.main()
