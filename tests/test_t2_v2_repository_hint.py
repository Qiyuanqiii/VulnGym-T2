"""Repository identity survives raw advisory intake without a hidden repo map."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from vulngym_t2.intake import load_jobs

GHSA = "GHSA-2345-6789-cfgh"
REPO = "https://github.com/example/project"
SHA = "a" * 40


class RepositoryHintTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="t2-hint-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.doc = {"ghsa_id": GHSA, "summary": "Synthetic input", "description": "Only fixture material.",
                    "source_code_location": REPO, "references": [f"{REPO}/commit/{SHA}",
                    f"https://github.com/other/dependency/commit/{'b' * 40}"]}
        self.file = self.root / "advisory.json"
        self.write()
        self.mock = patch("vulngym_t2.intake.RepoReader.info", return_value={"repo_url": None})
        self.mock.start()
        self.addCleanup(self.mock.stop)

    def write(self):
        self.file.write_text(json.dumps(self.doc), encoding="utf-8")

    def load(self, **kwargs):
        return load_jobs(advisory=self.file, repo=self.root, **kwargs)[0]

    def test_primary_hint_recovers_identity_and_same_repo_candidates(self):
        job = self.load()
        self.assertEqual(job["repo_url"], REPO)
        self.assertEqual(job["repo_identity_source"], "primary_advisory")
        self.assertEqual(job["fix_commits"], [SHA])
        self.assertIn("repository_identity_from_advisory", job["input_warnings"])
        self.assertNotIn("input_error", job)
        self.assertEqual(set(job["advisory_metadata"]), {"ghsa_id", "title", "vuln_ids"})

    def test_raw_map_and_explicit_record_preserve_same_identity_and_candidates(self):
        raw = self.load()
        mapped = self.load(repo_map={GHSA.upper(): {"repo_url": REPO, "path": str(self.root)}})
        batch = self.root / "batch.jsonl"
        batch.write_text(json.dumps({"advisory": str(self.file), "repo_url": REPO}) + "\n", encoding="utf-8")
        explicit = load_jobs(input_path=batch, repo=self.root)[0]
        for other in (mapped, explicit):
            for name in ("repo_url", "report_id", "fix_commits", "entry_id"):
                self.assertEqual(raw[name], other[name])

    def test_conflicting_primary_hint_does_not_replace_selected_repo(self):
        job = self.load(repo_map={GHSA.upper(): {"repo_url": "https://github.com/other/project"}})
        self.assertEqual(job["repo_url"], "https://github.com/other/project")
        self.assertIn("advisory_repository_identity_conflict", job["input_error"])
        self.assertEqual(job["fix_commits"], [])

    def test_wrong_primary_report_cannot_supply_repository_hint(self):
        job = self.load(source_link="https://github.com/advisories/GHSA-2222-3333-4444")
        self.assertIsNone(job["repo_url"])
        self.assertEqual(job["fix_commits"], [])
        self.assertIn("primary_advisory_report_mismatch", job["input_error"])

    def test_support_only_document_is_not_repository_authority(self):
        batch = self.root / "batch.jsonl"
        batch.write_text(json.dumps({"ghsa_id": GHSA, "documents": [{"path": str(self.file)}]}) + "\n", encoding="utf-8")
        job = load_jobs(input_path=batch, repo=self.root)[0]
        self.assertIsNone(job["repo_url"])
        self.assertIn("repository_identity_unavailable", job["input_warnings"])

    def test_missing_or_invalid_identity_is_no_longer_silent(self):
        for hint in (None, "https://other.invalid/repo", {"url": REPO}):
            with self.subTest(hint=hint):
                self.doc["source_code_location"] = hint
                self.write()
                job = self.load()
                self.assertIsNone(job["repo_url"])
                self.assertIn("repository_identity_unavailable", job["input_warnings"])
                if hint:
                    self.assertIn("invalid_advisory_repository_hint", job["input_warnings"])


if __name__ == "__main__":
    unittest.main()
