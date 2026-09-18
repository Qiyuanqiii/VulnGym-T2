"""Native OSV input checks; synthetic local material, no network or models."""

import json
from pathlib import Path
import tempfile
import unittest

from vulngym_t2.intake import MAX_DOCUMENT_CHARS, load_jobs


GHSA = "GHSA-2345-6789-cfgh"
OTHER_GHSA = "GHSA-2345-6789-jmpq"
REPO = "https://github.com/example/fixture"
FIX = "a" * 40


def source_record():
    return {
        "schema_version": "1.7.0",
        "id": GHSA,
        "summary": "Synthetic package advisory",
        "details": "Original details\nwith retained line breaks.",
        "aliases": ["CVE-2026-12345", "cve-2026-12345"],
        "affected": [{"package": {"name": "fixture", "ecosystem": "PyPI"},
                      "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.2.3"}]}]}],
        "references": [{"type": "ADVISORY", "url": f"https://github.com/advisories/{GHSA}"},
                       {"type": "FIX", "url": f"{REPO}/commit/{FIX}"}],
        "database_specific": {"github_reviewed": True, "cwe_ids": ["CWE-20"],
                              "source": "https://github.com/github/advisory-database"},
    }


class OsvIntakeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="vulngym-osv-intake-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()

    def load(self, value, **overrides):
        material = self.root / "osv.json"
        material.write_text(json.dumps(value), encoding="utf-8")
        manifest = self.root / "input.jsonl"
        row = {"advisory": material.name, "repo_path": "repo", "repo_url": REPO,
               "input_source_url": f"https://osv.dev/vulnerability/{value.get('id', GHSA)}",
               "source_provider": "osv", **overrides}
        manifest.write_text(json.dumps(row) + "\n", encoding="utf-8")
        return load_jobs(input_path=manifest)[0]

    def test_native_osv_is_bounded_source_material_with_real_provenance(self):
        raw = source_record()
        raw.update(entry_point={"file": "unread.py", "line": 99, "code": "unread"},
                   critical_operation={"file": "also-unread.py"}, verify=1, commit="b" * 40)
        job = self.load(raw)
        doc = job["documents"][0]
        self.assertEqual(doc["input_format"], "osv_json")
        self.assertIn("OSV source material", doc["text"])
        self.assertNotIn("GitHub advisory input", doc["text"])
        self.assertIn(raw["details"], doc["text"])
        self.assertIn("CVE-2026-12345", doc["text"])
        self.assertIn('"fixed": "1.2.3"', doc["text"])
        self.assertIn('"github_reviewed": true', doc["text"])
        self.assertIn('"source": "https://github.com/github/advisory-database"', doc["text"])
        self.assertIn("FIX: " + REPO, doc["text"])
        self.assertEqual(job["source_provider"], "osv")
        self.assertEqual(job["source_record_id"], GHSA)
        self.assertEqual(job["input_source_url"], f"https://osv.dev/vulnerability/{GHSA}")
        self.assertEqual(job["source_link"], f"https://github.com/advisories/{GHSA}")
        self.assertEqual(job["vuln_ids"], ["CVE-2026-12345", GHSA.upper()])
        self.assertEqual(job["fix_commits"], [FIX])
        self.assertNotIn("input_error", job)
        for key in ("entry_point", "critical_operation", "verify", "commit", "origin"):
            self.assertNotIn(key, job)
        self.assertNotIn("unread.py", doc["text"])
        self.assertIn("entry_point", doc["omitted_metadata_fields"])

    def test_alias_or_canonical_reference_can_establish_unique_ghsa(self):
        for identity_source in ("alias", "reference"):
            with self.subTest(identity_source=identity_source):
                raw = source_record()
                raw["id"] = "PYSEC-2026-1"
                if identity_source == "alias":
                    raw["aliases"].append(GHSA)
                    raw["references"] = []
                loaded = self.load(raw)
                self.assertEqual(loaded["report_id"], GHSA.upper())
                self.assertIn("PYSEC-2026-1", loaded["vuln_ids"])
                self.assertNotIn("input_error", loaded)

    def test_prose_and_noncanonical_links_cannot_supply_missing_ghsa(self):
        raw = source_record()
        raw["id"] = "PYSEC-2026-1"
        raw["details"] += " Related prose mentions " + GHSA
        raw["references"] = [{"type": "WEB", "url": url} for url in (
            f"https://example.invalid/{GHSA}",
            f"https://github.com/advisories/{GHSA}?from=other",
            f"https://github.com@other.invalid/advisories/{GHSA}",
        )]
        job = self.load(raw)
        self.assertTrue(job["report_id"].startswith("local-"))
        self.assertIn("osv_ghsa_missing", job["input_error"])
        self.assertNotIn("advisory_metadata", job)

    def test_ambiguous_ghsa_is_not_first_match_wins_even_with_explicit_url(self):
        raw = source_record()
        raw["aliases"].append(OTHER_GHSA)
        local = self.load(raw)
        self.assertTrue(local["report_id"].startswith("local-"))
        self.assertNotIn("advisory_metadata", local)
        explicit = self.load(raw, source_link=f"https://github.com/advisories/{GHSA}")
        self.assertIn("osv_ghsa_ambiguous", explicit["input_error"])
        self.assertNotIn("advisory_metadata", explicit)

    def test_unreviewed_unknown_or_withdrawn_cannot_become_reviewed_output(self):
        for review in (False, None, "true", 1):
            with self.subTest(review=review):
                raw = source_record()
                raw["database_specific"]["github_reviewed"] = review
                self.assertIn("osv_reviewed_origin_unconfirmed", self.load(raw)["input_error"])
        raw = source_record()
        raw.pop("database_specific")
        self.assertIn("osv_reviewed_origin_unconfirmed", self.load(raw)["input_error"])
        raw = source_record()
        raw["withdrawn"] = "2026-01-01T00:00:00Z"
        job = self.load(raw)
        self.assertIn("osv_record_withdrawn", job["input_error"])
        self.assertIn("Withdrawn: 2026-01-01", job["documents"][0]["text"])

    def test_only_fix_reference_matching_selected_repo_is_candidate(self):
        raw = source_record()
        raw["references"].extend([
            {"type": "FIX", "url": "https://github.com/other/dependency/commit/" + "b" * 40},
            {"type": "WEB", "url": REPO + "/commit/" + "c" * 40},
        ])
        raw["details"] += "\n" + REPO + "/commit/" + "d" * 40
        job = self.load(raw)
        self.assertEqual(job["fix_commits"], [FIX])
        self.assertIn("advisory_fix_commit_repository_mismatch_or_unknown", job["input_warnings"])
        self.assertIn("Unclassified revision links (not supplied as fixes", job["documents"][0]["text"])
        self.assertIn("WEB: " + REPO + "/commit/" + "c" * 40, job["documents"][0]["text"])

    def test_unclassified_web_revision_survives_long_reference_listing_without_fix_role(self):
        raw = source_record()
        raw["references"] = [{"type": "WEB", "url": "https://example.invalid/" + str(index)}
                             for index in range(500)]
        raw["references"].append({"type": "WEB", "url": REPO + "/commit/" + FIX})
        job = self.load(raw)
        doc = job["documents"][0]
        self.assertEqual(job["fix_commits"], [])
        self.assertIn("WEB: " + REPO + "/commit/" + FIX, doc["text"])
        self.assertIn("references", doc["truncated_fields"])

    def test_unclassified_revision_section_is_bounded(self):
        raw = source_record()
        raw["references"] = [{"type": "WEB", "url": REPO + "/commit/" + f"{index:040x}"}
                             for index in range(12)]
        job = self.load(raw)
        doc = job["documents"][0]
        section = doc["text"].split("Unclassified revision links", 1)[1].split("\n\n", 1)[0]
        self.assertEqual(section.count("WEB:"), 8)
        self.assertIn("revision_links", doc["truncated_fields"])
        self.assertEqual(job["fix_commits"], [])

    def test_invalid_native_shapes_remain_error_material_not_metadata(self):
        for key, value in (("affected", {}), ("aliases", [None]), ("references", ["https://example.invalid"]),
                           ("details", []), ("database_specific", []), ("id", "not valid")):
            with self.subTest(key=key):
                raw = source_record()
                raw[key] = value
                job = self.load(raw)
                self.assertIn("osv_response_invalid", job["input_error"])
                self.assertNotIn("advisory_metadata", job)
                self.assertEqual(job["documents"][0]["input_format"], "osv_json")
        raw = source_record()
        raw.pop("schema_version")
        raw.pop("affected")
        self.assertIn("osv_response_invalid", self.load(raw)["input_error"])

    def test_large_source_fields_are_bounded_and_fix_candidates_survive(self):
        raw = source_record()
        raw["details"] = "details " * 7000
        raw["affected"][0]["versions"] = [str(index) for index in range(1000)]
        raw["references"] = [{"type": "WEB", "url": "https://example.invalid/" + str(index)}
                             for index in range(500)] + raw["references"]
        job = self.load(raw)
        doc = job["documents"][0]
        self.assertLessEqual(len(doc["text"]), MAX_DOCUMENT_CHARS)
        self.assertTrue(doc["truncated"])
        self.assertIn("details", doc["truncated_fields"])
        self.assertIn("references", doc["truncated_fields"])
        self.assertEqual(job["fix_commits"], [FIX])

    def test_primary_identity_mismatch_is_still_rejected(self):
        job = self.load(source_record(), source_link=f"https://github.com/advisories/{OTHER_GHSA}")
        self.assertIn("primary_advisory_report_mismatch", job["input_error"])
        self.assertNotIn("advisory_metadata", job)

    def test_non_osv_json_preserves_existing_github_and_raw_paths(self):
        github = {"ghsa_id": GHSA, "summary": "Native GitHub", "description": "Public details"}
        github_doc = self.load(github)["documents"][0]
        self.assertEqual(github_doc["input_format"], "github_advisory_json")
        unrelated = {"id": "customer-1", "name": "Unrelated JSON object"}
        raw_doc = self.load(unrelated)["documents"][0]
        self.assertNotIn("input_format", raw_doc)
        self.assertEqual(json.loads(raw_doc["text"]), unrelated)


if __name__ == "__main__":
    unittest.main()
