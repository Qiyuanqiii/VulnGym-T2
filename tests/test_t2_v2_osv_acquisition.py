"""OSV intake acquisition tests use synthetic fixtures and never make requests."""

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
from urllib.error import HTTPError

from vulngym_t2 import acquisition as acq


GHSA = "GHSA-f8m6-h2c7-8h9x"
OTHER = "GHSA-f3f2-mcxc-pwjx"
GITHUB = "https://github.com/advisories/" + GHSA
OSV = "https://osv.dev/vulnerability/" + GHSA
API = "https://api.osv.dev/v1/vulns/" + GHSA


def record(identifier=GHSA):
    return {"id": identifier, "aliases": ["CVE-2021-43854"],
            "summary": "Synthetic source fixture", "details": "Source text, not annotations.",
            "database_specific": {"github_reviewed": True}, "affected": [],
            "references": [
                {"type": "ADVISORY", "url": GITHUB},
                {"type": "ADVISORY", "url": "https://github.com/example/fixture/security/advisories/" + GHSA},
                {"type": "PACKAGE", "url": "https://github.com/example/fixture"},
                {"type": "FIX", "url": "https://github.com/example/fixture/commit/" + "a" * 40},
                {"type": "WEB", "url": "https://github.com/pypa/advisory-database/blob/main/a.json"}]}


class OSVAcquisitionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="t2-osv-acquisition-",
                                                dir="D:/Temp" if os.name == "nt" else None)
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_mixed_urls_markdown_and_provider_scoped_deduplication(self):
        # Uppercase the ID, not URL paths, whose spelling remains significant.
        text = f"[{GITHUB}]({GITHUB}) <{OSV}> {API} {GITHUB.lower()} https://api.osv.dev/v1/vulns/{GHSA.upper()}/"
        self.assertEqual(acq.parse_advisory_urls(text), [GITHUB, OSV])
        self.assertEqual(acq.parse_advisory_urls("https://osv.dev/vulnerability/PYSEC-2021-1"),
                         ["https://osv.dev/vulnerability/PYSEC-2021-1"])
        self.assertEqual(acq.parse_advisory_urls("https://api.osv.dev/v1/vulns/cve-2021-43854"),
                         ["https://osv.dev/vulnerability/CVE-2021-43854"])
        with self.assertRaises(acq.AcquisitionError):
            acq.parse_ghsa_urls(OSV)

    def test_parser_rejects_other_endpoints_auth_ports_queries_and_traversal(self):
        bad = ["", "See " + OSV, OSV.replace("https:", "http:"), OSV + "?x=1", OSV + "#x",
               OSV + "/more", OSV.replace("osv.dev", "user@osv.dev"),
               OSV.replace("osv.dev", "osv.dev:443"), OSV.replace("osv.dev", "osv.dev.example"),
               "https://api.osv.dev/v1/query", "https://osv.dev/vulnerability/../file",
               "https://osv.dev/vulnerability/CVE-%2fetc", "https://osv.dev/vulnerability/CON",
               "https://osv.dev/vulnerability/PYSEC-1:stream"]
        for item in bad:
            with self.subTest(item=item), self.assertRaises(acq.AcquisitionError):
                acq.parse_advisory_urls(item)
        with patch.object(acq, "MAX_URLS", 1), self.assertRaisesRegex(ValueError, "advisory_url_limit"):
            acq.parse_advisory_urls(GITHUB + " " + OSV)
        with self.assertRaisesRegex(ValueError, "advisory_urls_too_large"):
            acq.parse_advisory_urls(" " * acq.MAX_TEXT_CHARS + OSV)

    def test_raw_record_identity_duplicates_nan_and_shape_checked(self):
        value = record()
        raw = json.dumps(value).encode()
        self.assertEqual(acq._decode_osv(raw, GHSA), value)
        bad = [b"{}", b"[]", raw.replace(GHSA.encode(), OTHER.encode(), 1), b'\xff',
               b'{"id":"x","id":"y"}', raw[:-1] + b',"other":NaN}',
               json.dumps({**value, "references": ["not an OSV reference"]}).encode(),
               json.dumps({**value, "affected": [None]}).encode(),
               json.dumps({**value, "aliases": [None]}).encode()]
        for item in bad:
            with self.subTest(item=item[:60]), self.assertRaisesRegex(ValueError, "osv_response_invalid"):
                acq._decode_osv(item, GHSA)
        with self.assertRaisesRegex(ValueError, "osv_too_large"):
            acq._decode_osv(b" " * (acq.MAX_ADVISORY_BYTES + 1), GHSA)

    def test_only_unique_structured_ghsa_identity_is_accepted(self):
        self.assertEqual(acq.osv_ghsa_identifier(record()), GHSA.upper())
        value = record("PYSEC-2021-1")
        self.assertEqual(acq.osv_ghsa_identifier(value), GHSA.upper())
        value["references"] = []
        value["details"] = "mentions " + GHSA
        with self.assertRaisesRegex(ValueError, "osv_ghsa_missing"):
            acq.osv_ghsa_identifier(value)
        value["aliases"] += [GHSA, OTHER]
        with self.assertRaisesRegex(ValueError, "osv_ghsa_ambiguous"):
            acq.osv_ghsa_identifier(value)

    def test_reviewed_origin_and_withdrawal_never_inferred(self):
        acq.require_osv_reviewed(record())
        for reviewed in (False, None, "true", 1):
            value = record()
            value["database_specific"]["github_reviewed"] = reviewed
            with self.assertRaisesRegex(ValueError, "osv_reviewed_origin_unconfirmed"):
                acq.require_osv_reviewed(value)
        value = {**record(), "withdrawn": "2026-01-01T00:00:00Z"}
        with self.assertRaisesRegex(ValueError, "osv_record_withdrawn"):
            acq.require_osv_reviewed(value)

    def test_osv_source_references_ignore_advisory_database_backlinks(self):
        self.assertEqual(acq._repository_from_osv(record()), "https://github.com/example/fixture")
        value = record()
        value["references"] = [item for item in value["references"] if item["type"] in {"ADVISORY", "WEB"}]
        self.assertEqual(acq._repository_from_osv(value), "https://github.com/example/fixture")
        value["references"] = [{"type": "WEB", "url": "https://github.com/pypa/advisory-database"}]
        with self.assertRaisesRegex(ValueError, "osv_repository_missing"):
            acq._repository_from_osv(value)

    def test_explicit_git_and_strong_reference_ambiguity_remain_visible(self):
        value = record()
        value["affected"] = [{"ranges": [{"type": "GIT", "repo": "https://github.com/example/actual"}]}]
        self.assertEqual(acq._repository_from_osv(value), "https://github.com/example/actual")
        value["affected"][0]["ranges"].append({"type": "GIT", "repo": "https://github.com/example/second"})
        with self.assertRaisesRegex(ValueError, "osv_repository_ambiguous"):
            acq._repository_from_osv(value)
        value["affected"] = [{"ranges": [{"type": "GIT", "repo": "https://example.org/repo"}]}]
        with self.assertRaisesRegex(ValueError, "osv_repository_unsupported"):
            acq._repository_from_osv(value)
        value = record()
        value["references"].append({"type": "SOURCE", "url": "https://github.com/another/project"})
        with self.assertRaisesRegex(ValueError, "osv_repository_ambiguous"):
            acq._repository_from_osv(value)

    def test_osv_request_is_fixed_bounded_unauthenticated_and_redirect_blocked(self):
        response = Mock()
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        response.headers = {}
        response.geturl.return_value = API
        response.read.return_value = json.dumps(record()).encode()
        opener = Mock()
        opener.open.return_value = response
        with patch.object(acq, "build_opener", return_value=opener):
            acq._download_osv(GHSA)
        request = opener.open.call_args.args[0]
        self.assertEqual(request.full_url, API)
        self.assertFalse(any(key.lower() == "authorization" for key, _ in request.header_items()))
        self.assertEqual(opener.open.call_args.kwargs["timeout"], acq.HTTP_TIMEOUT_SECONDS)
        response.read.assert_called_once_with(acq.MAX_ADVISORY_BYTES + 1)
        with self.assertRaisesRegex(ValueError, "osv_redirect_blocked"):
            acq._NoOSVRedirect().redirect_request(None, None, 302, "", {}, GITHUB)
        response.geturl.return_value = GITHUB
        with patch.object(acq, "build_opener", return_value=opener), self.assertRaisesRegex(ValueError, "osv_redirect_blocked"):
            acq._download_osv(GHSA)

    def test_osv_http_errors_are_distinct_and_never_retried(self):
        for status, expected in [(429, "osv_rate_limited"), (403, "osv_access_denied"),
                                 (404, "osv_not_found"), (500, "osv_http_failed")]:
            opener = Mock()
            opener.open.side_effect = HTTPError(API, status, "fixture", {}, None)
            with self.subTest(status=status), patch.object(acq, "build_opener", return_value=opener), \
                    self.assertRaisesRegex(ValueError, expected):
                acq._download_osv(GHSA)
            self.assertEqual(opener.open.call_count, 1)

    def test_raw_cache_is_separate_reused_and_invalid_content_retained(self):
        raw = json.dumps(record()).encode()
        with patch.object(acq, "_download_osv", return_value=raw) as fetch:
            target, value, cached = acq._cached_osv(self.root, GHSA)
            self.assertFalse(cached)
            self.assertEqual(target.parent.name, "osv")
            self.assertEqual(target.read_bytes(), raw)
            self.assertNotIn("ghsa_id", value)
            _, _, cached = acq._cached_osv(self.root, GHSA, allow_download=False)
            self.assertTrue(cached)
            self.assertEqual(fetch.call_count, 1)
            target.write_bytes(b"preserve this invalid cache")
            with self.assertRaisesRegex(ValueError, "osv_response_invalid"):
                acq._cached_osv(self.root, GHSA)
            self.assertEqual(target.read_bytes(), b"preserve this invalid cache")

    def test_acquired_osv_manifest_preserves_source_and_raw_document(self):
        raw = json.dumps(record()).encode()
        with patch.object(acq, "_download_osv", return_value=raw), \
                patch.object(acq, "_cached_repository", return_value=(self.root / "repository", True)), \
                patch.object(acq, "_download_advisory") as github:
            manifest = acq.acquire_batch([OSV], self.root)
        row = json.loads(manifest.read_text())
        self.assertEqual(row["source_link"], GITHUB)
        self.assertEqual(row["input_source_url"], OSV)
        self.assertEqual(row["source_provider"], "osv")
        self.assertEqual(row["source_record_id"], GHSA)
        self.assertEqual(Path(row["advisory"]).read_bytes(), raw)
        receipt = json.loads((manifest.parent / "acquisition.json").read_text())
        self.assertEqual(receipt["source"], "public_osv")
        self.assertEqual(receipt["ready"], 1)
        self.assertEqual(receipt["inputs"][0]["source_link"], GITHUB)
        self.assertEqual(receipt["http_model_attempts"], 0)
        github.assert_not_called()

    def test_missing_ambiguous_unreviewed_and_withdrawn_preserve_raw_without_clone(self):
        fixtures = []
        missing = record("PYSEC-2021-1")
        missing["references"] = []
        fixtures.append((missing, "osv_ghsa_missing"))
        ambiguous = record()
        ambiguous["aliases"].append(OTHER)
        fixtures.append((ambiguous, "osv_ghsa_ambiguous"))
        unreviewed = record()
        unreviewed["database_specific"] = {}
        fixtures.append((unreviewed, "osv_reviewed_origin_unconfirmed"))
        fixtures.append(({**record(), "withdrawn": "2026-01-01T00:00:00Z"}, "osv_record_withdrawn"))
        for index, (value, code) in enumerate(fixtures):
            raw = json.dumps(value).encode()
            with self.subTest(code=code), patch.object(acq, "_download_osv", return_value=raw), \
                    patch.object(acq, "_cached_repository") as clone:
                manifest = acq.acquire_batch(["https://osv.dev/vulnerability/" + value["id"]], self.root / str(index))
            row = json.loads(manifest.read_text())
            self.assertEqual(row["input_error"], code)
            self.assertEqual(Path(row["advisory"]).read_bytes(), raw)
            clone.assert_not_called()

    def test_provider_rate_limits_are_independent_without_hidden_fallback(self):
        raw = json.dumps(record()).encode()
        with patch.object(acq, "MAX_WORKERS", 1), \
                patch.object(acq, "_download_advisory", side_effect=acq.AcquisitionError("github_rate_limited")) as github, \
                patch.object(acq, "_download_osv", return_value=raw) as osv, \
                patch.object(acq, "_cached_repository", return_value=(self.root / "repository", True)):
            manifest = acq.acquire_batch([GITHUB, OSV, "https://github.com/advisories/" + OTHER], self.root)
        rows = [json.loads(line) for line in manifest.read_text().splitlines()]
        self.assertEqual(rows[0]["input_error"], "github_rate_limited")
        self.assertNotIn("input_error", rows[1])
        self.assertEqual(rows[2]["input_error"], "github_rate_limited")
        self.assertEqual(github.call_count, 1)
        self.assertEqual(osv.call_count, 1)

    def test_osv_rate_limit_stops_later_osv_requests(self):
        with patch.object(acq, "MAX_WORKERS", 1), \
                patch.object(acq, "_download_osv", side_effect=acq.AcquisitionError("osv_rate_limited")) as fetch, \
                patch.object(acq, "_download_advisory") as github, \
                patch.object(acq, "_cached_repository") as clone:
            manifest = acq.acquire_batch([OSV, "https://osv.dev/vulnerability/" + OTHER], self.root)
        self.assertEqual(fetch.call_count, 1)
        github.assert_not_called()
        clone.assert_not_called()
        self.assertTrue(all(json.loads(line)["input_error"] == "osv_rate_limited" for line in manifest.read_text().splitlines()))


if __name__ == "__main__":
    unittest.main()
