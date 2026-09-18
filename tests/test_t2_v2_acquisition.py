"""Offline public-input acquisition checks: never contact GitHub or a model."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch
from urllib.error import HTTPError

from vulngym_t2 import acquisition as acq
from vulngym_t2.intake import load_jobs


URLS = ["https://github.com/advisories/GHSA-f8m6-h2c7-8h9x",
        "https://github.com/advisories/GHSA-f3f2-mcxc-pwjx",
        "https://github.com/advisories/GHSA-8r55-rv5w-6pfm"]


def advisory(identifier, repository="https://github.com/example/fixture"):
    return {"ghsa_id": identifier.upper(), "summary": "Synthetic input only",
            "description": "Public source material; no generated annotations.",
            "references": [], "source_code_location": repository}


class AcquisitionTests(unittest.TestCase):
    def setUp(self):
        task_temp = Path("D:/Temp") if os.name == "nt" else None
        self.temp = tempfile.TemporaryDirectory(prefix="t2-acquisition-", dir=task_temp)
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_plain_whitespace_markdown_angles_and_dedup(self):
        text = f"[{URLS[0]}]({URLS[0]})\n<{URLS[1]}> {URLS[2]}\n{URLS[0].lower()}"
        self.assertEqual(acq.parse_ghsa_urls(text), URLS)

    def test_rejects_extra_prose_non_github_credentials_ports_queries_or_invalid_ids(self):
        for text in ("", "read " + URLS[0], URLS[0].replace("https:", "http:"),
                     URLS[0].replace("github.com", "github.com.example.org"),
                     URLS[0].replace("github.com", "user:pass@github.com"),
                     URLS[0].replace("github.com", "github.com:443"),
                     URLS[0] + "?x=1", URLS[0] + "#x", URLS[0] + "/extra",
                     "https://github.com/advisories/GHSA-aaaa-bbbb-cccc"):
            with self.subTest(text=text), self.assertRaises(acq.AcquisitionError):
                acq.parse_ghsa_urls(text)

    def test_limits_apply_after_dedup_and_to_text_size(self):
        self.assertEqual(len(acq.parse_ghsa_urls(" ".join([URLS[0]] * 21))), 1)
        with patch.object(acq, "MAX_URLS", 2), self.assertRaisesRegex(ValueError, "ghsa_url_limit"):
            acq.parse_ghsa_urls("\n".join(URLS))
        with self.assertRaisesRegex(ValueError, "ghsa_urls_too_large"):
            acq.parse_ghsa_urls(" " * acq.MAX_TEXT_CHARS + URLS[0])

    def test_explicit_repository_wins_without_inventing_versions(self):
        value = advisory("GHSA-f8m6-h2c7-8h9x")
        value["references"] = ["https://github.com/another/project/issues/10"]
        self.assertEqual(acq._repository_from_advisory(value), "https://github.com/example/fixture")
        self.assertNotIn("vulnerable_commit", value)
        self.assertNotIn("fix_commits", value)

    def test_repository_reference_must_be_unambiguous(self):
        value = {"references": ["https://github.com/example/fixture/commit/" + "a" * 40,
                                {"url": "https://github.com/Example/Fixture/issues/1"}]}
        self.assertEqual(acq._repository_from_advisory(value).lower(), "https://github.com/example/fixture")
        value["references"].append("https://github.com/another/project/pull/2")
        with self.assertRaisesRegex(ValueError, "repository_ambiguous"):
            acq._repository_from_advisory(value)
        for value in ({"references": []}, {"references": [URLS[0]]}):
            with self.assertRaisesRegex(ValueError, "repository_missing"):
                acq._repository_from_advisory(value)

    def test_bad_explicit_repository_is_not_replaced_by_a_reference_guess(self):
        for source in ("https://example.org/repo", "https://user:pass@github.com/a/b",
                       "https://github.com/a/b/tree/main", "file:///tmp/repo"):
            value = {"source_code_location": source, "references": ["https://github.com/a/b/commit/aaa"]}
            with self.assertRaisesRegex(ValueError, "repository_unsupported"):
                acq._repository_from_advisory(value)

    def test_advisory_identity_size_and_duplicate_keys_checked(self):
        identifier = URLS[0].rsplit("/", 1)[1]
        raw = json.dumps(advisory(identifier)).encode()
        self.assertEqual(acq._decode_advisory(raw, identifier)["ghsa_id"], identifier.upper())
        for bad in (b"{}", raw.replace(identifier.upper().encode(), b"GHSA-2345-6789-cfgh"),
                    b'{"ghsa_id":"x","ghsa_id":"y"}', b'\xff',
                    b" " * (acq.MAX_ADVISORY_BYTES + 1)):
            with self.assertRaises(acq.AcquisitionError):
                acq._decode_advisory(bad, identifier)

    def test_network_is_fixed_https_and_redirects_blocked(self):
        identifier = URLS[0].rsplit("/", 1)[1]
        response = Mock()
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        response.headers = {}
        response.geturl.return_value = "https://api.github.com/advisories/" + identifier.lower()
        response.read.return_value = json.dumps(advisory(identifier)).encode()
        opener = Mock()
        opener.open.return_value = response
        with patch.object(acq, "build_opener", return_value=opener):
            acq._download_advisory(identifier)
        request = opener.open.call_args.args[0]
        self.assertEqual(request.full_url, "https://api.github.com/advisories/" + identifier.lower())
        self.assertNotIn("Authorization", dict(request.header_items()))
        response.read.assert_called_once_with(acq.MAX_ADVISORY_BYTES + 1)
        with self.assertRaisesRegex(ValueError, "redirect_blocked"):
            acq._NoRedirect().redirect_request(None, None, 302, "redirect", {}, "https://elsewhere.example")

    def test_rate_limit_is_truthful_and_never_retried(self):
        opener = Mock()
        opener.open.side_effect = HTTPError("https://api.github.com/advisories/test", 403, "limit", {"X-RateLimit-Remaining": "0"}, None)
        with patch.object(acq, "build_opener", return_value=opener):
            with self.assertRaisesRegex(ValueError, "github_rate_limited"):
                acq._download_advisory(URLS[0].rsplit("/", 1)[1])
        self.assertEqual(opener.open.call_count, 1)

    def test_other_forbidden_response_is_not_falsely_reported_as_rate_limit(self):
        opener = Mock()
        opener.open.side_effect = HTTPError("https://api.github.com/advisories/test", 403, "denied", {}, None)
        with patch.object(acq, "build_opener", return_value=opener), \
                self.assertRaisesRegex(ValueError, "advisory_access_denied"):
            acq._download_advisory(URLS[0].rsplit("/", 1)[1])
        opener.open.side_effect = HTTPError("https://api.github.com/advisories/test", 429, "limit", {}, None)
        with patch.object(acq, "build_opener", return_value=opener), \
                self.assertRaisesRegex(ValueError, "github_rate_limited"):
            acq._download_advisory(URLS[0].rsplit("/", 1)[1])

    def test_cached_advisory_reused_and_invalid_cache_not_overwritten(self):
        identifier = URLS[0].rsplit("/", 1)[1]
        raw = json.dumps(advisory(identifier)).encode()
        with patch.object(acq, "_download_advisory", return_value=raw) as fetch:
            first, _, reused = acq._cached_advisory(self.root, identifier)
            self.assertFalse(reused)
            second, _, reused = acq._cached_advisory(self.root, identifier, allow_download=False)
            self.assertEqual(first, second)
            self.assertTrue(reused)
            self.assertEqual(fetch.call_count, 1)
            first.write_bytes(b"preserve invalid cache")
            with self.assertRaises(acq.AcquisitionError):
                acq._cached_advisory(self.root, identifier)
            self.assertEqual(first.read_bytes(), b"preserve invalid cache")

    def test_partial_failure_preserved_and_free_intake_receives_error(self):
        def fetch(identifier):
            if identifier.endswith("pwjx"):
                raise acq.AcquisitionError("advisory_not_found")
            return json.dumps(advisory(identifier)).encode()

        repository = self.root / "fake-repository"
        repository.mkdir()
        events = []
        with patch.object(acq, "_download_advisory", side_effect=fetch), \
                patch.object(acq, "_cached_repository", return_value=(repository, False)):
            manifest = acq.acquire_batch(URLS, self.root, events.append)
        rows = [json.loads(line) for line in manifest.read_text().splitlines()]
        self.assertEqual(len(rows), 3)
        self.assertEqual([row["source_link"] for row in rows], URLS)
        self.assertEqual(rows[1]["input_error"], "advisory_not_found")
        self.assertNotIn("input_error", rows[0])
        receipt = json.loads((manifest.parent / "acquisition.json").read_text())
        self.assertEqual((receipt["ready"], receipt["failed"], receipt["http_model_attempts"]), (2, 1, 0))
        jobs = load_jobs(input_path=manifest)
        self.assertEqual(len(jobs), 3)
        self.assertIn("advisory_not_found", jobs[1]["input_error"])
        self.assertTrue(any(event["phase"] == "ready" for event in events))
        self.assertTrue(any(event["phase"] == "failed" for event in events))

    def test_rate_limit_blocks_remaining_network_and_all_clone_attempts(self):
        with patch.object(acq, "MAX_WORKERS", 1), \
                patch.object(acq, "_download_advisory", side_effect=acq.AcquisitionError("github_rate_limited")) as fetch, \
                patch.object(acq, "_cached_repository") as clone:
            manifest = acq.acquire_batch(URLS, self.root)
        self.assertEqual(fetch.call_count, 1)
        clone.assert_not_called()
        rows = [json.loads(line) for line in manifest.read_text().splitlines()]
        self.assertEqual([row["input_error"] for row in rows], ["github_rate_limited"] * 3)

    def test_unique_manifests_preserve_prior_batch(self):
        with patch.object(acq, "_download_advisory", side_effect=acq.AcquisitionError("advisory_not_found")):
            first = acq.acquire_batch(URLS[:1], self.root)
            before = first.read_bytes()
            second = acq.acquire_batch(URLS[1:2], self.root)
        self.assertNotEqual(first, second)
        self.assertEqual(first.read_bytes(), before)

    def test_repository_cache_reuse_is_validated_and_does_not_clone(self):
        repository = "https://github.com/example/fixture"
        slug = acq.hashlib.sha256(repository.casefold().encode()).hexdigest()[:24]
        target = self.root / "repositories" / (slug + ".git")
        target.mkdir(parents=True)
        with patch.object(acq, "_validate_repository") as validate, \
                patch.object(acq, "_clone_repository") as clone:
            path, reused = acq._cached_repository(self.root, repository)
        self.assertEqual(path, target)
        self.assertTrue(reused)
        validate.assert_called_once_with(target, repository)
        clone.assert_not_called()

    def test_repository_cache_rejects_wrong_identity_shallow_or_unreadable_storage(self):
        repository = "https://github.com/example/fixture"
        good = {"repo_url": repository, "shallow": False, "errors": []}
        with patch.object(acq, "RepoReader") as reader:
            reader.return_value.info.return_value = good
            acq._validate_repository(self.root, repository)
            for changes in ({"repo_url": "https://github.com/another/project"},
                            {"shallow": True}, {"errors": ["commit_unavailable"]}):
                reader.return_value.info.return_value = {**good, **changes}
                with self.assertRaisesRegex(ValueError, "repository_cache_invalid"):
                    acq._validate_repository(self.root, repository)

    def test_concurrent_downloads_are_bounded_to_two(self):
        active = maximum = 0
        guard = threading.Lock()

        def fetch(identifier):
            nonlocal active, maximum
            with guard:
                active += 1
                maximum = max(maximum, active)
            time.sleep(0.03)
            with guard:
                active -= 1
            raise acq.AcquisitionError("advisory_not_found")

        with patch.object(acq, "_download_advisory", side_effect=fetch):
            acq.acquire_batch(URLS, self.root)
        self.assertEqual(maximum, 2)

    def test_git_environment_has_no_keys_helpers_or_external_git_config(self):
        with patch.dict(os.environ, {"DEEPSEEK_API_KEY": "synthetic", "GIT_CONFIG_COUNT": "1",
                                     "GIT_ASKPASS": "unwanted", "GITHUB_TOKEN": "synthetic"}):
            environment = acq._git_environment(self.root)
        for name in ("DEEPSEEK_API_KEY", "GITHUB_TOKEN", "GIT_CONFIG_COUNT"):
            self.assertNotIn(name, environment)
        self.assertEqual(environment["GIT_TERMINAL_PROMPT"], "0")
        self.assertEqual(environment["GIT_CONFIG_GLOBAL"], os.devnull)
        self.assertEqual(environment["GIT_ASKPASS"], "")
        self.assertTrue(Path(environment["TEMP"]).is_relative_to(self.root))

    def test_clone_arguments_never_checkout_filter_prompt_or_relax_tls(self):
        process = Mock()
        process.poll.return_value = 0
        process.returncode = 0
        job = Mock()
        with patch.object(acq.shutil, "which", return_value="git"), \
                patch.object(acq.shutil, "disk_usage", return_value=Mock(free=10 * 1024**3)), \
                patch.object(acq, "_tree_bytes", return_value=0), \
                patch.object(acq.subprocess, "Popen", return_value=process) as popen, \
                patch.object(acq._WindowsKillJob, "create", return_value=job), \
                patch.object(acq, "_terminate_process_tree"):
            acq._clone_repository("https://github.com/example/fixture", self.root / "repo.git", self.root)
        command = popen.call_args.args[0]
        self.assertIn("--bare", command)
        self.assertIn("credential.helper=", command)
        self.assertIn("http.sslVerify=true", command)
        self.assertIn("http.followRedirects=false", command)
        self.assertIn("--template=", command)
        self.assertIn("core.hooksPath=" + os.devnull, command)
        self.assertFalse(any("filter=" in item or "depth=" in item for item in command))
        self.assertNotIn("checkout", command)
        self.assertFalse(popen.call_args.kwargs["shell"])
        self.assertEqual(popen.call_args.kwargs["stderr"], subprocess.DEVNULL)

    def test_clone_over_size_terminates_only_owned_process_and_preserves_attempt(self):
        process = Mock()
        process.poll.return_value = None
        target = self.root / "attempt.git"
        target.mkdir()
        (target / "partial").write_bytes(b"preserve")
        job = Mock()

        def size(path, limit):
            return acq.MAX_REPOSITORY_BYTES + 1 if path == target else 0

        with patch.object(acq.shutil, "which", return_value="git"), \
                patch.object(acq.shutil, "disk_usage", return_value=Mock(free=10 * 1024**3)), \
                patch.object(acq, "_tree_bytes", side_effect=size), \
                patch.object(acq.subprocess, "Popen", return_value=process), \
                patch.object(acq._WindowsKillJob, "create", return_value=job), \
                patch.object(acq, "_terminate_process_tree") as terminate:
            with self.assertRaisesRegex(ValueError, "repository_download_too_large"):
                acq._clone_repository("https://github.com/example/fixture", target, self.root)
        self.assertEqual(terminate.call_args.args[0], process)
        self.assertEqual((target / "partial").read_bytes(), b"preserve")

    def test_clone_timeout_terminates_owned_tree(self):
        process = Mock()
        process.poll.return_value = None
        job = Mock()
        with patch.object(acq.shutil, "which", return_value="git"), \
                patch.object(acq.shutil, "disk_usage", return_value=Mock(free=10 * 1024**3)), \
                patch.object(acq, "_tree_bytes", return_value=0), \
                patch.object(acq.subprocess, "Popen", return_value=process), \
                patch.object(acq._WindowsKillJob, "create", return_value=job), \
                patch.object(acq.time, "monotonic", side_effect=[0, acq.CLONE_TIMEOUT_SECONDS + 1]), \
                patch.object(acq, "_terminate_process_tree") as terminate:
            with self.assertRaisesRegex(ValueError, "repository_download_timeout"):
                acq._clone_repository("https://github.com/example/fixture", self.root / "attempt.git", self.root)
        self.assertEqual(terminate.call_args.args[0], process)


if __name__ == "__main__":
    unittest.main()
