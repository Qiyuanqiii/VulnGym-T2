"""Explicit download routing checks: synthetic fixtures, no network or models."""

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
REPOSITORY = "https://github.com/example/fixture"


def github_record(identifier=GHSA):
    return {"ghsa_id": identifier.upper(), "summary": "Synthetic fixture",
            "description": "Public input only", "references": [],
            "source_code_location": REPOSITORY}


def osv_record():
    return {"id": GHSA, "summary": "Synthetic fixture", "details": "Public input only",
            "database_specific": {"github_reviewed": True},
            "references": [{"type": "SOURCE", "url": REPOSITORY}]}


class AcquisitionNetworkTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="t2-acquisition-network-")
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_network_mode_is_exact_and_rejected_before_io(self):
        self.assertEqual(acq.validate_network_mode("system"), "system")
        self.assertEqual(acq.validate_network_mode("direct"), "direct")
        for mode in (None, True, 0, [], {}, "", "SYSTEM", " direct", "direct ", "auto", "proxy"):
            with self.subTest(mode=mode), patch.object(acq, "Path") as path, \
                    patch.object(acq, "build_opener") as opener, \
                    patch.object(acq.subprocess, "Popen") as process:
                with self.assertRaisesRegex(acq.AcquisitionError, "^network_mode_invalid$"):
                    acq.acquire_batch([GITHUB], self.root, network_mode=mode)
                path.assert_not_called()
                opener.assert_not_called()
                process.assert_not_called()

    def test_http_direct_explicitly_disables_proxy_but_keeps_request_boundaries(self):
        providers = [(acq._download_advisory, acq._NoRedirect,
                      "https://api.github.com/advisories/" + GHSA.lower(), github_record()),
                     (acq._download_osv, acq._NoOSVRedirect,
                      "https://api.osv.dev/v1/vulns/" + GHSA, osv_record())]
        for download, redirect_type, api, record in providers:
            for mode in ("system", "direct"):
                with self.subTest(provider=download.__name__, mode=mode):
                    response = Mock()
                    response.__enter__ = Mock(return_value=response)
                    response.__exit__ = Mock(return_value=False)
                    response.headers = {}
                    response.geturl.return_value = api
                    raw = json.dumps(record).encode()
                    response.read.return_value = raw
                    opener = Mock()
                    opener.open.return_value = response
                    synthetic_environment = {"HTTPS_PROXY": "http://synthetic.invalid:8080"}
                    with patch.object(acq.os, "environ", synthetic_environment), \
                            patch.object(acq, "build_opener", return_value=opener) as build:
                        self.assertEqual(download(GHSA, network_mode=mode), raw)
                    self.assertEqual(synthetic_environment,
                                     {"HTTPS_PROXY": "http://synthetic.invalid:8080"})
                    handlers = build.call_args.args
                    self.assertIsInstance(handlers[0], redirect_type)
                    proxies = [handler for handler in handlers if isinstance(handler, acq.ProxyHandler)]
                    self.assertEqual(len(proxies), int(mode == "direct"))
                    if proxies:
                        self.assertEqual(proxies[0].proxies, {})
                    request = opener.open.call_args.args[0]
                    self.assertEqual(request.full_url, api)
                    self.assertFalse(any(key.lower() == "authorization" for key, _ in request.header_items()))
                    self.assertEqual(opener.open.call_args.kwargs, {"timeout": acq.HTTP_TIMEOUT_SECONDS})
                    self.assertEqual(opener.open.call_count, 1)
                    response.read.assert_called_once_with(acq.MAX_ADVISORY_BYTES + 1)
                    self.assertNotIn("context", build.call_args.kwargs)

    def test_direct_http_rate_limits_are_reported_once_without_another_route(self):
        for download, error_code in [(acq._download_advisory, "github_rate_limited"),
                                     (acq._download_osv, "osv_rate_limited")]:
            opener = Mock()
            opener.open.side_effect = HTTPError("https://synthetic.invalid", 429, "limited", {}, None)
            with self.subTest(provider=download.__name__), \
                    patch.object(acq, "build_opener", return_value=opener) as build, \
                    self.assertRaisesRegex(acq.AcquisitionError, error_code):
                download(GHSA, network_mode="direct")
            self.assertEqual(build.call_count, 1)
            self.assertEqual(opener.open.call_count, 1)
            self.assertTrue(any(isinstance(handler, acq.ProxyHandler) and handler.proxies == {}
                                for handler in build.call_args.args))

    def test_git_proxy_changes_are_child_only_and_system_whitelist_is_unchanged(self):
        original = {"PATH": "synthetic-path", "HTTP_PROXY": "synthetic-http",
                    "https_proxy": "synthetic-https", "All_Proxy": "synthetic-all",
                    "no_proxy": "synthetic-no-proxy", "NO_PROXY": "synthetic-uppercase",
                    "GIT_CONFIG_COUNT": "1", "GITHUB_TOKEN": "synthetic-token",
                    "DEEPSEEK_API_KEY": "synthetic-key", "GIT_ASKPASS": "synthetic-askpass"}
        environment = original.copy()
        with patch.object(acq.os, "environ", environment):
            system = acq._git_environment(self.root)
            direct = acq._git_environment(self.root, network_mode="direct")
            system_again = acq._git_environment(self.root, network_mode="system")
        self.assertEqual(environment, original)
        self.assertEqual(system, system_again)
        for key in ("HTTP_PROXY", "https_proxy", "All_Proxy", "no_proxy", "NO_PROXY"):
            self.assertEqual(system[key], original[key])
        self.assertEqual({key: value for key, value in direct.items() if key.upper().endswith("_PROXY")},
                         {"NO_PROXY": "*"})
        proxy_keys = {"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"}
        self.assertEqual({key: value for key, value in system.items() if key.upper() not in proxy_keys},
                         {key: value for key, value in direct.items() if key.upper() not in proxy_keys})
        for key in ("GIT_CONFIG_COUNT", "GITHUB_TOKEN", "DEEPSEEK_API_KEY"):
            self.assertNotIn(key, direct)
        self.assertEqual(direct["GIT_CONFIG_SYSTEM"], os.devnull)
        self.assertEqual(direct["GIT_CONFIG_GLOBAL"], os.devnull)
        self.assertEqual(direct["GIT_ASKPASS"], "")
        self.assertEqual(direct["GIT_TERMINAL_PROMPT"], "0")

    def test_clone_direct_adds_only_ephemeral_proxy_config_and_child_environment(self):
        captured = {}
        for mode in ("system", "direct"):
            process = Mock()
            process.poll.return_value = 0
            process.returncode = 0
            with patch.object(acq.shutil, "which", return_value="git"), \
                    patch.object(acq.shutil, "disk_usage", return_value=Mock(free=10 * 1024**3)), \
                    patch.object(acq, "_tree_bytes", return_value=0), \
                    patch.object(acq.subprocess, "Popen", return_value=process) as popen, \
                    patch.object(acq._WindowsKillJob, "create", return_value=Mock()), \
                    patch.object(acq, "_terminate_process_tree"), \
                    patch.object(acq.os, "environ", {"HTTPS_PROXY": "synthetic-proxy"}):
                acq._clone_repository(REPOSITORY, self.root / "repo.git", self.root, network_mode=mode)
            captured[mode] = popen.call_args
        system_command = captured["system"].args[0]
        direct_command = captured["direct"].args[0]
        self.assertNotIn("http.proxy=", system_command)
        proxy_index = direct_command.index("http.proxy=")
        self.assertEqual(direct_command[proxy_index - 1], "-c")
        self.assertLess(proxy_index, direct_command.index("clone"))
        self.assertEqual(direct_command[:proxy_index - 1] + direct_command[proxy_index + 1:], system_command)
        self.assertEqual(captured["system"].kwargs["env"]["HTTPS_PROXY"], "synthetic-proxy")
        self.assertNotIn("HTTPS_PROXY", captured["direct"].kwargs["env"])
        self.assertEqual(captured["direct"].kwargs["env"]["NO_PROXY"], "*")
        self.assertIn("http.sslVerify=true", direct_command)
        self.assertIn("http.followRedirects=false", direct_command)
        self.assertIn("credential.helper=", direct_command)
        self.assertIn("--bare", direct_command)
        self.assertFalse(captured["direct"].kwargs["shell"])

    def test_direct_batch_propagates_mode_and_reuses_provider_caches_across_modes(self):
        def clone(repository, target, root, *, network_mode):
            self.assertEqual(network_mode, "direct")
            self.assertEqual(repository, REPOSITORY)
            target.mkdir()

        with patch.object(acq, "_download_advisory", return_value=json.dumps(github_record()).encode()) as github, \
                patch.object(acq, "_download_osv", return_value=json.dumps(osv_record()).encode()) as osv, \
                patch.object(acq, "_clone_repository", side_effect=clone) as cloning, \
                patch.object(acq, "_validate_repository"):
            manifest = acq.acquire_batch([GITHUB, OSV], self.root, network_mode="direct")
            cached_manifest = acq.acquire_batch([GITHUB, OSV], self.root)
        github.assert_called_once_with(GHSA, network_mode="direct")
        osv.assert_called_once_with(GHSA, network_mode="direct")
        self.assertEqual(cloning.call_count, 1)
        rows = [json.loads(line) for line in manifest.read_text().splitlines()]
        self.assertEqual([row["input_source_url"] for row in rows], [GITHUB, OSV])
        self.assertEqual([row["source_provider"] for row in rows], ["github", "osv"])
        self.assertEqual([row["source_link"] for row in rows], [GITHUB, GITHUB])
        for path, mode in [(manifest, "direct"), (cached_manifest, "system")]:
            receipt = json.loads((path.parent / "acquisition.json").read_text())
            self.assertEqual(receipt["network_mode"], mode)
            self.assertEqual(receipt["source"], "public_mixed")
            self.assertEqual((receipt["ready"], receipt["failed"], receipt["http_model_attempts"]), (2, 0, 0))
            self.assertEqual(receipt["limits"]["parallel_downloads"], acq.MAX_WORKERS)
            if mode == "system":
                self.assertTrue(all(item["advisory_cached"] and item["repository_cached"]
                                    for item in receipt["inputs"]))

    def test_default_batch_accepts_legacy_download_and_clone_signatures(self):
        def clone(repository, target, root):
            target.mkdir()

        with patch.object(acq, "_download_advisory", side_effect=lambda identifier: json.dumps(github_record()).encode()), \
                patch.object(acq, "_download_osv", side_effect=lambda identifier: json.dumps(osv_record()).encode()), \
                patch.object(acq, "_clone_repository", side_effect=clone), \
                patch.object(acq, "_validate_repository"):
            manifest = acq.acquire_batch([GITHUB, OSV], self.root, network_mode="system")
        receipt = json.loads((manifest.parent / "acquisition.json").read_text())
        self.assertEqual(receipt["network_mode"], "system")
        self.assertEqual(receipt["ready"], 2)

    def test_direct_keeps_provider_rate_limits_and_never_switches_route_or_source(self):
        with patch.object(acq, "MAX_WORKERS", 1), \
                patch.object(acq, "_download_advisory", side_effect=acq.AcquisitionError("github_rate_limited")) as github, \
                patch.object(acq, "_download_osv", side_effect=acq.AcquisitionError("osv_rate_limited")) as osv, \
                patch.object(acq, "_cached_repository") as clone:
            manifest = acq.acquire_batch([GITHUB, OSV, "https://github.com/advisories/" + OTHER,
                                          "https://osv.dev/vulnerability/" + OTHER],
                                         self.root, network_mode="direct")
        github.assert_called_once_with(GHSA, network_mode="direct")
        osv.assert_called_once_with(GHSA, network_mode="direct")
        clone.assert_not_called()
        rows = [json.loads(line) for line in manifest.read_text().splitlines()]
        self.assertEqual([row["input_error"] for row in rows],
                         ["github_rate_limited", "osv_rate_limited"] * 2)
        receipt = json.loads((manifest.parent / "acquisition.json").read_text())
        self.assertEqual(receipt["network_mode"], "direct")
        self.assertEqual((receipt["ready"], receipt["failed"]), (0, 4))

    def test_direct_clone_failure_is_retained_without_fallback_or_retry(self):
        def clone(repository, target, root, *, network_mode):
            self.assertEqual(network_mode, "direct")
            target.mkdir()
            (target / "partial").write_bytes(b"retained synthetic fixture")
            raise acq.AcquisitionError("repository_download_failed")

        with patch.object(acq, "_download_advisory", return_value=json.dumps(github_record()).encode()), \
                patch.object(acq, "_clone_repository", side_effect=clone) as cloning, \
                patch.object(acq, "_download_osv") as osv:
            manifest = acq.acquire_batch([GITHUB], self.root, network_mode="direct")
        self.assertEqual(cloning.call_count, 1)
        osv.assert_not_called()
        self.assertEqual(json.loads(manifest.read_text())["input_error"], "repository_download_failed")
        partials = list((self.root / "attempts").glob("*/partial"))
        self.assertEqual(len(partials), 1)
        self.assertEqual(partials[0].read_bytes(), b"retained synthetic fixture")

    def test_direct_does_not_expand_advisory_url_allowlist(self):
        for url in ("http://github.com/advisories/" + GHSA, "https://localhost/advisories/" + GHSA,
                    GITHUB + "?proxy=direct", "https://user:pass@osv.dev/vulnerability/" + GHSA):
            with self.subTest(url=url), patch.object(acq, "build_opener") as opener, \
                    patch.object(acq.subprocess, "Popen") as process:
                with self.assertRaises(acq.AcquisitionError):
                    acq.acquire_batch([url], self.root / "not-created", network_mode="direct")
                opener.assert_not_called()
                process.assert_not_called()
        self.assertFalse((self.root / "not-created").exists())


if __name__ == "__main__":
    unittest.main()
