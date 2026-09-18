"""Pasted URL list integration: no network, credentials or model requests."""
import io
import json
from pathlib import Path
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from vulngym_t2.web import Handler
from vulngym_t2.web_portable import PortableRunManager
from vulngym_t2.web_runtime import RunManager


URLS = ["https://github.com/advisories/GHSA-f8m6-h2c7-8h9x",
        "https://github.com/advisories/GHSA-f3f2-mcxc-pwjx"]


class PreparedProcess:
    def __init__(self, inputs):
        self.stdout = io.BytesIO(json.dumps({"status": "prepared", "inputs": inputs}).encode())
        self.stderr = io.BytesIO()
        self.code = 1 if any(item.get("input_error") for item in inputs) else 0

    def wait(self):
        return self.code


class WebURLTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="t2-url-web-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.calls = []
        self.inputs = [{"report_id": url.rsplit("/", 1)[-1].upper(), "input_error": None}
                       for url in URLS]

        def popen(args, **kwargs):
            self.calls.append((args, kwargs))
            return PreparedProcess(self.inputs)

        self.manager = PortableRunManager(self.root / "runs", self.root / "counter.jsonl", popen=popen)

    def acquire(self, urls, root, progress=None):
        self.assertEqual(urls, URLS)
        self.assertEqual(root, self.root / "downloads")
        root.mkdir(exist_ok=True)
        target = root / "records.jsonl"
        target.write_text("\n".join(json.dumps({"source_link": url}) for url in urls), encoding="utf-8")
        if progress:
            progress({"event": "acquisition_finished", "total": 2, "private_diagnostic": "discard"})
        return target

    def wait_done(self, run_id):
        until = time.monotonic() + 5
        while self.manager.get(run_id).state == "preparing" and time.monotonic() < until:
            worker = self.manager.get(run_id).worker
            worker.join(.05)
        run = self.manager.get(run_id)
        self.assertNotEqual(run.state, "preparing")
        return run

    def test_markdown_and_spaces_are_one_free_batch_with_no_manual_paths(self):
        with patch("vulngym_t2.web_runtime.acquire_batch", self.acquire):
            text = f"[{URLS[0]}]({URLS[0]}) {URLS[1]}\n{URLS[1]}"
            run = self.wait_done(self.manager.prepare({"mode": "urls", "urls": text}))
        self.assertEqual(run.state, "prepared")
        self.assertEqual(len(run.inputs), 2)
        self.assertEqual(len(self.calls), 1)
        args, options = self.calls[0]
        self.assertIn("--prepare-only", args)
        self.assertNotIn("--request-ledger", args)
        self.assertNotIn("--key-stdin", args)
        self.assertNotIn("DEEPSEEK_API_KEY", options["env"])
        self.assertFalse(self.manager.ledger.exists())
        self.assertNotIn("private_diagnostic", repr(run.public()))

    def test_acquisition_failure_releases_active_state_and_preserves_folder(self):
        with patch("vulngym_t2.web_runtime.acquire_batch", side_effect=OSError("secret diagnostic")):
            run = self.wait_done(self.manager.prepare({"mode": "urls", "urls": " ".join(URLS)}))
        self.assertEqual((run.state, run.code), ("error", "url_acquisition_failed"))
        self.assertTrue(run.folder.exists())
        self.assertNotIn("secret diagnostic", repr(run.public()))
        self.assertEqual(self.calls, [])

    def test_all_failed_inputs_cannot_start_but_partial_batch_preserves_both_rows(self):
        self.inputs[0]["input_error"] = "public_repository_missing"
        with patch("vulngym_t2.web_runtime.acquire_batch", self.acquire):
            run = self.wait_done(self.manager.prepare({"mode": "urls", "urls": " ".join(URLS)}))
        self.assertEqual(run.state, "prepared")
        self.assertEqual(len(run.inputs), 2)
        self.inputs[1]["input_error"] = "public_repository_missing"
        self.assertEqual(run.exit_code, 1)
        with patch("vulngym_t2.web_runtime.acquire_batch", self.acquire):
            failed = self.wait_done(self.manager.prepare({"mode": "urls", "urls": " ".join(URLS)}))
        self.assertEqual((failed.state, failed.code), ("error", "no_ready_url_inputs"))
        with self.assertRaisesRegex(ValueError, "prepare_successfully_before_start"):
            self.manager.start(failed.id, "synthetic", 12, True)
        self.assertFalse(self.manager.ledger.exists())

    def test_second_preparation_is_blocked_during_acquisition(self):
        gate = threading.Event()
        entered = threading.Event()

        def wait_acquire(*args, **kwargs):
            entered.set()
            gate.wait(5)
            return self.acquire(*args, **kwargs)

        with patch("vulngym_t2.web_runtime.acquire_batch", wait_acquire):
            run_id = self.manager.prepare({"mode": "urls", "urls": " ".join(URLS)})
            try:
                self.assertTrue(entered.wait(2))
                with self.assertRaisesRegex(ValueError, "another_operation_is_active"):
                    self.manager.prepare({"mode": "urls", "urls": URLS[0]})
            finally:
                gate.set()
                self.wait_done(run_id)
        self.assertEqual(len(self.calls), 1)

    def test_invalid_url_readonly_and_keys_fail_before_network(self):
        with patch("vulngym_t2.web_runtime.acquire_batch") as acquire:
            with self.assertRaises(ValueError):
                self.manager.prepare({"mode": "urls", "urls": "http://127.0.0.1/private"})
            with self.assertRaisesRegex(ValueError, "unknown_prepare_property"):
                self.manager.prepare({"mode": "urls", "urls": URLS[0], "key": "synthetic"})
            for mode in ("system", "direct"):
                with self.subTest(mode=mode):
                    child = Mock()
                    readonly = RunManager(self.root / f"readonly-{mode}", read_only=True,
                                          network_mode=mode, popen=child)
                    with self.assertRaisesRegex(ValueError, "read_only_mode"):
                        readonly.prepare({"mode": "urls", "urls": URLS[0]})
                    self.assertTrue(readonly.read_only)
                    self.assertEqual(readonly.network_mode, mode)
                    self.assertIsNone(readonly.ledger)
                    self.assertFalse(readonly.root.exists())
                    self.assertEqual(readonly.runs, {})
                    child.assert_not_called()
            acquire.assert_not_called()
        self.assertEqual(self.manager.runs, {})

    def test_default_network_mode_is_system_and_keeps_legacy_acquire_signature(self):
        self.assertEqual(self.manager.network_mode, "system")
        with patch("vulngym_t2.web_runtime.acquire_batch", side_effect=self.acquire) as acquire:
            run = self.wait_done(self.manager.prepare({"mode": "urls", "urls": " ".join(URLS)}))
        self.assertEqual(run.state, "prepared")
        acquire.assert_called_once()
        self.assertEqual(acquire.call_args.kwargs.get("network_mode", "system"), "system")
        self.assertFalse(self.manager.ledger.exists())

    def test_direct_mode_is_forwarded_only_to_public_url_acquisition(self):
        self.manager = PortableRunManager(self.root / "direct-runs", self.root / "direct-counter.jsonl",
                                          network_mode="direct", popen=self.manager.popen)

        def direct_acquire(urls, root, progress=None, *, network_mode):
            self.assertEqual(network_mode, "direct")
            return self.acquire(urls, root, progress=progress)

        with patch("vulngym_t2.web_runtime.acquire_batch", side_effect=direct_acquire) as acquire:
            run = self.wait_done(self.manager.prepare({"mode": "urls", "urls": " ".join(URLS)}))
        self.assertEqual(run.state, "prepared")
        acquire.assert_called_once()
        self.assertEqual(acquire.call_args.kwargs["network_mode"], "direct")
        self.assertEqual(self.manager.snapshot()["network_mode"], "direct")
        self.assertEqual(len(self.calls), 1)
        args, options = self.calls[0]
        self.assertIn("--prepare-only", args)
        self.assertNotIn("--network-mode", args)
        self.assertNotIn("--key-stdin", args)
        self.assertNotIn("--request-ledger", args)
        self.assertNotIn("DEEPSEEK_API_KEY", options["env"])
        self.assertFalse(self.manager.ledger.exists())

    def test_invalid_manager_network_modes_fail_before_creating_directories(self):
        for mode in ("auto", "DIRECT", "", None, True, []):
            for portable in (False, True):
                with self.subTest(mode=mode, portable=portable):
                    target = self.root / "invalid-mode-runs"
                    with self.assertRaises(ValueError):
                        if portable:
                            PortableRunManager(target, self.root / "invalid-counter.jsonl", network_mode=mode)
                        else:
                            RunManager(target, read_only=True, network_mode=mode)
                    self.assertFalse(target.exists())
                    self.assertFalse((self.root / "invalid-counter.jsonl").exists())

    def test_api_state_exposes_network_mode_without_network_or_children(self):
        for mode in ("system", "direct"):
            with self.subTest(mode=mode):
                manager = RunManager(self.root / f"state-{mode}", read_only=True, network_mode=mode)
                handler = object.__new__(Handler)
                handler.path = "/api/state"
                handler.server = SimpleNamespace(manager=manager, server_port=8765,
                                                 origin="http://127.0.0.1:8765", token="synthetic-session")
                handler.headers = {"Host": "127.0.0.1:8765", "X-T2-Session": "synthetic-session"}
                handler.respond = Mock()
                with patch("vulngym_t2.web_runtime.acquire_batch") as acquire:
                    handler.do_GET()
                handler.respond.assert_called_once()
                status, state = handler.respond.call_args.args
                self.assertEqual(status, 200)
                self.assertEqual(state["network_mode"], mode)
                self.assertTrue(state["read_only"])
                self.assertFalse(manager.root.exists())
                acquire.assert_not_called()
        self.assertEqual(self.calls, [])

    def test_mixed_osv_links_share_free_preparation_and_keep_original_identity(self):
        osv = "https://osv.dev/vulnerability/GHSA-f8m6-h2c7-8h9x"
        expected = [URLS[1], osv]
        self.inputs = [{"report_id": url.rsplit("/", 1)[-1].upper(), "input_error": None}
                       for url in expected]

        def acquire(urls, root, progress=None):
            self.assertEqual(urls, expected)
            root.mkdir()
            manifest = root / "records.jsonl"
            manifest.write_text("", encoding="utf-8")
            progress({"phase": "ready", "source_link": URLS[0], "input_source_url": osv,
                      "index": 2, "total": 2, "private_diagnostic": "discard"})
            return manifest

        with patch("vulngym_t2.web_runtime.acquire_batch", acquire):
            pasted = (f"{URLS[1]} [{osv}]({osv}) "
                      "https://api.osv.dev/v1/vulns/GHSA-f8m6-h2c7-8h9x")
            run = self.wait_done(self.manager.prepare({"mode": "urls", "urls": pasted}))
        self.assertEqual(run.state, "prepared")
        self.assertEqual(len(run.inputs), 2)
        self.assertEqual(len(self.calls), 1)
        self.assertIn("--prepare-only", self.calls[0][0])
        self.assertFalse(self.manager.ledger.exists())
        event = next(e for e in run.events if e.get("event") == "acquisition_ready")
        self.assertEqual(event["report_id"], "GHSA-f8m6-h2c7-8h9x")
        self.assertNotIn("private_diagnostic", repr(run.public()))


if __name__ == "__main__":
    unittest.main()
