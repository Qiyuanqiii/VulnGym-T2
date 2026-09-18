"""Portable entry points must open the GUI without asking console questions."""
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import configure_launch
import launch_workbench
from vulngym_t2.web_portable import portable_manager
from vulngym_t2.web_runtime import FILES, RunManager


class DeliveryLauncherTests(unittest.TestCase):
    def test_default_compatibility_entry_opens_gui_without_console_input(self):
        with patch("builtins.input", side_effect=AssertionError("no terminal prompts")), \
                patch.object(configure_launch.launch_workbench, "main", return_value=0) as launch:
            self.assertEqual(configure_launch.main([]), 0)
            launch.assert_called_once_with([])

    def test_old_extraction_shortcut_still_opens_gui(self):
        with patch("builtins.input", side_effect=AssertionError("no terminal prompts")), \
                patch.object(configure_launch.launch_workbench, "main", return_value=0) as launch:
            self.assertEqual(configure_launch.main(["--extract", "--no-browser", "--port", "8765"]), 0)
            launch.assert_called_once_with(["--no-browser", "--port", "8765"])

    def test_readonly_is_explicit_and_preserved(self):
        with patch.object(configure_launch.launch_workbench, "main", return_value=0) as launch:
            configure_launch.main(["--read-only"])
            launch.assert_called_once_with(["--read-only"])

    def test_compatibility_entry_preserves_explicit_direct_mode(self):
        with patch.object(configure_launch.launch_workbench, "main", return_value=0) as launch:
            configure_launch.main(["--network-mode", "direct", "--check"])
            launch.assert_called_once_with(["--network-mode", "direct", "--check"])

    def test_cmd_shortcuts_never_invoke_terminal_setup(self):
        root = Path(configure_launch.__file__).resolve().parent
        for name in ("start.cmd", "start-extraction.cmd", "start-demo.cmd"):
            with self.subTest(name=name):
                script = (root / name).read_text(encoding="utf-8")
                self.assertIn('"launch_workbench.py"', script)
                self.assertNotIn("configure_launch.py", script)
                self.assertNotIn("set /p", script.lower())
                self.assertEqual("--read-only" in script, name == "start-demo.cmd")

    def test_direct_shortcut_delegates_without_changing_normal_startup(self):
        root = Path(configure_launch.__file__).resolve().parent
        direct = (root / "start-direct.cmd").read_text(encoding="utf-8")
        normal = (root / "start.cmd").read_text(encoding="utf-8")
        self.assertIn('call "%~dp0start.cmd" --network-mode direct %*', direct)
        self.assertNotIn("--network-mode", normal)
        for script in (normal, direct):
            self.assertNotIn("set /p", script.lower())
            self.assertNotIn("reg add", script.lower())
            self.assertNotIn("netsh", script.lower())
            for name in ("http_proxy", "https_proxy", "all_proxy", "no_proxy"):
                self.assertNotIn(name, script.lower())


class LauncherNetworkModeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="t2-launch-network-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.profile = self.root / "synthetic-profile"
        self.ledger = self.root / "synthetic-ledger.jsonl"
        self.ledger.write_text(json.dumps({
            "event": "authorization", "model": "deepseek-flash",
            "request_limit": 12, "automatic_retries": 0,
        }) + "\n", encoding="utf-8")
        self.example = self.root / "examples" / "run-synthetic"
        self.example.mkdir(parents=True)
        for name in FILES:
            value = json.dumps({"status": "completed", "input_count": 0}) if name == "summary.json" else ""
            (self.example / name).write_text(value, encoding="utf-8")

    def test_check_reports_and_forwards_default_and_direct_on_every_startup_path(self):
        paths = (("portable", []), ("read-only", ["--read-only"]),
                 ("live", ["--live", "--ledger", str(self.ledger), "--limit", "12"]))
        proxies = {"HTTP_PROXY": "http://proxy.invalid:8080",
                   "HTTPS_PROXY": "http://proxy.invalid:8081",
                   "ALL_PROXY": "http://proxy.invalid:8082", "NO_PROXY": "localhost"}
        before = self.ledger.read_bytes()

        def build_portable(root, **kwargs):
            return portable_manager(root, profile=self.profile, **kwargs)

        for mode, option in (("system", []), ("direct", ["--network-mode", "direct"])):
            for path, arguments in paths:
                with self.subTest(mode=mode, path=path), \
                        patch.object(launch_workbench, "ROOT", self.root), \
                        patch("vulngym_t2.web_runtime.RunManager", wraps=RunManager) as runtime, \
                        patch("vulngym_t2.web_portable.portable_manager", side_effect=build_portable) as portable, \
                        patch("vulngym_t2.web.LocalServer") as server, \
                        patch.object(launch_workbench.webbrowser, "open") as browser, \
                        patch("vulngym_t2.web_runtime.acquire_batch") as acquire, \
                        patch.object(RunManager, "_launch") as child, \
                        patch.dict(os.environ, proxies), \
                        patch("sys.stdout", new_callable=io.StringIO) as output:
                    self.assertEqual(launch_workbench.main(["--check", *option, *arguments]), 0)
                    state = json.loads(output.getvalue())
                    self.assertEqual(state["network_mode"], mode)
                    self.assertEqual(state["read_only"], path == "read-only")
                    self.assertEqual(state["status"], "ready")
                    self.assertEqual(state["example_runs"], 1)
                    self.assertEqual(state["http_model_requests"], 0)
                    if path == "portable":
                        portable.assert_called_once_with(self.root, network_mode=mode)
                        runtime.assert_not_called()
                    else:
                        portable.assert_not_called()
                        runtime.assert_called_once()
                        self.assertEqual(runtime.call_args.kwargs["network_mode"], mode)
                    self.assertEqual(server.call_args.args[0].network_mode, mode)
                    server.return_value.serve_forever.assert_not_called()
                    server.return_value.server_close.assert_called_once_with()
                    browser.assert_not_called()
                    acquire.assert_not_called()
                    child.assert_not_called()
                    self.assertEqual({name: os.environ.get(name) for name in proxies}, proxies)
                    self.assertEqual(self.ledger.read_bytes(), before)
                    self.assertFalse(self.profile.exists())
                    self.assertFalse(Path(str(self.ledger) + ".lock").exists())

    def test_saved_portable_profile_paths_preserve_network_mode_without_writes(self):
        before = self.ledger.read_bytes()
        for profile_mode in ("managed", "existing"):
            for network_mode in ("system", "direct"):
                with self.subTest(profile_mode=profile_mode, network_mode=network_mode):
                    profile = self.root / f"profile-{profile_mode}-{network_mode}"
                    profile.mkdir()
                    settings = profile / "workbench.json"
                    settings.write_text(json.dumps({
                        "version": 1, "mode": profile_mode, "ledger": str(self.ledger), "limit": 12,
                    }), encoding="utf-8")
                    settings_before = settings.read_bytes()
                    with patch.object(RunManager, "_launch") as child, \
                            patch("vulngym_t2.web_runtime.acquire_batch") as acquire:
                        manager = portable_manager(self.root / f"copy-{profile_mode}-{network_mode}",
                                                   profile=profile, network_mode=network_mode)
                        self.assertEqual(manager.snapshot()["network_mode"], network_mode)
                        self.assertFalse(manager.read_only)
                        self.assertEqual(manager.ledger, self.ledger)
                        child.assert_not_called()
                        acquire.assert_not_called()
                    self.assertEqual(settings.read_bytes(), settings_before)
                    self.assertEqual(self.ledger.read_bytes(), before)
                    self.assertFalse(Path(str(self.ledger) + ".lock").exists())

    def test_invalid_network_mode_is_rejected_before_startup(self):
        for mode in ("auto", "DIRECT", ""):
            with self.subTest(mode=mode), \
                    patch("vulngym_t2.web_runtime.RunManager") as runtime, \
                    patch("vulngym_t2.web_portable.portable_manager") as portable, \
                    patch("vulngym_t2.web.LocalServer") as server, \
                    patch("vulngym_t2.web_runtime.acquire_batch") as acquire, \
                    patch("sys.stderr", new_callable=io.StringIO), \
                    self.assertRaises(SystemExit) as error:
                launch_workbench.main(["--check", "--network-mode", mode])
            self.assertEqual(error.exception.code, 2)
            runtime.assert_not_called()
            portable.assert_not_called()
            server.assert_not_called()
            acquire.assert_not_called()


if __name__ == "__main__":
    unittest.main()
