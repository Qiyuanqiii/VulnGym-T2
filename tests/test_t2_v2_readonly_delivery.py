"""Read-only portable delivery uses saved results, never a ledger or child."""
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from vulngym_t2 import web
from vulngym_t2.web_runtime import FILES, RunManager


class ReadOnlyDeliveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="t2-readonly-delivery-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.runs_root = self.root / "never-created-runs"
        self.launch = Mock(side_effect=AssertionError("Read-only delivery must not start a child"))

    def manager(self):
        return RunManager(self.runs_root, read_only=True, popen=self.launch)

    def saved_result(self):
        folder = self.root / "saved-run"
        folder.mkdir()
        for name in FILES:
            value = json.dumps({"status": "completed", "input_count": 1}) if name == "summary.json" else ""
            (folder / name).write_text(value, encoding="utf-8")
        return folder

    def test_no_ledger_or_run_directory_is_created_and_budget_is_explicit(self):
        with patch("vulngym_t2.web_runtime.budget_snapshot", side_effect=AssertionError("No ledger read")):
            manager = self.manager()
            self.assertIsNone(manager.ledger)
            self.assertEqual(manager.budget(), {
                "available": False, "remaining": 0, "code": "read_only_mode", "read_only": True})
            self.assertIs(manager.snapshot()["read_only"], True)
        self.assertFalse(self.runs_root.exists())
        self.assertEqual(list(self.root.iterdir()), [])
        self.launch.assert_not_called()

    def test_import_and_export_saved_result_remain_read_only(self):
        folder = self.saved_result()
        before = {path.name: path.read_bytes() for path in folder.iterdir()}
        manager = self.manager()
        run_id = manager.import_result(folder)
        self.assertEqual(manager.result(run_id)["summary"]["status"], "completed")
        self.assertEqual(manager.result(run_id)["entries"], [])
        self.assertEqual(manager.snapshot()["runs"][0]["state"], "imported")
        self.assertEqual(manager.file(run_id, "drafts.jsonl"), folder / "drafts.jsonl")
        self.assertEqual(before, {path.name: path.read_bytes() for path in folder.iterdir()})
        self.assertFalse(self.runs_root.exists())
        self.launch.assert_not_called()

    def test_readonly_does_not_inspect_supplied_ledger_or_authorization(self):
        ledger = Mock()
        manager = RunManager(self.runs_root, ledger, 100, effective_limit=99,
                             historical=1, read_only=True, popen=self.launch)
        ledger.resolve.assert_not_called()
        self.assertIsNone(manager.ledger)
        self.assertIsNone(manager.limit)
        self.assertEqual(manager.budget()["remaining"], 0)
        self.assertFalse(self.runs_root.exists())

    def test_direct_mutation_methods_reject_before_validation_or_disk_access(self):
        manager = self.manager()
        for operation in (
            lambda: manager.prepare({"text": "Fixture"}),
            lambda: manager.prepare(None),
            lambda: manager.start("anything", "synthetic", 1, True),
            lambda: manager.stop("anything"),
            lambda: manager._launch(None, [], preparation=True),
        ):
            with self.subTest(operation=operation), self.assertRaisesRegex(ValueError, "^read_only_mode$"):
                operation()
        self.assertEqual(manager.runs, {})
        self.assertFalse(self.runs_root.exists())
        self.launch.assert_not_called()

    def test_authorized_http_handlers_cannot_bypass_readonly_mode(self):
        manager = self.manager()
        for path, payload in (("/api/prepare", {"text": "Fixture"}),
                              ("/api/start", {"run_id": "anything", "key": "synthetic", "max_requests": 1, "confirmed": True}),
                              ("/api/stop", {"run_id": "anything"})):
            with self.subTest(path=path):
                raw = json.dumps(payload).encode()
                handler = web.Handler.__new__(web.Handler)
                handler.path = path
                handler.headers = {"Content-Length": str(len(raw)), "Content-Type": "application/json"}
                handler.rfile = io.BytesIO(raw)
                handler.server = SimpleNamespace(manager=manager)
                handler.allowed = Mock(return_value=True)  # Even a valid session is read-only.
                handler.respond = Mock()
                handler.do_POST()
                handler.respond.assert_called_once_with(400, {"code": "read_only_mode"})
        self.assertFalse(self.runs_root.exists())
        self.launch.assert_not_called()

    def test_cli_readonly_imports_without_ledger_and_does_not_bind_a_real_port(self):
        folder = self.saved_result()
        server = Mock(origin="http://127.0.0.1:0")
        with patch.object(web, "LocalServer", return_value=server) as server_type, patch("sys.stdout", new_callable=io.StringIO):
            code = web.main(["--read-only", "--runs-root", str(self.runs_root), "--review-dir", str(folder), "--port", "0"])
        self.assertEqual(code, 0)
        manager = server_type.call_args.args[0]
        self.assertTrue(manager.read_only)
        self.assertIsNone(manager.ledger)
        self.assertEqual(len(manager.runs), 1)
        self.assertEqual(next(iter(manager.runs.values())).state, "imported")
        server.serve_forever.assert_called_once()
        server.server_close.assert_called_once()
        self.assertFalse(self.runs_root.exists())

    def test_normal_cli_still_requires_both_budget_arguments_before_server(self):
        for extra in ([], ["--authorization-limit", "100"], ["--request-ledger", str(self.root / "absent.jsonl")]):
            with self.subTest(extra=extra), patch.object(web, "LocalServer") as server, patch("sys.stderr", new_callable=io.StringIO):
                with self.assertRaises(SystemExit) as error:
                    web.main(["--runs-root", str(self.runs_root), *extra])
                self.assertEqual(error.exception.code, 2)
                server.assert_not_called()
        self.assertFalse(self.runs_root.exists())

    def test_normal_manager_does_not_create_a_missing_ledger(self):
        for ledger in (None, self.root / "missing-ledger.jsonl"):
            with self.subTest(ledger=ledger), self.assertRaisesRegex(ValueError, "existing_shared_ledger_required"):
                RunManager(self.runs_root, ledger, 100, popen=self.launch)
        self.assertEqual(list(self.root.iterdir()), [])
        self.launch.assert_not_called()


if __name__ == "__main__":
    unittest.main()
