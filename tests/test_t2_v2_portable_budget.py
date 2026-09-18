"""Portable GUI accounting tests: temporary ledgers, fake children, no HTTP."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from tests.test_t2_v2_web import FakeProcess
from vulngym_t2.llm import MAX_RUN_REQUESTS, RequestLedger
from vulngym_t2.web_portable import PortableRunManager, portable_manager
from vulngym_t2.web_runtime import Run, RunManager


class PortableBudgetTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="t2-portable-budget-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.profile = self.root / "local-profile"
        self.counter = self.profile / "requests.jsonl"
        self.child = Mock(side_effect=AssertionError("real child must not launch"))

    def manager(self, name="first-copy", *, profile=None, popen=None):
        return portable_manager(self.root / name,
                                profile=self.profile if profile is None else profile,
                                popen=self.child if popen is None else popen)

    def prepared(self, manager, run_id="synthetic"):
        folder = manager.root / run_id
        folder.mkdir()
        run = Run(run_id, folder, folder / "output", state="prepared",
                  args=["--advisory", str(folder / "synthetic.txt")])
        manager.runs[run_id] = run
        return run

    def consume(self, path, *, limit, count=1):
        """Account for synthetic completed attempts without constructing a client."""
        ledger = RequestLedger(path, limit=limit, model="deepseek-flash")
        try:
            for _ in range(count):
                number = ledger.reserve(run_id="synthetic", case_id="offline-fixture")
                ledger.finish(number, status="success", usage=None, seconds=0)
        finally:
            ledger.close()

    def settings(self, *, mode="existing", ledger=None, **values):
        self.profile.mkdir(parents=True, exist_ok=True)
        path = self.profile / "workbench.json"
        path.write_text(json.dumps({"version": 1, "mode": mode,
                                    "ledger": str(ledger or self.counter), **values}),
                        encoding="utf-8")
        return path

    def assert_launch_budget(self, launch, *, path, limit, cap, effective=None):
        launch.assert_called_once()
        args = launch.call_args.args[1]
        for flag, value in (("--request-ledger", path), ("--authorization-limit", limit),
                            ("--max-requests", cap)):
            self.assertEqual(args[args.index(flag) + 1], str(value))
        self.assertIn("--key-stdin", args)
        self.assertNotIn("--extend-authorization", args)
        self.assertFalse(launch.call_args.kwargs["preparation"])
        if effective is None:
            self.assertNotIn("--effective-request-limit", args)
        else:
            self.assertEqual(args[args.index("--effective-request-limit") + 1], str(effective))

    def test_startup_and_free_preparation_do_not_create_account_or_receive_key(self):
        calls = []

        def prepare_child(args, **kwargs):
            calls.append((args, kwargs))
            self.assertIn("--prepare-only", args)
            return FakeProcess({"status": "prepared", "inputs": [{"report_id": "synthetic"}]})

        with patch("vulngym_t2.web_portable.RequestLedger",
                   side_effect=AssertionError("free preparation must not open accounting")), \
                patch.dict(os.environ, {"DEEPSEEK_API_KEY": "synthetic-must-not-forward"}):
            manager = self.manager(popen=prepare_child)
            self.assertIsInstance(manager, PortableRunManager)
            self.assertEqual(calls, [])
            budget = manager.snapshot()["budget"]
            self.assertEqual((budget["used"], budget["pending"], budget["authorization_limit"]), (0, 0, 0))
            run_id = manager.prepare({"text": "Synthetic public advisory"})
            manager.get(run_id).worker.join(5)
            self.assertFalse(manager.get(run_id).worker.is_alive())
            self.assertEqual(manager.get(run_id).state, "prepared")
        self.assertEqual(len(calls), 1)
        args, options = calls[0]
        self.assertNotIn("--key-stdin", args)
        self.assertNotIn("--request-ledger", args)
        self.assertNotIn("DEEPSEEK_API_KEY", options["env"])
        self.assertFalse(options["shell"])
        self.assertFalse(self.profile.exists())
        self.assertFalse(self.counter.exists())
        self.assertFalse(self.counter.with_suffix(".jsonl.lock").exists())

    def test_invalid_key_confirmation_cap_and_unprepared_run_never_create_counter(self):
        manager = self.manager()
        run = self.prepared(manager)
        invalid = [("synthetic", 1, value) for value in (False, None, 1, "true")]
        invalid += [(key, 1, True) for key in (None, "", "bad key", "bad\nkey", "x" * 501)]
        invalid += [("synthetic", cap, True) for cap in (None, 0, -1, True, 1.5, "1", MAX_RUN_REQUESTS + 1)]
        with patch.object(manager, "_launch", return_value=True) as launch:
            for key, cap, confirmed in invalid:
                with self.subTest(key=key, cap=cap, confirmed=confirmed), self.assertRaises(ValueError):
                    manager.start(run.id, key, cap, confirmed)
                self.assertFalse(self.counter.exists())
                self.assertFalse(self.profile.exists())
            run.state = "error"
            with self.assertRaisesRegex(ValueError, "prepare_successfully_before_start"):
                manager.start(run.id, "synthetic", 1, True)
            launch.assert_not_called()
        self.child.assert_not_called()

    def test_first_confirmed_batch_persists_only_its_authorization_and_passes_cap(self):
        manager = self.manager()
        run = self.prepared(manager)
        secret = "synthetic-not-persisted"
        with patch.object(manager, "_launch", return_value=True) as launch:
            manager.start(run.id, secret, 3, True)
        self.assert_launch_budget(launch, path=self.counter, limit=3, cap=3)
        rows = [json.loads(line) for line in self.counter.read_bytes().splitlines()]
        self.assertEqual(rows, [{"event": "authorization", "request_limit": 3,
                                "model": "deepseek-flash", "automatic_retries": 0}])
        self.assertEqual(manager.budget()["used"], 0)
        for path in self.profile.rglob("*"):
            if path.is_file():
                self.assertNotIn(secret.encode(), path.read_bytes())
        self.child.assert_not_called()

    def test_new_package_roots_reuse_usage_and_extend_only_to_used_plus_confirmed_cap(self):
        first = self.manager()
        run = self.prepared(first)
        with patch.object(first, "_launch", return_value=True):
            first.start(run.id, "synthetic", 3, True)
        self.consume(self.counter, limit=3, count=2)
        original = self.counter.read_bytes()
        second = self.manager("second-unzip")
        self.assertEqual(second.ledger, first.ledger)
        self.assertEqual(second.budget()["used"], 2)
        self.assertEqual(self.counter.read_bytes(), original)
        run = self.prepared(second)
        with patch.object(second, "_launch", return_value=True) as launch:
            second.start(run.id, "synthetic", 4, True)
        self.assert_launch_budget(launch, path=self.counter, limit=6, cap=4)
        extended = self.counter.read_bytes()
        self.assertTrue(extended.startswith(original))
        self.assertEqual(json.loads(extended.splitlines()[-1]), {
            "event": "authorization_extended", "previous_limit": 3,
            "request_limit": 6, "requests_used": 2})
        third = self.manager("third-unzip")
        run = self.prepared(third)
        with patch.object(third, "_launch", return_value=True) as launch:
            third.start(run.id, "synthetic", 1, True)
        self.assert_launch_budget(launch, path=self.counter, limit=6, cap=1)
        self.assertEqual(third.budget()["used"], 2)
        self.assertEqual(self.counter.read_bytes(), extended)
        self.child.assert_not_called()

    def test_corrupt_incomplete_pending_and_invalid_contract_counters_are_never_overwritten(self):
        header = {"event": "authorization", "request_limit": 3,
                  "model": "deepseek-flash", "automatic_retries": 0}
        valid = (json.dumps(header) + "\n").encode()
        cases = {
            "empty": b"",
            "corrupt": b"not-json\n",
            "partial-line": valid + b'{"event":',
            "missing-newline": valid.rstrip(b"\n"),
            "non-object": valid + b"[]\n",
            "pending": valid + b'{"event":"http_started","request":1}\n',
            "invalid-header-contract": (json.dumps({**header, "automatic_retries": 1}) + "\n").encode(),
            "invalid-extension-contract": valid + b'{"event":"authorization_extended","request_limit":4}\n',
        }
        for name, original in cases.items():
            with self.subTest(case=name):
                profile = self.root / name
                profile.mkdir()
                counter = profile / "requests.jsonl"
                counter.write_bytes(original)
                manager = self.manager(name + "-package", profile=profile)
                run = self.prepared(manager)
                with patch.object(manager, "_launch", return_value=True) as launch:
                    with self.assertRaises(ValueError):
                        manager.start(run.id, "synthetic", 2, True)
                    launch.assert_not_called()
                self.assertEqual(counter.read_bytes(), original)
                self.assertEqual(run.state, "prepared")
                if name == "pending":
                    self.assertEqual(manager.budget()["used"], 1)
                    self.assertEqual(manager.budget()["pending"], 1)
        self.child.assert_not_called()

    def test_fixed_original_profile_preserves_3000_2999_1_and_never_extends(self):
        self.profile.mkdir()
        self.consume(self.counter, limit=3000, count=2)
        settings = self.settings(limit=3000, effective_limit=2999, historical_requests=1)
        original, configuration = self.counter.read_bytes(), settings.read_bytes()
        manager = self.manager()
        self.assertIs(type(manager), RunManager)
        budget = manager.budget()
        self.assertEqual((budget["authorization_limit"], budget["effective_authorization_limit"],
                          budget["limit"], budget["used"], budget["remaining"]),
                         (3000, 2999, 3000, 3, 2997))
        run = self.prepared(manager)
        with patch.object(manager, "_launch", return_value=True) as launch:
            manager.start(run.id, "synthetic", 3, True)
        self.assert_launch_budget(launch, path=self.counter, limit=3000, cap=3, effective=2999)
        self.assertEqual(self.counter.read_bytes(), original)
        self.assertEqual(settings.read_bytes(), configuration)
        reopened = self.manager("another-fixed-copy")
        self.assertEqual(reopened.budget(), budget)
        self.assertEqual(reopened.ledger, manager.ledger)
        self.assertEqual(self.counter.read_bytes(), original)
        self.child.assert_not_called()

    def test_fixed_profile_rejects_cap_above_effective_remaining_without_extension(self):
        self.profile.mkdir()
        self.consume(self.counter, limit=3000, count=2)
        # A narrowed fixture makes the remaining-cap boundary cheap to exercise.
        self.settings(limit=3000, effective_limit=3, historical_requests=1)
        manager = self.manager()
        run = self.prepared(manager)
        original = self.counter.read_bytes()
        with patch.object(manager, "_launch", return_value=True) as launch:
            with self.assertRaisesRegex(ValueError, "request_cap_exceeds_remaining"):
                manager.start(run.id, "synthetic", 2, True)
            launch.assert_not_called()
            manager.start(run.id, "synthetic", 1, True)
        self.assert_launch_budget(launch, path=self.counter, limit=3000, cap=1, effective=3)
        self.assertEqual(self.counter.read_bytes(), original)
        self.consume(self.counter, limit=3000)
        reopened = self.manager("exhausted-copy")
        run = self.prepared(reopened)
        original = self.counter.read_bytes()
        self.assertEqual(reopened.budget()["remaining"], 0)
        with patch.object(reopened, "_launch", return_value=True) as launch:
            with self.assertRaisesRegex(ValueError, "request_cap_exceeds_remaining"):
                reopened.start(run.id, "synthetic", 1, True)
            launch.assert_not_called()
        self.assertEqual(self.counter.read_bytes(), original)

    def test_profile_referencing_missing_counter_fails_instead_of_resetting_usage(self):
        for mode in ("managed", "existing"):
            with self.subTest(mode=mode):
                settings = self.settings(mode=mode, limit=3000, effective_limit=2999,
                                         historical_requests=1)
                original = settings.read_bytes()
                with self.assertRaisesRegex(ValueError, "managed_usage_unavailable"):
                    self.manager(mode + "-missing-copy")
                self.assertEqual(settings.read_bytes(), original)
                self.assertFalse(self.counter.exists())
                self.assertFalse(self.counter.with_suffix(".jsonl.lock").exists())
        self.child.assert_not_called()

    def test_newly_authorized_counter_is_pinned_and_missing_file_cannot_reset_next_copy(self):
        first = self.manager()
        run = self.prepared(first)
        with patch.object(first, "_launch", return_value=True):
            first.start(run.id, "synthetic", 3, True)
        self.consume(self.counter, limit=3)
        settings = self.profile / "workbench.json"
        original_settings = settings.read_bytes()
        self.assertEqual(json.loads(original_settings), {
            "version": 1, "mode": "managed", "ledger": str(self.counter)})
        self.assertEqual(first.budget()["used"], 1)
        # Remove only this test's temporary accounting fixture, never user data.
        self.assertTrue(self.counter.resolve().is_relative_to(self.root))
        self.counter.unlink()
        self.assertFalse(first.budget()["available"])
        self.assertEqual(first.budget()["code"], "managed_usage_unavailable")
        with self.assertRaisesRegex(ValueError, "managed_usage_unavailable"):
            self.manager("new-copy-after-missing-counter")
        self.assertFalse(self.counter.exists())
        self.assertEqual(settings.read_bytes(), original_settings)
        self.child.assert_not_called()

    def test_legacy_package_counter_is_pinned_and_reused_across_unzip_roots(self):
        previous = self.root / "old-copy" / "data" / "own-requests.jsonl"
        previous.parent.mkdir(parents=True)
        self.consume(previous, limit=4, count=1)
        original = previous.read_bytes()
        first = self.manager("old-copy")
        self.assertEqual(first.ledger, previous)
        self.assertEqual(first.budget()["used"], 1)
        second = self.manager("new-copy")
        self.assertEqual(second.ledger, previous)
        self.assertEqual(second.budget()["used"], 1)
        self.assertEqual(previous.read_bytes(), original)
        self.assertFalse(self.counter.exists())
        self.child.assert_not_called()


if __name__ == "__main__":
    unittest.main()
