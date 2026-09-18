"""Local Windows sharing contention: bounded wait, durable stop and diagnosis."""
import ctypes
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from vulngym_t2 import cli, output
from tests.test_t2_v2_output import fixture, StubRepoReader


def windows_error(number):
    error = OSError(13, "synthetic-private-path-must-not-leak")
    error.winerror = number
    return error


class OutputPublicationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="t2-output-publish-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def writer(self):
        writer = output.BatchWriter(self.root / "run")
        job, result = fixture()
        writer.record(job, output.finalize_result(job, result, StubRepoReader()))
        return writer

    def test_only_windows_32_33_receive_three_bounded_local_waits(self):
        for number in (32, 33):
            with patch.object(output.os, "name", "nt"), \
                 patch.object(output.os, "replace", side_effect=[windows_error(number)] * 3 + [None]) as replace, \
                 patch.object(output.time, "sleep") as sleep:
                output._replace_final_output("source", "target")
                self.assertEqual(replace.call_count, 4)
                self.assertEqual([call.args[0] for call in sleep.call_args_list], [0.05, 0.1, 0.2])
        for system, error in (("nt", windows_error(5)), ("nt", OSError("disk error")),
                              ("posix", windows_error(32)), ("nt", KeyboardInterrupt())):
            with patch.object(output.os, "name", system), \
                 patch.object(output.os, "replace", side_effect=error) as replace, \
                 patch.object(output.time, "sleep") as sleep, self.assertRaises(type(error)):
                output._replace_final_output("source", "target")
            self.assertEqual(replace.call_count, 1)
            sleep.assert_not_called()

    def test_exhausted_contention_preserves_originals_and_all_staging_without_summary(self):
        writer = self.writer()
        before = {p.name: p.read_bytes() for p in writer.directory.iterdir()}
        with patch.object(output.os, "replace", side_effect=windows_error(32)) as replace, \
             patch.object(output.time, "sleep"), self.assertRaises(output.OutputPublicationError) as caught:
            writer.finish({"status": "completed"})
        self.assertEqual(replace.call_count, 4 if os.name == "nt" else 1)
        self.assertEqual(str(caught.exception), "output_finalize_replace_failed")
        self.assertEqual(caught.exception.diagnostics, {"phase": "output_finalize_replace",
            "target": "entries.jsonl", "errno": 13, "winerror": 32})
        self.assertTrue(all((writer.directory / name).read_bytes() == raw for name, raw in before.items()))
        self.assertEqual(len(list(writer.directory.glob(".t2-output-*.tmp"))), 5)
        self.assertFalse((writer.directory / "summary.json").exists())
        with self.assertRaisesRegex(RuntimeError, "batch_write_failed"):
            writer.finish()

    def test_denial_and_staging_error_stop_once_and_are_sanitized(self):
        for phase in ("replace", "stage"):
            # Separate output ownership, not a retry of an already failed writer.
            writer = output.BatchWriter(self.root / phase)
            with patch.object(output.os, "replace" if phase == "replace" else "fsync", side_effect=windows_error(5)) as call, \
                 patch.object(output.time, "sleep") as sleep, self.assertRaises(output.OutputPublicationError) as caught:
                writer.finish()
            self.assertEqual(call.call_count, 1)
            sleep.assert_not_called()
            self.assertEqual(caught.exception.diagnostics["phase"], "output_finalize_" + phase)
            self.assertNotIn("synthetic-private-path", str(caught.exception) + json.dumps(caught.exception.diagnostics))

    def test_cli_reports_phase_system_error_and_safe_target_without_credentials(self):
        failure = output.OutputPublicationError("replace", "entries.jsonl", windows_error(32))
        with patch.object(cli, "load_jobs", side_effect=failure), redirect_stdout(io.StringIO()) as stdout:
            code = cli.main(["--input", "synthetic.jsonl", "--prepare-only"])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(stdout.getvalue()), {"status": "error", "code": "output_finalize_replace_failed",
            "phase": "output_finalize_replace", "target": "entries.jsonl", "errno": 13, "winerror": 32})

    @unittest.skipUnless(os.name == "nt", "Windows sharing semantics only")
    def test_actual_windows_reader_lock_can_be_access_denied_and_is_never_retried(self):
        writer = self.writer()
        # A controlled handle on our synthetic output; no process inventory or
        # user-file lock is changed. Models/network/target code are not involved.
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateFileW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32,
                                      ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p]
        kernel.CreateFileW.restype = ctypes.c_void_p
        kernel.CloseHandle.argtypes = [ctypes.c_void_p]
        kernel.CloseHandle.restype = ctypes.c_int
        handle = kernel.CreateFileW(str(writer.directory / "entries.jsonl"), 0x80000000, 1, None, 3, 0, None)
        self.assertNotEqual(handle, ctypes.c_void_p(-1).value)
        attempts, waits = [], []
        original_replace = output.os.replace
        def replace(src, dst):
            try:
                return original_replace(src, dst)
            except OSError as error:
                attempts.append(error.winerror)
                raise
        before = (writer.directory / "entries.jsonl").read_bytes()
        try:
            with (patch.object(output.os, "replace", side_effect=replace),
                  patch.object(output.time, "sleep", side_effect=waits.append),
                  self.assertRaises(output.OutputPublicationError) as caught):
                writer.finish({"status": "completed"})
            self.assertEqual(caught.exception.diagnostics["winerror"], 5)
        finally:
            kernel.CloseHandle(handle)
        self.assertEqual(attempts, [5])
        self.assertEqual(waits, [])
        self.assertEqual((writer.directory / "entries.jsonl").read_bytes(), before)
        self.assertFalse((writer.directory / "summary.json").exists())
        self.assertEqual(len(list(writer.directory.glob(".t2-output-*.tmp"))), 5)
        with self.assertRaisesRegex(RuntimeError, "batch_write_failed"):
            writer.finish()
        # A distinct synthetic writer after our own test handle is closed proves
        # normal publication; this does not resume or alter the failed writer.
        clean = output.BatchWriter(self.root / "clean")
        supplied, result = fixture()
        clean.record(supplied, output.finalize_result(supplied, result, StubRepoReader()))
        self.assertEqual(clean.finish({"status": "completed"})["candidate_count"], 1)


if __name__ == "__main__":
    unittest.main()
