"""Small offline archives preserve optional report-conflict sidecars."""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from scripts import package_t2_v2


class PackageConflictsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="t2-package-conflicts-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        for name in ("README_T2_V2.md", "SCHEMA.md", "LICENSE"):
            (self.root / name).write_text("Synthetic fixture only.\n", encoding="utf-8")
        self.run = self.root / "run"
        self.run.mkdir()
        self.summary = {
            "status": "completed", "input_count": 1, "entry_count": 0,
            "draft_count": 1, "input_failure_count": 0,
        }
        for name in ("entries.jsonl", "reports.jsonl", "review.jsonl", "actions.jsonl"):
            (self.run / name).write_text("", encoding="utf-8")
        self.destination = self.root / "small.zip"
        self.patches = patch.multiple(
            package_t2_v2, ROOT=self.root, MODULES=(), VENDOR=(), DOCS=(),
            PUBLIC_INPUT_FILES=(),
        )
        self.patches.start()
        self.addCleanup(self.patches.stop)

    def build(self):
        (self.run / "summary.json").write_text(json.dumps(self.summary), encoding="utf-8")
        return package_t2_v2.build(self.destination, [self.run])

    def test_packages_existing_conflict_file_verbatim(self):
        self.summary["report_conflict_count"] = 1
        body = b'{"report_id":"GHSA-2222-3333-4444","conflicts":["commit"]}\n'
        (self.run / "report_conflicts.jsonl").write_bytes(body)
        self.build()
        with zipfile.ZipFile(self.destination) as archive:
            self.assertEqual(archive.read("examples/run-01/report_conflicts.jsonl"), body)

    def test_legacy_run_does_not_require_conflict_file(self):
        self.build()
        with zipfile.ZipFile(self.destination) as archive:
            self.assertIn("examples/run-01/summary.json", archive.namelist())
            self.assertNotIn("examples/run-01/report_conflicts.jsonl", archive.namelist())
            self.assertIn("scripts/smoke_t2_v2.py", archive.namelist())

    def test_archive_write_failure_does_not_publish_partial_destination(self):
        with patch.object(zipfile.ZipFile, "writestr", side_effect=OSError("Synthetic disk full")):
            with self.assertRaises(OSError):
                self.build()
        self.assertFalse(self.destination.exists())
        self.assertEqual(list(self.root.glob("t2-package-*")), [])

    def test_archive_publication_preserves_existing_destination(self):
        self.destination.write_bytes(b"keep existing output")
        with self.assertRaises(FileExistsError):
            self.build()
        self.assertEqual(self.destination.read_bytes(), b"keep existing output")
        self.assertEqual(list(self.root.glob("t2-package-*")), [])

    def test_declared_conflicts_require_the_sidecar(self):
        self.summary["report_conflict_count"] = 1
        with self.assertRaisesRegex(ValueError, "^example_report_conflicts_missing$"):
            self.build()
        self.assertFalse(self.destination.exists())
        with patch("sys.argv", ["package_t2_v2", "--output", str(self.destination),
                                "--example-run", str(self.run)]), patch("builtins.print") as printed:
            self.assertEqual(package_t2_v2.main(), 1)
        self.assertEqual(json.loads(printed.call_args.args[0])["code"],
                         "example_report_conflicts_missing")
        self.assertFalse(self.destination.exists())


if __name__ == "__main__":
    unittest.main()
