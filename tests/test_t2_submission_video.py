"""Bounded, offline demo identity checks; no application or submission build."""
from __future__ import annotations

import hashlib
from pathlib import Path
import tempfile
import unittest

from scripts import package_t2_submission as submission


class SubmissionVideoTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="t2-submission-video-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        readme = b"Open demo/T2-demo.mp4; the video is supplied as-is.\n"
        self.contents = {
            "README.md": readme,
            "README_START.md": readme,
            "ENGINEERING_README.md": b"Preserve the engineering guide.\n",
            "demo/T2-five-minute-replay.webm": b"old montage",
            "demo/T2-demo.mp4": b"previous recording",
            "demo/README.md": b"Keep non-video documentation.\n",
        }

    def install(self, name, data):
        video = self.root / name
        video.write_bytes(data)
        return submission.install_demo(self.contents, video)

    def test_mp4_keeps_bytes_and_container_extension(self):
        data = b"\x00\x00\x00\x18ftypisom\x00\x00\x00\x00isommp42" + bytes(range(256))
        metadata = self.install("vulngym t2演示.MP4", data)
        self.assertEqual(metadata, {
            "path": "demo/T2-demo.mp4", "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "source_filename": "vulngym t2演示.MP4", "transcoded": False,
        })
        self.assertEqual(self.contents[metadata["path"]], data)
        self.assertNotIn("demo/T2-five-minute-replay.webm", self.contents)
        self.assertEqual([name for name in self.contents if name.endswith((".mp4", ".webm"))],
                         ["demo/T2-demo.mp4"])
        self.assertEqual(self.contents["demo/README.md"], b"Keep non-video documentation.\n")
        self.assertEqual(self.contents["ENGINEERING_README.md"], b"Preserve the engineering guide.\n")

    def test_legacy_webm_updates_both_readmes_and_removes_old_video(self):
        data = b"\x1a\x45\xdf\xa3" + b"synthetic WebM fixture"
        metadata = self.install("old-replay.webm", data)
        self.assertEqual(metadata["path"], "demo/T2-demo.webm")
        self.assertEqual(self.contents[metadata["path"]], data)
        self.assertEqual([name for name in self.contents if name.endswith((".mp4", ".webm"))],
                         ["demo/T2-demo.webm"])
        for name in ("README.md", "README_START.md"):
            self.assertIn(b"demo/T2-demo.webm", self.contents[name])
            self.assertNotIn(b"demo/T2-demo.mp4", self.contents[name])

    def test_invalid_input_does_not_mutate_package_contents(self):
        for name, data, error in (
            ("unsupported.mov", b"fixture", "unsupported_demo_video_extension"),
            ("empty.mp4", b"", "empty_demo_video"),
            ("mislabeled.webm", b"\x00\x00\x00\x18ftypisom", "demo_video_container_extension_mismatch"),
            ("mislabeled.mp4", b"\x1a\x45\xdf\xa3fixture", "demo_video_container_extension_mismatch"),
        ):
            with self.subTest(name=name):
                before = dict(self.contents)
                with self.assertRaisesRegex(ValueError, "^" + error + "$"):
                    self.install(name, data)
                self.assertEqual(self.contents, before)

    def test_current_start_guide_uses_new_demo_without_montage_claim(self):
        guide = (submission.ROOT / "README_START.md").read_text(encoding="utf-8")
        self.assertIn("demo/T2-demo.mp4", guide)
        self.assertNotIn("T2-five-minute-replay.webm", guide)
        self.assertNotIn("五分钟字幕回放", guide)
        self.assertIn("demo_video", guide)


if __name__ == "__main__":
    unittest.main()
