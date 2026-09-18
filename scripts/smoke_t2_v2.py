"""Run offline fault-injection smoke checks; never discover a key or call HTTP.

Uses only temporary synthetic Git/source/material fixtures and a model transport
stand-in. Passing is an engineering check, not a real-model accuracy result.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys
import unittest


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--temp-root", type=Path, help="existing temporary parent; defaults to the D: runtime temp directory on Windows")
    args = parser.parse_args(argv)
    previous_temp_root = os.environ.get("T2_SMOKE_TEMP_ROOT")
    if args.temp_root is not None:
        parent = args.temp_root.resolve()
        if not parent.is_dir():
            parser.error("--temp-root must be an existing directory")
        os.environ["T2_SMOKE_TEMP_ROOT"] = str(parent)
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    try:
        suite = unittest.defaultTestLoader.loadTestsFromName("tests.test_t2_v2_resilience_smoke")
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        # A missing Git installation skips the fixture tests under discovery,
        # but an explicit smoke invocation must not report an untested success.
        return 0 if result.wasSuccessful() and not result.skipped else 1
    finally:
        sys.path.pop(0)
        if args.temp_root is not None:
            if previous_temp_root is None:
                os.environ.pop("T2_SMOKE_TEMP_ROOT", None)
            else:
                os.environ["T2_SMOKE_TEMP_ROOT"] = previous_temp_root


if __name__ == "__main__":
    raise SystemExit(main())
