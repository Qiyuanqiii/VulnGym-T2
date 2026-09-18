"""Compatibility entry point: open the web GUI, never prompt in the terminal."""
from __future__ import annotations

import sys

import launch_workbench


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    # Old start-extraction.cmd used this flag. It now simply means normal GUI.
    args = [value for value in args if value != "--extract"]
    return launch_workbench.main(args)


if __name__ == "__main__":
    raise SystemExit(main())
