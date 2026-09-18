"""Build an explicit Windows portable submission from the existing product packager."""
from __future__ import annotations

import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import tempfile
import zipfile

if __package__:
    from .package_t2_v2 import ROOT, build
else:
    from package_t2_v2 import ROOT, build


def install_demo(contents: dict[str, bytes], video: Path) -> dict:
    """Replace the demo without re-encoding or disguising its container type."""
    suffix = video.suffix.lower()
    if suffix not in {".mp4", ".webm"}:
        raise ValueError("unsupported_demo_video_extension")
    data = video.read_bytes()
    if not data:
        raise ValueError("empty_demo_video")
    # Check the container header, not the full recording or its semantic content.
    if ((suffix == ".mp4" and data[4:8] != b"ftyp")
            or (suffix == ".webm" and not data.startswith(b"\x1a\x45\xdf\xa3"))):
        raise ValueError("demo_video_container_extension_mismatch")
    archive_path = "demo/T2-demo" + suffix
    for name in list(contents):
        if name.startswith("demo/") and Path(name).suffix.lower() in {".mp4", ".webm"}:
            del contents[name]
    contents[archive_path] = data
    for name in ("README.md", "README_START.md"):
        contents[name] = re.sub(
            rb"demo/T2-(?:demo\.(?:mp4|webm)|five-minute-replay\.webm)",
            archive_path.encode("ascii"), contents[name],
        )
    return {"path": archive_path, "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "source_filename": video.name, "transcoded": False}


def package(destination, python_root, examples, design, video):
    destination = destination.resolve()
    if destination.exists() or not destination.parent.is_dir():
        raise ValueError("destination_must_be_new_in_existing_directory")
    python_root = python_root.resolve()
    with tempfile.TemporaryDirectory(prefix="submission-build-", dir=destination.parent) as temporary:
        core = Path(temporary) / "core.zip"
        build(core, examples, design)
        with zipfile.ZipFile(core) as archive:
            contents = {item.filename: archive.read(item) for item in archive.infolist()}
        for name in ("start.cmd", "start-direct.cmd", "start-extraction.cmd", "start-demo.cmd", "launch_workbench.py", "configure_launch.py", "README_START.md"):
            contents[name] = (ROOT / name).read_bytes()
        contents["ENGINEERING_README.md"] = contents["README.md"]
        contents["README.md"] = contents["README_START.md"]
        contents["tests/web_ui_interactions.cjs"] = (ROOT / "tests" / "web_ui_interactions.cjs").read_bytes()
        contents["scripts/package_t2_submission.py"] = Path(__file__).read_bytes()
        contents["tests/test_t2_submission_video.py"] = (ROOT / "tests" / "test_t2_submission_video.py").read_bytes()
        demo = install_demo(contents, video)
        demo_input_files = ("README.md", "advisory.json", "public.diff", "record.jsonl", "urls.txt")
        demo_input_root = ROOT / "examples" / "demo_nltk"
        if not demo_input_root.is_dir():
            demo_input_root = ROOT / "演示数据" / "NLTK"
        for name in demo_input_files:
            contents["演示数据/NLTK/" + name] = (demo_input_root / name).read_bytes()
        for name in ("python.exe", "python3.dll", "python313.dll", "vcruntime140.dll",
                     "vcruntime140_1.dll", "LICENSE.txt"):
            contents["runtime/python/" + name] = (python_root / name).read_bytes()
        for path in sorted((python_root / "DLLs").iterdir()):
            if (path.is_file() and path.suffix.lower() in {".dll", ".pyd", ".txt"}
                    and not path.name.startswith("_test")
                    and path.name not in {"_ctypes_test.pyd", "_tkinter.pyd", "tcl86t.dll", "tk86t.dll"}):
                contents["runtime/python/DLLs/" + path.name] = path.read_bytes()
        contents["runtime/python/THIRD_PARTY_LICENSES.html"] = (python_root / "Doc" / "html" / "license.html").read_bytes()
        stdlib = io.BytesIO()
        excluded = {"site-packages", "__pycache__", "test", "tests", "idlelib", "tkinter", "turtledemo", "ensurepip"}
        library = python_root / "Lib"
        with zipfile.ZipFile(stdlib, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for path in sorted(library.rglob("*")):
                relative = path.relative_to(library)
                if not path.is_file() or path.is_symlink() or any(part in excluded for part in relative.parts):
                    continue
                if relative.as_posix() == "turtle.py":
                    continue
                if path.suffix.lower() not in {".py", ".txt", ".pem", ".crt", ".json"}:
                    continue
                archive.write(path, relative.as_posix())
        contents["runtime/python/python313.zip"] = stdlib.getvalue()
        # Isolated search path, relative to this runtime, not the developer PC.
        contents["runtime/python/python313._pth"] = b"python313.zip\r\nDLLs\r\n.\r\n..\\..\r\n"
        for name, data in contents.items():
            if not name.startswith("runtime/") and name.endswith((".py", ".md", ".json", ".jsonl", ".txt", ".cmd")):
                if re.search(rb"sk-[A-Za-z0-9]{24,}", data):
                    raise ValueError("credential_like_literal_in_selected_text:" + name)
        manifest = {"product": "VulnGym T2", "platform": "Windows x64", "python": "3.13.12",
                    "default_mode": "web GUI with system-default download routing; each model run requires GUI confirmation",
                    "download_network_modes": {"system": "start.cmd", "direct": "start-direct.cmd"},
                    "model_requests_during_packaging": 0,
                    "demo_video": demo,
                    "demo_input": {"path": "演示数据/NLTK", "files": list(demo_input_files),
                                   "target_repository_included": False,
                                   "repository_selection": "Supply the local NLTK Git directory in the GUI."},
                    "original_billing_ledger_included": False, "target_repositories_included": False,
                    "entrypoint": "start.cmd", "files": sorted(contents),
                    "evaluation_note": "Development examples with verify=0, not blind-test accuracy or human approval."}
        contents["SUBMISSION.json"] = json.dumps(manifest, ensure_ascii=False, indent=2).encode("utf-8")
        pending = Path(temporary) / "submission.zip"
        with zipfile.ZipFile(pending, "x", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, data in sorted(contents.items()):
                archive.writestr(name, data)
        if pending.stat().st_size > 190_000_000:
            raise ValueError("submission_exceeds_upload_margin")
        with zipfile.ZipFile(pending) as archive:
            if archive.testzip() is not None:
                raise ValueError("archive_readback_failed")
        # No existing destination is overwritten.
        import os
        os.link(pending, destination)
        return {"status": "packaged", "file": str(destination), "archive_bytes": destination.stat().st_size,
                "files": len(contents), "model_requests": 0}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--python-root", type=Path, required=True)
    parser.add_argument("--example-run", type=Path, action="append", required=True)
    parser.add_argument("--design-pdf", type=Path, required=True)
    parser.add_argument("--video", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(package(args.output, args.python_root, args.example_run, args.design_pdf, args.video)))


if __name__ == "__main__":
    main()
