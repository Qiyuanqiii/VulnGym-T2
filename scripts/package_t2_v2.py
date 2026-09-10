"""Build a small explicit T2 source/demo archive, excluding the legacy tree."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import zipfile


ROOT = Path(__file__).resolve().parents[1]
MODULES = ("__init__", "__main__", "cli", "intake", "llm", "output", "pending", "pipeline", "protocol", "repository", "report", "review_export", "source_refs", "transport")
VENDOR = ("__init__", "bounded_process", "git_repository", "models", "schema_adapter")
DOCS = ("t2_v2_design", "t2_v2_demo", "t2_v2_packaging", "t2_v2_iteration_history", "t2_v2_results", "t2_goals", "t2_case_notes", "t2_v41_results")
PUBLIC_RESULTS = ("entries.jsonl", "reports.jsonl", "review.jsonl", "actions.jsonl", "summary.json", "assessment.md")
PUBLIC_INPUT_FILES = (
    "README.md", "urls.txt", "repo-map.example.json",
    "cache/GHSA-JP4J-Q5FC-58GV.json", "cache/GHSA-8C4J-F57C-35CF.json",
    "cache/GHSA-MQ4R-H2GH-QV7X.json", "cache/GHSA-CM35-V4VP-5XVX.json",
    "v41/full-urls.txt", "v41/reduced-inputs.example.jsonl",
    "v41/strict-targeted-inputs.example.jsonl",
    "v41/GHSA-8C4J-F57C-35CF.json", "v41/GHSA-MQ4R-H2GH-QV7X.json",
)


def build(destination: Path, example_runs: list[Path], design_pdf: Path | None = None):
    sources = {f"vulngym_t2/{name}.py": ROOT / "vulngym_t2" / f"{name}.py" for name in MODULES}
    sources.update({f"vulngym_t2/_vendor/{name}.py": ROOT / "vulngym_t2" / "_vendor" / f"{name}.py" for name in VENDOR})
    sources.update({f"docs/{name}.md": ROOT / "docs" / f"{name}.md" for name in DOCS})
    sources.update({f"examples/t2_v2_input/{name}": ROOT / "examples" / "t2_v2_input" / name
                    for name in PUBLIC_INPUT_FILES})
    sources.update({name: ROOT / name for name in ("SCHEMA.md", "LICENSE")})
    readme = ROOT / "README_T2_V2.md"
    if not readme.is_file():
        # A delivered archive names the product README simply README.md. Permit
        # re-packaging that layout, but not an arbitrary old project README.
        delivery = ROOT / "DELIVERY.json"
        if not delivery.is_file() or json.loads(delivery.read_text(encoding="utf-8")).get("product") != "VulnGym T2 v2":
            raise ValueError("product_readme_missing")
        readme = ROOT / "README.md"
    sources["README.md"] = readme
    sources["scripts/package_t2_v2.py"] = Path(__file__).resolve()
    if design_pdf is not None:
        sources["docs/T2-design.pdf"] = design_pdf
    for path in sorted((ROOT / "tests").glob("test_t2_v2_*.py")):
        sources[f"tests/{path.name}"] = path
    # No ledgers, raw transcripts, keys, local Git objects, target repositories,
    # private benchmark data, legacy code or unselected output trees enter here.
    for index, directory in enumerate(example_runs, 1):
        summary = json.loads((directory / "summary.json").read_text(encoding="utf-8"))
        if (not isinstance(summary, dict) or not isinstance(summary.get("status"), str)
                or summary["status"] in {"running", "started", "pending", "in_progress"}
                or any(type(summary.get(field)) is not int or summary[field] < 0
                       for field in ("input_count", "entry_count", "draft_count", "input_failure_count"))
                or summary["input_count"] != summary["entry_count"] + summary["draft_count"] + summary["input_failure_count"]
                or not all((directory / name).is_file() for name in PUBLIC_RESULTS[:-1])):
            raise ValueError("example_run_not_finalized")
        for name in PUBLIC_RESULTS:
            path = directory / name
            if path.is_file():
                sources[f"examples/run-{index:02d}/{name}"] = path
    total = 0
    contents = {}
    for name, path in sources.items():
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"missing_or_linked_source:{name}")
        total += path.stat().st_size
        if total > 30_000_000:
            raise ValueError("explicit_package_over_30mb")
        data = path.read_bytes()
        contents[name] = data
    if not destination.parent.is_dir():
        raise ValueError("package_parent_missing")
    with zipfile.ZipFile(destination, "x", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in sorted(contents.items()):
            archive.writestr(name, data)
        archive.writestr("tests/__init__.py", "")
        archive.writestr(".gitignore", "__pycache__/\n*.py[cod]\n.env\n.env.*\nruns/\n*.lock\nrequests.jsonl\n")
        archive.writestr("DELIVERY.json", json.dumps({"product": "VulnGym T2 v2", "runtime": "Python standard library + Git; no third-party Python packages", "packaging_python": sys.version.split()[0], "runtime_source_files": sorted(name for name in sources if name.startswith("vulngym_t2/")), "source_files": len(sources), "example_runs": len(example_runs), "human_verified": False, "evaluation_note": "Examples preserve their actual completed/error/draft status. They are overlapping development runs, not blind accuracy measurements. V4.1 Flash full-input and reduced-input diagnostics, observed prose improvements and remaining failures are documented in docs/t2_v41_results.md. Offline exports do not change model or human verification status. See docs/t2_case_notes.md for older narrative corrections; docs/T2-design.pdf is the initial delivery snapshot."}, ensure_ascii=False, indent=2))
    return {"status": "packaged", "files": len(sources) + 3, "uncompressed_bytes": total,
            "archive_bytes": destination.stat().st_size, "example_runs": len(example_runs)}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--example-run", type=Path, action="append", default=[])
    p.add_argument("--design-pdf", type=Path, help="optional rendered short design PDF")
    args = p.parse_args()
    try:
        print(json.dumps(build(args.output, args.example_run, args.design_pdf)))
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        # Source file identities may be printed; raw model/provider material may not.
        print(json.dumps({"status": "package_failed", "code": type(exc).__name__}))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
