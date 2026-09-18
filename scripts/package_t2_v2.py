"""Build a small explicit T2 source/demo archive, excluding the legacy tree."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile
import zipfile


ROOT = Path(__file__).resolve().parents[1]
MODULES = (
    "__init__", "__main__", "acquisition", "annotation_rules", "candidate_navigation", "cli", "completion_json",
    "entry_navigation", "evidence_context", "evidence_focus", "evidence_navigation", "imported_call_navigation", "intake", "llm", "multi_entry",
    "output", "pending", "pipeline", "prompt_evidence", "protocol", "read_plan_protocol",
    "repository", "report", "review_export", "revision_navigation",
    "source_refs", "staged_protocol", "support_consistency", "transport", "web", "web_runtime", "web_portable",
)
VENDOR = ("__init__", "bounded_process", "git_repository", "models", "schema_adapter")
DOCS = (
    "t2_v2_design", "t2_v2_demo", "t2_v2_packaging", "t2_v2_iteration_history", "t2_v2_results",
    "t2_goals", "t2_case_notes", "t2_v41_results", "t2_annotation_contract", "t2_web_gui",
    "t2_mentor_gap_20260911", "t2_saved_evidence_review_20260911", "t2_robustness_20260911",
    "t2_active_repair_20260911", "t2_evidence_repair_20260911", "t2_guidance_repair_20260911",
    "t2_snapshot_v2_retest_20260911", "t2_support_consistency_20260911",
    "t2_cross_project_20260912", "t2_real_retest_20260912",
    "t2_closeout_20260913", "t2_closeout_content_review_20260913",
    "t2_representative_validation_20260913", "t2_representative_content_review_20260913",
    "t2_representative_airflow_v75_review_20260913", "t2_representative_airflow_v76_review_20260913",
    "t2_representative_airflow_v77_review_20260913", "t2_representative_airflow_v78_review_20260913",
    "t2_representative_airflow_v79_review_20260913",
    "t2_representative_chain_review_20260913", "t2_representative_chain_v73_review_20260913",
    "t2_representative_chain_v78_review_20260913", "t2_representative_chain_v79_review_20260913",
    "t2_representative_chain_v80_review_20260914",
    "t2_representative_crawler_review_20260913", "t2_representative_langchain_v75_review_20260913",
    "t2_representative_new_cases_review_20260913", "t2_representative_nltk_review_20260913",
    "t2_representative_nltk_v73_review_20260913", "t2_representative_nltk_v78_review_20260913",
    "t2_representative_nltk_v79_review_20260913", "t2_representative_nltk_v80_review_20260914",
    "t2_representative_regression_v72_review_20260913", "t2_representative_regression_v73_review_20260913",
    "t2_representative_regression_v74_review_20260913", "t2_representative_sql_v73_review_20260913",
    "t2_representative_sql_v79_review_20260913",
    "t2_encoding_budget_note_20260913", "t2_reading_strategy_note_20260914",
    "t2_representative_airflow_v81_review_20260914", "t2_representative_sql_v81_review_20260914",
    "t2_representative_nltk_v81_review_20260914", "t2_representative_chain_v81_review_20260914",
    "t2_representative_nltk_v83_review_20260914", "t2_representative_sql_v83_review_20260914",
    "t2_representative_airflow_v83_review_20260914",
    "t2_representative_nltk_v84_review_20260914", "t2_review_gap_loop", "t2_url_batch_20260914",
)
EVALUATION_NOTE = (
    "Examples preserve each run's recorded configuration, implementation version and completed/error/draft status. "
    "They are overlapping development runs, not blind accuracy measurements or human-approved labels. "
    "Packaging and offline exports do not upgrade historical runs to results of the packaged implementation. "
    "Consult docs/t2_representative_validation_20260913.md and the linked per-run reviews for current evidence, "
    "configuration differences and remaining gaps; older diagnostics are in docs/t2_v41_results.md and "
    "docs/t2_case_notes.md. The optional docs/T2-design.pdf is the explicitly supplied design document; "
    "read its own version and date rather than treating it as a quality acceptance certificate. "
    "source_files and example_runs describe this actual archive, not test coverage or extraction accuracy."
)
PUBLIC_RESULTS = ("entries.jsonl", "reports.jsonl", "review.jsonl", "actions.jsonl", "summary.json", "assessment.md")
OPTIONAL_PUBLIC_RESULTS = ("report_conflicts.jsonl", "drafts.jsonl")
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
    sources.update({f"vulngym_t2/web_assets/{name}": ROOT / "vulngym_t2" / "web_assets" / name
                    for name in ("index.html", "app.css", "app.js",
                                 "brand/vulngym.png", "brand/README.md",
                                 "fonts/jetbrains-mono-latin-wght-normal.woff2",
                                 "fonts/OFL.txt", "fonts/README.md") if "web" in MODULES})
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
    sources["scripts/smoke_t2_v2.py"] = Path(__file__).resolve().with_name("smoke_t2_v2.py")
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
                or not all((directory / name).is_file() for name in PUBLIC_RESULTS[:-1])):
            raise ValueError("example_run_not_finalized")
        if "counting_version" in summary:
            # Script entry point must also work without an installed package.
            from importlib import import_module
            sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
            try:
                reader = import_module("vulngym_t2.review_export")
            finally:
                sys.path.pop(0)
            root = directory.resolve()
            reviews = reader._rows(reader._read(root, "review.jsonl"), max_records=reader.MAX_MULTI_RECORDS)
            entries = reader._rows(reader._read(root, "entries.jsonl"), max_records=reader.MAX_MULTI_RECORDS)
            reader._validate(summary, entries, reviews)
        elif summary["input_count"] != summary["entry_count"] + summary["draft_count"] + summary["input_failure_count"]:
            raise ValueError("example_run_not_finalized")
        conflict_count = summary.get("report_conflict_count", 0)
        if type(conflict_count) is not int or conflict_count < 0:
            raise ValueError("example_run_not_finalized")
        if conflict_count > 0 and not (directory / "report_conflicts.jsonl").is_file():
            raise ValueError("example_report_conflicts_missing")
        for name in PUBLIC_RESULTS + OPTIONAL_PUBLIC_RESULTS:
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
    # Publish only a fully closed archive. A same-filesystem hard link is an
    # atomic no-overwrite operation; interruption leaves no misleading final ZIP.
    # The context removes only this newly created, precisely scoped directory.
    with tempfile.TemporaryDirectory(prefix="t2-package-", dir=destination.parent) as staging:
        pending = Path(staging) / "archive.zip"
        with zipfile.ZipFile(pending, "x", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, data in sorted(contents.items()):
                archive.writestr(name, data)
            archive.writestr("tests/__init__.py", "")
            archive.writestr(".gitignore", "__pycache__/\n*.py[cod]\n.env\n.env.*\nruns/\n*.lock\nrequests.jsonl\n")
            archive.writestr("DELIVERY.json", json.dumps({"product": "VulnGym T2 v2", "runtime": "Python standard library + Git; no third-party Python packages", "packaging_python": sys.version.split()[0], "runtime_source_files": sorted(name for name in sources if name.startswith("vulngym_t2/")), "source_files": len(sources), "example_runs": len(example_runs), "human_verified": False, "evaluation_note": EVALUATION_NOTE}, ensure_ascii=False, indent=2))
        os.link(pending, destination)
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
        code = ("example_report_conflicts_missing"
                if isinstance(exc, ValueError) and str(exc) == "example_report_conflicts_missing"
                else type(exc).__name__)
        print(json.dumps({"status": "package_failed", "code": code}))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
