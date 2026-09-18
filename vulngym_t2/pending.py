"""Export an unstarted URL-list suffix from a cleanly stopped public batch.

This is an offline input-list operation, not checkpoint recovery or permission
to make another request. It never loads advisory caches, repositories, provider
clients, credentials or request ledgers. Changed source material is not checked.
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import re

from .review_export import _input_reviews, _float


MAX_INPUT_BYTES = 4 * 1024 * 1024
MAX_PUBLIC_BYTES = 20_000_000
MAX_INPUTS = 500
_GHSA = r"GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}"
_URL = re.compile(
    r"https://github\.com/(?:advisories/|[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/security/advisories/)"
    + f"(?P<report>{_GHSA})/?", re.I)
_ENTRY = re.compile(r"entry-[0-9]{5}")


def _local(path: str | Path) -> Path:
    value = str(path)
    if "://" in value or value.startswith(("\\\\", "//")):
        raise ValueError("pending_local_path_required")
    return Path(path)


def _read(path: Path, limit: int, label: str) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"pending_{label}_unavailable")
    try:
        with path.open("rb") as stream:
            value = stream.read(limit + 1)
    except OSError as error:
        raise ValueError(f"pending_{label}_unreadable") from error
    if len(value) > limit:
        raise ValueError(f"pending_{label}_too_large")
    return value


def _text(raw: bytes, label: str) -> str:
    try:
        return raw.decode("utf-8-sig", errors="strict")
    except UnicodeError as error:
        raise ValueError(f"pending_{label}_not_utf8") from error


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate_json_key")
        value[key] = item
    return value


def _reject_constant(value):
    raise ValueError("nonstandard_json_constant")


def _json_object(text: str, label: str) -> dict:
    try:
        value = json.loads(text, object_pairs_hook=_unique_object,
                           parse_constant=_reject_constant, parse_float=_float)
    except (ValueError, RecursionError) as error:
        raise ValueError(f"pending_{label}_json_invalid") from error
    if not isinstance(value, dict):
        raise ValueError(f"pending_{label}_object_required")
    return value


def _urls(path: Path, *, allow_repeated_reports: bool = False) -> list[dict]:
    rows, seen = [], set()
    for line in _text(_read(path, MAX_INPUT_BYTES, "input"), "input").splitlines():
        url = line.strip()
        if not url or url.startswith("#"):
            continue
        match = _URL.fullmatch(url)
        if match is None:
            raise ValueError("pending_ghsa_url_list_required")
        report_id = match["report"].upper()
        if report_id in seen and not allow_repeated_reports:
            raise ValueError("pending_duplicate_input_report_id")
        seen.add(report_id)
        rows.append({"input_index": len(rows) + 1, "report_id": report_id, "source_link": url})
        if len(rows) > MAX_INPUTS:
            raise ValueError("pending_input_limit_exceeded")
    if not rows:
        raise ValueError("pending_input_empty")
    return rows


def plan_pending(input_path: str | Path, run_dir: str | Path) -> dict:
    """Prove a processed GHSA prefix, returning only public input identities.

    Every saved input, including provider-failure drafts and input failures,
    counts as processed once, regardless of candidate count. An unfinished run is refused:
    its next item may already have issued a request without a durable review.
    The input is the original URL list, not a filtered or reordered replacement.
    """
    root = _local(run_dir).resolve()
    summary_raw = _read(root / "summary.json", min(MAX_PUBLIC_BYTES, 1024 * 1024), "summary")
    summary = _json_object(_text(summary_raw, "summary"), "summary")
    rows = _urls(_local(input_path), allow_repeated_reports=summary.get("counting_version") == "input-review-v2")
    status = summary.get("status")
    if not isinstance(status, str) or status not in {"completed", "completed_with_errors", "provider_stopped"}:
        raise ValueError("pending_run_boundary_uncertain")
    review_raw = _read(root / "review.jsonl", MAX_PUBLIC_BYTES - len(summary_raw), "review")
    reviews = [_json_object(line, "review")
               for line in _text(review_raw, "review").splitlines() if line.strip()]
    if "counting_version" in summary:
        return _plan_multi(rows, summary, reviews)
    expected = {"requested_input_count": len(rows), "input_count": len(reviews),
                "unprocessed_input_count": len(rows) - len(reviews)}
    if len(reviews) > len(rows) or any(
            type(summary.get(key)) is not int or summary[key] != value
            for key, value in expected.items()):
        raise ValueError("pending_summary_count_mismatch")
    if status in {"completed", "completed_with_errors"} and len(reviews) != len(rows):
        raise ValueError("pending_completed_run_has_unprocessed_inputs")

    seen_reports, seen_entries, counts = set(), set(), Counter()
    for index, review in enumerate(reviews):
        report_id, entry_id = review.get("report_id"), review.get("entry_id")
        if not isinstance(report_id, str) or not isinstance(entry_id, str) or not _ENTRY.fullmatch(entry_id):
            raise ValueError("pending_review_identity_invalid")
        if report_id in seen_reports or entry_id in seen_entries:
            raise ValueError("pending_duplicate_review_id")
        seen_reports.add(report_id)
        seen_entries.add(entry_id)
        expected_report = rows[index]["report_id"]
        # Intake emits this canonical public URL for both supported URL forms.
        expected_source = "https://github.com/advisories/GHSA-" + expected_report[5:].lower()
        if report_id != expected_report or review.get("source_link") != expected_source:
            raise ValueError("pending_processed_prefix_mismatch")
        review_status = review.get("status")
        if not isinstance(review_status, str) or review_status not in {"complete", "draft", "input_failure"}:
            raise ValueError("pending_review_status_invalid")
        counts[review_status] += 1
    expected_counts = {"candidate_count": counts["complete"], "entry_count": counts["complete"],
                       "schema_entry_count": counts["complete"], "draft_count": counts["draft"],
                       "input_failure_count": counts["input_failure"]}
    if any(type(summary.get(key)) is not int or summary[key] != value
           for key, value in expected_counts.items()):
        raise ValueError("pending_summary_status_count_mismatch")
    return {"status": "pending_ready", "source_status": status, "http_attempts": 0,
            "requested_input_count": len(rows), "processed_input_count": len(reviews),
            "pending_input_count": len(rows) - len(reviews),
            "processed_by_status": {key: counts[key] for key in ("complete", "draft", "input_failure")},
            "pending": rows[len(reviews):], "requires_separate_run_authorization": True,
            "checkpoint_restored": False, "source_materials_compared": False}


def _plan_multi(rows: list[dict], summary: dict, reviews: list[dict]) -> dict:
    try:
        groups = _input_reviews(summary, reviews)
    except ValueError as error:
        raise ValueError("pending_input_review_mapping_invalid") from error
    if summary["requested_input_count"] != len(rows):
        raise ValueError("pending_summary_count_mismatch")
    for index, group in enumerate(groups):
        if not _ENTRY.fullmatch(group["input_id"]) or any(
                not _ENTRY.fullmatch(identity) for identity in group["review_entry_ids"]):
            raise ValueError("pending_review_identity_invalid")
        expected_report = rows[index]["report_id"]
        expected_source = "https://github.com/advisories/GHSA-" + expected_report[5:].lower()
        if group["report_id"] != expected_report or group["source_link"] != expected_source:
            raise ValueError("pending_processed_prefix_mismatch")
    counts = Counter(group["status"] for group in groups)
    processed = len(groups)
    return {"status": "pending_ready", "source_status": summary["status"], "http_attempts": 0,
            "counting_version": summary["counting_version"], "requested_input_count": len(rows),
            "processed_input_count": processed, "pending_input_count": len(rows) - processed,
            "review_count": len(reviews),
            "processed_by_status": {key: counts[key] for key in ("complete", "partial", "draft", "input_failure")},
            "pending": rows[processed:], "requires_separate_run_authorization": True,
            "checkpoint_restored": False, "source_materials_compared": False}


def export_pending(input_path: str | Path, run_dir: str | Path, output: str | Path) -> dict:
    """Write a new URL list only after every prefix check succeeds."""
    destination = _local(output)
    if destination.resolve().is_relative_to(_local(run_dir).resolve()):
        raise ValueError("pending_output_must_be_outside_run")
    if destination.exists() or destination.is_symlink():
        raise ValueError("pending_output_exists")
    plan = plan_pending(input_path, run_dir)
    try:
        with destination.open("x", encoding="utf-8", newline="\n") as stream:
            stream.write("".join(row["source_link"] + "\n" for row in plan["pending"]))
    except FileExistsError as error:
        raise ValueError("pending_output_exists") from error
    except OSError as error:
        raise ValueError("pending_output_write_failed") from error
    return plan


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Offline export of unstarted GHSA URLs; never retries or runs a task.")
    parser.add_argument("--input", required=True, type=Path, help="original GHSA URL list, not JSONL")
    parser.add_argument("--run-dir", required=True, type=Path, help="completed, completed_with_errors or provider_stopped run")
    parser.add_argument("--output", required=True, type=Path, help="new URL-list file outside the old run directory")
    args = parser.parse_args(argv)
    try:
        result = export_pending(args.input, args.run_dir, args.output)
    except (OSError, ValueError) as error:
        code = str(error)
        if not re.fullmatch(r"pending_[a-z_]+", code):
            code = "pending_local_operation_failed"
        print(json.dumps({"status": "error", "code": code, "http_attempts": 0}))
        return 2
    print(json.dumps(result, ensure_ascii=False, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
