"""Report-first CLI: public materials and a local repository in, JSONL out."""
from __future__ import annotations

import argparse
import getpass
import json
import os
from pathlib import Path
import re
import sys
import time
from datetime import datetime, timezone

from .intake import load_jobs
from .llm import DeepSeekClient, MODEL, RequestLedger
from .output import BatchWriter, finalize_result
from .pipeline import produce
from .repository import RepoReader
from .transport import validate_model_id


def _code(exc: Exception, fallback: str) -> str:
    value = str(exc)
    return value if re.fullmatch(r"[a-z][a-z0-9_]{0,95}", value) else fallback


def _emit(value, stream=sys.stdout):
    print(json.dumps(value, ensure_ascii=False, allow_nan=False), file=stream, flush=True)


def _positive(upper):
    def parse(value):
        integer = int(value)
        if not 1 <= integer <= upper:
            raise argparse.ArgumentTypeError(f"must be between 1 and {upper}")
        return integer
    return parse


def parser():
    p = argparse.ArgumentParser(description="Extract reviewed drafts of VulnGym records from advisory material and local Git source.")
    inputs = p.add_mutually_exclusive_group(required=True)
    inputs.add_argument("--advisory", type=Path, help="local advisory file or flat material-bundle directory")
    inputs.add_argument("--input", type=Path, help="JSONL reports, or one GHSA URL per line")
    p.add_argument("--repo", type=Path, help="already cloned local target repository (never executed)")
    p.add_argument("--source-link", help="GHSA URL, otherwise inferred from the advisory")
    p.add_argument("--cache-dir", type=Path, help="cached GHSA documents for a URL-list batch")
    p.add_argument("--repo-map", type=Path, help="JSON map from report/project to local repositories")
    p.add_argument("--output", type=Path, help="new output directory; existing output is never overwritten")
    p.add_argument("--prepare-only", action="store_true", help="check materials and repositories without credentials or HTTP")
    p.add_argument("--request-ledger", type=Path, help="persistent shared HTTP budget file; reuse it for every authorized run")
    p.add_argument("--authorization-limit", type=_positive(500), default=500)
    p.add_argument("--max-requests", type=_positive(500), default=80, help="HTTP ceiling for this run, not a target")
    p.add_argument("--max-calls-per-report", type=_positive(16), default=8)
    p.add_argument("--max-tool-calls", type=_positive(64), default=24)
    p.add_argument("--max-tokens", type=_positive(32768), default=8192)
    p.add_argument("--model", type=validate_model_id, default=MODEL,
                   help="exact authorized DeepSeek model ID; no alias substitution or automatic fallback")
    p.add_argument("--response-mode", choices=("json", "strict_tool"), default="json",
                   help="json compatibility mode or explicit beta strict function-output mode")
    p.add_argument("--stop-on-format-error", action="store_true",
                   help="stop the whole batch on a malformed answer instead of continuing only unstarted inputs")
    p.add_argument("--reasoning-effort", choices=("low", "high", "max"), default="high")
    p.add_argument("--timeout", type=_positive(300), default=300)
    p.add_argument("--key-stdin", action="store_true", help="read one key line from a pipe (never a terminal); otherwise env or hidden prompt")
    return p


def prepare(jobs):
    """Cheap local preflight; errors remain attached to their input, not dropped."""
    readers = {}
    checks = []
    for index, job in enumerate(jobs):
        info = None
        if not job.get("input_error"):
            try:
                reader = RepoReader(job["repo_path"])
                info = reader.info()
                readers[index] = reader
                if not job.get("repo_url") and info.get("repo_url"):
                    job["repo_url"] = info["repo_url"]
            except Exception as exc:
                job["input_error"] = _code(exc, "repository_unavailable")
        checks.append({"report_id": job.get("report_id"), "entry_id": job.get("entry_id"),
                       "document_count": len(job.get("documents", [])),
                       "fix_candidates": len(job.get("fix_commits", [])),
                       "repo_available": info is not None, "input_error": job.get("input_error")})
    return readers, checks


def run_batch(jobs, readers, client, output, *, max_calls=8, max_tool_calls=24,
              continue_on_format_error=True):
    """One job at a time; persist each finished job before moving to the next."""
    writer = BatchWriter(output)
    started = time.monotonic()
    processed = 0
    case_failures = []
    status, exit_code = "completed", 0
    try:
        for index, job in enumerate(jobs):
            case_id = job.get("report_id", f"input-{index + 1}")
            start_case = getattr(client, "start_next_case", None)
            if client.halted:
                if (continue_on_format_error and case_failures and callable(start_case)
                        and getattr(client, "can_continue_after_format_error", False) is True
                        and start_case(case_id, continue_on_format_error=True)):
                    case_failures[-1]["continued"] = True
                    _emit({"event": "format_failure_isolated", **case_failures[-1],
                           "next_report_id": case_id}, sys.stderr)
                else:
                    status, exit_code = "provider_stopped", 2
                    break
            elif callable(start_case):
                start_case(case_id)
            else:
                client.case_id = case_id
            _emit({"event": "report_started", "index": index + 1, "total": len(jobs),
                   "report_id": client.case_id}, sys.stderr)
            repo = readers.get(index)
            if job.get("input_error"):
                result = {"fields": {}, "field_reviews": {}, "evidence": [], "actions": [],
                          "model_calls": 0, "tool_calls": 0, "errors": []}
            else:
                result = produce(job, client, repo, max_calls=max_calls, max_tool_calls=max_tool_calls)
            finalized = finalize_result(job, result, repo)
            writer.record(job, finalized)
            processed += 1
            if client.halted and getattr(client, "can_continue_after_format_error", False) is True:
                case_failures.append({"report_id": case_id,
                                      "code": _code(client.halted, "response_format_error"),
                                      "continued": False})
            _emit({"event": "report_finished", "index": index + 1,
                   "complete_candidate": finalized["entry"] is not None,
                   "model_calls": result.get("model_calls", 0), "http_attempts": client.calls}, sys.stderr)
        if client.halted:
            if (continue_on_format_error and processed == len(jobs)
                    and getattr(client, "can_continue_after_format_error", False) is True):
                status, exit_code = "completed_with_errors", 2
            else:
                status, exit_code = "provider_stopped", 2
        elif case_failures:
            status, exit_code = "completed_with_errors", 2
    except KeyboardInterrupt:
        status, exit_code = "interrupted", 130
    except Exception as exc:
        status, exit_code = _code(exc, "batch_processing_failed"), 2
    summary = writer.finish({"status": status, "requested_input_count": len(jobs),
                             "unprocessed_input_count": len(jobs) - processed,
                             "format_failure_count": len(case_failures), "case_failures": case_failures,
                             "continue_on_format_error": continue_on_format_error,
                             "elapsed_seconds": round(time.monotonic() - started, 3),
                             "provider": client.summary()})
    return summary, exit_code


def main(argv=None):
    args = parser().parse_args(argv)
    client = ledger = None
    secret = ""
    try:
        jobs = load_jobs(input_path=args.input, advisory=args.advisory, repo=args.repo,
                         source_link=args.source_link, cache_dir=args.cache_dir, repo_map=args.repo_map)
        if not jobs:
            raise ValueError("no_inputs")
        readers, checks = prepare(jobs)
        if args.prepare_only:
            _emit({"status": "prepared", "http_attempts": 0, "inputs": checks})
            return 1 if any(row["input_error"] for row in checks) else 0
        if args.output is None or args.request_ledger is None:
            raise ValueError("output_and_request_ledger_required")
        if args.output.exists():
            raise ValueError("output_directory_exists")
        if args.max_tokens < 256:
            raise ValueError("output_token_limit_invalid")
        if args.key_stdin:
            if sys.stdin.isatty():
                raise ValueError("key_stdin_requires_pipe_use_hidden_prompt_in_terminal")
            secret = sys.stdin.readline(512).strip()
        else:
            secret = os.environ.get("DEEPSEEK_API_KEY", "")
            if not secret:
                if not sys.stdin.isatty():
                    raise ValueError("api_key_missing_use_env_or_key_stdin")
                secret = getpass.getpass("Temporary DeepSeek key (hidden): ")
        if not secret:
            raise ValueError("api_key_missing")
        ledger = RequestLedger(args.request_ledger.resolve(), limit=args.authorization_limit, model=args.model)
        client = DeepSeekClient(secret, ledger, run_id=datetime.now(timezone.utc).strftime("t2-%Y%m%dT%H%M%S-%f"),
                                max_requests=args.max_requests, max_tokens=args.max_tokens,
                                reasoning_effort=args.reasoning_effort, timeout=args.timeout, model=args.model,
                                response_mode=args.response_mode,
                                progress=lambda event: _emit(event, sys.stderr))
        secret = ""
        summary, code = run_batch(jobs, readers, client, args.output, max_calls=args.max_calls_per_report,
                                 max_tool_calls=args.max_tool_calls,
                                 continue_on_format_error=not args.stop_on_format_error)
        _emit(summary)
        return code
    except KeyboardInterrupt:
        _emit({"status": "interrupted"})
        return 130
    except Exception as exc:
        _emit({"status": "error", "code": _code(exc, "startup_or_output_failed")})
        return 2
    finally:
        secret = ""
        if client is not None:
            client.close()
        if ledger is not None:
            ledger.close()


if __name__ == "__main__":
    raise SystemExit(main())
