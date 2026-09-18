"""Local UI adapter. The CLI remains the only extraction and budget writer.

No shell, background retries or credential persistence. URL preparation can
acquire public GitHub material; model use requires a separate explicit action. Saved results
are exposed only after the child exits, or from server-selected review folders.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import uuid

from .intake import MAX_DOCUMENT_BYTES, _input_json
from .llm import effective_request_limit
from .acquisition import acquire_batch, parse_advisory_urls, validate_network_mode

FILES = ("entries.jsonl", "drafts.jsonl", "reports.jsonl", "report_conflicts.jsonl",
         "review.jsonl", "actions.jsonl", "summary.json")
ACTIVE = {"preparing", "running", "stopping"}
PROFILE = ["--model", "deepseek-flash", "--response-mode", "staged_tool",
           "--thinking", "enabled", "--annotation-format", "assessed_tool",
           "--read-format", "plan_tool", "--reasoning-effort", "low", "--multi-entry",
           "--max-tokens", "32768", "--max-calls-per-report", "12",
           "--max-tool-calls", "64", "--timeout", "300", "--stop-on-format-error"]
MAX_VIEW_BYTES = 32 * 1024 * 1024


def read_bytes(path: Path, limit: int) -> bytes:
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError("file_too_large_for_web_view")
    return data


def budget_snapshot(path: Path, limit: int, historical: int, *, effective_limit: int | None = None) -> dict:
    """Read-only display, never acquire the writer lock or modify the ledger.

    The CLI independently enforces the full ledger contract before any HTTP.
    A partial line or pending attempt is not interpreted as zero consumption.
    """
    try:
        ceiling = effective_request_limit(limit, effective_limit)
        raw = read_bytes(path, 2_000_000)
        if not raw.endswith(b"\n"):
            raise ValueError("ledger_updating_or_incomplete")
        rows = [_input_json(line) for line in raw.splitlines()]
        if not rows or rows[0].get("event") != "authorization":
            raise ValueError("ledger_invalid")
        recorded = rows[0].get("request_limit")
        model = rows[0].get("model")
        starts, finishes, tokens = set(), set(), 0
        unknown = 0
        for row in rows[1:]:
            event, number = row.get("event"), row.get("request")
            if event == "http_started":
                if type(number) is not int or number != len(starts) + 1:
                    raise ValueError("ledger_invalid")
                starts.add(number)
            elif event == "http_finished":
                if number not in starts or number in finishes:
                    raise ValueError("ledger_invalid")
                finishes.add(number)
                usage = row.get("usage") or {}
                if type(usage.get("total_tokens")) is int and usage["total_tokens"] >= 0:
                    tokens += usage["total_tokens"]
                else:
                    unknown += 1
            elif event == "authorization_extended":
                recorded = row.get("request_limit")
            else:
                raise ValueError("ledger_invalid")
        if recorded != limit or model != "deepseek-flash" or len(starts) > limit:
            raise ValueError("ledger_authorization_mismatch")
        result = {"available": True, "used": len(starts) + historical,
                "generation_used": len(starts), "limit": ceiling + historical,
                "remaining": max(0, ceiling - len(starts)), "pending": len(starts - finishes),
                "reported_tokens": tokens, "unknown_usage": unknown + len(starts - finishes),
                "currency_cost_measured": False}
        if effective_limit is not None:
            result.update(authorization_limit=limit, effective_authorization_limit=ceiling)
        return result
    except (OSError, ValueError, TypeError, AttributeError):
        return {"available": False, "code": "ledger_unavailable_or_updating", "remaining": None}


def local_path(value, *, required=False) -> Path | None:
    if not value and not required:
        return None
    if (not isinstance(value, str) or not value or len(value) > 2000
            or "://" in value or value.startswith(("\\\\", "//"))):
        raise ValueError("local_path_required")
    path = Path(value)
    if not path.is_absolute():
        raise ValueError("absolute_local_path_required")
    return path.resolve()


@dataclass
class Run:
    id: str
    folder: Path
    output: Path
    state: str = "preparing"
    args: list[str] = field(default_factory=list)
    inputs: list[dict] = field(default_factory=list)
    events: deque = field(default_factory=lambda: deque(maxlen=60))
    progress: dict = field(default_factory=dict)
    processed_count: int = 0
    summary: dict | None = None
    exit_code: int | None = None
    code: str | None = None
    process: object = None
    worker: object = None
    input_mode: str = "material"
    created: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def public(self):
        return {"id": self.id, "state": self.state, "inputs": self.inputs,
                "events": list(self.events), "progress": self.progress,
                "processed_count": self.processed_count,
                "summary": self.summary, "exit_code": self.exit_code, "code": self.code,
                "created": self.created, "output_path": str(self.output), "input_mode": self.input_mode,
                "results_available": self.state in {"finished", "imported"}}


class RunManager:
    def __init__(self, root: Path, ledger: Path | None = None, limit: int | None = None,
                 historical=0, *, popen=subprocess.Popen, effective_limit: int | None = None,
                 read_only: bool = False, network_mode: str = "system"):
        if type(read_only) is not bool:
            raise ValueError("read_only_mode_invalid")
        self.network_mode = validate_network_mode(network_mode)
        self.read_only = read_only
        self.root, self.popen = root.resolve(), popen
        if read_only:
            # Delivery playback has no authorization account. Do not construct,
            # inspect or simulate a ledger, or create a new-run directory.
            self.ledger, self.limit, self.historical, self.effective_limit = None, None, 0, None
        else:
            if ledger is None:
                raise ValueError("existing_shared_ledger_required")
            effective_request_limit(limit, effective_limit)
            self.ledger = ledger.resolve()
            if not self.ledger.is_file():
                raise ValueError("existing_shared_ledger_required")
            self.limit, self.historical = limit, historical
            self.effective_limit = effective_limit
            self.root.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.runs: dict[str, Run] = {}
        self.package_root = Path(__file__).resolve().parent.parent

    def budget(self):
        if self.read_only:
            return {"available": False, "remaining": 0, "code": "read_only_mode", "read_only": True}
        return budget_snapshot(self.ledger, self.limit, self.historical,
                               **({"effective_limit": self.effective_limit}
                                  if self.effective_limit is not None else {}))

    def snapshot(self):
        with self.lock:
            return {"runs": [run.public() for run in reversed(list(self.runs.values()))],
                    "budget": self.budget(), "model": "deepseek-flash",
                    "max_run_requests": 500, "automatic_retries": 0, "read_only": self.read_only,
                    "network_mode": self.network_mode}

    def _require_writable(self):
        if self.read_only:
            raise ValueError("read_only_mode")

    def _idle(self):
        if any(run.state in ACTIVE for run in self.runs.values()):
            raise ValueError("another_operation_is_active")

    def get(self, run_id: str) -> Run:
        if run_id not in self.runs:
            raise ValueError("unknown_run")
        return self.runs[run_id]

    def import_result(self, folder: Path):
        """Only the server launcher, never a web-supplied arbitrary path."""
        output = folder.resolve()
        summary = _input_json(read_bytes(output / "summary.json", 2_000_000))
        if not isinstance(summary, dict) or not isinstance(summary.get("status"), str):
            raise ValueError("invalid_result_summary")
        with self.lock:
            run_id = uuid.uuid4().hex[:16]
            self.runs[run_id] = Run(run_id, output, output, state="imported", summary=summary)
        return run_id

    def prepare(self, payload: dict) -> str:
        self._require_writable()
        # Validate the entire request before allocating anything on disk.
        if set(payload) - {"mode", "text", "name", "files", "repo", "source_link", "input_path", "cache_dir", "repo_map", "urls"}:
            raise ValueError("unknown_prepare_property")
        mode = payload.get("mode", "material")
        if mode == "urls":
            return self._prepare_urls(parse_advisory_urls(payload.get("urls")))
        repo = local_path(payload.get("repo"))
        cache = local_path(payload.get("cache_dir"))
        mapping = local_path(payload.get("repo_map"))
        source = payload.get("source_link", "")
        if not isinstance(source, str) or len(source) > 2000:
            raise ValueError("source_link_invalid")
        uploads = []
        if mode == "batch":
            input_path = local_path(payload.get("input_path"), required=True)
            if not input_path.is_file():
                raise ValueError("input_file_missing")
        elif mode == "material":
            input_path = None
            supplied = payload.get("files", [])
            if not isinstance(supplied, list) or len(supplied) > 8:
                raise ValueError("maximum_eight_material_files")
            supplied = list(supplied)
            text = payload.get("text", "")
            if not isinstance(text, str):
                raise ValueError("material_text_invalid")
            if text.strip():
                name = "advisory.txt"
                try:
                    if isinstance(_input_json(text), dict):
                        name = "advisory.json"
                except ValueError:
                    pass
                supplied.insert(0, {"name": payload.get("name", name), "text": text})
            if not 1 <= len(supplied) <= 8:
                raise ValueError("provide_material_not_only_a_url")
            for index, item in enumerate(supplied):
                if not isinstance(item, dict) or not isinstance(item.get("text"), str):
                    raise ValueError("material_text_invalid")
                name = item.get("name", "material.txt")
                if not isinstance(name, str) or Path(name).suffix.lower() not in {".txt", ".md", ".json", ".html", ".patch", ".diff"}:
                    raise ValueError("material_file_type_invalid")
                data = item["text"].encode("utf-8")
                if len(data) > MAX_DOCUMENT_BYTES:
                    raise ValueError("material_file_too_large")
                # Client filenames are labels, not filesystem paths.
                uploads.append((f"material-{index:02d}{Path(name).suffix.lower()}", data))
        else:
            raise ValueError("input_mode_invalid")
        with self.lock:
            self._idle()
            if len(self.runs) >= 64:
                raise ValueError("session_run_limit_restart_to_continue")
            run_id = uuid.uuid4().hex[:16]
            folder = self.root / run_id
            folder.mkdir()
            args = []
            if input_path:
                args += ["--input", str(input_path)]
            else:
                paths = []
                for name, data in uploads:
                    path = folder / name
                    path.write_bytes(data)
                    paths.append(path)
                if len(paths) == 1:
                    args += ["--advisory", str(paths[0])]
                else:
                    # First file is the primary advisory; the rest are support.
                    row = {"advisory": str(paths[0]), "documents": [{"path": str(p)} for p in paths[1:]]}
                    batch = folder / "input.jsonl"
                    batch.write_text(json.dumps(row, ensure_ascii=False) + "\n", encoding="utf-8")
                    args += ["--input", str(batch)]
            for flag, value in (("--repo", repo), ("--cache-dir", cache), ("--repo-map", mapping), ("--source-link", source)):
                if value:
                    args += [flag, str(value)]
            run = Run(run_id, folder, folder / "output", args=args)
            self.runs[run_id] = run
            self._launch(run, [*args, "--prepare-only"], preparation=True)
            return run_id

    def _prepare_urls(self, urls: list[str]) -> str:
        """A single pasted list creates one asynchronous, free preparation job."""
        with self.lock:
            self._idle()
            if len(self.runs) >= 64:
                raise ValueError("session_run_limit_restart_to_continue")
            run_id = uuid.uuid4().hex[:16]
            folder = self.root / run_id
            folder.mkdir()
            run = Run(run_id, folder, folder / "output", input_mode="urls")
            run.inputs = [{"report_id": url.rsplit("/", 1)[-1],
                           "input_error": None} for url in urls]
            self.runs[run_id] = run
            run.worker = threading.Thread(target=self._acquire_and_prepare,
                                          args=(run, urls), daemon=True)
            run.worker.start()
            return run_id

    def _acquire_and_prepare(self, run: Run, urls: list[str]):
        def progress(event):
            # Only public typed progress, never HTTP bodies or Git stderr.
            clean = {key: value for key, value in event.items()
                     if key in {"event", "report_id", "index", "total", "status", "code"}}
            if event.get("phase") in {"advisory", "repository", "ready", "failed"}:
                clean.update(event="acquisition_" + event["phase"], status=event["phase"])
                source = event.get("input_source_url", event.get("source_link", ""))
                if source in urls:
                    clean["report_id"] = source.rsplit("/", 1)[-1]
            with self.lock:
                run.events.append(clean)
                run.progress.update(clean)
        try:
            network_options = {"network_mode": self.network_mode} if self.network_mode != "system" else {}
            manifest = acquire_batch(urls, self.root.parent / "downloads", progress=progress, **network_options)
            with self.lock:
                run.args = ["--input", str(manifest)]
                launched = self._launch(run, [*run.args, "--prepare-only"], preparation=True)
                observer = run.worker
            if launched:
                observer.join()
        except Exception as exc:
            # The preparation thread must always leave its active state. Keep
            # downloaded material on failure; never expose arbitrary exceptions.
            code = str(exc) if isinstance(exc, ValueError) else "url_acquisition_failed"
            if not code.isascii() or not code.replace("_", "").isalnum() or len(code) > 90:
                code = "url_acquisition_failed"
            with self.lock:
                run.state, run.code = "error", code
                progress({"event": "acquisition_failed", "code": code})

    def start(self, run_id: str, key: str, cap: int, confirmed: bool):
        self._require_writable()
        if confirmed is not True:
            raise ValueError("explicit_run_confirmation_required")
        if not isinstance(key, str) or not 1 <= len(key) <= 500 or not all(33 <= ord(c) <= 126 for c in key):
            raise ValueError("api_key_missing_or_invalid")
        with self.lock:
            self._idle()
            run = self.get(run_id)
            if run.state != "prepared":
                raise ValueError("prepare_successfully_before_start")
            budget = self.budget()
            if not budget["available"] or budget["pending"]:
                raise ValueError("ledger_unavailable_or_unfinished_request")
            if type(cap) is not int or not 1 <= cap <= min(500, budget["remaining"]):
                raise ValueError("request_cap_exceeds_remaining")
            args = [*run.args, "--output", str(run.output), "--request-ledger", str(self.ledger),
                    "--authorization-limit", str(self.limit), "--max-requests", str(cap),
                    "--stop-after-current-file", str(run.folder / "stop-after-current"), "--key-stdin"]
            if self.effective_limit is not None:
                args += ["--effective-request-limit", str(self.effective_limit)]
            run.state, run.events, run.progress = "running", deque(maxlen=60), {}
            run.exit_code, run.code = None, None
            if not self._launch(run, args, preparation=False, key=key):
                raise ValueError("cli_launch_failed")

    def _launch(self, run, args, *, preparation, key=""):
        self._require_writable()
        env = dict(os.environ)
        env.pop("DEEPSEEK_API_KEY", None)
        env["PYTHONUTF8"], env["PYTHONDONTWRITEBYTECODE"] = "1", "1"
        env["TEMP"] = env["TMP"] = str(run.folder)
        try:
            proc = self.popen([sys.executable, "-m", "vulngym_t2.cli", *PROFILE, *args],
                              cwd=self.package_root, env=env, shell=False,
                              stdin=subprocess.PIPE if key else subprocess.DEVNULL,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
        except OSError:
            run.state, run.code = "error", "cli_launch_failed"
            return False
        run.process = proc
        if key:
            try:
                proc.stdin.write((key + "\n").encode("utf-8"))
                proc.stdin.close()
            except (OSError, ValueError):
                run.code = "key_delivery_failed_no_retry"
            finally:
                key = ""
        run.worker = threading.Thread(target=self._observe, args=(run, preparation), daemon=True)
        run.worker.start()
        return True

    def _observe(self, run, preparation):
        """Drain both pipes, keeping only bounded typed events, never raw logs."""
        def progress():
            while True:
                raw = run.process.stderr.readline(65537)
                if not raw:
                    break
                if len(raw) > 65536:
                    continue
                try:
                    event = _input_json(raw)
                    if not isinstance(event, dict) or event.get("event") not in {
                        "http_started", "http_finished", "report_started", "report_finished", "format_failure_isolated"
                    }:
                        continue
                    # Child diagnostics/source/key strings cannot enter the UI log.
                    clean = {k: v for k, v in event.items() if k in {
                        "event", "request", "report_id", "index", "total", "status", "seconds",
                        "complete_candidate", "model_calls", "http_attempts"}}
                    with self.lock:
                        run.events.append(clean)
                        run.progress.update(clean)
                        if clean["event"] == "report_finished":
                            run.processed_count += 1
                except (ValueError, TypeError):
                    continue
        reader = threading.Thread(target=progress, daemon=True)
        reader.start()
        raw = run.process.stdout.read(4 * 1024 * 1024 + 1)
        # Drain unexpected excess without retaining it or blocking the child.
        while run.process.stdout.read(65536):
            pass
        code = run.process.wait()
        reader.join()
        run.process.stdout.close()
        run.process.stderr.close()
        try:
            result = _input_json(raw)
            if not isinstance(result, dict):
                raise ValueError("invalid_cli_summary")
        except ValueError:
            result = {"status": "error", "code": "cli_summary_unavailable_preserve_output"}
        with self.lock:
            run.exit_code = code
            if preparation:
                run.inputs = result.get("inputs", [])
                # CLI exit 1 can be a completed precheck with individual input
                # failures. URL batches keep those rows and allow the ready
                # inputs to proceed after the same explicit model confirmation.
                partial_urls = (run.input_mode == "urls" and code == 1
                                and any(item.get("input_error") for item in run.inputs)
                                and any(not item.get("input_error") for item in run.inputs))
                checked = result.get("status") == "prepared"
                run.state = "prepared" if checked and (code == 0 or partial_urls) else "error"
                if run.state == "error":
                    run.code = result.get("code", "input_preparation_failed")
                if checked and run.input_mode == "urls" and not any(not item.get("input_error") for item in run.inputs):
                    run.state, run.code = "error", "no_ready_url_inputs"
            else:
                run.summary = result
                run.state = "finished" if (run.output / "summary.json").is_file() else "error"
                run.code = run.code or (result.get("code") if run.state == "error" else None)

    def stop(self, run_id):
        self._require_writable()
        with self.lock:
            run = self.get(run_id)
            if run.state not in {"running", "stopping"}:
                raise ValueError("no_running_batch")
            (run.folder / "stop-after-current").touch(exist_ok=True)
            run.state = "stopping"

    def file(self, run_id, name):
        with self.lock:
            run = self.get(run_id)
            if run.state not in {"finished", "imported"} or name not in FILES:
                raise ValueError("result_not_available")
            path = (run.output / name).resolve()
            if not path.is_relative_to(run.output.resolve()) or not path.is_file():
                raise ValueError("result_file_unavailable")
            return path

    def result(self, run_id):
        result = {}
        for name, key in (("summary.json", "summary"), ("entries.jsonl", "entries"), ("review.jsonl", "reviews")):
            raw = read_bytes(self.file(run_id, name), MAX_VIEW_BYTES)
            result[key] = _input_json(raw) if name.endswith(".json") else [_input_json(line) for line in raw.splitlines() if line.strip()]
        return result
