"""Loopback-only Web GUI: python -m vulngym_t2.web --help."""
from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import secrets
import sys
from urllib.parse import urlsplit

from .intake import _input_json
from .llm import MAX_AUTHORIZED_REQUESTS, effective_request_limit
from .web_runtime import ACTIVE, RunManager, read_bytes

ASSETS = Path(__file__).with_name("web_assets")
STATIC_TYPES = {
    "/app.css": "text/css; charset=utf-8",
    "/app.js": "text/javascript; charset=utf-8",
    "/brand/vulngym.png": "image/png",
    "/brand/README.md": "text/plain; charset=utf-8",
    "/fonts/jetbrains-mono-latin-wght-normal.woff2": "font/woff2",
    "/fonts/OFL.txt": "text/plain; charset=utf-8",
}
MAX_BODY = 4 * 1024 * 1024


class LocalServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, manager, port=8765):
        self.manager, self.token = manager, secrets.token_urlsafe(32)
        super().__init__(("127.0.0.1", port), Handler)
        self.origin = f"http://127.0.0.1:{self.server_port}"


class Handler(BaseHTTPRequestHandler):
    server_version = "T2Local"

    def log_message(self, *args):
        pass  # UI polling must not create permanent request logs.

    def setup(self):
        super().setup()
        self.connection.settimeout(15)

    def respond(self, status, data, content_type="application/json; charset=utf-8", filename=None):
        if not isinstance(data, bytes):
            data = json.dumps(data, ensure_ascii=False, allow_nan=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
        if filename:
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.end_headers()
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError, TimeoutError):
            pass

    def allowed(self, *, api=False):
        if self.headers.get("Host") != f"127.0.0.1:{self.server.server_port}":
            self.respond(403, {"code": "loopback_host_required"})
            return False
        origin = self.headers.get("Origin")
        if origin is not None and origin != self.server.origin:
            self.respond(403, {"code": "same_origin_required"})
            return False
        if api and not secrets.compare_digest(self.headers.get("X-T2-Session", ""), self.server.token):
            self.respond(403, {"code": "local_session_required"})
            return False
        return True

    def do_GET(self):
        path = urlsplit(self.path).path
        if not self.allowed(api=path.startswith("/api/")):
            return
        try:
            if path == "/":
                page = (ASSETS / "index.html").read_text(encoding="utf-8")
                self.respond(200, page.replace("__SESSION_TOKEN__", self.server.token).encode("utf-8"), "text/html; charset=utf-8")
            elif path in STATIC_TYPES:
                self.respond(200, (ASSETS / path[1:]).read_bytes(), STATIC_TYPES[path])
            elif path == "/api/state":
                self.respond(200, self.server.manager.snapshot())
            elif path.startswith("/api/result/") and len(path.split("/")) == 4:
                self.respond(200, self.server.manager.result(path.split("/")[3]))
            elif path.startswith("/api/download/") and len(path.split("/")) == 5:
                _, _, _, run_id, name = path.split("/")
                file = self.server.manager.file(run_id, name)
                self.respond(200, read_bytes(file, 64 * 1024 * 1024), "application/octet-stream", name)
            else:
                self.respond(404, {"code": "not_found"})
        except (ValueError, OSError, TypeError):
            self.respond(400, {"code": "result_unavailable_or_too_large"})

    def do_POST(self):
        if not self.allowed(api=True):
            return
        payload = {}
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if not 1 <= size <= MAX_BODY or self.headers.get("Content-Type", "").split(";")[0] != "application/json":
                self.respond(413, {"code": "bounded_json_body_required"})
                return
            payload = _input_json(self.rfile.read(size))
            if not isinstance(payload, dict):
                raise ValueError("json_object_required")
            path = urlsplit(self.path).path
            manager = self.server.manager
            if path == "/api/prepare":
                self.respond(202, {"run_id": manager.prepare(payload)})
            elif path == "/api/start":
                key = payload.pop("key", "")
                try:
                    manager.start(payload.get("run_id"), key, payload.get("max_requests"), payload.get("confirmed"))
                finally:
                    key = ""
                self.respond(202, {"status": "started"})
            elif path == "/api/stop":
                manager.stop(payload.get("run_id"))
                self.respond(202, {"status": "stopping_after_current"})
            else:
                self.respond(404, {"code": "not_found"})
        except ValueError as exc:
            # Only application-owned symbolic error codes, never raw input/key.
            code = str(exc)
            if not code.isascii() or not code.replace("_", "").isalnum() or len(code) > 90:
                code = "invalid_request"
            self.respond(400, {"code": code})
        except (OSError, TypeError, TimeoutError):
            self.respond(400, {"code": "local_operation_failed"})
        finally:
            if isinstance(payload, dict):
                payload.clear()


def main(argv=None):
    parser = argparse.ArgumentParser(description="Local T2 workspace; no Node or web dependencies. Normal runs require an existing shared ledger; --read-only only views saved results.")
    parser.add_argument("--runs-root", required=True, type=Path, help="local directory for new inputs/results (prefer a data drive)")
    parser.add_argument("--read-only", action="store_true", help="view saved --review-dir outputs only; disable prepare/start/stop and do not use a ledger")
    parser.add_argument("--request-ledger", type=Path, help="reuse the existing shared request ledger (required unless --read-only)")
    parser.add_argument("--authorization-limit", type=int, help="already-authorized generation ceiling, required unless --read-only; no extension here")
    parser.add_argument("--effective-request-limit", type=int,
                        help="optional lower cumulative generation ceiling; enforced by the CLI without changing the ledger")
    parser.add_argument("--historical-requests", type=int, default=0, help="known extra calls outside this ledger, display accounting only")
    parser.add_argument("--review-dir", action="append", default=[], type=Path, help="explicit completed output to view read-only; repeatable")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--network-mode", choices=("system", "direct"), default="system",
                        help="public material download routing; no automatic fallback")
    args = parser.parse_args(argv)
    if not args.read_only and (args.request_ledger is None or args.authorization_limit is None):
        parser.error("--request-ledger and --authorization-limit are required unless --read-only")
    if ((args.authorization_limit is not None and not 1 <= args.authorization_limit <= MAX_AUTHORIZED_REQUESTS)
            or not 0 <= args.historical_requests <= MAX_AUTHORIZED_REQUESTS or not 0 <= args.port <= 65535):
        parser.error("invalid limit or port")
    if not args.read_only:
        try:
            effective_request_limit(args.authorization_limit, args.effective_request_limit)
        except ValueError:
            parser.error("effective request limit must be within the ledger authorization")
    manager = RunManager(args.runs_root, args.request_ledger, args.authorization_limit, args.historical_requests,
                         network_mode=args.network_mode,
                         **({"effective_limit": args.effective_request_limit}
                            if args.effective_request_limit is not None else {}),
                         **({"read_only": True} if args.read_only else {}))
    for directory in args.review_dir:
        manager.import_result(directory)
    server = LocalServer(manager, args.port)
    mode = "read-only saved results; no model requests" if args.read_only else "Ctrl+C: finish current input, then exit"
    print(f"T2 local workspace: {server.origin} ({mode})", flush=True)
    try:
        server.serve_forever(poll_interval=0.3)
    except KeyboardInterrupt:
        active = [run for run in manager.runs.values() if run.state in ACTIVE]
        for run in active:
            if run.state in {"running", "stopping"}:
                manager.stop(run.id)
        if active:
            print("Finishing the current local operation before exit; no new input will start.", flush=True)
            for run in active:
                if run.worker is not None:
                    run.worker.join()
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
