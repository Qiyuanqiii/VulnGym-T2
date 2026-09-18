"""Open the portable web workbench directly; no terminal configuration needed."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import webbrowser

ROOT = Path(__file__).resolve().parent


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--no-browser", action="store_true")
    parser.add_argument("--check", action="store_true", help="validate packaged results and startup, then exit")
    parser.add_argument("--port", type=int, default=0, help="0 chooses an unused loopback port")
    parser.add_argument("--network-mode", choices=("system", "direct"), default="system",
                        help="public material downloads: system defaults, or explicit direct access without proxies")
    parser.add_argument("--live", action="store_true", help="enable user-confirmed extraction")
    parser.add_argument("--read-only", action="store_true", help="only replay saved results; no model calls")
    parser.add_argument("--ledger", type=Path)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--effective-limit", type=int)
    parser.add_argument("--historical-requests", type=int, default=0)
    parser.add_argument("--initialize-own-budget", action="store_true",
                        help="explicitly initialize a NEW independent account budget; never reset existing usage")
    args = parser.parse_args(argv)
    if args.read_only and (args.live or args.ledger is not None or args.initialize_own_budget):
        parser.error("--read-only cannot be combined with extraction arguments")
    if not 0 <= args.port <= 65535:
        parser.error("invalid port")
    if args.initialize_own_budget and (not args.live or args.check):
        parser.error("budget initialization requires --live and is prohibited with --check")
    if not args.live and any(value is not None for value in (args.ledger, args.limit, args.effective_limit)):
        parser.error("ledger arguments require --live")
    from vulngym_t2.web import LocalServer
    from vulngym_t2.web_runtime import ACTIVE, RunManager
    from vulngym_t2.llm import MAX_AUTHORIZED_REQUESTS
    if args.live:
        if args.ledger is None or args.limit is None or not 1 <= args.limit <= MAX_AUTHORIZED_REQUESTS:
            parser.error("--live requires --ledger PATH and --limit AUTHORIZED_REQUEST_COUNT")
        if not 0 <= args.historical_requests <= MAX_AUTHORIZED_REQUESTS:
            parser.error("invalid historical request count")
        ledger_path = args.ledger.resolve()
        if args.initialize_own_budget:
            if ledger_path.exists():
                parser.error("refusing to replace an existing ledger; omit --initialize-own-budget to reuse it")
            from vulngym_t2.llm import RequestLedger
            ledger_path.parent.mkdir(parents=True, exist_ok=True)
            ledger = RequestLedger(ledger_path, limit=args.limit, model="deepseek-flash",
                                   effective_limit=args.effective_limit)
            ledger.close()
        manager = RunManager(ROOT / "data" / "runs", ledger_path, args.limit, args.historical_requests,
                             effective_limit=args.effective_limit, network_mode=args.network_mode)
        if not manager.budget().get("available"):
            parser.error("ledger is unavailable or does not match the specified authorization")
    elif args.read_only:
        manager = RunManager(ROOT / "data" / "runs", read_only=True, network_mode=args.network_mode)
    else:
        from vulngym_t2.web_portable import portable_manager
        manager = portable_manager(ROOT, network_mode=args.network_mode)
    results = sorted((ROOT / "examples").glob("run-*/summary.json"))
    if not results:
        parser.error("no packaged example runs found; extract the full submission ZIP first")
    for summary in results:
        manager.import_result(summary.parent)
    # Exercise actual result parsing, not only the presence of summary files.
    for run in manager.runs.values():
        manager.result(run.id)
    server = LocalServer(manager, args.port)
    try:
        if args.check:
            print(json.dumps({"status": "ready", "read_only": manager.read_only,
                              "network_mode": manager.network_mode,
                              "example_runs": len(manager.runs), "python": sys.version.split()[0],
                              "root": str(ROOT), "http_model_requests": 0}, ensure_ascii=False))
            return 0
        print("VulnGym T2 - " + ("Extraction enabled; each run still requires key and confirmation."
                                if not manager.read_only else "Demo: saved results only; no model calls."), flush=True)
        print("Open: " + server.origin, flush=True)
        print("Public material downloads: " + manager.network_mode + ". Model transport is unchanged.", flush=True)
        print("Keep this window open. Press Ctrl+C to stop.", flush=True)
        if not args.no_browser:
            try:
                webbrowser.open(server.origin)
            except OSError:
                print("Open the printed address in your browser manually.", flush=True)
        try:
            server.serve_forever(poll_interval=0.3)
        except KeyboardInterrupt:
            active = [run for run in manager.runs.values() if run.state in ACTIVE]
            for run in active:
                if run.state in {"running", "stopping"}:
                    manager.stop(run.id)
            for run in active:
                if run.worker is not None:
                    run.worker.join()
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as exc:
        print("Startup failed (" + type(exc).__name__ + "). Extract the complete ZIP to a writable folder; see README_START.md.", file=sys.stderr)
        raise SystemExit(1)
