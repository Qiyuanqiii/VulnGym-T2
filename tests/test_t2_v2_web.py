"""Offline GUI adapter/HTTP tests. Synthetic child, no model/network billing."""
import io
from html.parser import HTMLParser
import json
from pathlib import Path
import tempfile
import threading
import unittest
import re
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from vulngym_t2.web import LocalServer
from vulngym_t2.web_runtime import FILES, RunManager, budget_snapshot


class InputPipe(io.BytesIO):
    def close(self):
        self.captured = self.getvalue()
        super().close()


class FakeProcess:
    def __init__(self, result, progress=(), gate=None):
        self.stdin = InputPipe()
        self.stdout = io.BytesIO(json.dumps(result).encode())
        self.stderr = io.BytesIO(b"".join(json.dumps(row).encode() + b"\n" for row in progress))
        self.gate = gate

    def wait(self):
        if self.gate is not None:
            self.gate.wait(5)
        return 0


class WebTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="t2-web-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.ledger = self.root / "requests.jsonl"
        self.header = {"event": "authorization", "model": "deepseek-flash", "request_limit": 100, "automatic_retries": 0}
        self.ledger.write_text(json.dumps(self.header) + "\n", encoding="utf-8")
        self.calls, self.children = [], []
        self.gate = None
        self.child_events = [{"event": "http_started", "request": 1, "unexpected_raw": "do not retain"}]

        def launch(args, **kwargs):
            self.calls.append((args, kwargs))
            if "--prepare-only" in args:
                result = {"status": "prepared", "inputs": [{"report_id": "synthetic", "input_error": None}]}
                proc = FakeProcess(result)
            else:
                output = Path(args[args.index("--output") + 1])
                self.outputs(output)
                result = {"status": "completed", "candidate_count": 0, "input_count": 1}
                proc = FakeProcess(result, self.child_events, self.gate)
            self.children.append(proc)
            return proc
        self.manager = RunManager(self.root / "runs", self.ledger, 100, 1, popen=launch)

    def outputs(self, output):
        output.mkdir()
        for name in FILES:
            (output / name).write_text(json.dumps({"status": "completed", "input_count": 1}) if name == "summary.json" else "", encoding="utf-8")

    def prepared(self, **values):
        run_id = self.manager.prepare({"text": "Synthetic public material", **values})
        self.manager.get(run_id).worker.join(5)
        self.assertEqual(self.manager.get(run_id).state, "prepared")
        return run_id

    def server(self):
        server = LocalServer(self.manager, 0)
        worker = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": .02}, daemon=True)
        worker.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server

    def request(self, server, path, data=None, headers=None):
        request = Request(server.origin + path,
                          data=json.dumps(data).encode() if data is not None else None,
                          headers=headers or {})
        try:
            response = urlopen(request, timeout=5)
        except HTTPError as error:
            response = error
        with response:
            return response.status, response.read(), response.headers

    def test_preparation_is_free_and_does_not_receive_a_key_or_write_ledger(self):
        before = self.ledger.read_bytes()
        self.prepared()
        args, options = self.calls[0]
        self.assertIn("--prepare-only", args)
        self.assertNotIn("--key-stdin", args)
        self.assertNotIn("--request-ledger", args)
        self.assertNotIn("DEEPSEEK_API_KEY", options["env"])
        self.assertFalse(options["shell"])
        self.assertEqual(self.ledger.read_bytes(), before)
        self.assertFalse(Path(str(self.ledger) + ".lock").exists())

    def test_pasted_json_is_preserved_as_a_primary_json_file(self):
        data = {"ghsa_id": "GHSA-2345-6789-cfgh", "summary": "Fixture", "description": "Fixture"}
        run_id = self.prepared(text=json.dumps(data))
        run = self.manager.get(run_id)
        path = Path(run.args[1])
        self.assertEqual(path.suffix, ".json")
        self.assertEqual(json.loads(path.read_text()), data)

    def test_multiple_files_keep_first_primary_and_never_use_client_paths(self):
        run_id = self.prepared(text="", files=[{"name": "../../primary.json", "text": "{}"}, {"name": "support.md", "text": "Fixture"}])
        run = self.manager.get(run_id)
        record = json.loads(Path(run.args[1]).read_text())
        self.assertTrue(Path(record["advisory"]).is_relative_to(run.folder))
        self.assertEqual(len(record["documents"]), 1)
        self.assertFalse((self.root / "primary.json").exists())

    def test_secret_only_goes_to_child_stdin_and_fixed_profile_is_used(self):
        run_id = self.prepared()
        secret = "synthetic-temporary-secret"
        self.manager.start(run_id, secret, 3, True)
        self.manager.get(run_id).worker.join(5)
        args, options = self.calls[-1]
        self.assertEqual(self.children[-1].stdin.captured, (secret + "\n").encode())
        self.assertNotIn(secret, repr(args) + repr(options) + repr(self.manager.snapshot()))
        self.assertEqual(args[args.index("--annotation-format") + 1], "assessed_tool")
        self.assertEqual(args[args.index("--request-ledger") + 1], str(self.ledger))
        self.assertNotIn("--extend-authorization", args)
        for path in (self.root / "runs").rglob("*"):
            if path.is_file():
                self.assertNotIn(secret.encode(), path.read_bytes())
        self.assertNotIn("unexpected_raw", self.manager.get(run_id).events[0])

    def test_child_profile_matches_saved_low_multi_entry_run_without_raising_confirmed_cap(self):
        run_id = self.prepared()
        self.manager.start(run_id, "synthetic", 3, True)
        self.manager.get(run_id).worker.join(5)
        args, _ = self.calls[-1]
        for flag, expected in (("--model", "deepseek-flash"),
                               ("--response-mode", "staged_tool"),
                               ("--thinking", "enabled"),
                               ("--annotation-format", "assessed_tool"),
                               ("--read-format", "plan_tool"),
                               ("--reasoning-effort", "low"),
                               ("--max-tokens", "32768"),
                               ("--max-calls-per-report", "12"),
                               ("--max-requests", "3")):
            with self.subTest(flag=flag):
                self.assertEqual(args.count(flag), 1)
                self.assertEqual(args[args.index(flag) + 1], expected)
        self.assertEqual(args.count("--multi-entry"), 1)
        self.assertIn("--stop-on-format-error", args)
        self.assertNotIn("--extend-authorization", args)
        self.assertEqual(self.manager.snapshot()["automatic_retries"], 0)
        self.assertEqual(len(self.calls), 2)

    def test_page_defaults_to_twelve_requests_and_explicit_authorization(self):
        class CapInput(HTMLParser):
            def __init__(self):
                super().__init__()
                self.cap = None

            def handle_starttag(self, tag, attrs):
                values = dict(attrs)
                if tag == "input" and values.get("id") == "cap":
                    self.cap = values

        server = self.server()
        page = self.request(server, "/")[1].decode("utf-8")
        parsed = CapInput()
        parsed.feed(page)
        self.assertIsNotNone(parsed.cap)
        self.assertEqual(parsed.cap["value"], "12")
        self.assertIn("每份资料最多12次请求 · 多候选 · 不自动重试", page)
        self.assertEqual(self.calls, [])

    def test_one_active_child_stop_is_cooperative_and_live_output_not_readable(self):
        run_id = self.prepared()
        self.gate = threading.Event()
        self.addCleanup(self.gate.set)
        self.manager.start(run_id, "synthetic", 3, True)
        self.assertIsNone(self.manager.get(run_id).exit_code)
        with self.assertRaisesRegex(ValueError, "another_operation_is_active"):
            self.manager.prepare({"text": "another"})
        with self.assertRaisesRegex(ValueError, "result_not_available"):
            self.manager.file(run_id, "summary.json")
        self.manager.stop(run_id)
        run = self.manager.get(run_id)
        self.assertEqual(run.state, "stopping")
        self.assertTrue((run.folder / "stop-after-current").is_file())
        self.assertEqual(len(self.calls), 2)
        self.gate.set()
        run.worker.join(5)
        self.assertEqual(run.state, "finished")

    def test_confirmation_cap_and_pending_ledger_block_before_launch(self):
        run_id = self.prepared()
        for cap, confirmed in ((3, False), (101, True), (True, True), (0, True)):
            with self.subTest(cap=cap, confirmed=confirmed), self.assertRaises(ValueError):
                self.manager.start(run_id, "synthetic", cap, confirmed)
        with self.ledger.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps({"event": "http_started", "request": 1}) + "\n")
        with self.assertRaisesRegex(ValueError, "unfinished_request"):
            self.manager.start(run_id, "synthetic", 3, True)
        self.assertEqual(len(self.calls), 1)

    def test_readonly_budget_counts_reserved_attempt_and_historical_extra(self):
        with self.ledger.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps({"event": "http_started", "request": 1}) + "\n")
        before = self.ledger.read_bytes()
        value = budget_snapshot(self.ledger, 100, 1)
        self.assertEqual((value["used"], value["limit"], value["remaining"], value["pending"]), (2, 101, 99, 1))
        self.assertEqual(self.ledger.read_bytes(), before)
        with self.ledger.open("ab") as stream:
            stream.write(b'{"event":')
        self.assertFalse(self.manager.budget()["available"])

    def test_downloads_are_fixed_to_finished_registered_outputs(self):
        folder = self.root / "old-result"
        self.outputs(folder)
        run_id = self.manager.import_result(folder)
        self.assertEqual(self.manager.file(run_id, "summary.json"), folder / "summary.json")
        self.assertEqual(self.manager.file(run_id, "drafts.jsonl"), folder / "drafts.jsonl")
        for name in ("../requests.jsonl", "requests.jsonl", "../summary.json"):
            with self.assertRaises(ValueError):
                self.manager.file(run_id, name)
        self.assertEqual(self.manager.result(run_id)["entries"], [])

    def test_page_assets_headers_and_unauthorized_requests(self):
        server = self.server()
        code, page, headers = self.request(server, "/")
        self.assertEqual(code, 200)
        self.assertIn(server.token.encode(), page)
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])
        self.assertEqual(self.request(server, "/app.js")[0], 200)
        self.assertEqual(self.request(server, "/api/state")[0], 403)
        self.assertEqual(self.request(server, "/", headers={"Host": "evil.invalid"})[0], 403)
        self.assertEqual(self.request(server, "/api/state", headers={"X-T2-Session": server.token, "Origin": "https://evil.invalid"})[0], 403)
        self.assertEqual(self.request(server, "/../requests.jsonl")[0], 404)

    def test_http_prepare_and_result_without_paid_call(self):
        server = self.server()
        headers = {"X-T2-Session": server.token, "Origin": server.origin, "Content-Type": "application/json"}
        code, raw, _ = self.request(server, "/api/prepare", {"text": "Fixture"}, headers)
        self.assertEqual(code, 202)
        run_id = json.loads(raw)["run_id"]
        self.manager.get(run_id).worker.join(5)
        code, raw, _ = self.request(server, "/api/state", headers=headers)
        self.assertEqual(code, 200)
        self.assertEqual(json.loads(raw)["runs"][0]["state"], "prepared")
        self.assertNotIn("--key-stdin", self.calls[0][0])

    def test_local_font_and_license_are_served_without_broadening_asset_paths(self):
        server = self.server()
        before = self.ledger.read_bytes()
        code, font, headers = self.request(server, "/fonts/jetbrains-mono-latin-wght-normal.woff2")
        self.assertEqual(code, 200)
        self.assertEqual(headers["Content-Type"], "font/woff2")
        self.assertEqual(font[:4], b"wOF2")
        self.assertEqual(len(font), 40404)
        code, license_text, headers = self.request(server, "/fonts/OFL.txt")
        self.assertEqual(code, 200)
        self.assertIn(b"SIL OPEN FONT LICENSE Version 1.1", license_text)
        self.assertEqual(headers["Content-Type"], "text/plain; charset=utf-8")
        for path in ("/fonts/../web.py", "/fonts/README.md", "/fonts/unknown.woff2"):
            self.assertEqual(self.request(server, path)[0], 404)
        self.assertEqual(self.ledger.read_bytes(), before)
        self.assertEqual(self.calls, [])

    def test_page_keeps_all_javascript_controls_and_loads_only_local_assets(self):
        class PageStructure(HTMLParser):
            def __init__(self):
                super().__init__()
                self.ids, self.assets = [], []

            def handle_starttag(self, tag, attrs):
                values = dict(attrs)
                if "id" in values:
                    self.ids.append(values["id"])
                if tag in {"script", "link", "img"}:
                    self.assets.append(values.get("src", values.get("href", "")))

        server = self.server()
        page = PageStructure()
        page.feed(self.request(server, "/")[1].decode("utf-8"))
        javascript = self.request(server, "/app.js")[1].decode("utf-8")
        self.assertEqual(len(page.ids), len(set(page.ids)))
        self.assertTrue(set(re.findall(r'\$\("([^"]+)"\)', javascript)).issubset(page.ids))
        self.assertEqual(set(page.assets), {"/app.css", "/app.js", "/fonts/jetbrains-mono-latin-wght-normal.woff2", "/brand/vulngym.png"})

    def test_official_logo_and_attribution_are_fixed_local_assets(self):
        server = self.server()
        code, logo, headers = self.request(server, "/brand/vulngym.png")
        self.assertEqual(code, 200)
        self.assertEqual(headers["Content-Type"], "image/png")
        self.assertEqual(logo[:8], b"\x89PNG\r\n\x1a\n")
        self.assertEqual(len(logo), 57505)
        code, attribution, _ = self.request(server, "/brand/README.md")
        self.assertEqual(code, 200)
        self.assertIn(b"Tencent/VulnGym", attribution)
        for path in ("/brand/unknown.png", "/brand/../web.py"):
            self.assertEqual(self.request(server, path)[0], 404)
        self.assertEqual(self.calls, [])

    def test_bounded_event_log_does_not_reduce_processed_count(self):
        run_id = self.prepared()
        self.child_events = [{"event": "report_finished", "index": index + 1} for index in range(75)]
        self.manager.start(run_id, "synthetic", 3, True)
        run = self.manager.get(run_id)
        run.worker.join(5)
        self.assertEqual(len(run.events), 60)
        self.assertEqual(run.public()["processed_count"], 75)

    def test_launch_failure_is_reported_not_claimed_started(self):
        run_id = self.prepared()
        def fail(*args, **kwargs):
            raise OSError("synthetic launch failure")
        self.manager.popen = fail
        with self.assertRaisesRegex(ValueError, "cli_launch_failed"):
            self.manager.start(run_id, "synthetic", 3, True)
        self.assertEqual(self.manager.get(run_id).state, "error")

    def test_http_start_stop_and_export_use_the_same_adapter(self):
        server = self.server()
        headers = {"X-T2-Session": server.token, "Origin": server.origin, "Content-Type": "application/json"}
        run_id = self.prepared()
        self.gate = threading.Event()
        self.addCleanup(self.gate.set)
        code, _, _ = self.request(server, "/api/start", {"run_id": run_id, "key": "synthetic", "max_requests": 3, "confirmed": True}, headers)
        self.assertEqual(code, 202)
        self.assertEqual(self.request(server, "/api/stop", {"run_id": run_id}, headers)[0], 202)
        self.gate.set()
        self.manager.get(run_id).worker.join(5)
        code, raw, _ = self.request(server, f"/api/result/{run_id}", headers=headers)
        self.assertEqual(code, 200)
        self.assertEqual(json.loads(raw)["entries"], [])
        code, raw, reply_headers = self.request(server, f"/api/download/{run_id}/summary.json", headers=headers)
        self.assertEqual(code, 200)
        self.assertEqual(raw, self.manager.file(run_id, "summary.json").read_bytes())
        self.assertIn('filename="summary.json"', reply_headers["Content-Disposition"])

    def test_non_object_and_cross_origin_posts_do_not_start_a_child(self):
        server = self.server()
        headers = {"X-T2-Session": server.token, "Content-Type": "application/json"}
        self.assertEqual(self.request(server, "/api/prepare", ["bad"], headers)[0], 400)
        headers["Origin"] = "https://unrelated.invalid"
        self.assertEqual(self.request(server, "/api/prepare", {"text": "Fixture"}, headers)[0], 403)
        self.assertEqual(self.calls, [])


if __name__ == "__main__":
    unittest.main()
