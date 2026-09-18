"""Offline end-to-end fault injection, not a replay or model-quality benchmark.

The CLI, Git reader, protocol, controller, writer and review exporter are real.
Only model HTTP transport is replaced; fixture source is read, never executed.
"""
from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from vulngym_t2 import cli, staged_protocol
from vulngym_t2.llm import MODEL, RequestLedger
from vulngym_t2.review_export import export_review


ROOT = Path(__file__).resolve().parents[1]
GHSA = "GHSA-2345-6789-CFGH"
FIXTURE_SOURCE = "def handle(value):\n    return value\n"


def child_environment():
    """Pass an OS/runtime allowlist, never discover or copy credentials."""
    env = {key: os.environ[key] for key in
           ("PATH", "SystemRoot", "WINDIR", "COMSPEC", "TEMP", "TMP") if key in os.environ}
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
               GIT_CONFIG_SYSTEM=os.devnull, GIT_TERMINAL_PROMPT="0",
               GIT_NO_LAZY_FETCH="1", GIT_ALLOW_PROTOCOL="file", GIT_OPTIONAL_LOCKS="0",
               PYTHONDONTWRITEBYTECODE="1", PYTHONPATH=str(ROOT))
    return env


def evidence_from(messages):
    records = {}
    for message in messages:
        if message.get("role") != "user":
            continue
        try:
            body = json.loads(message.get("content", ""))
        except (TypeError, ValueError):
            continue
        if not isinstance(body, dict):
            continue
        for item in body.get("evidence", []) + body.get("tool_results", []):
            if isinstance(item, dict) and item.get("id"):
                records[item["id"]] = item
    return list(records.values())


class SyntheticTransport:
    def __init__(self, sha, scenario):
        self.sha, self.scenario = sha, scenario
        self.requests = 0
        self.read_rounds = 0
        self.annotations = 0

    def snapshot(self, payload):
        evidence = evidence_from(payload["messages"])
        advisory = next(item for item in evidence if item.get("kind") == "advisory")
        read = next((item for item in evidence if item.get("tool") == "read_file" and item.get("success")), None)
        answer = staged_protocol.snapshot_from_state({}, {})
        if read is None or self.scenario == "unknown":
            return answer
        location = lambda line: {"evidence_ref": read["id"], "start_line": line,
                                 "end_line": line, "desc": "Synthetic fixture line, no real vulnerability claim."}
        values = {"commit": self.sha, "vuln_title": "Synthetic pass-through fixture",
                  "vuln_category_l1": "Synthetic category", "vuln_category_l2": "Synthetic subtype",
                  "entry_point": location(1), "critical_operation": location(2), "vuln_ids": [GHSA]}
        for field, value in values.items():
            answer[field] = {"value": value, "status": "supported", "reason": "Synthetic test evidence only.",
                             "evidence_refs": [advisory["id"], read["id"]]}
        answer["commit"]["revision_basis"] = "behavior_at_revision"
        if self.scenario == "missing_field":
            answer.pop("entry_point")
        elif self.scenario == "bad_reference":
            answer["entry_point"]["value"]["evidence_ref"] = "E9999"
            answer["entry_point"]["evidence_refs"] = ["E9999"]
        return answer

    def __call__(self, body, _synthetic_credential, _timeout):
        payload = json.loads(body)
        self.requests += 1
        tools = {item["function"]["name"] for item in payload["tools"]}
        if tools == {"submit_annotation"}:
            self.annotations += 1
            if self.scenario == "cancel_review" and self.annotations == 2:
                raise KeyboardInterrupt
            name, arguments = "submit_annotation", self.snapshot(payload)
            if self.scenario == "native_failure" or (self.scenario == "second_candidate_failure" and self.annotations == 3):
                arguments = {"unexpected_root": True}
        elif tools == {"propose_candidates"}:
            name = "propose_candidates"
            reference = next(item["id"] for item in evidence_from(payload["messages"])
                             if item.get("kind") == "advisory")
            arguments = {"candidates": [{"scope": "Synthetic first scope", "evidence_refs": [reference]},
                                         {"scope": "Synthetic second scope", "evidence_refs": [reference]}]}
        elif len(tools) < 8:  # Existing narrow follow-up stage; no new read loop.
            name, arguments = "finish_reading", {"reason": "no_further_useful_read"}
        else:
            self.read_rounds += 1
            if self.read_rounds % 2:
                name, arguments = "read_file", {"commit": self.sha, "path": "fixture.py",
                                                "start_line": 1, "end_line": 2}
                if self.scenario == "missing_history":
                    arguments["commit"] = "f" * 40
            else:
                name, arguments = "finish_reading", {"reason": "enough_evidence"}
        return json.dumps({"object": "chat.completion", "model": MODEL, "choices": [{"index": 0, "finish_reason": "tool_calls",
            "message": {"role": "assistant", "content": None, "tool_calls": [{"id": "smoke-call",
                "type": "function", "function": {"name": name, "arguments": json.dumps(arguments)}}]}}],
            "usage": {"prompt_tokens": 2, "completion_tokens": 3, "total_tokens": 5}}).encode()


class ResilienceSmokeTests(unittest.TestCase):
    def setUp(self):
        temp_root = os.environ.get("T2_SMOKE_TEMP_ROOT")
        if temp_root is None and os.name == "nt":
            temp_root = "D:/VulnGym-bv2-runtime/tmp"
        self.temporary = tempfile.TemporaryDirectory(prefix="t2-resilience-smoke-", dir=temp_root)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.git = shutil.which("git", path=child_environment().get("PATH"))
        if self.git is None:
            self.skipTest("Git unavailable: offline Git fixture cannot be created")
        self.git_run("init", "--quiet")
        (self.repo / "fixture.py").write_text(FIXTURE_SOURCE, encoding="utf-8")
        self.git_run("add", "--", "fixture.py")
        self.git_run("-c", "user.name=Offline fixture", "-c", "user.email=fixture@example.invalid",
                     "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "Synthetic source only")
        self.sha = self.git_run("rev-parse", "HEAD")
        self.git_run("config", "--local", "remote.origin.url", "https://github.com/example/smoke.git")
        self.advisory = self.root / "advisory.md"
        self.advisory.write_text(f"{GHSA}\nSynthetic fixture, not a vulnerability claim.\n", encoding="utf-8")

    def git_run(self, *args):
        return subprocess.run([self.git, "-c", f"core.hooksPath={os.devnull}", "-C", str(self.repo), *args],
                              check=True, capture_output=True, text=True, timeout=20,
                              env=child_environment()).stdout.strip()

    def run_cli(self, scenario, *, multi=False, requests=8, calls=8, exhausted=False):
        output = self.root / "output"
        ledger_path = self.root / "synthetic-requests.jsonl"
        limit = 1 if exhausted else 24
        if exhausted:
            ledger = RequestLedger(ledger_path, limit=limit)
            try:
                number = ledger.reserve(run_id="synthetic-prefill", case_id="synthetic-prefill")
                ledger.finish(number, status="success", usage={"prompt_tokens": 0, "completion_tokens": 0,
                              "total_tokens": 0}, seconds=0)
            finally:
                ledger.close()
        send = SyntheticTransport(self.sha, scenario)
        stdout, stderr = io.StringIO(), io.StringIO()
        argv = ["--advisory", str(self.advisory), "--repo", str(self.repo), "--output", str(output),
                "--request-ledger", str(ledger_path), "--authorization-limit", str(limit),
                "--key-stdin", "--response-mode", "staged_tool", "--thinking", "disabled",
                "--max-requests", str(requests), "--max-calls-per-report", str(calls)]
        if multi:
            argv.append("--multi-entry")
        original_open = Path.open

        def failing_open(path, mode="r", *args, **kwargs):
            if path == output / "review.jsonl" and mode == "a":
                raise OSError("Synthetic append failure; not an observed provider response")
            return original_open(path, mode, *args, **kwargs)

        with contextlib.ExitStack() as faults, patch("vulngym_t2.transport._post_official_strict", send), \
             patch("vulngym_t2.transport.socket.create_connection", side_effect=AssertionError("Network forbidden")), \
             patch("vulngym_t2.cli.sys.stdin", io.StringIO("synthetic-smoke-no-credential\n")), \
             contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            if scenario == "output_failure":
                faults.enter_context(patch.object(Path, "open", failing_open))
            code = cli.main(argv)
        if scenario == "output_failure":
            self.assertFalse((output / "summary.json").exists())
            self.assertEqual(json.loads(stdout.getvalue())["status"], "error")
            # The actual ledger lock must have been released even on output failure.
            reopened = RequestLedger(ledger_path, limit=limit)
            reopened.close()
            return code, None, [], [], send
        summary = json.loads((output / "summary.json").read_text(encoding="utf-8"))
        reviews = [json.loads(line) for line in (output / "review.jsonl").read_text(encoding="utf-8").splitlines()]
        entries = [json.loads(line) for line in (output / "entries.jsonl").read_text(encoding="utf-8").splitlines()]
        self.assertLessEqual(send.requests, requests)
        self.assertEqual(summary["provider"]["http_attempts"], send.requests)
        self.assertEqual(summary["provider"]["automatic_retries"], 0)
        self.assertEqual(json.loads(stdout.getvalue().splitlines()[-1])["status"], summary["status"])
        self.assertNotIn("synthetic-smoke-no-credential", stdout.getvalue() + stderr.getvalue())
        export_review(output, self.root / "review.md")
        self.assertTrue((self.root / "review.md").is_file())
        self.assertEqual(self.git_run("status", "--porcelain"), "")
        return code, summary, reviews, entries, send

    def test_complete_fixture_uses_real_source_and_exports_fifteen_fields(self):
        code, summary, reviews, entries, send = self.run_cli("complete")
        self.assertEqual(code, 0)
        self.assertEqual(summary["entry_count"], 1)
        self.assertEqual(len(entries[0]), 15)
        self.assertEqual(entries[0]["verify"], 0)
        self.assertEqual(entries[0]["entry_point"]["code"], FIXTURE_SOURCE.splitlines()[0])
        self.assertEqual(reviews[0]["self_review_status"], "completed")
        self.assertEqual(send.annotations, 2)

    def test_output_append_failure_stops_without_publishing_a_summary(self):
        code, _, _, _, send = self.run_cli("output_failure")
        self.assertEqual(code, 2)
        self.assertEqual(send.annotations, 2)

    def test_unknown_fields_remain_a_user_visible_draft(self):
        code, summary, reviews, entries, _ = self.run_cli("unknown")
        self.assertEqual(code, 0)
        self.assertEqual((summary["entry_count"], summary["draft_count"]), (0, 1))
        self.assertEqual(entries, [])
        self.assertEqual(reviews[0]["status"], "draft")

    def test_missing_field_is_not_filled_or_promoted(self):
        _, summary, reviews, entries, _ = self.run_cli("missing_field")
        self.assertEqual(entries, [])
        self.assertEqual(summary["draft_count"], 1)
        self.assertTrue(any(item["field"] == "entry_point" for item in reviews[0]["annotation_errors"]))

    def test_bad_reference_does_not_create_a_complete_entry(self):
        _, summary, reviews, entries, _ = self.run_cli("bad_reference")
        self.assertEqual(entries, [])
        self.assertEqual(summary["draft_count"], 1)
        self.assertNotEqual(reviews[0]["field_reviews"]["entry_point"]["status"], "supported")

    def test_native_format_failure_counts_an_input_without_continuation(self):
        code, summary, _, entries, _ = self.run_cli("native_failure")
        self.assertEqual(code, 2)
        self.assertEqual(entries, [])
        self.assertEqual(summary["format_failure_count"], 1)
        self.assertEqual(summary["case_failures"][0]["failure_kind"], "format")
        self.assertFalse(summary["case_failures"][0]["continued"])

    def test_failed_later_candidate_does_not_downgrade_completed_first(self):
        code, summary, reviews, entries, _ = self.run_cli("second_candidate_failure", multi=True, calls=12, requests=12)
        self.assertEqual(code, 2)
        self.assertEqual(summary["format_failure_count"], 1)
        self.assertEqual(len(entries), 1)
        self.assertEqual(reviews[0]["status"], "complete")
        self.assertEqual(reviews[1]["status"], "draft")

    def test_missing_local_history_stays_unknown_without_fetch(self):
        _, summary, reviews, entries, _ = self.run_cli("missing_history")
        self.assertEqual(entries, [])
        self.assertEqual(summary["draft_count"], 1)
        reads = [item for item in reviews[0]["evidence"] if item.get("tool") == "read_file"]
        self.assertTrue(reads)
        self.assertFalse(reads[0]["success"])
        self.assertTrue(reviews[0]["tool_errors"])
        self.assertNotEqual(reviews[0]["field_reviews"]["commit"]["status"], "supported")

    def test_exhausted_authorization_makes_no_model_transport_call(self):
        code, summary, _, entries, send = self.run_cli("complete", exhausted=True)
        self.assertEqual(code, 2)
        self.assertEqual(send.requests, 0)
        self.assertEqual(entries, [])
        self.assertEqual(summary["provider"]["authorization_http_attempts"], 1)

    def test_cancel_during_self_review_preserves_initial_draft(self):
        code, summary, reviews, entries, send = self.run_cli("cancel_review")
        self.assertEqual(code, 130)
        self.assertEqual(summary["status"], "interrupted")
        self.assertEqual(summary["unprocessed_input_count"], 0)
        self.assertEqual(entries, [])
        self.assertEqual(reviews[0]["status"], "draft")
        self.assertEqual(send.annotations, 2)
        self.assertTrue(reviews[0]["field_reviews"])

    def test_subprocess_help_and_prepare_only_need_no_credentials(self):
        for args, expected in ((["--help"], 0),
                               (["--advisory", str(self.advisory), "--repo", str(self.repo), "--prepare-only"], 0),
                               (["--advisory", str(self.advisory), "--repo", str(self.root / "missing"), "--prepare-only"], 1)):
            with self.subTest(args=args):
                process = subprocess.run([sys.executable, "-B", "-m", "vulngym_t2", *args], cwd=self.root,
                                         env=child_environment(), stdin=subprocess.DEVNULL,
                                         capture_output=True, text=True, timeout=30)
                self.assertEqual(process.returncode, expected, process.stderr)
                if "--prepare-only" in args:
                    self.assertEqual(json.loads(process.stdout)["http_attempts"], 0)


if __name__ == "__main__":
    unittest.main()
