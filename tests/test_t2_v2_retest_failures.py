"""Regressions from observed error shapes, using only synthetic responses.

These are not replays: the real raw completion was not retained. The injected
malformed tool arguments must remain a visible failure without another send.
"""
import copy
from contextlib import ExitStack
from html import unescape
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from vulngym_t2 import annotation_rules, staged_protocol, transport
from vulngym_t2.llm import DeepSeekClient, MODEL, ProviderError, RequestLedger
from vulngym_t2.output import BatchWriter, finalize_result
from vulngym_t2.pipeline import ENTRY_FIELDS, _ProductionSession, _reason_citation_feedback, produce
from vulngym_t2.report import build_assessment
from vulngym_t2.repository import RepoReader
from vulngym_t2.review_export import export_review
from tests.test_t2_v2_pipeline import VULNERABLE, evidence_from, job
from tests.test_t2_v2_staged_pipeline import MemoryRepo, READ, full_annotation


def envelope(tool, arguments):
    return json.dumps({"object": "chat.completion", "model": MODEL,
        "choices": [{"index": 0, "finish_reason": "tool_calls", "message": {
            "role": "assistant", "content": None, "tool_calls": [{"id": "synthetic-call",
            "type": "function", "function": {"name": tool, "arguments": arguments}}]}}],
        "usage": {"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5}}).encode()


class MissingHeadRepo(MemoryRepo):
    def info(self):
        return {**super().info(), "head": None, "errors": ["commit_unavailable"]}

    def call(self, tool, arguments):
        if tool == "list_refs":
            self.calls.append((tool, copy.deepcopy(arguments)))
            return {"refs": [{"name": "refs/heads/local", "commit": VULNERABLE}]}
        return super().call(tool, arguments)


class UnknownClient:
    response_mode = "staged_tool"
    multi_entry = False
    halted = None

    def __init__(self):
        self.messages = []

    def complete(self, messages, *, stage):
        self.messages.append(copy.deepcopy(messages))
        return staged_protocol.normalize_calls([{
            "tool": "submit_annotation", "arguments": staged_protocol.snapshot_from_state({}, {})}], stage)


class RetestFailureTests(unittest.TestCase):
    def test_actual_appended_instruction_is_in_the_context_limit(self):
        for extra in (0, 1):
            client = UnknownClient()
            session = _ProductionSession(job(False), client, MemoryRepo(), 2, 0)
            session.prepare()
            system_size = len(annotation_rules.TASK_RULES + "\n" + annotation_rules.for_phase("annotation"))
            wire_size = len(staged_protocol.instruction("annotation"))
            session.messages = [{"role": "system", "content": "replaced"},
                                {"role": "user", "content": "x" * (100_000 - system_size - wire_size + extra)}]
            session.complete("draft")
            self.assertEqual(len(client.messages), 1 - extra)
            self.assertEqual(session.result["model_calls"], 1 - extra)

    def test_citation_feedback_is_bounded_and_reaches_original_self_review(self):
        issue = {"evidence_ref": "E0010", "start_line": 1, "end_line": 20,
                 "visible_start_line": 1, "visible_end_line": 2,
                 "code": "reason_citation_out_of_bounds", "severity": "error"}
        massive = {"reason_citation_checks": {field: {"citations": [issue] * 16} for field in ENTRY_FIELDS}}
        packet = _reason_citation_feedback(massive)
        self.assertLessEqual(len(json.dumps(packet, ensure_ascii=False, separators=(",", ":"))), 3000)
        self.assertGreater(packet["omitted"], 0)

        class CitationClient(UnknownClient):
            def complete(self, messages, *, stage):
                self.messages.append(copy.deepcopy(messages))
                if len(self.messages) == 1:
                    return staged_protocol.normalize_calls([{"tool": READ[0], "arguments": READ[1]}], stage)
                tool, arguments = full_annotation({"messages": messages})
                ref = next(item["id"] for item in evidence_from(messages) if item.get("tool") == "read_file")
                arguments["entry_point"]["reason"] = ref + (":1-20" if len(self.messages) == 2 else ":1")
                return staged_protocol.normalize_calls([{"tool": tool, "arguments": arguments}], stage)

        client, repo = CitationClient(), MemoryRepo()
        supplied = job(False)
        result = produce(supplied, client, repo, max_calls=3)
        feedback = next(action["reason_citation_checks"] for action in result["actions"]
                        if action["action"] == "draft_validation")
        self.assertEqual(feedback["issues"][0]["field"], "entry_point")
        self.assertEqual(feedback["issues"][0]["visible_end_line"], 2)
        self.assertIn("reason_citation_checks", json.dumps(client.messages[-1]))
        self.assertEqual(result["model_calls"], 3)
        self.assertEqual(result["self_review_status"], "completed")
        final = finalize_result(supplied, result, repo)
        self.assertIsNotNone(final["entry"])
        self.assertEqual(final["review"]["reason_citation_checks"]["entry_point"]["citations"][0]["code"], "covered")

    def test_known_missing_head_supplies_refs_once_without_selecting_a_commit(self):
        client, repo = UnknownClient(), MissingHeadRepo()
        result = produce(job(False), client, repo, max_calls=2, max_tool_calls=1)
        refs = [item for item in evidence_from(client.messages[0]) if item.get("tool") == "list_refs"]
        self.assertEqual(len(refs), 1)
        self.assertTrue(refs[0]["success"])
        self.assertEqual(repo.calls, [("list_refs", {"limit": 8})])
        self.assertEqual(result["tool_calls"], 1)
        self.assertNotIn("commit", result["fields"])
        self.assertEqual(result["model_calls"], 2)

    def test_real_missing_head_repository_prefetches_refs_with_reader_defaults(self):
        git = shutil.which("git")
        if git is None:
            self.skipTest("Git unavailable: cannot create the offline object fixture")
        temp_root = "D:/VulnGym-bv2-runtime/tmp" if os.name == "nt" else None
        with tempfile.TemporaryDirectory(prefix="t2-missing-head-", dir=temp_root) as temporary:
            repo_path = Path(temporary) / "fixture.git"
            repo_path.mkdir()
            env = {key: os.environ[key] for key in
                   ("PATH", "SystemRoot", "WINDIR", "COMSPEC", "TEMP", "TMP") if key in os.environ}
            env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_SYSTEM=os.devnull,
                       GIT_CONFIG_GLOBAL=os.devnull, GIT_TERMINAL_PROMPT="0",
                       GIT_NO_LAZY_FETCH="1", GIT_ALLOW_PROTOCOL="file", GIT_OPTIONAL_LOCKS="0")

            def local_git(*arguments, input_text=None):
                return subprocess.run(
                    [git, "-c", f"core.hooksPath={os.devnull}", "-C", str(repo_path), *arguments],
                    input=input_text, check=True, capture_output=True, text=True,
                    timeout=10, env=env,
                ).stdout.strip()

            local_git("init", "--bare", "--quiet")
            # An empty tree supplies real history without any target source file.
            tree = local_git("mktree", input_text="")
            commit = local_git("-c", "user.name=Synthetic Fixture",
                               "-c", "user.email=fixture@example.invalid",
                               "-c", "commit.gpgsign=false", "commit-tree", tree,
                               "-m", "Synthetic navigation only")
            reference = "refs/remotes/origin/fixture"
            local_git("update-ref", reference, commit)
            local_git("symbolic-ref", "HEAD", "refs/heads/intentionally-missing")
            repo, client = RepoReader(repo_path), UnknownClient()
            self.assertIsNone(repo.info()["head"])
            with self.assertRaisesRegex(ValueError, "invalid_ref_prefix"):
                repo.call("list_refs", {"prefix": "", "limit": 8})

            supplied = job(False)
            supplied["repo_path"] = str(repo_path)
            result = produce(supplied, client, repo, max_calls=2, max_tool_calls=1)
            refs = [item for item in evidence_from(client.messages[0]) if item.get("tool") == "list_refs"]
            self.assertEqual(len(refs), 1)
            self.assertTrue(refs[0]["success"])
            self.assertEqual(refs[0]["arguments"], {"limit": 8})
            self.assertIsNone(refs[0]["result"]["prefix"])
            self.assertEqual([(row["name"], row["commit"]) for row in refs[0]["result"]["refs"]],
                             [(reference, commit)])
            self.assertEqual(result["tool_calls"], 1)
            self.assertEqual(result["model_calls"], 2)
            self.assertNotIn("commit", result["fields"])
            self.assertNotIn("suggested_value", result["field_reviews"]["commit"])
            self.assertNotEqual(result["field_reviews"]["commit"]["status"], "supported")
            self.assertIsNone(repo.info()["head"])

    def test_reference_prefetch_does_not_expand_zero_budget_or_valid_head(self):
        for repo, calls, tools in ((MissingHeadRepo(), 0, 4), (MissingHeadRepo(), 2, 0), (MemoryRepo(), 2, 4)):
            with self.subTest(repo=type(repo).__name__, calls=calls, tools=tools):
                result = produce(job(False), UnknownClient(), repo, max_calls=calls, max_tool_calls=tools)
                self.assertFalse(any(tool == "list_refs" for tool, _ in repo.calls))
                self.assertEqual(result["tool_calls"], 0)

    def test_public_diagnostics_do_not_echo_answer_unknown_labels_or_boolean_coordinates(self):
        diagnostic = {"phase": "parse_completion_json", "json_error_kind": "JSONDecodeError",
                      "json_decode_message": "Expecting ',' delimiter", "json_decode_line": 1,
                      "json_decode_column": 40, "answer_characters": 39, "format_error_isolatable": True,
                      "refusal_present": False, "raw_response": "not-for-export", "arbitrary": "not-for-export"}
        before = copy.deepcopy(diagnostic)
        result = transport.public_failure_diagnostics(diagnostic)
        self.assertNotIn("not-for-export", json.dumps(result))
        self.assertEqual(result, transport.public_failure_diagnostics(result))
        self.assertEqual(diagnostic, before)
        self.assertEqual(transport.public_failure_diagnostics({"phase": "unknown_secret_phase",
            "json_decode_message": "untrusted server message", "json_decode_line": True,
            "json_decode_column": -1, "answer_characters": 10**20, "refusal_present": "false"}), {})

    def test_public_tool_failure_metadata_is_bounded_idempotent_and_read_only(self):
        diagnostic = {"tool_call_count": 4, "unknown_tool_count": 1,
                      "tool_names": ["search_code", "read_file", "search_code"],
                      "arguments": "not-for-export", "unknown_name": "not-for-export"}
        before = copy.deepcopy(diagnostic)
        expected = {"tool_call_count": 4, "unknown_tool_count": 1,
                    "tool_names": ["read_file", "search_code"]}
        self.assertEqual(transport.public_failure_diagnostics(diagnostic), expected)
        self.assertEqual(transport.public_failure_diagnostics(expected), expected)
        self.assertEqual(diagnostic, before)
        for invalid in ({"tool_call_count": True, "unknown_tool_count": -1,
                         "tool_names": ["read_file", "not-for-export"]},
                        {"tool_call_count": 10**20, "unknown_tool_count": "1",
                         "tool_names": "not-for-export"}):
            with self.subTest(invalid=invalid):
                self.assertEqual(transport.public_failure_diagnostics(invalid), {})

    def test_bad_self_review_json_keeps_draft_and_public_parse_layer_without_retry(self):
        with ExitStack() as stack:
            tmp = stack.enter_context(tempfile.TemporaryDirectory(prefix="t2-retest-regression-"))
            root = Path(tmp).resolve()
            ledger = RequestLedger(root / "ledger.jsonl", limit=8)
            stack.callback(ledger.close)
            sent = []

            def send(body, _dummy_key, _timeout):
                payload = json.loads(body)
                sent.append(payload)
                if len(sent) == 1:
                    return envelope(READ[0], json.dumps(READ[1]))
                if len(sent) == 2:
                    tool, arguments = full_annotation(payload)
                    return envelope(tool, json.dumps(arguments))
                if len(sent) == 3:
                    # Valid HTTP envelope, malformed JSON in a known tool argument.
                    return envelope("submit_annotation", '{"commit":{"value":"not-for-export"}')
                self.fail("An unplanned fourth HTTP request was sent")

            client = DeepSeekClient("synthetic-test-credential", ledger, run_id="synthetic-retest",
                max_requests=3, response_mode="staged_tool", thinking="disabled", send=send)
            stack.callback(client.close)
            supplied, repo = job(False), MemoryRepo()
            result = produce(supplied, client, repo, max_calls=3)
            final = finalize_result(supplied, result, repo)
            self.assertEqual(result["initial_draft_status"], "accepted")
            self.assertEqual(result["self_review_status"], "failed")
            self.assertIsNone(final["entry"])
            self.assertTrue(final["review"]["draft_fields"]["entry_point"])
            self.assertEqual(final["review"]["prompt_revision"], staged_protocol.PROMPT_REVISION)
            failure = next(row for row in final["review"]["actions"] if row["action"] == "model_failure")
            self.assertEqual(failure["code"], "deepseek_response_invalid_json")
            self.assertEqual(failure["stage"], "self_review")
            self.assertEqual(failure["diagnostics"]["phase"], "parse_completion_json")
            self.assertEqual(failure["diagnostics"]["json_decode_message"], "Expecting ',' delimiter")
            with self.assertRaises(ProviderError):
                client.complete(sent[-1]["messages"], stage="annotation")
            self.assertEqual(len(sent), 3)
            self.assertEqual(ledger.started, 3)
            self.assertEqual(ledger.usage_unknown, 0)
            self.assertFalse(ledger._pending)
            writer = BatchWriter(root / "run")
            writer.record(supplied, final)
            writer.finish({"status": "completed_with_errors", "format_failure_count": 1,
                           "requested_input_count": 1, "unprocessed_input_count": 0,
                           "provider": client.summary()})
            export_review(root / "run", root / "review.md")
            report = build_assessment(root / "run").read_text(encoding="utf-8")
            self.assertIn("parse_completion_json", report.replace("\\_", "_"))
            self.assertIn("parse_completion_json", unescape((root / "review.md").read_text(encoding="utf-8")))
            persisted = "\n".join(path.read_text(encoding="utf-8") for path in root.rglob("*")
                                  if path.is_file() and path.suffix != ".lock")
            self.assertNotIn("not-for-export", persisted)
            self.assertNotIn("synthetic-test-credential", persisted)


if __name__ == "__main__":
    unittest.main()
