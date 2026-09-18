"""One real alternative source yields the next read to the existing model slot."""
import copy
import json
from types import SimpleNamespace
import unittest

from tests import test_t2_v2_assessed_tool as assessed_fixture
from tests import test_t2_v2_staged_pipeline as fixture
from tests.test_t2_v2_pipeline import job, VULNERABLE, FIXED, evidence_from
from vulngym_t2.pipeline import _ProductionSession


PATH = "src/handler.ts"
TEST_PATH = "tests/handler.test.ts"


class CallerRepo(fixture.MemoryRepo):
    sources = {
        PATH: ["export function gate(ctx) {", "  return ctx.allowed;", "}"],
        TEST_PATH: ["// synthetic test padding " + "x" * 70] * 80 + [
            "export function exercise(ctx) {", "  gate(ctx);", "}"] + ["// trailing test data"] * 40,
        "src/consumer.ts": ["export function consume(value) {", "  persist(value);", "}"],
    }

    def __init__(self, alternative="source"):
        super().__init__()
        self.alternative = alternative

    def call(self, tool, arguments):
        self.calls.append((tool, copy.deepcopy(arguments)))
        commit = arguments.get("commit")
        if tool == "inspect_commit":
            return {"commit": commit, "parents": [], "message": "Synthetic repository change"}
        if tool == "search_code":
            query, paths = arguments["query"], arguments.get("paths")
            matches = [{"file": path, "line": index, "code": code}
                for path, lines in self.sources.items() if not paths or path in paths
                for index, code in enumerate(lines, 1) if query in code]
            if commit == FIXED and self.alternative == "no_match":
                matches = []
            return {"commit": commit, "query": query, "paths": paths, "matches": matches,
                    "complete": True, "truncated": False, "skipped_count": 0}
        if tool != "read_file":
            raise AssertionError(tool)
        path = arguments["path"]
        if commit == FIXED and self.alternative == "failed":
            return {"error": "source_file_unavailable"}
        first = arguments.get("start_line", 1)
        last = min(arguments.get("end_line", 300), len(self.sources[path]))
        lines = self.sources[path][first - 1:last]
        if commit == FIXED and self.alternative in {"empty", "blank"}:
            first, last, lines = 1, 1, ["" if self.alternative == "empty" else "   "]
        return {"commit": VULNERABLE if commit == FIXED and self.alternative == "wrong_sha" else commit,
                "path": "src/unrelated.ts" if commit == FIXED and self.alternative == "wrong_path" else path,
                "start_line": first, "end_line": last, "total_lines": len(self.sources[path]),
                "lines": [{"line": first + offset, "code": line} for offset, line in enumerate(lines)],
                "text": "\n".join(lines), "truncated": False, "has_more": last < len(self.sources[path])}


def seeded_state(client, *, alternative="source", max_calls=8):
    state = _ProductionSession(job(False), client, CallerRepo(alternative), max_calls, 24)
    state.prepare()
    source = state.read_tool("read_file", {"commit": VULNERABLE, "path": PATH, "start_line": 1, "end_line": 3})
    state.read_tool("inspect_commit", {"commit": VULNERABLE})
    state.read_tool("inspect_commit", {"commit": FIXED})
    state.result["fields"]["commit"] = VULNERABLE
    state.result["field_reviews"]["commit"].update(status="uncertain", revision_basis="inspected_only")
    state.result["field_reviews"]["entry_point"].update(status="uncertain", evidence_refs=[source["id"]],
        suggested_value={"evidence_ref": source["id"], "start_line": 1, "end_line": 1})
    state.messages.append({"role": "user", "content": json.dumps({"evidence": state.result["evidence"]})})
    state.drafted, state.initial_valid_updates = True, 1
    state.result["initial_draft_status"] = "accepted"
    return state


class AlternativeHandoffControllerTests(unittest.TestCase):
    def client(self, *, staged=True, multi=False):
        return SimpleNamespace(response_mode="staged_tool" if staged else "strict_tool",
            annotation_format="assessed_tool" if staged else "snapshot_tool", multi_entry=multi,
            halted=None, remaining_requests=16)

    def test_real_source_replaces_caller_chain_and_keeps_more_context_without_field_changes(self):
        deferred = seeded_state(self.client())
        original = copy.deepcopy(deferred.result["field_reviews"])
        deferred.navigate_entry_context({}, defer_after_alternative=True)
        continued = seeded_state(self.client())
        continued.navigate_entry_context({})  # Existing no-followup navigation contract.
        self.assertFalse(any(args.get("path") == TEST_PATH for tool, args in deferred.repo.calls))
        self.assertTrue(any(tool == "read_file" and args.get("path") == TEST_PATH for tool, args in continued.repo.calls))
        self.assertEqual(deferred.result["field_reviews"], original)
        self.assertEqual(deferred.result["fields"]["commit"], VULNERABLE)
        self.assertEqual(deferred.result["model_calls"], 0)
        self.assertLess(deferred.result["tool_calls"], continued.result["tool_calls"])
        self.assertLess(sum(len(row["content"]) for row in deferred.messages),
                        sum(len(row["content"]) for row in continued.messages))
        self.assertTrue(deferred.followup_context_fits())
        self.assertEqual(deferred.review_instruction_budget(), continued.review_instruction_budget())

    def test_unsuccessful_or_non_source_alternatives_keep_original_caller_path(self):
        for mode in ("no_match", "failed", "empty", "blank", "wrong_sha", "wrong_path"):
            with self.subTest(mode=mode):
                state = seeded_state(self.client(), alternative=mode)
                state.navigate_entry_context({}, defer_after_alternative=True)
                self.assertTrue(any(tool == "search_code" and args.get("commit") == FIXED
                                    for tool, args in state.repo.calls))
                if mode != "no_match":
                    self.assertTrue(any(row["action"] == "alternative_snapshot_read"
                                        for row in state.result["actions"]))
                self.assertTrue(any(tool == "read_file" and args.get("path") == TEST_PATH
                                    for tool, args in state.repo.calls))
                self.assertTrue(any(row["action"] == "entry_navigation" for row in state.result["actions"]))

    def test_multi_and_legacy_keep_original_caller_path_even_with_handoff_requested(self):
        for settings in ({"multi": True}, {"staged": False}):
            with self.subTest(settings=settings):
                state = seeded_state(self.client(**settings))
                state.navigate_entry_context({}, defer_after_alternative=True)
                self.assertTrue(any(tool == "read_file" and args.get("path") == TEST_PATH
                                    for tool, args in state.repo.calls))


class AlternativeHandoffWireTests(unittest.TestCase):
    setUp = assessed_fixture.AssessedToolTests.setUp
    client = assessed_fixture.AssessedToolTests.client

    def run_finished(self, *, explicit_path=None, max_calls=8, client_limit=16):
        payloads, decisions = [], []
        def send(body, *_):
            payload = json.loads(body)
            payloads.append(payload)
            if "tools" not in payload:
                return assessed_fixture.envelope(content=assessed_fixture.NOTE)
            names = [row["function"]["name"] for row in payload["tools"]]
            if names == ["submit_annotation"]:
                return assessed_fixture.envelope(call=fixture.annotation())
            decisions.append(payload)
            if explicit_path and len(decisions) == 1:
                return assessed_fixture.envelope(call=("read_file", {
                    "commit": VULNERABLE, "path": explicit_path, "start_line": 1, "end_line": 3}))
            return assessed_fixture.envelope(call=fixture.FINISH)
        started_before = self.ledger.started
        client = self.client(send, max_requests=client_limit)
        state = seeded_state(client, max_calls=max_calls)
        state.finish_draft()
        self.assertEqual(state.result["model_calls"], client.calls)
        self.assertEqual(self.ledger.started - started_before, client.calls)
        self.assertEqual(client.summary()["automatic_retries"], 0)
        self.assertLessEqual(client.calls, min(max_calls, client_limit))
        self.assertEqual(state.result["self_review_status"], "completed")
        return state, payloads, decisions

    def test_existing_followup_sees_actual_alternative_then_explicit_consumer_without_auto_test(self):
        state, payloads, decisions = self.run_finished(explicit_path="src/consumer.ts")
        self.assertEqual(len(decisions), 2)
        before_decision = evidence_from(decisions[0]["messages"])
        self.assertTrue(any(row.get("tool") == "read_file" and row["result"].get("commit") == FIXED
                            for row in before_decision))
        self.assertFalse(any(row.get("result", {}).get("path") == TEST_PATH for row in before_decision))
        self.assertFalse(any(tool == "search_code" and not args.get("paths") for tool, args in state.repo.calls))
        self.assertTrue(any(row.get("tool") == "read_file" and row["arguments"].get("path") == "src/consumer.ts"
                            and row.get("success") for row in state.result["evidence"]))
        self.assertEqual(state.result["model_calls"], 4)  # read, finish, review assessment/encoding
        self.assertIsNone(state.result["fields"].get("commit"))
        self.assertTrue(all(sum(len(m["content"]) for m in p["messages"]) <= 100_000 for p in payloads))

    def test_explicit_model_test_read_is_still_allowed(self):
        state, _, decisions = self.run_finished(explicit_path=TEST_PATH)
        self.assertEqual(len(decisions), 2)
        reads = [row for row in state.result["actions"] if row.get("tool") == "read_file"]
        test_receipt = next(row for row in state.result["evidence"] if row.get("arguments", {}).get("path") == TEST_PATH)
        self.assertTrue(any(row.get("evidence_ref") == test_receipt["id"] and row.get("automatic") is False for row in reads))

    def test_insufficient_local_or_client_followup_reserve_keeps_original_navigation(self):
        for local, global_limit in ((3, 16), (8, 3)):
            with self.subTest(local=local, global_limit=global_limit):
                state, _, decisions = self.run_finished(max_calls=local, client_limit=global_limit)
                self.assertEqual(decisions, [])
                self.assertTrue(any(tool == "read_file" and args.get("path") == TEST_PATH
                                    for tool, args in state.repo.calls))
                self.assertEqual(state.result["model_calls"], 2)


if __name__ == "__main__":
    unittest.main()
