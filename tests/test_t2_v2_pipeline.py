"""Focused, offline protocol tests; fixtures are not a real-model benchmark."""

import copy
import json
import unittest

from vulngym_t2.pipeline import ENTRY_FIELDS, READ_TOOLS, produce


VULNERABLE = "a" * 40
FIXED = "b" * 40
SOURCE = ["def serve(request):", "    return execute(request.args['expression'])"]


def job(fixes=True):
    return {
        "entry_id": "entry-00001", "report_id": "GHSA-2222-3333-4444",
        "source_link": "https://github.com/advisories/GHSA-2222-3333-4444",
        "repo_url": "https://github.com/example/service", "repo_path": "D:/unused",
        "documents": [{"name": "advisory", "kind": "advisory", "text":
            "CVE-2026-12345: Expression execution. A public expression argument is passed to execute without a restriction. The patch replaces execute."}],
        "fix_commits": [FIXED] if fixes else [],
    }


class StubRepo:
    def __init__(self, missing_fix=False):
        self.calls = []
        self.missing_fix = missing_fix

    def info(self):
        return {"repo_path": "D:/unused", "repo_url": "https://github.com/example/service",
                "head": VULNERABLE, "shallow": False}

    def call(self, tool, arguments):
        self.calls.append((tool, copy.deepcopy(arguments)))
        if tool not in READ_TOOLS:
            raise AssertionError("unexposed tool reached repository")
        if tool == "inspect_commit":
            if self.missing_fix:
                raise ValueError("commit not available")
            return {"commit": FIXED, "parents": [VULNERABLE],
                    "changed_paths": ["service/handler.py"], "message": "restrict expression execution"}
        if tool == "read_diff":
            return {"before": VULNERABLE, "after": FIXED, "paths": ["service/handler.py"],
                    "diff": "-    return execute(request.args['expression'])\n+    return allowed_expression(request.args['expression'])"}
        if tool == "read_file":
            return {"commit": arguments["commit"], "path": arguments["path"],
                    "start_line": 1, "end_line": 2, "total_lines": 2,
                    "text": "\n".join(SOURCE),
                    "lines": [{"line": i + 1, "code": code} for i, code in enumerate(SOURCE)]}
        if tool == "list_files":
            return {"commit": arguments["commit"], "paths": ["service/handler.py"]}
        return {"commit": arguments["commit"], "matches": []}


class StubClient:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.messages = []

    def complete(self, messages):
        self.messages.append(copy.deepcopy(messages))
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response(messages) if callable(response) else copy.deepcopy(response)


def evidence_from(messages):
    records = {}
    for message in messages:
        if message["role"] != "user":
            continue
        try:
            body = json.loads(message["content"])
        except json.JSONDecodeError:
            continue
        if not isinstance(body, dict):
            continue
        for item in body.get("evidence", []) + body.get("tool_results", []) + body.get("additional_shared_evidence", []):
            if isinstance(item, dict) and item.get("id"):
                records[item["id"]] = item
    return list(records.values())


def choose_source(messages):
    records = evidence_from(messages)
    inspected = next((e for e in records if e.get("tool") == "inspect_commit" and e.get("success")), None)
    if inspected:
        commit = inspected["result"]["parents"][0]
        path = inspected["result"]["changed_paths"][0]
    else:
        commit = next(e["result"]["head"] for e in records if e["kind"] == "repository")
        path = "service/handler.py"
    return {"action": "tools", "plan": "Read changed expression handler to compare actual source with the advisory.",
            "calls": [{"tool": "read_file", "arguments": {"commit": commit, "path": path}}]}


def source_draft(messages):
    records = evidence_from(messages)
    advisory = next(e for e in records if e["kind"] == "advisory")
    read = next(e for e in records if e.get("tool") == "read_file" and e["success"])
    data = read["result"]
    fields = {
        "vuln_ids": ["CVE-2026-12345", "GHSA-2222-3333-4444"],
        "commit": data["commit"], "vuln_title": "Expression execution",
        "vuln_category_l1": "Code injection", "vuln_category_l2": "Expression injection",
        "entry_point": {"file": data["path"], "line": 1, "code": data["lines"][0]["code"]},
        "critical_operation": {"file": data["path"], "line": 2, "code": data["lines"][1]["code"]},
        "verify": 1,
    }
    reviews = {}
    for name in fields:
        refs = [advisory["id"], read["id"]] if name in {"commit", "entry_point", "critical_operation"} else [advisory["id"]]
        reviews[name] = {"status": "supported", "reason": "The shown source and advisory agree on the unrestricted expression behavior.", "evidence_refs": refs}
    reviews["commit"]["revision_basis"] = "behavior_at_revision"
    return {"action": "draft", "fields": fields, "field_reviews": reviews, "summary": "Source inspected; automatic assessment only."}


def retain_review(_messages):
    return {"action": "draft", "fields": {}, "field_reviews": {}, "summary": "Retain this draft after reviewing shown evidence."}


def metadata_job():
    value = job(False)
    metadata = {"ghsa_id": value["report_id"], "title": "Supplied advisory title",
                "vuln_ids": ["CVE-2026-12345", value["report_id"]]}
    value["advisory_metadata"] = copy.deepcopy(metadata)
    value["documents"][0]["advisory_metadata"] = copy.deepcopy(metadata)
    return value


class PipelineTests(unittest.TestCase):
    def test_commit_basis_is_required_despite_a_source_read(self):
        for basis in (None, "inspected_only", "unknown", "invented", []):
            with self.subTest(basis=basis):
                def draft(messages):
                    reply = source_draft(messages)
                    if basis is None:
                        reply["field_reviews"]["commit"].pop("revision_basis")
                    else:
                        reply["field_reviews"]["commit"]["revision_basis"] = basis
                    return reply
                result = produce(job(False), StubClient(choose_source, draft, retain_review), StubRepo())
                self.assertNotIn("commit", result["fields"])
                review = result["field_reviews"]["commit"]
                self.assertEqual(review["status"], "uncertain")
                self.assertEqual(review["suggested_value"], VULNERABLE)
                self.assertEqual(review["revision_basis"], basis if basis in ("inspected_only", "unknown") else "unknown")
                self.assertEqual(result["fields"]["vuln_title"], "Expression execution")
                self.assertEqual(result["model_calls"], 3)

    def test_commit_basis_can_be_corrected_in_the_existing_self_review(self):
        def incomplete(messages):
            reply = source_draft(messages)
            reply["field_reviews"]["commit"].pop("revision_basis")
            return reply

        def correct(messages):
            self.assertIn("revision_basis", messages[-1]["content"])
            return source_draft(messages)

        result = produce(job(False), StubClient(choose_source, incomplete, correct), StubRepo())
        self.assertEqual(result["fields"]["commit"], VULNERABLE)
        self.assertEqual(result["field_reviews"]["commit"]["revision_basis"], "behavior_at_revision")
        self.assertEqual(result["model_calls"], 3)
        self.assertEqual(result["tool_calls"], 1)
        self.assertEqual(sum(item.get("stage") == "self_review" for item in result["actions"]), 1)

    def test_commit_basis_with_only_history_evidence_remains_uncertain(self):
        draft = {"action": "draft", "fields": {"commit": VULNERABLE}, "field_reviews": {
            "commit": {"status": "supported", "revision_basis": "behavior_at_revision",
                       "reason": "A claimed mechanism at this parent has not actually been read.", "evidence_refs": ["E0004", "E0005"]}}}
        result = produce(job(), StubClient(draft, retain_review), StubRepo(), max_calls=2)
        self.assertNotIn("commit", result["fields"])
        self.assertEqual(result["field_reviews"]["commit"]["suggested_value"], VULNERABLE)
        self.assertEqual(result["field_reviews"]["commit"]["revision_basis"], "behavior_at_revision")
        self.assertEqual(result["model_calls"], 2)

    def test_no_fix_input_can_request_local_history_before_source_reads(self):
        class HistoryRepo(StubRepo):
            def call(self, tool, arguments):
                if tool in {"list_refs", "search_history"}:
                    self.calls.append((tool, copy.deepcopy(arguments)))
                    if tool == "list_refs":
                        return {"refs": [{"name": "refs/tags/v1", "commit": VULNERABLE}], "truncated": False}
                    return {"commit": FIXED, "matches": [{"commit": FIXED, "parents": [VULNERABLE],
                            "subject": "CVE-2026-12345 expression restriction"}], "truncated": False,
                            "negative_result_conclusive": False}
                return super().call(tool, arguments)

        def inspect_found(messages):
            history = next(row for row in evidence_from(messages) if row.get("tool") == "search_history")
            return {"action": "tools", "plan": "Inspect the candidate, not assume it is vulnerable.",
                    "calls": [{"tool": "inspect_commit", "arguments": {"commit": history["result"]["matches"][0]["commit"]}}]}

        repo = HistoryRepo()
        client = StubClient(
            {"action": "tools", "calls": [{"tool": "list_refs", "arguments": {"prefix": "refs/tags/", "limit": 5}}]},
            {"action": "tools", "calls": [{"tool": "search_history", "arguments": {"query": "CVE-2026-12345", "limit": 5}}]},
            inspect_found, choose_source, source_draft, retain_review)
        result = produce(job(False), client, repo, max_calls=6)
        self.assertEqual([name for name, _ in repo.calls], ["list_refs", "search_history", "inspect_commit", "read_file"])
        self.assertEqual(result["model_calls"], 6)
        self.assertEqual(result["fields"]["commit"], VULNERABLE)
        self.assertEqual(result["fields"]["verify"], 0)
        self.assertTrue(any(row.get("tool") == "search_history" and row["success"] for row in result["evidence"]))

    def test_history_clues_alone_do_not_fill_a_vulnerable_commit(self):
        class HistoryRepo(StubRepo):
            def call(self, tool, arguments):
                self.calls.append((tool, arguments))
                return {"refs": [{"name": "refs/tags/old-release", "commit": VULNERABLE}], "truncated": False}
        result = produce(job(False), StubClient(
            {"action": "tools", "calls": [{"tool": "list_refs", "arguments": {}}]},
            retain_review, retain_review), HistoryRepo(), max_calls=3)
        self.assertNotIn("commit", result["fields"])
        self.assertNotIn("entry_point", result["fields"])
        self.assertEqual(result["field_reviews"]["commit"]["status"], "missing")

    def test_existing_self_review_receives_real_validation_feedback(self):
        def malformed(messages):
            response = source_draft(messages)
            response["fields"]["critical_operation"]["code"] = "not the source code"
            return response

        def correct(messages):
            review_instruction = messages[-1]["content"]
            self.assertIn("check desc and reason", review_instruction)
            self.assertIn("fix/parent/selected SHA roles", review_instruction)
            self.assertIn("advisory-only premises", review_instruction)
            feedback = [json.loads(message["content"])["draft_validation"]
                        for message in messages if '"draft_validation":' in message["content"]][-1]
            self.assertTrue(any(item["field"] == "critical_operation" for item in feedback["errors"]))
            return source_draft(messages)

        result = produce(job(), StubClient(choose_source, malformed, correct), StubRepo())
        self.assertEqual(result["model_calls"], 3)
        self.assertEqual(result["tool_calls"], 3)
        self.assertEqual(result["fields"]["critical_operation"]["code"], SOURCE[1])
        self.assertEqual(sum(action["action"] == "draft_validation" for action in result["actions"]), 1)

    def test_complete_field_path_uses_actual_reads_and_one_self_review(self):
        repo = StubRepo()
        client = StubClient(choose_source, source_draft, retain_review)
        result = produce(job(), client, repo)
        self.assertEqual(set(result["fields"]), set(ENTRY_FIELDS))
        self.assertEqual(result["fields"]["critical_operation"]["code"], SOURCE[1])
        self.assertEqual(result["fields"]["verify"], 0)
        self.assertEqual(result["model_calls"], 3)
        self.assertEqual(result["tool_calls"], 3)
        self.assertEqual(result["self_review_status"], "completed")
        self.assertEqual([name for name, _ in repo.calls], ["inspect_commit", "read_diff", "read_file"])
        self.assertEqual([a["stage"] for a in result["actions"] if a["action"] == "model_call"],
                         ["plan_and_read", "plan_and_read", "self_review"])
        self.assertEqual(client.messages[1][-2]["role"], "assistant")
        self.assertIn("tool_results", client.messages[1][-1]["content"])
        self.assertTrue(all(len("".join(m["content"] for m in messages)) <= 100_000 for messages in client.messages))

    def test_missing_fix_does_not_abort_or_make_parent_vulnerable(self):
        repo = StubRepo(missing_fix=True)

        def partial(messages):
            reply = source_draft(messages)
            reply["field_reviews"]["commit"].update(status="uncertain", reason="Without available history the affected revision is not established.")
            return reply

        client = StubClient(choose_source, partial, retain_review)
        result = produce(job(), client, repo)
        self.assertEqual(result["model_calls"], 3)
        self.assertEqual(result["fields"]["vuln_title"], "Expression execution")
        self.assertNotIn("commit", result["fields"])
        self.assertEqual(result["field_reviews"]["commit"]["suggested_value"], VULNERABLE)
        self.assertEqual(result["field_reviews"]["entry_point"]["status"], "uncertain")
        self.assertTrue(any("inspect_commit failed" in error for error in result["errors"]))

    def test_self_review_transport_failure_preserves_useful_draft(self):
        for response in (TimeoutError("do-not-log-secret"), json.JSONDecodeError("bad JSON", "", 0),
                         {"action": "tools", "calls": []}, {"action": "draft", "fields": []}):
            with self.subTest(response=type(response).__name__):
                client = StubClient(choose_source, source_draft, response)
                result = produce(job(), client, StubRepo())
                self.assertEqual(result["fields"]["vuln_title"], "Expression execution")
                self.assertEqual(result["fields"]["commit"], VULNERABLE)
                self.assertEqual(result["self_review_status"], "failed")
                self.assertEqual(result["model_calls"], 3)
                self.assertTrue(result["errors"])
                self.assertNotIn("do-not-log-secret", json.dumps(result))
        result = produce(job(False), StubClient(retain_review), StubRepo(), max_calls=1)
        self.assertEqual(result["self_review_status"], "not_requested")
        self.assertEqual(result["model_calls"], 1)

    def test_first_transport_failure_preserves_metadata_and_history_without_commit_guess(self):
        result = produce(job(), StubClient(ConnectionError("private-token")), StubRepo())
        self.assertEqual(result["fields"]["project"], "service")
        self.assertEqual(result["fields"]["report_id"], "GHSA-2222-3333-4444")
        self.assertEqual(result["tool_calls"], 2)
        self.assertNotIn("commit", result["fields"])
        self.assertEqual(result["field_reviews"]["commit"]["status"], "missing")
        self.assertNotIn("private-token", json.dumps(result))

    def test_supplied_advisory_fields_survive_first_transport_failure_with_matching_evidence(self):
        supplied = metadata_job()
        result = produce(supplied, StubClient(ConnectionError("private-token")), StubRepo())
        self.assertEqual(result["fields"]["vuln_title"], supplied["advisory_metadata"]["title"])
        self.assertEqual(result["fields"]["vuln_ids"], supplied["advisory_metadata"]["vuln_ids"])
        records = {item["id"]: item for item in result["evidence"]}
        for name in ("vuln_title", "vuln_ids"):
            self.assertEqual(result["field_reviews"][name]["status"], "supported")
            for ref in result["field_reviews"][name]["evidence_refs"]:
                self.assertEqual(records[ref]["kind"], "advisory")
                self.assertEqual(records[ref]["advisory_metadata"]["ghsa_id"], supplied["report_id"])
        for name in ("commit", "entry_point", "critical_operation", "vuln_category_l1", "vuln_category_l2"):
            self.assertNotIn(name, result["fields"])

    def test_advisory_seed_requires_matching_document_and_does_not_select_conflicting_title(self):
        for mismatch in ("job", "document", "missing_document"):
            supplied = metadata_job()
            if mismatch == "job":
                supplied["advisory_metadata"]["ghsa_id"] = "GHSA-5555-6666-7777"
            elif mismatch == "document":
                supplied["documents"][0]["advisory_metadata"]["ghsa_id"] = "GHSA-5555-6666-7777"
            else:
                supplied["documents"][0].pop("advisory_metadata")
            with self.subTest(mismatch=mismatch):
                result = produce(supplied, StubClient(), StubRepo(), max_calls=0)
                self.assertNotIn("vuln_title", result["fields"])
                self.assertEqual(result["fields"]["vuln_ids"], [supplied["report_id"]])
        conflicting = metadata_job()
        conflicting["documents"].append(copy.deepcopy(conflicting["documents"][0]))
        conflicting["documents"][1]["advisory_metadata"]["title"] = "Different supplied title"
        result = produce(conflicting, StubClient(), StubRepo(), max_calls=0)
        self.assertNotIn("vuln_title", result["fields"])
        self.assertEqual(result["field_reviews"]["vuln_title"]["status"], "conflicting")

    def test_model_can_refine_seeded_title_but_unestablished_replacements_keep_input_facts(self):
        def refined(messages):
            advisory = next(item for item in evidence_from(messages) if item["kind"] == "advisory")
            return {"action": "draft", "fields": {"vuln_title": "Source-supported refined title", "vuln_ids": []},
                    "field_reviews": {name: {"status": "supported", "reason": "Supported by the matching advisory.",
                                               "evidence_refs": [advisory["id"]]} for name in ("vuln_title", "vuln_ids")}}
        result = produce(metadata_job(), StubClient(refined, retain_review), StubRepo(), max_calls=2)
        self.assertEqual(result["fields"]["vuln_title"], "Source-supported refined title")
        self.assertEqual(result["fields"]["vuln_ids"], metadata_job()["advisory_metadata"]["vuln_ids"])
        missing = {"action": "draft", "fields": {"vuln_title": None, "vuln_ids": None},
                   "field_reviews": {name: {"status": "missing", "reason": "Not established by this response.",
                                             "evidence_refs": []} for name in ("vuln_title", "vuln_ids")}}
        result = produce(metadata_job(), StubClient(missing, retain_review), StubRepo(), max_calls=2)
        self.assertEqual(result["fields"]["vuln_title"], "Supplied advisory title")
        self.assertEqual(result["fields"]["vuln_ids"], metadata_job()["advisory_metadata"]["vuln_ids"])
        disputed = {"action": "draft", "fields": {}, "field_reviews": {
            "vuln_title": {"status": "conflicting", "reason": "Supplied title conflicts with the investigated issue.",
                           "evidence_refs": ["E0002"]}}}
        result = produce(metadata_job(), StubClient(disputed, missing), StubRepo(), max_calls=2)
        self.assertNotIn("vuln_title", result["fields"])
        self.assertEqual(result["field_reviews"]["vuln_title"]["status"], "conflicting")

    def test_controller_repository_name_survives_model_value_without_review(self):
        draft = {"action": "draft", "fields": {"project": "unreviewed replacement",
                 "repo_url": "https://github.com/other/project"}, "field_reviews": {}}
        for supplied_url in (True, False):
            supplied = job(False)
            if not supplied_url:
                supplied.pop("repo_url")
            with self.subTest(supplied_url=supplied_url):
                result = produce(supplied, StubClient(draft, retain_review), StubRepo(), max_calls=2)
                self.assertEqual(result["fields"]["project"], "service")
                self.assertEqual(result["fields"]["repo_url"], "https://github.com/example/service")
                self.assertEqual(result["field_reviews"]["project"]["status"], "supported")
                self.assertEqual(result["field_reviews"]["project"]["evidence_refs"],
                                 result["field_reviews"]["repo_url"]["evidence_refs"])

    def test_capped_calls_and_repeated_requests_are_not_reexecuted(self):
        request = {"action": "tools", "calls": [{"tool": "read_file", "arguments": {"commit": VULNERABLE, "path": "service/handler.py"}}] * 9}
        client = StubClient(request, request, request, request)
        repo = StubRepo()
        result = produce(job(False), client, repo, max_calls=4, max_tool_calls=2)
        self.assertLessEqual(result["model_calls"], 4)
        self.assertEqual(result["tool_calls"], 1)
        self.assertEqual(len(repo.calls), 1)
        self.assertIn("reused_evidence_ref", client.messages[1][-1]["content"])
        self.assertNotIn("commit", result["fields"])

    def test_self_review_downgrades_bad_field_without_erasing_other_fields(self):
        review = {"action": "draft", "fields": {}, "field_reviews": {
            "entry_point": {"status": "uncertain", "reason": "Function reachability is not demonstrated by this read.", "evidence_refs": ["E0006"]}}, "summary": "Reachability remains uncertain."}
        result = produce(job(), StubClient(choose_source, source_draft, review), StubRepo())
        self.assertNotIn("entry_point", result["fields"])
        self.assertEqual(result["field_reviews"]["entry_point"]["suggested_value"]["line"], 1)
        self.assertEqual(result["fields"]["critical_operation"]["line"], 2)
        self.assertEqual(result["fields"]["vuln_title"], "Expression execution")

    def test_no_outside_tools_or_self_review_tool_execution(self):
        request = {"action": "tools", "plan": "Untrusted test request", "calls": [
            {"tool": "shell", "arguments": {"command": "arbitrary command"}},
            {"tool": ["read_file"], "arguments": {}},
            {"tool": "read_file", "arguments": {"commit": VULNERABLE, "path": "a", "shell": True}}]}
        draft = {"action": "draft", "fields": {}, "field_reviews": {}}
        client = StubClient(request, draft, choose_source)
        repo = StubRepo()
        result = produce(job(False), client, repo)
        self.assertEqual(repo.calls, [])
        self.assertEqual(result["tool_calls"], 0)
        self.assertEqual(result["model_calls"], 3)
        self.assertTrue(any("Self-review must return a draft" in error for error in result["errors"]))

    def test_advisory_only_locations_and_invented_evidence_are_suggestions(self):
        draft = {"action": "draft", "fields": {
            "commit": VULNERABLE, "entry_point": {"file": "guessed.py", "line": 1, "code": "guess()"},
            "vuln_title": "Invented evidence", "verify": 1},
            "field_reviews": {
                "commit": {"status": "supported", "reason": "Test claim.", "evidence_refs": ["E0002"]},
                "entry_point": {"status": "supported", "reason": "Advisory claim without a read.", "evidence_refs": ["E0002"]},
                "vuln_title": {"status": "supported", "reason": "Nonexistent evidence.", "evidence_refs": ["E9999"]}}}
        result = produce(job(False), StubClient(draft, retain_review), StubRepo())
        self.assertNotIn("entry_point", result["fields"])
        self.assertNotIn("vuln_title", result["fields"])
        self.assertEqual(result["field_reviews"]["entry_point"]["status"], "uncertain")
        self.assertEqual(result["field_reviews"]["vuln_title"]["suggested_value"], "Invented evidence")
        self.assertEqual(result["fields"]["verify"], 0)


if __name__ == "__main__":
    unittest.main()
