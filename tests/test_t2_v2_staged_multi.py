"""Serial candidate snapshots; all provider responses and source are synthetic."""
import copy
import json
import unittest

from vulngym_t2 import staged_protocol
from vulngym_t2.output import finalize_job
from tests.test_t2_v2_pipeline import evidence_from, job
from tests import test_t2_v2_staged_pipeline as fixture
from tests.test_t2_v2_staged_pipeline import READ, FINISH, full_annotation


def proposals(payload, count=2, duplicate=False):
    read = next(row for row in evidence_from(payload["messages"]) if row.get("tool") == "read_file")
    candidates = [{"scope": f"Independent synthetic scope {index}", "evidence_refs": [read["id"]]}
                  for index in range(count)]
    if duplicate and candidates:
        candidates.insert(1, copy.deepcopy(candidates[0]))
    return "propose_candidates", {"candidates": candidates}


def full_for_scope(payload):
    tool, snapshot = full_annotation(payload)
    scope = next(value["candidate_scope"]["scope"]
                 for row in payload["messages"] if row["content"].startswith('{')
                 for value in [json.loads(row["content"])] if "candidate_scope" in value)
    snapshot["vuln_title"]["value"] = scope
    return tool, snapshot


def bad_container(payload):
    tool, snapshot = full_for_scope(payload)
    snapshot["slot"] = 1
    return tool, snapshot


class SerialMultiTests(unittest.TestCase):
    setUp = fixture.StagedPipelineTests.setUp
    run_script = fixture.StagedPipelineTests.run_script

    def finalize(self, result, repo):
        return finalize_job(job(False), result, repo,
                            entry_ids={1: job(False)["entry_id"], 2: "entry-00002",
                                       3: "entry-00003", 4: "entry-00004"})

    def test_two_candidates_share_reads_and_each_get_one_complete_snapshot_review(self):
        result, _, client, repo, payloads = self.run_script(
            [READ, FINISH, proposals, full_for_scope, full_for_scope, full_for_scope, full_for_scope],
            multi_entry=True, max_calls=7)
        self.assertIsNone(client.halted)
        self.assertEqual((result["model_calls"], result["tool_calls"], len(repo.calls)), (7, 1, 1))
        group = self.finalize(result, repo)
        self.assertEqual(group["status"], "complete")
        self.assertTrue(all(item["entry"]["verify"] == 0 for item in group["items"]))
        self.assertEqual([entry["slot"] for entry in result["entry_results"]], [1, 2])
        for entry in result["entry_results"]:
            self.assertEqual(entry["self_review_status"], "completed")
            self.assertEqual(sum(a["action"] == "self_review" for a in entry["actions"]), 1)
        self.assertEqual([p["tools"][0]["function"]["name"] for p in payloads[2:]],
                         ["propose_candidates"] + ["submit_annotation"] * 4)
        for payload in payloads[3:]:
            schema = payload["tools"][0]["function"]["parameters"]
            self.assertEqual(set(schema["required"]), set(staged_protocol.ANNOTATION_FIELDS))
            self.assertNotIn("slot", schema["properties"])
            snapshots = [json.loads(row["content"]) for row in payload["messages"]
                         if row["role"] == "assistant" and row["content"].startswith('{"commit":')]
            for snapshot in snapshots:
                self.assertEqual(set(snapshot), set(staged_protocol.ANNOTATION_FIELDS))
        # Earlier original scopes are labeled context, not full annotations.
        last_scope = "Independent synthetic scope 1"
        self.assertIn(last_scope, json.dumps(payloads[-1]["messages"]))
        scope = next(json.loads(row["content"])["candidate_scope"] for row in payloads[-1]["messages"]
                     if row["content"].startswith("{") and "candidate_scope" in json.loads(row["content"]))
        self.assertEqual(scope["previous_candidates_context"]["candidates"][0]["proposed_scope"],
                         "Independent synthetic scope 0")
        self.assertNotIn("vuln_title", scope["previous_candidates_context"])

    def test_later_invalid_review_does_not_invalidate_completed_sibling(self):
        result, _, client, repo, _ = self.run_script(
            [READ, FINISH, proposals, full_for_scope, full_for_scope, full_for_scope, bad_container],
            multi_entry=True, max_calls=7)
        self.assertIsNotNone(client.halted)
        group = self.finalize(result, repo)
        self.assertEqual(group["status"], "partial")
        self.assertIsNotNone(group["items"][0]["entry"])
        self.assertIsNone(group["items"][1]["entry"])
        self.assertEqual(group["items"][0]["review"]["self_review_status"], "completed")
        self.assertEqual(group["items"][1]["review"]["self_review_status"], "failed")
        self.assertEqual(group["items"][0]["review"]["pipeline_errors"], [])
        self.assertTrue(group["items"][1]["review"]["pipeline_errors"])

    def test_provider_stop_does_not_start_remaining_candidate(self):
        result, _, client, repo, _ = self.run_script(
            [READ, FINISH, proposals, full_for_scope, bad_container], multi_entry=True, max_calls=7)
        self.assertIsNotNone(client.halted)
        self.assertEqual(result["model_calls"], 5)
        second = result["entry_results"][1]
        self.assertEqual(second["initial_draft_status"], "not_received")
        self.assertEqual(second["self_review_status"], "not_requested")
        self.assertEqual(second["actions"][0]["action"], "candidate_skipped")
        self.assertIsNone(self.finalize(result, repo)["items"][1]["entry"])

    def test_remaining_budget_selects_one_candidate_without_increasing_limit(self):
        result, _, client, repo, _ = self.run_script(
            [READ, FINISH, lambda p: proposals(p, 4), full_for_scope, full_for_scope],
            multi_entry=True, max_calls=5)
        plan = next(row for row in result["actions"] if row["action"] == "candidate_plan")
        self.assertEqual((plan["proposed_count"], plan["selected_count"], plan["omitted_count"]), (4, 1, 3))
        self.assertEqual(len(result["entry_results"]), 1)
        self.assertEqual(result["model_calls"], 5)
        self.assertIsNotNone(self.finalize(result, repo)["items"][0]["entry"])
        self.assertEqual(client.summary()["automatic_retries"], 0)

    def test_exact_duplicate_scopes_are_not_assigned_extra_ids(self):
        result, _, _, _, _ = self.run_script(
            [READ, FINISH, lambda p: proposals(p, 2, True),
             full_for_scope, full_for_scope, full_for_scope, full_for_scope],
            multi_entry=True, max_calls=7)
        plan = next(row for row in result["actions"] if row["action"] == "candidate_plan")
        self.assertEqual((plan["selected_count"], plan["duplicate_count"]), (2, 1))

    def test_empty_candidate_plan_is_preserved_without_inventing_slot(self):
        result, _, client, repo, _ = self.run_script(
            [READ, FINISH, ("propose_candidates", {"candidates": []})], multi_entry=True, max_calls=5)
        self.assertIsNone(client.halted)
        self.assertNotIn("entry_results", result)
        self.assertEqual(result["model_calls"], 3)
        self.assertIsNone(self.finalize(result, repo)["items"][0]["entry"])

    def test_unknown_candidate_references_are_not_used_for_annotation(self):
        result, _, _, _, _ = self.run_script(
            [READ, FINISH, ("propose_candidates", {"candidates": [
                {"scope": "unsupported scope", "evidence_refs": ["E9999"]}]})],
            multi_entry=True, max_calls=5)
        self.assertNotIn("entry_results", result)
        plan = next(row for row in result["actions"] if row["action"] == "candidate_plan")
        self.assertEqual((plan["selected_count"], plan["omitted_count"]), (0, 1))


if __name__ == "__main__":
    unittest.main()
