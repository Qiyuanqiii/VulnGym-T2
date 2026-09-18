"""Observed candidate-body reads reach the actual assessed wire, without HTTP."""
import copy
import json
import unittest

from tests import test_t2_v2_assessed_tool as assessed_fixture
from tests import test_t2_v2_candidate_body_navigation as navigation_fixture
from tests import test_t2_v2_staged_pipeline as staged_fixture
from vulngym_t2.pipeline import ENTRY_FIELDS, _ProductionSession


BODY_MARKER = "new_candidate_body_only"


class ProbeRepo(navigation_fixture.MemoryRepo):
    """Records only synthetic source, never accesses a filesystem repository."""

    def __init__(self, timeline):
        super().__init__()
        self.timeline = timeline

    def call(self, tool, arguments):
        self.timeline.append(("local_read", arguments["path"]))
        result = super().call(tool, arguments)
        code = [f"export function {BODY_MARKER}(x) {{", "  return x; }"]
        result.update(text="\n".join(code),
                      lines=[{"line": index + 1, "code": value}
                             for index, value in enumerate(code)])
        return result


class CandidateProbeWireTests(unittest.TestCase):
    setUp = assessed_fixture.AssessedToolTests.setUp
    client = assessed_fixture.AssessedToolTests.client

    def run_candidates(self, *, max_calls=9, max_tool_calls=24, closed_context=False,
                       client_requests=None):
        # Two assessed slots still send eight actual requests. Admission now
        # also needs one shared encoding-only allowance, which these valid
        # encodings leave unused; it must not become another model decision.
        timeline, payloads, observed_fields = [], [], []
        holder = {}

        def send(body, *_):
            payload = json.loads(body)
            state = holder["state"]
            scope = state.active_candidate_scope["scope"]
            stage = state.result["actions"][-1]["stage"]
            timeline.append(("send", scope, stage))
            payloads.append((scope, stage, payload))
            observed_fields.append(copy.deepcopy(state.result["fields"]))
            if "tools" not in payload:
                return assessed_fixture.envelope(content="These synthetic fields remain unestablished.")
            self.assertEqual([row["function"]["name"] for row in payload["tools"]],
                             ["submit_annotation"])
            return assessed_fixture.envelope(call=staged_fixture.annotation())

        client = self.client(send, multi_entry=True,
                             max_requests=max_calls if client_requests is None else client_requests)
        client.start_next_case("GHSA-2222-3333-4444")
        repo = ProbeRepo(timeline)
        state = _ProductionSession({"report_id": "GHSA-2222-3333-4444"},
                                   client, repo, max_calls, max_tool_calls)
        _, evidence = navigation_fixture.inputs()
        evidence.append(navigation_fixture.source("E0003", navigation_fixture.LEFT))
        state.result["evidence"] = evidence
        state.evidence_by_id = {row["id"]: row for row in evidence}
        state.result["field_reviews"] = {
            name: {"status": "missing", "reason": "Not established.", "evidence_refs": []}
            for name in ENTRY_FIELDS
        }
        state.messages = [{"role": "system", "content": "Use only saved evidence."},
                          {"role": "user", "content": json.dumps({"evidence": evidence})}]
        state.candidate_proposals = [
            {"scope": "Left store branch", "evidence_refs": ["E0001", "E0003"]},
            {"scope": "Right store branch", "evidence_refs": ["E0001", "E0002"]},
        ]
        if closed_context:
            state.navigation_context_limit = lambda: 100
        holder["state"] = state
        result = state.run_candidates()
        return state, result, timeline, payloads, observed_fields

    def test_read_precedes_its_initial_assessment_without_backfilling_prior_slot(self):
        state, result, timeline, payloads, fields = self.run_candidates()
        self.assertEqual(state.repo.calls,
                         [("read_file", {"commit": navigation_fixture.OLD,
                                         "path": navigation_fixture.RIGHT,
                                         "start_line": 1, "end_line": 180})])
        self.assertEqual([row[0] for row in timeline], ["send"] * 4 + ["local_read"] + ["send"] * 4)
        self.assertEqual([stage for _, stage, _ in payloads],
                         ["draft_assessment", "draft", "self_review_assessment", "self_review"] * 2)
        for scope, _, payload in payloads:
            self.assertEqual(BODY_MARKER in json.dumps(payload), scope == "Right store branch")
        first, second = result["entry_results"]
        self.assertNotIn("E0004", first["candidate_provenance"]["slot_end"]["evidence_refs"])
        self.assertTrue(all("E0004" not in row["evidence_refs"]
                            for row in first["candidate_provenance"]["model_call_evidence"]))
        self.assertIn("E0004", second["candidate_provenance"]["model_call_evidence"][0]["evidence_refs"])
        self.assertFalse(any(row.get("action") == "candidate_source_probe" for row in first["actions"]))
        self.assertEqual(sum(row.get("action") == "candidate_source_probe" for row in second["actions"]), 1)
        self.assertEqual((result["model_calls"], self.ledger.started, len(payloads)), (8, 8, 8))
        plan = next(row for row in result["actions"] if row["action"] == "candidate_plan")
        self.assertEqual((plan["selected_count"], plan["omitted_count"], plan["encoding_reserve"]), (2, 0, 1))
        self.assertEqual(state.shared_encoding_reserve, 1)
        self.assertFalse(any(row["action"] == "annotation_encoding_reserve"
                             for entry in result["entry_results"] for row in entry["actions"]))
        self.assertEqual(result["tool_calls"], 1)
        self.assertEqual(state.client.summary()["automatic_retries"], 0)
        self.assertTrue(all(not value.get("commit") and not value.get("entry_point")
                            and not value.get("critical_operation") for value in fields))
        for entry in (first, second):
            for name in ("commit", "entry_point", "critical_operation"):
                self.assertFalse(entry["fields"].get(name))
                self.assertNotEqual(entry["field_reviews"][name]["status"], "supported")

    def test_local_tool_budget_does_not_add_a_probe_or_extra_model_decision(self):
        state, result, _, payloads, _ = self.run_candidates(max_tool_calls=2)
        self.assertEqual(state.repo.calls, [])
        self.assertEqual((result["model_calls"], self.ledger.started, len(payloads)), (8, 8, 8))
        self.assertNotIn(BODY_MARKER, json.dumps(payloads))
        self.assertEqual(result["tool_calls"], 0)

    def test_no_selected_slot_cannot_spend_a_source_read(self):
        state, result, _, payloads, _ = self.run_candidates(max_calls=3)
        self.assertEqual(state.repo.calls, [])
        self.assertEqual((result["model_calls"], self.ledger.started, len(payloads)), (0, 0, 0))

    def test_exhausted_client_annotation_budget_cannot_spend_a_source_read(self):
        state, result, _, payloads, _ = self.run_candidates(client_requests=3)
        self.assertEqual(state.repo.calls, [])
        self.assertLessEqual((result["model_calls"]), 3)
        self.assertEqual(self.ledger.started, len(payloads))

    def test_context_reserve_preserves_normal_draft_and_review_without_probe(self):
        state, result, _, payloads, _ = self.run_candidates(closed_context=True)
        self.assertEqual(state.repo.calls, [])
        self.assertEqual((result["model_calls"], self.ledger.started, len(payloads)), (8, 8, 8))
        self.assertNotIn(BODY_MARKER, json.dumps(payloads))
        second = result["entry_results"][1]
        self.assertTrue(any(row.get("action") == "candidate_source_probe_skipped"
                            and row.get("reason") == "reserve_annotation_review_context"
                            for row in second["actions"]))


if __name__ == "__main__":
    unittest.main()
