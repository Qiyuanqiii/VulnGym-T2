"""Controller budgets/order only; pure navigation selectors have separate tests."""
import copy
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from vulngym_t2.pipeline import _ProductionSession, _READ_CONTEXT_LIMIT
from vulngym_t2.output import _saved_actions
from tests.test_t2_v2_pipeline import job, VULNERABLE
from tests.test_t2_v2_staged_pipeline import MemoryRepo, READ


SEED = {"arguments": {"commit": VULNERABLE, "query": "def serve"}, "evidence_refs": ["E0001"]}
REQUEST = {"arguments": READ[1], "anchor_line": 1}


class NavigationRecoveryHookTests(unittest.TestCase):
    def session(self):
        client = SimpleNamespace(response_mode="staged_tool", annotation_format="assessed_tool", halted=None)
        session = _ProductionSession(job(False), client, MemoryRepo(), 12, 24)
        session.prepare()
        return session

    def probe(self, session):
        with patch("vulngym_t2.revision_navigation.initial_snapshot_probe_seed", return_value=copy.deepcopy(SEED)), \
             patch("vulngym_t2.revision_navigation.initial_snapshot_probe_read", return_value=copy.deepcopy(REQUEST)):
            session.probe_initial_snapshot()

    def test_probe_once_two_real_reads_no_model_or_field_changes(self):
        session = self.session()
        original = copy.deepcopy({k: session.result[k] for k in ("fields", "field_reviews")})
        self.probe(session)
        self.probe(session)
        self.assertEqual(session.result["tool_calls"], 2)
        self.assertEqual(session.result["model_calls"], 0)
        self.assertTrue(session.initial_snapshot_probe_attempted)
        self.assertEqual({k: session.result[k] for k in original}, original)
        actions = _saved_actions(session.result["actions"])
        self.assertEqual([a["action"] for a in actions if a["action"].startswith("initial_snapshot_")],
                         ["initial_snapshot_search", "initial_snapshot_source"])
        self.assertIn("untrusted source receipts", session.messages[-1]["content"])

    def test_closed_context_provider_model_and_tool_reserves_do_not_probe(self):
        for reason in ("read_closed", "context", "provider", "model", "tool"):
            with self.subTest(reason=reason):
                session = self.session()
                if reason == "read_closed":
                    session.read_context_closed = True
                elif reason == "context":
                    session.messages.append({"role": "user", "content": "x" * _READ_CONTEXT_LIMIT})
                elif reason == "provider":
                    session.client.halted = "provider_stopped"
                elif reason == "model":
                    session.result["model_calls"] = session.max_calls - 3
                else:
                    session.max_tool_calls = 1
                self.probe(session)
                self.assertEqual(session.result["tool_calls"], 0)
                self.assertFalse(session.initial_snapshot_probe_attempted)

    def test_probe_failed_selection_consumes_single_attempt_without_source(self):
        session = self.session()
        with patch("vulngym_t2.revision_navigation.initial_snapshot_probe_seed", return_value=SEED), \
             patch("vulngym_t2.revision_navigation.initial_snapshot_probe_read", return_value=None):
            session.probe_initial_snapshot()
            session.probe_initial_snapshot()
        self.assertEqual(session.result["tool_calls"], 1)
        self.assertTrue(session.initial_snapshot_probe_attempted)

    def test_exploration_hook_runs_after_batch_before_next_completion(self):
        session = self.session()
        sequence = []
        def complete(stage):
            sequence.append(stage)
            session.result["model_calls"] += 1
            return ({"action": "tools", "calls": [{"tool": "list_refs", "arguments": {"limit": 1}}]}
                    if len(sequence) == 1 else None)
        with patch.object(session, "complete", side_effect=complete), \
             patch.object(session, "probe_initial_snapshot", side_effect=lambda: sequence.append("probe")):
            session.read_and_draft()
        self.assertEqual(sequence, ["plan_and_read", "probe", "plan_and_read"])

    def test_imported_read_replaces_caller_expansion_and_stays_semantically_unapproved(self):
        session = self.session()
        original = copy.deepcopy(session.result["field_reviews"])
        with patch("vulngym_t2.imported_call_navigation.imported_call_seed", return_value=SEED), \
             patch("vulngym_t2.imported_call_navigation.imported_definition_read", return_value=REQUEST), \
             patch("vulngym_t2.entry_navigation.navigate_entry", side_effect=AssertionError("No caller/test expansion")):
            session.navigate_entry_context({})
        self.assertEqual(session.result["tool_calls"], 2)
        self.assertTrue(session.imported_call_attempted)
        self.assertEqual(session.result["field_reviews"], original)
        self.assertEqual(session.result["model_calls"], 0)
        actions = [a for a in _saved_actions(session.result["actions"]) if a["action"].startswith("imported_call_")]
        self.assertEqual(len(actions), 2)
        self.assertTrue(all(a["semantic_approval"] is False for a in actions))

    def test_imported_read_budget_does_not_mark_attempt_or_bypass_provider_stop(self):
        for blocked in ("tool", "provider", "context"):
            session = self.session()
            if blocked == "tool":
                session.max_tool_calls = 3
            elif blocked == "provider":
                session.client.halted = "provider_stopped"
            else:
                # prepare context is compacted, so cap the actual navigation allowance.
                session.navigation_context_limit = lambda: 1
            with patch("vulngym_t2.imported_call_navigation.imported_call_seed", return_value=SEED):
                session.navigate_entry_context({})
            self.assertEqual(session.result["tool_calls"], 0)
            self.assertFalse(session.imported_call_attempted)


if __name__ == "__main__":
    unittest.main()
