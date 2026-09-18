"""Revision guidance regressions, using synthetic receipts and no model calls."""
from copy import deepcopy
import unittest

from vulngym_t2 import annotation_rules
from vulngym_t2.output import _commit_support_problem
from vulngym_t2.pipeline import produce
from tests.test_t2_v2_pipeline import StubRepo, VULNERABLE, choose_source, job, source_draft


def revision_rule():
    return annotation_rules.TASK_RULES.split("R3 REVISION:", 1)[1].split("R4 LOCATIONS:", 1)[0]


class CapturingStagedClient:
    response_mode = "staged_tool"
    thinking = "disabled"
    multi_entry = False

    def __init__(self):
        self.calls = []
        self.reads = 0

    def complete(self, messages, *, stage):
        self.calls.append((stage, deepcopy(messages)))
        if stage == "read":
            self.reads += 1
            return choose_source(messages) if self.reads == 1 else {"action": "finish_reading", "reason": "enough_evidence"}
        if stage == "annotation":
            return source_draft(messages)
        raise AssertionError("No additional phase is authorized by this fixture")


class RevisionBasisGuidanceTests(unittest.TestCase):
    def test_behavior_and_release_mapping_are_separate_evidence_questions(self):
        rule = " ".join(revision_rule().split())
        self.assertIn("Missing release mapping alone does not invalidate established behavior_at_revision", rule)
        self.assertIn("The relevant defective mechanism and its necessary premises must be established", rule)
        self.assertNotIn("If your reason says no affected revision is established", rule)
        self.assertNotIn("Never claim a mapping you have not established; keep the candidate uncertain instead", rule)

    def test_range_basis_needs_mapping_not_just_fix_parent_and_range(self):
        rule = " ".join(revision_rule().split())
        self.assertIn("affected_range_and_source requires both that mechanism and cited evidence connecting the exact SHA to an affected release/range", rule)
        self.assertIn("A quoted advisory range plus a fix-parent relationship is not that mapping", rule)
        self.assertIn("An official version table is one possible source, not a mandatory format", rule)
        self.assertIn("use behavior_at_revision only if its mechanism is established; otherwise retain uncertainty", rule)

    def test_unknown_read_only_revision_and_scope_do_not_get_promoted(self):
        rule = " ".join(revision_rule().split())
        self.assertIn("A source read alone is inspected_only", rule)
        self.assertIn("Do not select a stronger basis merely to fill the field", rule)
        self.assertIn("Keep affected-release membership separate from observed behavior in the reason", rule)
        self.assertIn("EP/CO references must use this same selected SHA", rule)
        self.assertLess(len(revision_rule()), 1900)

    def test_self_review_rechecks_mechanism_and_mapping_without_new_calls(self):
        phase = annotation_rules.for_phase("review")
        self.assertIn("For commit, distinguish an unestablished mechanism from an unmapped release range", phase)
        self.assertIn("do not demand a version table for behavior_at_revision", phase)
        client, repo = CapturingStagedClient(), StubRepo()
        result = produce(job(False), client, repo, max_calls=4, max_tool_calls=4)
        self.assertEqual([stage for stage, _ in client.calls], ["read", "read", "annotation", "annotation"])
        self.assertEqual((result["model_calls"], result["tool_calls"]), (4, 1))
        self.assertEqual(result["self_review_status"], "completed")
        for _, messages in client.calls:
            self.assertEqual(messages[0]["role"], "system")
            self.assertIn(revision_rule(), messages[0]["content"])
        self.assertIn(phase, client.calls[-1][1][0]["content"])

    def test_existing_mechanical_contract_still_requires_a_real_same_sha_read(self):
        evidence = {"E0001": {"id": "E0001", "tool": "read_file", "success": True,
                    "result": {"commit": VULNERABLE, "path": "src/api.py", "text": "observed_mechanism()"}}}
        reason = "The relevant mechanism is observed at this SHA; release membership was not mapped."
        before = deepcopy(evidence)
        self.assertIsNone(_commit_support_problem(VULNERABLE, "behavior_at_revision", reason, ["E0001"], evidence))
        for basis in ("inspected_only", "unknown"):
            self.assertEqual(_commit_support_problem(VULNERABLE, basis, reason, ["E0001"], evidence)[0],
                             "revision_basis_not_established")
        for change in ("wrong_sha", "not_read", "failed", "no_bytes"):
            records = deepcopy(evidence)
            if change == "wrong_sha":
                records["E0001"]["result"]["commit"] = "b" * 40
            elif change == "not_read":
                records["E0001"]["tool"] = "inspect_commit"
            elif change == "failed":
                records["E0001"]["success"] = False
            else:
                records["E0001"]["result"].pop("text")
            self.assertEqual(_commit_support_problem(VULNERABLE, "behavior_at_revision", reason, ["E0001"], records)[0],
                             "revision_source_not_read")
        self.assertEqual(evidence, before)


if __name__ == "__main__":
    unittest.main()
