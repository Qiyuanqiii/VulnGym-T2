"""Field-local descriptions guide judgments without weakening schema validation."""
from copy import deepcopy
import unittest

from vulngym_t2 import annotation_rules, protocol, staged_protocol as staged


class FieldGuidanceTests(unittest.TestCase):
    def test_documented_receiver_requires_corroboration_not_name_guessing(self):
        guidance = annotation_rules.DOCUMENTED_ENTRY_GUIDANCE
        self.assertIn(guidance, annotation_rules.ASSESSMENT_TASK_RULES)
        self.assertIn(guidance, annotation_rules.ENTRY_DECISION_GUIDANCE)
        for required in ("same-SHA reads", "forwarding call and named method", "advisory/patch evidence",
                         "not source-proved dispatch", "Names alone", "contradictory evidence",
                         "missing local connection still require uncertainty", "not mandatory"):
            self.assertIn(required, guidance)
        self.assertIn("R5 permits a corroborated documented receiver", annotation_rules.ASSESSMENT_INSTRUCTION)
        self.assertIn("not source-proved dispatch", annotation_rules.ASSESSMENT_INSTRUCTION)

    def test_entry_kind_does_not_inherit_an_unrelated_callback_requirement(self):
        schema = staged.tool_definitions("annotation")[0]["function"]["parameters"]
        text = schema["properties"]["entry_point"]["description"]
        self.assertEqual(text, annotation_rules.ENTRY_DECISION_GUIDANCE)
        for required in ("does not require callback registration", "response origin",
                         "advisory-only origin premises", "outside the window", "Separate those claims"):
            self.assertIn(required, text)
        self.assertIn("does not itself require callback\nregistration", annotation_rules.TASK_RULES)
        for required in ("advisory is admissible evidence", "explicitly advisory-attributed origin",
                         "unproved necessary local connection", "not a claim"):
            self.assertIn(required, text)

    def test_branch_scope_is_supplied_beside_revision_and_operation(self):
        schema = staged.tool_definitions("annotation")[0]["function"]["parameters"]
        for field in ("commit", "critical_operation"):
            text = schema["properties"][field]["description"]
            self.assertIn(annotation_rules.BRANCH_DECISION_GUIDANCE, text)
            for required in ("NOT source facts", "when C is false", "neighboring function",
                             "another SHA", "do not assume", "keep uncertainty"):
                self.assertIn(required, text)

    def test_coarse_category_has_its_own_no_cwe_required_boundary(self):
        schema = staged.tool_definitions("annotation")[0]["function"]["parameters"]
        text = schema["properties"]["vuln_category_l1"]["description"]
        self.assertEqual(text, annotation_rules.COARSE_CATEGORY_DECISION_GUIDANCE)
        self.assertIn("no exact CWE number", text)
        self.assertIn("keep uncertainty if its actual mechanism is unclear", text)
        self.assertEqual(schema["properties"]["vuln_category_l2"]["description"],
                         annotation_rules.CATEGORY_DECISION_GUIDANCE)

    def test_trace_guidance_requires_intervening_code_not_assumed_adjacency(self):
        schema = staged.tool_definitions("annotation")[0]["function"]["parameters"]
        text = schema["properties"]["trace"]["description"]
        self.assertEqual(text, annotation_rules.TRACE_DECISION_GUIDANCE)
        for required in ("check the intervening code", "reassignment, filter or guard",
                         "per observed branch", "zero-iteration return can preserve input",
                         "separate unknowns", "Preserve if/unless polarity", "independently supported"):
            self.assertIn(required, text)
        self.assertIn("Same-function steps are not necessarily adjacent statements", annotation_rules.TASK_RULES)
        self.assertIn("actual mounting\nreceipt cited in the reason", annotation_rules.TASK_RULES)
        self.assertLessEqual(len(text), 800)

    def test_version_cases_are_next_to_the_commit_the_model_fills(self):
        schema = staged.tool_definitions("annotation")[0]["function"]["parameters"]
        self.assertEqual(schema["properties"]["commit"]["description"],
                         annotation_rules.REVISION_DECISION_GUIDANCE)
        text = schema["properties"]["commit"]["description"]
        for required in ("Conditional example (not facts)", "supported + behavior_at_revision",
                         "Do NOT use uncertain solely", "mechanism or a necessary premise is not established",
                         "both mechanism and exact-SHA release mapping"):
            self.assertIn(required, text)
        self.assertEqual(schema["properties"]["critical_operation"]["description"],
                         annotation_rules.LOCAL_OPERATION_GUIDANCE)

    def test_shared_state_is_a_conditional_bridge_not_automatic_execution(self):
        for text in (annotation_rules.ASSESSMENT_INSTRUCTION,
                     annotation_rules.TRACE_DECISION_GUIDANCE):
            with self.subTest(text=text[:30]):
                for required in ("Shared file/state", "ordered operations without direct calls",
                                 "read producer/consumer evidence", "execution conditions",
                                 "A write alone is not later execution"):
                    self.assertIn(required, text)
        rules = " ".join(annotation_rules.TASK_RULES.split())
        self.assertIn("both sides, resource identity and necessary execution conditions", rules)
        self.assertIn("Missing essential connections require uncertain/empty trace", rules)
        self.assertIn("An unread essential callee outranks registration or optional trace",
                      annotation_rules.for_phase("followup"))
        self.assertNotIn("missing caller bridge", annotation_rules.for_phase("review"))

    def test_lazy_flow_preserves_consumption_and_unknown_dispatch(self):
        for text in (annotation_rules.ASSESSMENT_INSTRUCTION,
                     annotation_rules.TRACE_DECISION_GUIDANCE):
            self.assertIn("generator/lazy consumption", text)
            self.assertIn("unknown returned types do not establish dispatch", text.lower())
        rules = " ".join(annotation_rules.TASK_RULES.split())
        self.assertIn("construction from actual consumption and resumption after yields", rules)
        self.assertIn("preserve filters, branch and stopping conditions", rules)
        self.assertIn("unknown returned object's type does not establish which method is dispatched", rules)

    def test_fix_comparison_and_revision_inventory_keep_their_actual_evidence_scope(self):
        self.assertIn("retaining earlier checks", annotation_rules.BRANCH_DECISION_GUIDANCE)
        self.assertIn("do not describe addition as replacement", annotation_rules.BRANCH_DECISION_GUIDANCE)
        self.assertIn("added conditions from retained checks", annotation_rules.ASSESSMENT_INSTRUCTION)
        identity = annotation_rules.RECEIPT_IDENTITY_GUIDANCE
        self.assertIn("inspected SHAs from all successful receipts", identity)
        self.assertIn("source-read SHAs from read_file result.commit/line only", identity)
        self.assertIn(identity, annotation_rules.ASSESSMENT_INSTRUCTION)
        self.assertIn(identity, annotation_rules.ENCODING_INSTRUCTION)
        self.assertIn("inspected SHAs with all successful receipts", annotation_rules.for_phase("review"))

    def test_evidence_guidance_stays_generic_and_within_its_existing_size(self):
        text = " ".join((annotation_rules.TASK_RULES, annotation_rules.ASSESSMENT_INSTRUCTION,
                         annotation_rules.TRACE_DECISION_GUIDANCE))
        for marker in ("GHSA-", "CVE-", "langchain", "nltk", "airflow", "n8n",
                       "recursive_url_loader.py", "MicrosoftSql.node.ts"):
            self.assertNotIn(marker, text)
        self.assertNotRegex(text, r"\b[0-9a-f]{40}\b")
        self.assertLessEqual(len(annotation_rules.ASSESSMENT_INSTRUCTION), 2_999)
        self.assertLessEqual(len(annotation_rules.TRACE_DECISION_GUIDANCE), 800)
        self.assertLessEqual(len(annotation_rules.TASK_RULES), 12_804)

    def test_descriptions_do_not_alter_any_wire_values_or_validation(self):
        schema = staged.tool_definitions("annotation")[0]["function"]["parameters"]
        plain = deepcopy(schema)
        for field in plain["properties"].values():
            field.pop("description", None)
        for name, value in ((None, None), ("commit", "f" * 40), ("commit", 12),
                            ("critical_operation", {}), ("critical_operation", [])):
            snapshot = staged.snapshot_from_state({}, {})
            if name:
                snapshot[name]["value"] = value
            self.assertEqual(protocol._matches(snapshot, schema), protocol._matches(snapshot, plain))
        self.assertEqual(set(schema["properties"]), set(staged.ANNOTATION_FIELDS))
        self.assertEqual(staged.STAGED_WIRE_VERSION, "snapshot-v2")


if __name__ == "__main__":
    unittest.main()
