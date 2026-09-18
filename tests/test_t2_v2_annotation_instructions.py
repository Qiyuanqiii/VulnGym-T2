"""Offline prompt-shape checks, not evidence that real generation is reliable."""
import copy
import json
import unittest

from vulngym_t2 import annotation_rules, protocol, staged_protocol as staged, transport
from tests.test_t2_v2_protocol import tool_envelope
from tests.test_t2_v2_staged_protocol import annotation, decision, location


class AnnotationInstructionTests(unittest.TestCase):
    def normalize(self, arguments):
        return staged.normalize_calls([{"tool": "submit_annotation", "arguments": arguments}], "annotation")

    def test_unknown_template_is_generated_from_serializer_and_matches_current_schema(self):
        template = json.loads(staged.annotation_template_json())
        self.assertEqual(template, staged.snapshot_from_state({}, {}))
        schema = staged.tool_definitions("annotation")[0]["function"]["parameters"]
        self.assertTrue(protocol._matches(template, schema))
        self.assertEqual(set(template), set(staged.ANNOTATION_FIELDS))
        result = self.normalize(template)
        self.assertEqual(result["fields"], {})
        self.assertEqual(set(result["field_reviews"]), set(staged.ANNOTATION_FIELDS))
        self.assertTrue(all(review["status"] == "missing" for review in result["field_reviews"].values()))
        self.assertNotIn("annotation_errors", result)
        for field in ("entry_point", "critical_operation"):
            self.assertEqual(template[field]["value"], {"evidence_ref": "", "start_line": 0, "end_line": 0, "desc": ""})
        template["entry_point"]["value"]["desc"] = "caller mutation"
        self.assertEqual(json.loads(staged.annotation_template_json())["entry_point"]["value"]["desc"], "")

    def test_annotation_instruction_embeds_one_parseable_template_not_pseudo_json(self):
        text = staged.instruction("annotation")
        marker = "Complete unknown arguments template (JSON):\n"
        self.assertEqual(text.count(marker), 1)
        self.assertEqual(json.loads(text.split(marker)[1]), staged.snapshot_from_state({}, {}))
        for old in ("value=''", "evidence_ref:'", "start_line:0", "scope:'", "```"):
            self.assertNotIn(old, text)
        self.assertIn("value is required in EVERY decision", text)
        self.assertIn("FORMAT ONLY, not input facts", text)
        self.assertIn("permission to erase established fields", text)
        self.assertIn("Keep still-justified decisions", text)
        self.assertIn("not a code fence or prose wrapper", text)

    def test_enumerated_values_are_exactly_the_current_schema_values(self):
        text = staged.instruction("annotation")
        def array_after(prefix):
            return json.loads(text.split(prefix)[1].splitlines()[0])
        statuses = array_after("Allowed status values (JSON array): ")
        bases = array_after("Allowed commit revision_basis values (JSON array): ")
        schema = staged.tool_definitions("annotation")[0]["function"]["parameters"]
        self.assertEqual(statuses, list(protocol.STATUSES))
        self.assertEqual(bases, list(protocol.REVISION_BASES))
        for field, shape in schema["properties"].items():
            self.assertEqual(statuses, shape["properties"]["status"]["enum"])
            if field == "commit":
                self.assertEqual(bases, shape["properties"]["revision_basis"]["enum"])
            else:
                self.assertNotIn("revision_basis", shape["properties"])
        self.assertIn("Category labels belong in value, not status", text)
        self.assertIn("E followed by 4 to 8 digits", text)

    def test_prompt_revision_and_size_do_not_imply_a_new_wire_or_hard_reason_limit(self):
        self.assertEqual(staged.PROMPT_REVISION, "snapshot-guidance-v85")
        self.assertIn("multiple source IDs belong only in evidence_refs", annotation_rules.TASK_RULES)
        self.assertEqual(staged.STAGED_WIRE_VERSION, "snapshot-v2")
        self.assertEqual(staged.MULTI_STAGED_WIRE_VERSION, "candidate-serial-snapshot-v2")
        text = staged.instruction("annotation")
        self.assertIn(staged.PROMPT_REVISION, text)
        self.assertLessEqual(len(text), 4_500)
        self.assertLessEqual(len(staged.annotation_template_json()), 1_600)
        self.assertLessEqual(len(text) + len(annotation_rules.for_phase("review")), 6_000)
        self.assertIn("reason <=300", text)
        self.assertIn("reason <=2000", text)
        self.assertIn("retain necessary uncertainty", text)
        self.assertIn("2000-character hard limit remains unchanged", annotation_rules.TASK_RULES)
        reason = "r" * 1_979 + " Synthetic caveat end"
        self.assertEqual(len(reason), 2_000)
        result = self.normalize(annotation(vuln_title=decision("Title", reason=reason))[0]["arguments"])
        self.assertEqual(result["field_reviews"]["vuln_title"]["reason"], reason)
        bad = self.normalize(annotation(vuln_title=decision("Title", reason=reason + "x"))[0]["arguments"])
        self.assertEqual(bad["annotation_errors"][0]["code"], "reason_limit")

    def test_candidate_example_is_legal_json_and_not_an_instruction_to_invent_scope(self):
        text = staged.instruction("candidate_selection")
        example = json.loads(text.split("Candidate arguments example (JSON):\n")[1])
        schema = staged.tool_definitions("candidate_selection")[0]["function"]["parameters"]
        self.assertTrue(protocol._matches(example, schema))
        self.assertEqual(staged.normalize_calls([{"tool": "propose_candidates", "arguments": example}],
                                                "candidate_selection")["action"], "candidates")
        self.assertIn("shape only", text)
        self.assertIn("not supplied facts", text)
        self.assertIn("An empty candidates list is valid", text)
        self.assertNotIn("scope:'", text)
        self.assertIn(staged.PROMPT_REVISION, text)
        self.assertLessEqual(len(text), 1_000)

    def test_real_enum_error_shapes_are_not_normalized_into_supported(self):
        for status in ("Supported", "supported-by-source", "unknown", "uncertain/missing"):
            args = annotation(vuln_category_l1=decision("Injection", status),
                              critical_operation=decision(location()))[0]["arguments"]
            before = copy.deepcopy(args)
            with self.subTest(status=status):
                result = self.normalize(args)
                self.assertNotIn("vuln_category_l1", result["fields"])
                self.assertNotIn("vuln_category_l1", result["field_reviews"])
                self.assertEqual(result["annotation_errors"], [{"field": "vuln_category_l1", "code": "enum_mismatch",
                    "path": "$[0].arguments.vuln_category_l1.status"}])
                self.assertEqual(result["fields"]["critical_operation"], location())
                self.assertEqual(args, before)
        args = annotation(commit=decision("a" * 40, revision_basis="affected_revision"))[0]["arguments"]
        self.assertEqual(self.normalize(args)["annotation_errors"], [{"field": "commit", "code": "enum_mismatch",
            "path": "$[0].arguments.commit.revision_basis"}])

    def test_uncertain_location_missing_value_is_rejected_but_complete_unknown_is_valid(self):
        for field in ("entry_point", "critical_operation"):
            args = annotation(vuln_title=decision("Legal sibling"))[0]["arguments"]
            args[field] = {"status": "uncertain", "reason": "Not established.", "evidence_refs": []}
            with self.subTest(field=field):
                result = self.normalize(args)
                self.assertEqual(result["fields"], {"vuln_title": "Legal sibling"})
                self.assertEqual(result["annotation_errors"], [{"field": field, "code": "missing_property",
                    "path": "$[0].arguments." + field + ".value"}])
                args[field]["value"] = json.loads(staged.annotation_template_json())[field]["value"]
                valid = self.normalize(args)
                self.assertNotIn("annotation_errors", valid)
                self.assertEqual(valid["field_reviews"][field]["status"], "uncertain")
                self.assertNotIn(field, valid["fields"])

    def test_pseudo_or_truncated_json_is_still_not_repaired_by_template_guidance(self):
        for arguments in ("{'entry_point': {}}", '{"entry_point":{"status":"uncertain"}',
                          '{"entry_point":null,', '```json\n{}\n```'):
            body = json.loads(tool_envelope(arguments=arguments))
            body["choices"][0]["message"]["tool_calls"][0]["function"]["name"] = "submit_annotation"
            with self.subTest(arguments=arguments), self.assertRaises(transport.TransportError):
                transport.parse_chat_response(json.dumps(body).encode(), response_mode="staged_tool", stage="annotation")

    def test_read_recovery_guidance_is_conditional_navigation_not_extra_mandatory_work(self):
        for text in (staged.instruction("read"), annotation_rules.for_phase("read")):
            self.assertIn("explicit revision", text)
            self.assertIn("refs", text)
            self.assertIn("source_file_unavailable", text)
            self.assertIn("list_files", text)
            self.assertIn("before another read_file", text)
            self.assertIn("budget", text)
        self.assertIn("only when needed", staged.instruction("read"))
        self.assertIn("not mandatory reads on every input", annotation_rules.for_phase("read"))
        self.assertIn("Failed receipts do not prove absence", annotation_rules.for_phase("read"))

    def test_factory_role_requires_evidence_and_empty_trace_does_not_cure_ep_uncertainty(self):
        entry = annotation_rules.TASK_RULES.split("R5 ENTRY:", 1)[1].split("R6 OPERATION/FLOW:", 1)[0]
        entry = " ".join(entry.split())
        self.assertIn("construction factory or registration wrapper alone", entry)
        self.assertIn("does not establish the external callback", entry)
        self.assertIn("necessary factory-to-handler role or dispatch relationship", entry)
        self.assertIn("inferred only from names, mark entry_point uncertain", entry)
        self.assertIn("an empty trace does not cure that missing EP premise", entry)
        self.assertIn("directly evidenced handler/input read", entry)
        self.assertIn("Retain the unverified location as a suggestion", entry)
        self.assertIn("not a blanket rejection", entry)
        self.assertIn("with directly read callback evidence", entry)
        self.assertIn("without runtime experiments", entry)
        self.assertIn("only its unseen tail is unavailable", entry)
        self.assertIn("candidate_scope is a proposal", entry)

    def test_review_conflict_requires_evidence_or_downgrade_not_deleted_caveats(self):
        review = annotation_rules.for_phase("review")
        self.assertIn("For supported_reason_conflict, first recheck the affected field's essential premise", review)
        self.assertIn("already-read direct evidence", review)
        self.assertIn("if needed, a better location", review)
        self.assertIn("or mark that field uncertain", review)
        self.assertIn("Do not resolve the conflict by deleting caveats or rewriting the admission alone", review)
        self.assertIn("not new evidence or approval", review)
        self.assertIn("one model self-review", review)
        self.assertIn("or read more tools", review)
        self.assertLessEqual(len(staged.instruction("annotation")) + len(review), 6_000)

    def test_missing_specific_guard_is_scoped_in_every_field_reason(self):
        rules = " ".join(annotation_rules.TASK_RULES.split())
        self.assertIn("In every field's reason, a missing specific guard in the shown path", rules)
        self.assertIn('does not establish "no guards" globally', rules)
        self.assertIn("Scope the claim to the observed guard and path", rules)
        self.assertIn("other checks may exist and must not be denied without evidence", rules)
        self.assertIn("A specific missing guard may be described as such", rules)


if __name__ == "__main__":
    unittest.main()
