"""Read-strategy contract checks; real navigation is evaluated separately."""
import unittest

from vulngym_t2 import annotation_rules, staged_protocol


class ReadStrategyTests(unittest.TestCase):
    def test_read_guidance_prioritizes_known_path_and_reachable_history(self):
        instruction = annotation_rules.for_phase("read")
        self.assertIn("read_diff(path=that file)", instruction)
        self.assertIn("then read actual source", instruction)
        self.assertIn("Sparse refs do not mean shallow history", instruction)
        self.assertIn("one unscoped query", instruction)
        self.assertIn("only a candidate, never an affected label", instruction)
        self.assertIn("within the original budget", instruction)
        self.assertIn("retain genuine uncertainty", instruction)
        self.assertIn("read actual source around the most relevant shown hit before broadening search", instruction)
        self.assertIn("inspect/read that candidate rather than repeatedly searching titles", instruction)
        self.assertIn("changed paths do not describe the entire snapshot", instruction)
        self.assertLessEqual(len(instruction), 2000)

    def test_followup_prioritizes_missing_binding_then_input_consumer_and_registration(self):
        instruction = annotation_rules.for_phase("followup")
        self.assertIn("Reuse saved windows", instruction)
        # The v84 prerequisite pass precedes, rather than removes, the original
        # input-construction -> consumer -> optional-registration priorities.
        binding = instruction.index("missing receiver binding")
        consumption = instruction.index("actual lazy/generator consumption needed for a claimed connection")
        construction = instruction.index("then input assignment/construction/transformation")
        consumer = instruction.index("then consumer")
        registration = instruction.index("registration or optional trace")
        self.assertLess(binding, construction)
        self.assertLess(consumption, construction)
        self.assertLess(construction, consumer)
        self.assertLess(consumer, registration)
        self.assertIn("An unread essential callee outranks registration or optional trace", instruction)
        self.assertIn("Choose one focused read or finish_reading", instruction)
        self.assertIn("within the remaining decision budget", instruction)
        self.assertIn("Other SHA: search_history", instruction)
        self.assertIn("with observed change/release clues", instruction)
        self.assertIn("No guessed paths/SHAs", instruction)
        self.assertIn("read_file hits before search", instruction)
        self.assertIn("No annotation", instruction)
        self.assertIn("no runtime test is required", instruction)
        self.assertLessEqual(len(instruction), 500)

    def test_navigation_guidance_has_no_case_answers_or_extra_tools(self):
        text = annotation_rules.for_phase("read") + annotation_rules.for_phase("followup")
        for marker in ("GHSA-", "cypher.py", "airflow", "langchain", "61882", "46595"):
            self.assertNotIn(marker, text)
        self.assertNotRegex(text, r"\b[0-9a-f]{40}\b")
        names = {tool["function"]["name"] for tool in staged_protocol.tool_definitions("read")}
        self.assertIn("read_diff", names)
        self.assertIn("search_history", names)
        self.assertIn("finish_reading", names)
        self.assertEqual(len(names), 8)


if __name__ == "__main__":
    unittest.main()
