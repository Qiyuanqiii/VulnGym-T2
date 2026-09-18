"""Conflicting supplied repair/affected roles remain reviewable, never relabeled."""
from copy import deepcopy
import unittest

from vulngym_t2.output import finalize_result
from tests.test_t2_v2_output import COMMIT, StubRepoReader, fixture


class RevisionRoleConflictTests(unittest.TestCase):
    def test_reported_fix_cannot_be_automatically_exported_as_affected(self):
        job, result = fixture()
        job["fix_commits"] = [COMMIT]
        original = deepcopy(result)
        repo = StubRepoReader()
        final = finalize_result(job, result, repo)
        self.assertIsNone(final["entry"])
        self.assertIsNone(final["review"]["draft_fields"]["commit"])
        self.assertEqual(final["review"]["suggested_values"]["commit"], COMMIT)
        self.assertEqual(final["review"]["field_reviews"]["commit"]["status"], "conflicting")
        self.assertIn("selected_revision_is_reported_fix", [row["code"] for row in final["review"]["errors"]])
        self.assertEqual(final["review"]["suggested_values"]["entry_point"], result["fields"]["entry_point"])
        self.assertEqual(result, original)
        self.assertEqual(repo.calls, [])

    def test_unrelated_fix_and_absent_fix_do_not_demote_a_source_supported_revision(self):
        for values in ([], ["b" * 40], None):
            job, result = fixture()
            job["fix_commits"] = values
            self.assertIsNotNone(finalize_result(job, result, StubRepoReader())["entry"])

    def test_resolved_fix_alias_uses_successful_supplied_inspection_only(self):
        for successful, supplied, blocked in ((True, True, True), (False, True, False), (True, False, False)):
            job, result = fixture()
            job["fix_commits"] = ["repair-tag"] if supplied else []
            result["evidence"].append({"id": "E0004", "tool": "inspect_commit", "success": successful,
                "arguments": {"commit": "repair-tag"}, "result": {"commit": COMMIT, "parents": ["b" * 40]}})
            final = finalize_result(job, result, StubRepoReader())
            self.assertEqual(final["entry"] is None, blocked)

    def test_no_automatic_parent_choice_or_approval_of_an_incomplete_fix_claim(self):
        job, result = fixture()
        job["fix_commits"] = [COMMIT]
        result["field_reviews"]["commit"]["reason"] = "The supplied fix is incomplete; the model claims behavior remains."
        final = finalize_result(job, result, StubRepoReader())
        self.assertIsNone(final["entry"])
        self.assertEqual(final["review"]["suggested_values"]["commit"], COMMIT)
        self.assertEqual(final["review"]["field_reviews"]["commit"]["status"], "conflicting")


if __name__ == "__main__":
    unittest.main()
