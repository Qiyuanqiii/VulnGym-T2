"""Synthetic normalization audit boundaries; no HTTP, files, or target reads."""
import copy
import json
import unittest

from vulngym_t2 import staged_protocol
from vulngym_t2.output import _saved_actions, finalize_result
from vulngym_t2.pipeline import produce
from tests.test_t2_v2_pipeline import job
from tests.test_t2_v2_retest_failures import UnknownClient
from tests.test_t2_v2_staged_pipeline import FINISH, READ, MemoryRepo, full_annotation


class MaxAuditClient(UnknownClient):
    """Return two complete, valid snapshots with all 42 redundant containers."""

    def complete(self, messages, *, stage):
        self.messages.append(copy.deepcopy(messages))
        if stage == "read":
            tool, arguments = READ if len(self.messages) == 1 else FINISH
        else:
            if stage != "annotation":
                raise AssertionError("Unexpected extra model stage")
            tool, arguments = full_annotation({"messages": messages})
            arguments["trace"] = copy.deepcopy(arguments["entry_point"])
            arguments["trace"]["value"] = [
                copy.deepcopy(arguments["entry_point"]["value"]) for _ in range(32)
            ]
            for field in staged_protocol.ANNOTATION_FIELDS:
                arguments[field]["name"] = field
            for field in ("entry_point", "critical_operation"):
                arguments[field]["value"]["status"] = arguments[field]["status"]
            for location in arguments["trace"]["value"]:
                location["status"] = arguments["trace"]["status"]
        return staged_protocol.normalize_calls(
            [{"tool": tool, "arguments": arguments}], stage
        )


def audit_record():
    return {
        "field": "entry_point",
        "code": "redundant_properties_removed",
        "path": "$[0].arguments.entry_point.value",
        "removed_keys": ["status"],
    }


class NormalizationAuditTests(unittest.TestCase):
    def test_two_maximum_snapshots_keep_all_audits_and_final_review_action(self):
        supplied, client, repo = job(False), MaxAuditClient(), MemoryRepo()
        result = produce(supplied, client, repo, max_calls=4)
        finalized = finalize_result(supplied, result, repo)
        saved = finalized["review"]["actions"]
        packets = [row["normalizations"] for row in saved
                   if row["action"] == "annotation_properties_normalized"]

        self.assertEqual([len(packet) for packet in packets], [42, 42])
        self.assertEqual(sum(map(len, packets)), 84)
        self.assertEqual(len(saved), len(result["actions"]))
        self.assertLessEqual(len(saved), 96)
        self.assertEqual(saved[-1]["action"], "self_review")
        self.assertEqual(result["self_review_status"], "completed")
        self.assertEqual(result["annotation_errors"], [])
        self.assertEqual(result["model_calls"], 4)
        self.assertEqual(len(client.messages), 4)
        self.assertEqual(result["tool_calls"], 1)
        self.assertEqual(len(repo.calls), 1)
        self.assertIsNotNone(finalized["entry"])
        self.assertEqual(finalized["entry"]["verify"], 0)

    def test_legacy_single_record_is_saved_as_a_packet_with_its_slot(self):
        record = audit_record()
        old_action = {"action": "annotation_properties_normalized", **record, "slot": 2}
        original = copy.deepcopy(old_action)
        self.assertEqual(_saved_actions([old_action]), [{
            "action": "annotation_properties_normalized",
            "normalizations": [record], "slot": 2,
        }])
        self.assertEqual(old_action, original)

    def test_batch_filters_unknown_record_keys_and_paths_without_losing_valid_siblings(self):
        valid = audit_record()
        invalid = [
            {**valid, "unknown_property": "untrusted-prose"},
            {**valid, "removed_keys": ["unknown_property"]},
            {**valid, "path": "$[0].arguments.commit.value"},
            {**valid, "field": "unknown_field"},
        ]
        action = {
            "action": "annotation_properties_normalized",
            "normalizations": [*invalid[:2], valid, *invalid[2:]],
            "slot": 1, "unknown_wrapper": "untrusted-prose",
        }
        original = copy.deepcopy(action)
        saved = _saved_actions([action])
        self.assertEqual(saved, [{
            "action": "annotation_properties_normalized",
            "normalizations": [valid], "slot": 1,
        }])
        self.assertEqual(action, original)
        self.assertNotIn("untrusted", json.dumps(saved))
        self.assertNotIn("unknown", json.dumps(saved))
        self.assertEqual(_saved_actions([{
            "action": "annotation_properties_normalized", "normalizations": invalid,
        }]), [])
        self.assertEqual(_saved_actions([{
            "action": "annotation_properties_normalized", "normalizations": [valid] * 43,
        }]), [])


if __name__ == "__main__":
    unittest.main()
