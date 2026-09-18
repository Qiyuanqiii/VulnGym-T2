"""Render only saved candidate metadata; all records are synthetic."""
from copy import deepcopy
import unittest
from unittest.mock import patch

from tests.test_t2_v2_review_export import fixture
from vulngym_t2.review_export import _candidate_provenance_lines, render_packet


def provenance():
    return {"original_proposal": {"scope": "Original proposed branch", "evidence_refs": ["E0001"]},
            "model_call_evidence": [
                {"stage": "draft_assessment", "call": 4, "evidence_count": 2, "last_evidence_ref": "E0002"},
                {"stage": "self_review", "call": 7, "evidence_count": 3, "last_evidence_ref": "E0003"}],
            "later_shared_evidence_status": "recorded", "later_shared_evidence_refs": ["E0004"]}


class ReviewExportProvenanceTests(unittest.TestCase):
    def test_saved_proposal_and_call_boundaries_precede_evidence_without_mutation(self):
        summary, entries, reviews = fixture()
        reviews[0].update(candidate_provenance=provenance(), self_review_status="failed")
        reviews[0]["candidate_provenance"].update(annotation={"hidden": "FULL ANNOTATION NOT DISPLAYED"},
                                                   previous_candidates_context={"raw": "PRIOR SNAPSHOT NOT DISPLAYED"})
        before = deepcopy((summary, entries, reviews))
        with patch("socket.socket", side_effect=AssertionError("network forbidden")):
            packet = render_packet(summary, entries, reviews)
        section = packet.split("## 逐条复核 ")[1]
        self.assertLess(section.index("### 原始候选提案与证据时间边界"), section.index("### 证据清单"))
        self.assertIn("Original proposed branch", section)
        self.assertIn("E0001", section)
        self.assertIn("| draft&#95;assessment | 4 | 2 | E0002 |", section)
        self.assertIn("| self&#95;review | 7 | 3 | E0003 |", section)
        self.assertIn("E0004", section)
        self.assertIn("失败调用也可有截止记录", section)
        self.assertIn("可用不等于调用成功", section)
        self.assertIn("每个字节都已见", section)
        self.assertIn("后来共享回执未用于该候选当时评估", section)
        self.assertNotIn("NOT DISPLAYED", section)
        self.assertEqual((summary, entries, reviews), before)

    def test_missing_unknown_and_malformed_boundaries_never_imply_no_later_reads(self):
        for metadata in (None, [], {}, {"later_shared_evidence_status": "unknown_boundary", "later_shared_evidence_refs": []},
                         {"later_shared_evidence_status": "recorded", "later_shared_evidence_refs": None},
                         {"later_shared_evidence_status": "recorded", "later_shared_evidence_refs": ["invented"]}):
            with self.subTest(metadata=metadata):
                section = "\n".join(_candidate_provenance_lines({"candidate_provenance": metadata}))
                self.assertIn("未记录或边界未知", section)
                self.assertIn("不能推断没有补读", section)
                self.assertNotIn("这些后来共享回执未用于", section)

    def test_recorded_empty_later_list_and_no_calls_keep_their_narrow_meaning(self):
        metadata = provenance()
        metadata.update(model_call_evidence=[], later_shared_evidence_refs=[])
        section = "\n".join(_candidate_provenance_lines({"candidate_provenance": metadata}))
        self.assertIn("逐 model_call 列表为空", section)
        self.assertIn("不据此补造成功评估", section)
        self.assertIn("空列表仅指候选结束后无已记录新增", section)
        self.assertIn("不表示候选内部没有补读", section)
        self.assertNotIn("边界未知", section)

    def test_provenance_cells_reuse_escaping_redaction_and_bounded_display(self):
        metadata = provenance()
        metadata["original_proposal"]["scope"] = '<script>\n| [link](javascript:boom) D:\\private\\secret.txt sk-syntheticsecret123 ' + "z" * 8100
        metadata["model_call_evidence"] = [{"stage": "<script>\n" + "a" * 100, "call": index + 1,
                                           "evidence_count": 2, "last_evidence_ref": "E0002",
                                           "messages": "PRIVATE PAYLOAD NOT DISPLAYED"} for index in range(257)]
        section = "\n".join(_candidate_provenance_lines({"candidate_provenance": metadata}))
        self.assertNotIn("<script>", section)
        self.assertNotIn("[link]", section)
        self.assertNotIn("secret.txt", section)
        self.assertNotIn("syntheticsecret", section)
        self.assertNotIn("PRIVATE PAYLOAD", section)
        self.assertIn("&#60;script&#62;", section)
        self.assertIn("local path redacted", section)
        self.assertIn("truncated", section)
        self.assertIn("另有 1 项未展开", section)
        self.assertNotIn("| 257 |", section)
        metadata.update(original_proposal={"scope": {"annotation": "NO OBJECT DUMP"}, "evidence_refs": [{}]},
                        model_call_evidence=[{"stage": {}, "call": True, "evidence_count": True}, []])
        section = "\n".join(_candidate_provenance_lines({"candidate_provenance": metadata}))
        self.assertNotIn("NO OBJECT DUMP", section)
        self.assertIn("未记录", section)


if __name__ == "__main__":
    unittest.main()
