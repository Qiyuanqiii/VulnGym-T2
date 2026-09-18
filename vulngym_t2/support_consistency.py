"""Conservative detection of explicit self-disclaimed support, not source truth.

Only a small set of field-specific admissions can hold a field for review.
An empty result does NOT establish semantic consistency. A nonempty trace is
checked separately; its missing links cannot invalidate independent fields.
No files, model calls, source parsing, or changes to the input assessment.
"""
from __future__ import annotations

from collections.abc import Mapping
import re

RULE_VERSION = "declared-support-v6"
_FIELDS = {"entry_point", "critical_operation", "commit", "trace"}
_ABSENT = (r"(?:is|are|was|were|remains?|has|have)\s+"
           r"(?:(?:still|currently)\s+)?(?:not\s+(?:(?:directly|yet|independently)\s+)?"
           r"(?:been\s+)?(?:read|shown|established|evidenced|verified|confirmed|demonstrated)"
           r"|(?:unknown|unestablished|unverified))")
# Hypotheses, quotations and explicitly historical accounts are not current
# admissions. Prefer a missed ambiguous phrase to inventing its intended role.
_AMBIGUOUS = re.compile(
    r'"|[“”]|\b(?:if|suppose|hypothetical|previously|earlier|formerly|initially)\b'
    r"|\b(?:now|subsequently)\s+(?:read|established|evidenced|verified|confirmed)\b"
    r"|假设|如果|此前|之前|先前|现已", re.IGNORECASE)
_OPTIONAL = re.compile(r"\b(?:optional|unclaimed|omitted|unrelated)\b|可选|未声称|无关", re.IGNORECASE)
_OUTSIDE_CLAIM = re.compile(r"\b(?:unclaimed|omitted|unrelated)\b|未声称|无关", re.IGNORECASE)


def _missing(subject, *, link_context=False):
    gap = (r"(?:(?!\b(?:but|although|however|while|whereas|and)\b)[^,.;\n]){0,70}?"
           if link_context else r"\s+")
    return re.compile(r"\b(?:" + subject + r")\b" + gap + _ABSENT, re.IGNORECASE)


_ENTRY_ROLE = _missing(r"(?:entry(?:[- ]point)?|external (?:entry|handler|callback)) (?:role|identity)")
_FACTORY = re.compile(r"\b(?:factory|constructor|registration)\b", re.IGNORECASE)
# All three signals must occur in the EP's own current sentence. A mention of
# a diff or an absent optional trace alone is not an entry-role contradiction.
_EXTERNAL_DISPATCH = re.compile(r"\bexternal\b[^,.;\n]{0,80}\b(?:dispatch|callback|handler)\b", re.IGNORECASE)
_ONLY_DIFF = re.compile(r"\b(?:is|was|remains?)\s+(?:only|solely)\s+(?:shown|evidenced|established)"
                        r"\s+(?:via|by|in|through)\s+(?:the\s+)?(?:patch\s+)?diff\b", re.IGNORECASE)
_NO_DISPATCH_READ = re.compile(r"\bnot\s+(?:a|an)\s+(?:(?:actual|direct|source)\s+)?read(?:[- ]file)?"
                               r"\s+receipt\s+for\s+(?:the\s+)?(?:dispatch|callback)\b", re.IGNORECASE)
_LINK_UNREAD = _missing(r"bridge|dispatch|caller connection|callback connection", link_context=True)
_ENTRY_FLOW_UNREAD = _missing(r"(?:downstream|entry[- ]to[- ]operation) (?:link|bridge|connection|data[- ]flow)", link_context=True)
_LINK_INFERRED = re.compile(
    r"\b(?:bridge|dispatch|connection|entry(?:[- ]point)? (?:role|relationship))\b"
    r"[^.;\n]{0,50}?\b(?:is|was|remains?)\s+(?:(?:only|merely|solely|still)\s+)?"
    r"(?:inferred|assumed|guessed)\s+(?:only\s+)?(?:from|based on)\s+"
    r"(?:(?:the|function|symbol|method)\s+)?(?:naming|names?)\b", re.IGNORECASE)
# A framework-subclass inference needs the same conservative review as a
# factory-name inference, but only when direct reading is explicitly disclaimed.
_FRAMEWORK_INFERRED = re.compile(
    r"\b(?:dispatch|registration|callback connection)\b[^.;\n]{0,130}?"
    r"\b(?:is|was|remains?)\s+(?:(?:only|merely|solely|still)\s+)?inferred\s+from\s+"
    r"(?:the\s+)?framework\s+(?:subclass|base class|convention|naming)\b", re.IGNORECASE)
_FRAMEWORK_UNREAD = re.compile(r"\bnot\s+(?:(?:separately|directly|independently)\s+)?read\b", re.IGNORECASE)
_OPERATION_BEHAVIOR = _missing(
    r"(?:reported|defective|vulnerable) behavior (?:at|of|in) (?:the )?(?:selected|this) (?:operation|call)"
    r"|(?:selected|this) operation's (?:reported|defective|vulnerable) behavior")
_REVISION_BEHAVIOR = _missing(
    r"(?:(?:reported|defective|vulnerable|affected) )?behavior at (?:the )?(?:selected|chosen|this) (?:sha|revision|commit)")
_RANGE_MAPPING = _missing(
    r"(?:sha|revision|commit)[- ]to[- ](?:advisory[- ])?(?:version|range) mapping"
    r"|(?:sha|revision|commit)(?: to)? (?:the )?(?:advisory|affected) (?:range|version) mapping"
    r"|mapping of (?:this|the selected|the chosen) (?:sha|revision|commit) to (?:the )?(?:advisory|affected) range")
_ENTRY_ROLE_ZH = re.compile(r"(?:外部入口|入口点|入口|回调)(?:身份|角色)(?:仍|尚|目前)?(?:未|无法)(?:确认|建立|证实)")
_FACTORY_BRIDGE_ZH = re.compile(r"(?:工厂|构造|注册).{0,100}(?:调度|连接|调用关系).{0,30}(?:未读取|未读|未确认).{0,80}(?:仅|只).{0,12}(?:命名|名字).{0,8}(?:推断|猜测)")
# These are admissions about the field's own binding or explicitly necessary
# relation, not a demand for runtime type tests or every downstream callee.
_RECEIVER_BINDING = _missing(
    r"(?:receiver|returned[- ]object) (?:type(?: binding)?|class(?: binding)?|binding|assignment)(?: itself)?")
_INSTANCE_UNREAD = re.compile(
    r"\b[a-z_]\w*\s+(?:is|was)\s+not\s+(?:(?:directly|independently)\s+)?"
    r"(?:read|shown|established|evidenced|confirmed)\s+as\s+(?:an?\s+)?"
    r"[a-z_]\w*\s+instance\b", re.IGNORECASE)
_REQUIRED_RELATION = _missing(
    r"(?:required|necessary|essential) (?:(?:local|receiver|type|dispatch|data[- ]flow|generator|lazy) )?"
    r"(?:premise|binding|relationship|connection|link|bridge|consumer|consumption|assignment|dispatch)")
_REQUIRED_RELATION_ZH = re.compile(
    r"(?:必需|必要)(?:的)?(?:局部|接收对象|返回对象|类型|调用|数据流|生成器)?"
    r"(?:前提|绑定|关系|连接|消费|赋值)(?:仍|尚|目前)?(?:未|无法)(?:读取|确认|建立|证实)")
_TRACE_RELATION = _missing(
    r"trace(?:'s)? (?:link|connection|bridge|ordering)"
    r"|(?:generator|lazy) (?:consumer|consumption|activation)")

# Identity inferred from a filename/docstring is not by itself a contradiction:
# a local API fact can stand without claiming which implementation it dispatches
# to. Hold only the conjunction of that explicit unread identity and a concrete
# connection claim in this same field's bounded, current reason. These finite
# forms are not a type resolver and deliberately leave ambiguous prose alone.
_OBJECT = r"(?:loaded|returned)[- ]object(?:'s)?"
_IDENTITY = (rf"(?:{_OBJECT}\s+(?:(?:class|type)\s+)?identity"
             rf"|{_OBJECT}\s+(?:class|type)"
             rf"|(?:(?:class|type)\s+)?identity\s+of\s+(?:the\s+)?{_OBJECT})")
_IDENTITY_HINT = r"(?:paths?|names?|naming|docstrings?|documentation)"
_OBJECT_IDENTITY_UNREAD = re.compile(
    rf"\b{_IDENTITY}\b[^,;!?\n]{{0,90}}?\b(?:is|was|remains?)\s+"
    r"(?:(?:only|merely|solely|still)\s+)?(?:inferred|assumed)\s+(?:only\s+)?(?:from|based on)\s+"
    rf"[^,;!?\n]{{0,80}}?\b{_IDENTITY_HINT}\b(?:\s*[/&]\s*{_IDENTITY_HINT})*"
    r"\s*,?\s*(?:(?:and|but)\s+)?(?:is\s+)?not\s+"
    r"(?:(?:separately|directly|independently)\s+)?(?:read|shown|established|verified|confirmed)\b",
    re.IGNORECASE)
_METHOD_NAME = r"[a-z_]\w*(?:\.[a-z_]\w*)*(?:\(\))?"
_ASSERTED_CONNECTION = re.compile(
    rf"\b(?:shows|establishes|demonstrates|confirms)\s+(?:the\s+)?{_METHOD_NAME}\s*(?:->|→)\s*{_METHOD_NAME}"
    r"|\b(?:dispatch|entry[- ]to[- ]operation (?:connection|link)|cross[- ]method (?:connection|link))"
    r"\b(?:(?!\b(?:not|never|unknown|unproven|inferred|but|while|whereas|and)\b)[^,;!?\n]){0,90}?"
    r"\b(?:is|was)\s+(?:shown|established|confirmed|demonstrated)\b",
    re.IGNORECASE)
_CONNECTION_NOT_CLAIMED = re.compile(
    r"\b(?:do(?:es)? not|don't)\s+(?:claim|assert)\b[^,;!?\n]{0,70}\b(?:connection|dispatch|link|chain)\b"
    r"|\bno\s+(?:(?:downstream|cross[- ]method|entry[- ]to[- ]operation)\s+)?"
    r"(?:connection|dispatch|link|chain)\s+is\s+claimed\b"
    r"|\b(?:connection|dispatch|link|chain)\s+is\s+not\s+claimed\b",
    re.IGNORECASE)
_IDENTITY_CONTEXT = re.compile(
    r"\b(?:historical|quoted|previous|prior)\b|\b(?:note|report|example)\s+(?:says?|said|states?)\b",
    re.IGNORECASE)


def _object_identity_dispatch_disclaimed(text, *, field):
    # Keep qualified method names intact without changing the legacy parser.
    # Exclude quotation/history and expressly unrelated/omitted claims before
    # combining sentences; never combine assessments, fields or candidates.
    sentences = [" ".join(part.split()) for part in re.split(r"[;!?。；！？\r\n]+|\.(?=\s|$)", text)]
    outside_claim = _OUTSIDE_CLAIM if field == "trace" else _OPTIONAL
    current = [part for part in sentences if part and not _AMBIGUOUS.search(part)
               and not _IDENTITY_CONTEXT.search(part) and not outside_claim.search(part)]
    if any(_CONNECTION_NOT_CLAIMED.search(part) for part in current):
        return False
    return (any(_OBJECT_IDENTITY_UNREAD.search(part) for part in current)
            and any(_ASSERTED_CONNECTION.search(part) for part in current))


def check_support(field, assessment, *, value=None) -> dict:
    """Return bounded review issues for current, explicit support contradictions.

This is intentionally NOT a general English/Chinese semantic classifier. It
does not search other fields, infer negative source facts, or accept corrections
as proven merely because the model removed an uncertainty phrase.
"""
    packet = {"version": RULE_VERSION, "issues": [], "truncated": False}
    if not isinstance(field, str) or field not in _FIELDS or not isinstance(assessment, Mapping) or assessment.get("status") != "supported":
        return packet
    # Trace may legitimately be omitted. Only an actual nonempty field value
    # makes a flow claim; suggested/omitted values are never resurrected here.
    if field == "trace" and (not isinstance(value, list) or not value):
        return packet
    reason = assessment.get("reason")
    if not isinstance(reason, str):
        return packet
    packet["truncated"] = len(reason) > 2000 or assessment.get("reason_truncated") is True
    text = reason[:2000].replace("’", "'").replace("‘", "'")
    for part in re.split(r"[.;!?。；！？\r\n]+", text):
        sentence = " ".join(part.split())
        if not sentence or _AMBIGUOUS.search(sentence):
            continue
        rule, prerequisite = None, None
        outside_claim = (_OUTSIDE_CLAIM if field == "trace" else _OPTIONAL).search(sentence)
        if field in ("entry_point", "critical_operation", "trace") and not outside_claim:
            if _RECEIVER_BINDING.search(sentence) or _INSTANCE_UNREAD.search(sentence):
                rule, prerequisite = "receiver_binding_disclaimed", "receiver_binding"
            elif _REQUIRED_RELATION.search(sentence) or _REQUIRED_RELATION_ZH.search(sentence):
                rule, prerequisite = "required_relation_disclaimed", "required_field_relation"
        if field == "trace" and not rule and not outside_claim and _TRACE_RELATION.search(sentence):
            rule, prerequisite = "trace_connection_disclaimed", "trace_connection"
        if not rule and field == "entry_point" and not _OPTIONAL.search(sentence):
            if _ENTRY_ROLE.search(sentence) or _ENTRY_ROLE_ZH.search(sentence):
                rule = "entry_role_disclaimed"
            elif (_EXTERNAL_DISPATCH.search(sentence) and _ONLY_DIFF.search(sentence)
                  and _NO_DISPATCH_READ.search(sentence)):
                rule = "entry_dispatch_diff_only"
            elif ((_FACTORY.search(sentence) and _LINK_UNREAD.search(sentence) and _LINK_INFERRED.search(sentence))
                  or _FACTORY_BRIDGE_ZH.search(sentence)):
                rule = "factory_dispatch_inferred"
            elif _FRAMEWORK_INFERRED.search(sentence) and _FRAMEWORK_UNREAD.search(sentence):
                rule = "framework_dispatch_inferred"
            elif _ENTRY_FLOW_UNREAD.search(sentence):
                rule = "entry_flow_disclaimed"
            prerequisite = "external_entry_role"
        elif not rule and field == "critical_operation" and _OPERATION_BEHAVIOR.search(sentence):
            rule, prerequisite = "operation_behavior_disclaimed", "operation_behavior"
        elif field == "commit":
            if _REVISION_BEHAVIOR.search(sentence):
                rule, prerequisite = "revision_behavior_disclaimed", "affected_behavior"
            elif assessment.get("revision_basis") == "affected_range_and_source" and _RANGE_MAPPING.search(sentence):
                rule, prerequisite = "range_mapping_disclaimed", "affected_range_mapping"
        if rule:
            packet["issues"].append({"code": "supported_reason_conflict", "prerequisite": prerequisite, "rule": rule})
            break
    if (not packet["issues"] and field in ("entry_point", "critical_operation", "trace")
            and _object_identity_dispatch_disclaimed(text, field=field)):
        packet["issues"].append({"code": "supported_reason_conflict",
            "prerequisite": "receiver_identity_for_dispatch", "rule": "object_identity_dispatch_disclaimed"})
    return packet


def public_checks(value) -> dict:
    """Bounded controller metadata; never echo arbitrary model keys or prose."""
    output = {}
    allowed = {"external_entry_role": {"entry_role_disclaimed", "factory_dispatch_inferred", "entry_dispatch_diff_only", "framework_dispatch_inferred", "entry_flow_disclaimed"},
               "operation_behavior": {"operation_behavior_disclaimed"},
               "affected_behavior": {"revision_behavior_disclaimed"},
               "affected_range_mapping": {"range_mapping_disclaimed"},
               "receiver_binding": {"receiver_binding_disclaimed"},
               "required_field_relation": {"required_relation_disclaimed"},
               "trace_connection": {"trace_connection_disclaimed"},
               "receiver_identity_for_dispatch": {"object_identity_dispatch_disclaimed"}}
    v5_rules = {"receiver_binding_disclaimed", "required_relation_disclaimed", "trace_connection_disclaimed"}
    v6_rules = {"object_identity_dispatch_disclaimed"}
    for field in ("commit", "entry_point", "critical_operation", "trace"):
        packet = value.get(field) if isinstance(value, Mapping) else None
        if not isinstance(packet, Mapping) or packet.get("version") not in ("declared-support-v1", "declared-support-v2", "declared-support-v3", "declared-support-v4", "declared-support-v5", RULE_VERSION):
            continue
        issues = packet.get("issues")
        for row in issues[:1] if isinstance(issues, list) else []:
            if (isinstance(row, Mapping) and row.get("code") == "supported_reason_conflict"
                    and isinstance(row.get("prerequisite"), str)
                    and isinstance(row.get("rule"), str)
                    and row["rule"] in allowed.get(row["prerequisite"], set())):
                if packet["version"] == "declared-support-v1" and row["rule"] == "entry_dispatch_diff_only":
                    continue
                if packet["version"] in ("declared-support-v1", "declared-support-v2") and row["rule"] == "framework_dispatch_inferred":
                    continue
                if packet["version"] not in ("declared-support-v4", "declared-support-v5", RULE_VERSION) and row["rule"] == "entry_flow_disclaimed":
                    continue
                if row["rule"] in v5_rules and (packet["version"] not in ("declared-support-v5", RULE_VERSION) or field == "commit"):
                    continue
                if row["rule"] in v6_rules and (packet["version"] != RULE_VERSION or field == "commit"):
                    continue
                if field == "trace" and row["rule"] not in v5_rules | v6_rules:
                    continue
                if field != "trace" and row["rule"] == "trace_connection_disclaimed":
                    continue
                output[field] = {"version": packet["version"], "issues": [dict(
                    code=row["code"], prerequisite=row["prerequisite"], rule=row["rule"])],
                    "truncated": packet.get("truncated") is True}
    return output


def basis_changed(field, before_value, before_review, value, review, evidence, *, selected_commit=None) -> bool:
    """A necessary reconsideration signal, not proof that a correction is right.

Changing only the reason/description/status or reordering citations cannot
clear a recorded conflict. A new source selection, newly cited successful
source at the chosen revision, or narrowing an overclaimed revision basis can
be reassessed by the normal checks. Those checks still do not prove semantics.
"""
    def selection(location):
        if isinstance(location, list):
            return tuple(selection(item) for item in location)
        return tuple(location.get(key) for key in ("file", "line", "code")) if isinstance(location, Mapping) else location

    if selection(value) != selection(before_value):
        return True
    if (field == "commit" and before_review.get("revision_basis") == "affected_range_and_source"
            and review.get("revision_basis") == "behavior_at_revision"):
        return True
    old_refs = before_review.get("evidence_refs", [])
    refs = review.get("evidence_refs", [])
    added = set(refs) - set(old_refs)
    for receipt in evidence:
        if (isinstance(receipt, Mapping) and receipt.get("id") in added
                and receipt.get("tool") == "read_file" and receipt.get("success") is True
                and not receipt.get("error") and isinstance(receipt.get("result"), Mapping)
                and not receipt["result"].get("error") and isinstance(selected_commit, str)
                and receipt["result"].get("commit") == selected_commit):
            return True
    return False
