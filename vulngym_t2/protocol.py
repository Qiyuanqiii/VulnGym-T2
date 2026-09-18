"""Pure, bounded submit_step answer-container protocol; never executes tools."""
from __future__ import annotations

import copy
import json
import math
import re

STRICT_TOOL_NAME = "submit_step"
ENTRY_FIELDS = (
    "entry_id", "report_id", "source_link", "vuln_ids", "origin", "project",
    "repo_url", "commit", "vuln_title", "vuln_category_l1", "vuln_category_l2",
    "entry_point", "critical_operation", "trace", "verify",
)
REVISION_BASES = ("behavior_at_revision", "affected_range_and_source", "inspected_only", "unknown")
STATUSES = ("supported", "uncertain", "missing", "conflicting")
STRICT_PROTOCOL_INSTRUCTION = """For this request use exactly ONE submit_step function call as the
structured answer container, instead of the earlier text-JSON reply examples.
It does not execute anything or grant new tools. Its action/calls still request
only the existing bounded repository reads; all earlier evidence and safety
rules remain in force. Never put serialized JSON into a string value.
Supply action, plan, calls, records, summary. For action=tools, use 1-6 calls,
records=[] and summary=''. For action=draft, calls=[] and plan=''. Each record
contains a unique field name, has_value, typed value, status, brief reason,
evidence_refs and revision_basis. Omit unchanged fields from records. For an
unknown value use has_value=false and value='' (not supported); this placeholder
is discarded, never supplied as a fact. With has_value=true, uncertain/missing/
conflicting values remain unverified suggestions. For entry_point,
critical_operation, and each trace location, return only a read-evidence
reference: {evidence_ref:'E0001',start_line:1,end_line:2,desc:''}. Both line
numbers are positive integers and end_line must be at least start_line.
The reference must identify existing successful read_file evidence at the
selected revision, and that evidence must actually contain every requested
line. Do not use an advisory, diff, search hit, failed read or another revision.
The controller copies the exact saved source lines; do not output file, line,
code, or transcribe source text in a location. Keep desc concise, or use ''.
If no valid already-read reference covers the location, leave its value
unknown rather than inventing a reference or range. verify can only be integer
0. Maximum 15 records, 24 evidence references per field, 32 trace locations;
keep prose concise.
For commit, explicitly choose revision_basis: behavior_at_revision means cited
source establishes the behavior at that revision, affected_range_and_source
also establishes its relation to the advisory affected range, inspected_only
only means the revision was read, unknown means neither is established. Reading
a revision alone does not confirm it is an advisory-affected version. Keep the
mechanism reason separate. All other fields must use revision_basis='unknown'.
Every call argument listed in the schema is required. Empty optional prefix or
path means no filter; search_code.paths=[] means no path filter; read_file
end_line=0 means the normal bounded read window. Use explicit starting commits,
not an invented HEAD. Typical limits: list_refs=30, search_history=20,
list_files=100; offset=0 and start_line=1 when appropriate. Do not request
additional calls during a draft-only or self-review turn.
"""


_PROTOCOL_REASONS = frozenset({
    "schema_mismatch", "expected_object", "expected_array", "expected_string",
    "expected_integer", "expected_boolean", "missing_property", "unexpected_properties",
    "enum_mismatch", "pattern_mismatch", "numeric_range", "union_mismatch",
    "json_node_limit", "json_depth_limit", "string_limit", "object_key_limit",
    "array_limit", "unsupported_value_type", "json_bytes_limit", "calls_limit",
    "records_limit", "plan_limit", "summary_limit", "tools_calls_required",
    "tools_records_forbidden", "tools_summary_forbidden", "blank_argument",
    "draft_calls_forbidden", "draft_plan_forbidden", "duplicate_record", "reason_limit",
    "evidence_refs_limit", "evidence_ref_invalid", "revision_basis_noncommit",
    "supported_without_value", "trace_limit", "location_range_invalid",
})
_DIAGNOSTIC_PATH = re.compile(r"\$(?:\.(?:action|plan|calls|records|summary|tool|arguments|"
    r"name|has_value|value|status|reason|evidence_refs|revision_basis|commit|prefix|limit|"
    r"query|path|offset|start_line|end_line|paths|before|after|evidence_ref|desc)|\[[0-9]{1,5}\])*")


def is_safe_diagnostic_item(name, value):
    """Only fixed reason codes and schema-property/index paths may cross out."""
    if not isinstance(value, str):
        return False
    if name == "protocol_reason":
        return value in _PROTOCOL_REASONS
    if name == "protocol_path":
        return len(value) <= 200 and _DIAGNOSTIC_PATH.fullmatch(value) is not None
    return False


class ProtocolError(ValueError):
    error_code = "deepseek_strict_protocol_invalid"

    def __init__(self, reason="schema_mismatch", path="$"):
        super().__init__(self.error_code)
        self.diagnostic = {
            "phase": "validate_submit_step",
            "protocol_reason": reason if is_safe_diagnostic_item("protocol_reason", reason) else "schema_mismatch",
            "protocol_path": path if is_safe_diagnostic_item("protocol_path", path) else "$",
        }


def _object(properties):
    return {"type": "object", "properties": properties, "required": list(properties),
            "additionalProperties": False}


def _string(*, enum=None, pattern=None, description=None):
    value = {"type": "string"}
    if enum is not None:
        value["enum"] = list(enum)
    if pattern is not None:
        value["pattern"] = pattern
    if description is not None:
        value["description"] = description
    return value


def _integer(low=0, high=100_000_000):
    return {"type": "integer", "minimum": low, "maximum": high}


def _array(item):
    return {"type": "array", "items": item}


def _location():
    """Internal read reference; the pipeline expands the final public location."""
    return _object({"evidence_ref": _string(pattern=r"^E[0-9]{4,8}$"),
                    "start_line": _integer(1), "end_line": _integer(1), "desc": _string()})


def _record(names, value_schema, has_value, *, revision_bases=("unknown",)):
    return _object({"name": _string(enum=names),
                    "has_value": {"type": "boolean", "enum": [has_value]},
                    "value": value_schema, "status": _string(enum=STATUSES),
                    "reason": _string(), "evidence_refs": _array(_string()),
                    "revision_basis": _string(enum=revision_bases)})


def _schema():
    arguments = {
        "inspect_commit": {"commit": _string()},
        "list_refs": {"prefix": _string(), "limit": _integer(1, 100)},
        "search_history": {"query": _string(), "commit": _string(), "path": _string(), "limit": _integer(1, 50)},
        "list_files": {"commit": _string(), "prefix": _string(), "offset": _integer(0, 1_000_000), "limit": _integer(1, 200)},
        "read_file": {"commit": _string(), "path": _string(), "start_line": _integer(1), "end_line": _integer()},
        "search_code": {"commit": _string(), "query": _string(), "paths": _array(_string())},
        "read_diff": {"before": _string(), "after": _string(), "path": _string()},
    }
    calls = {"anyOf": [_object({"tool": _string(enum=[name]), "arguments": _object(args)})
                       for name, args in arguments.items()]}
    text_fields = [name for name in ENTRY_FIELDS if name not in {
        "commit", "vuln_ids", "entry_point", "critical_operation", "trace", "verify"}]
    records = {"anyOf": [
        _record(["commit"], _string(enum=[""]), False, revision_bases=REVISION_BASES),
        _record([name for name in ENTRY_FIELDS if name != "commit"], _string(enum=[""]), False),
        _record(["commit"], _string(), True, revision_bases=REVISION_BASES),
        _record(text_fields, _string(), True),
        _record(["vuln_ids"], _array(_string()), True),
        _record(["entry_point", "critical_operation"], _location(), True),
        _record(["trace"], _array(_location()), True),
        _record(["verify"], {"type": "integer", "enum": [0]}, True),
    ]}
    return _object({"action": _string(enum=["tools", "draft"]), "plan": _string(),
                    "calls": _array(calls), "records": _array(records), "summary": _string()})


def strict_tool_definition():
    """Return a fresh official strict-mode definition without unsupported bounds."""
    return {"type": "function", "function": {
        "name": STRICT_TOOL_NAME, "strict": True,
        "description": "Submit one structured planning or draft answer; this container never executes a tool.",
        "parameters": _schema()}}


def _bounded(value, *, allow_json_scalars=False):
    """Enforce resource bounds before schema checks, without coercing values.

    Staged annotations isolate null/finite-number type errors per field. The
    legacy strict record contract continues rejecting these scalars globally.
    """
    nodes = 0

    def visit(item, depth):
        nonlocal nodes
        nodes += 1
        if nodes > 10_000 or depth > 16:
            raise ProtocolError("json_node_limit" if nodes > 10_000 else "json_depth_limit")
        if isinstance(item, str):
            if len(item) > 32_000:
                raise ProtocolError("string_limit")
        elif isinstance(item, dict):
            if any(not isinstance(key, str) or len(key) > 64 for key in item):
                raise ProtocolError("object_key_limit")
            for child in item.values():
                visit(child, depth + 1)
        elif isinstance(item, list):
            if len(item) > 64:
                raise ProtocolError("array_limit")
            for child in item:
                visit(child, depth + 1)
        elif allow_json_scalars and (item is None or type(item) is float and math.isfinite(item)):
            pass
        elif type(item) not in (bool, int):
            raise ProtocolError("unsupported_value_type")
    visit(value, 0)
    try:
        encoded = json.dumps(value, ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (ValueError, UnicodeError):
        raise ProtocolError("unsupported_value_type") from None
    if len(encoded) > 1_048_576:
        raise ProtocolError("json_bytes_limit")


def _matches(value, schema):
    """Validate only the small schema vocabulary this module itself generates."""
    if "anyOf" in schema:
        return any(_matches(value, choice) for choice in schema["anyOf"])
    kind = schema["type"]
    if kind == "object":
        return (isinstance(value, dict) and set(value) == set(schema["properties"])
                and all(_matches(value[key], child) for key, child in schema["properties"].items()))
    if kind == "array":
        return isinstance(value, list) and all(_matches(item, schema["items"]) for item in value)
    if kind == "string":
        valid = isinstance(value, str) and ("pattern" not in schema or re.fullmatch(schema["pattern"], value) is not None)
    elif kind == "integer":
        valid = type(value) is int and schema.get("minimum", value) <= value <= schema.get("maximum", value)
    elif kind == "boolean":
        valid = type(value) is bool
    else:
        return False
    return valid and ("enum" not in schema or value in schema["enum"])


def _schema_error(value, schema, path="$"):
    """Explain an existing rejection; never determine whether to accept it.

    Paths use schema-owned property names, never keys copied from the answer.
    Known discriminators select an anyOf branch, but their values are not logged.
    """
    if _matches(value, schema):
        return None
    if "anyOf" in schema:
        candidates = schema["anyOf"]
        if not isinstance(value, dict):
            return "union_mismatch", path
        selected = False
        for discriminator in ("tool", "name", "has_value"):
            tagged = [choice for choice in candidates
                      if "enum" in choice.get("properties", {}).get(discriminator, {})]
            if not tagged or len(tagged) != len(candidates):
                continue
            if discriminator not in value:
                return "missing_property", path + "." + discriminator
            matches = [choice for choice in tagged if _matches(
                value[discriminator], choice["properties"][discriminator])]
            if not matches:
                tag_schema = dict(tagged[0]["properties"][discriminator])
                tag_schema["enum"] = [item for choice in tagged
                                      for item in choice["properties"][discriminator]["enum"]]
                return _schema_error(value[discriminator], tag_schema, path + "." + discriminator)
            candidates, selected = matches, True
        return _schema_error(value, candidates[0], path) if selected else ("union_mismatch", path)
    kind = schema["type"]
    if kind == "object":
        if not isinstance(value, dict):
            return "expected_object", path
        for key in schema["properties"]:
            if key not in value:
                return "missing_property", path + "." + key
        if set(value) - set(schema["properties"]):
            return "unexpected_properties", path
        for key, child in schema["properties"].items():
            error = _schema_error(value[key], child, path + "." + key)
            if error is not None:
                return error
    elif kind == "array":
        if not isinstance(value, list):
            return "expected_array", path
        for index, item in enumerate(value):
            error = _schema_error(item, schema["items"], path + f"[{index}]")
            if error is not None:
                return error
    elif kind == "string":
        if not isinstance(value, str):
            return "expected_string", path
        if "pattern" in schema and re.fullmatch(schema["pattern"], value) is None:
            return "pattern_mismatch", path
    elif kind == "integer":
        if type(value) is not int:
            return "expected_integer", path
        if not schema.get("minimum", value) <= value <= schema.get("maximum", value):
            return "numeric_range", path
    elif kind == "boolean" and type(value) is not bool:
        return "expected_boolean", path
    if "enum" in schema and value not in schema["enum"]:
        return "enum_mismatch", path
    return "schema_mismatch", path


def normalize_step(value):
    """Validate, then normalize a typed answer without filling unknown values."""
    _bounded(value)
    schema = _schema()
    if not _matches(value, schema):
        raise ProtocolError(*(_schema_error(value, schema) or ("schema_mismatch", "$")))
    if len(value["calls"]) > 6 or len(value["records"]) > 15:
        raise ProtocolError("calls_limit" if len(value["calls"]) > 6 else "records_limit",
                            "$.calls" if len(value["calls"]) > 6 else "$.records")
    if len(value["plan"]) > 500 or len(value["summary"]) > 1000:
        raise ProtocolError("plan_limit" if len(value["plan"]) > 500 else "summary_limit",
                            "$.plan" if len(value["plan"]) > 500 else "$.summary")
    if value["action"] == "tools":
        if not value["calls"] or value["records"] or value["summary"]:
            reason, path = (("tools_calls_required", "$.calls") if not value["calls"] else
                            ("tools_records_forbidden", "$.records") if value["records"] else
                            ("tools_summary_forbidden", "$.summary"))
            raise ProtocolError(reason, path)
        calls = copy.deepcopy(value["calls"])
        for call_index, call in enumerate(calls):
            args, tool = call["arguments"], call["tool"]
            optional_strings = ({"list_refs": ("prefix",), "list_files": ("prefix",),
                                 "search_history": ("path",), "read_diff": ("path",)}).get(tool, ())
            for key in optional_strings:
                if args[key] == "":
                    del args[key]
            if tool == "read_file" and args["end_line"] == 0:
                del args["end_line"]
            if tool == "search_code" and args["paths"] == []:
                del args["paths"]
            for key in ("commit", "before", "after", "query"):
                if key in args and not args[key].strip():
                    raise ProtocolError("blank_argument", f"$.calls[{call_index}].arguments.{key}")
            if tool == "read_file":
                if not args["path"].strip():
                    raise ProtocolError("blank_argument", f"$.calls[{call_index}].arguments.path")
                if "end_line" in args and args["end_line"] < args["start_line"]:
                    raise ProtocolError("numeric_range", f"$.calls[{call_index}].arguments.end_line")
        return {"action": "tools", "plan": value["plan"], "calls": calls}
    if value["calls"] or value["plan"]:
        raise ProtocolError("draft_calls_forbidden" if value["calls"] else "draft_plan_forbidden",
                            "$.calls" if value["calls"] else "$.plan")
    fields, reviews = {}, {}
    for record_index, record in enumerate(value["records"]):
        record_path = f"$.records[{record_index}]"
        name = record["name"]
        if name in reviews or len(record["reason"]) > 2000 or len(record["evidence_refs"]) > 24:
            reason, path = (("duplicate_record", ".name") if name in reviews else
                            ("reason_limit", ".reason") if len(record["reason"]) > 2000 else
                            ("evidence_refs_limit", ".evidence_refs"))
            raise ProtocolError(reason, record_path + path)
        for ref_index, ref in enumerate(record["evidence_refs"]):
            if re.fullmatch(r"E[0-9]{4,8}", ref) is None:
                raise ProtocolError("evidence_ref_invalid", record_path + f".evidence_refs[{ref_index}]")
        if name != "commit" and record["revision_basis"] != "unknown":
            raise ProtocolError("revision_basis_noncommit", record_path + ".revision_basis")
        if record["status"] == "supported" and not record["has_value"]:
            raise ProtocolError("supported_without_value", record_path + ".has_value")
        if name == "trace" and record["has_value"] and len(record["value"]) > 32:
            raise ProtocolError("trace_limit", record_path + ".value")
        if name in {"entry_point", "critical_operation", "trace"} and record["has_value"]:
            locations = record["value"] if name == "trace" else [record["value"]]
            for location_index, location in enumerate(locations):
                if location["end_line"] < location["start_line"]:
                    path = record_path + ".value" + (f"[{location_index}]" if name == "trace" else "")
                    raise ProtocolError("location_range_invalid", path + ".end_line")
            # Evidence existence, read success, revision and source coverage
            # require the pipeline's saved evidence, not this syntax validator.
        review = {key: copy.deepcopy(record[key]) for key in ("status", "reason", "evidence_refs")}
        if name == "commit":
            review["revision_basis"] = record["revision_basis"]
        if record["has_value"]:
            if record["status"] == "supported":
                fields[name] = copy.deepcopy(record["value"])
            else:
                review["suggested_value"] = copy.deepcopy(record["value"])
        reviews[name] = review
    return {"action": "draft", "fields": fields, "field_reviews": reviews, "summary": value["summary"]}
