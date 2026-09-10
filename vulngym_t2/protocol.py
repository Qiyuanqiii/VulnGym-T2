"""Pure, bounded submit_step answer-container protocol; never executes tools."""
from __future__ import annotations

import copy
import json
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


class ProtocolError(ValueError):
    error_code = "deepseek_strict_protocol_invalid"

    def __init__(self):
        super().__init__(self.error_code)


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


def _record(names, value_schema, has_value):
    return _object({"name": _string(enum=names),
                    "has_value": {"type": "boolean", "enum": [has_value]},
                    "value": value_schema, "status": _string(enum=STATUSES),
                    "reason": _string(), "evidence_refs": _array(_string()),
                    "revision_basis": _string(enum=REVISION_BASES)})


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
        "vuln_ids", "entry_point", "critical_operation", "trace", "verify"}]
    records = {"anyOf": [
        _record(ENTRY_FIELDS, _string(enum=[""]), False),
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


def _bounded(value):
    nodes = 0

    def visit(item, depth):
        nonlocal nodes
        nodes += 1
        if nodes > 10_000 or depth > 16:
            raise ProtocolError()
        if isinstance(item, str):
            if len(item) > 32_000:
                raise ProtocolError()
        elif isinstance(item, dict):
            if any(not isinstance(key, str) or len(key) > 64 for key in item):
                raise ProtocolError()
            for child in item.values():
                visit(child, depth + 1)
        elif isinstance(item, list):
            if len(item) > 64:
                raise ProtocolError()
            for child in item:
                visit(child, depth + 1)
        elif type(item) not in (bool, int):
            raise ProtocolError()
    visit(value, 0)
    if len(json.dumps(value, ensure_ascii=False, allow_nan=False).encode("utf-8")) > 1_048_576:
        raise ProtocolError()


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


def normalize_step(value):
    """Validate, then normalize a typed answer without filling unknown values."""
    _bounded(value)
    if not _matches(value, _schema()):
        raise ProtocolError()
    if len(value["calls"]) > 6 or len(value["records"]) > 15:
        raise ProtocolError()
    if len(value["plan"]) > 500 or len(value["summary"]) > 1000:
        raise ProtocolError()
    if value["action"] == "tools":
        if not value["calls"] or value["records"] or value["summary"]:
            raise ProtocolError()
        calls = copy.deepcopy(value["calls"])
        for call in calls:
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
            if any(not args[key].strip() for key in ("commit", "before", "after", "query") if key in args):
                raise ProtocolError()
        return {"action": "tools", "plan": value["plan"], "calls": calls}
    if value["calls"] or value["plan"]:
        raise ProtocolError()
    fields, reviews = {}, {}
    for record in value["records"]:
        name = record["name"]
        if name in reviews or len(record["reason"]) > 2000 or len(record["evidence_refs"]) > 24:
            raise ProtocolError()
        if any(re.fullmatch(r"E[0-9]{4,8}", ref) is None for ref in record["evidence_refs"]):
            raise ProtocolError()
        if name != "commit" and record["revision_basis"] != "unknown":
            raise ProtocolError()
        if record["status"] == "supported" and not record["has_value"]:
            raise ProtocolError()
        if name == "trace" and record["has_value"] and len(record["value"]) > 32:
            raise ProtocolError()
        if name in {"entry_point", "critical_operation", "trace"} and record["has_value"]:
            locations = record["value"] if name == "trace" else [record["value"]]
            if any(location["end_line"] < location["start_line"] for location in locations):
                raise ProtocolError()
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
