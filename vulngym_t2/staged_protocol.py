"""Small stage-specific native-call schemas; normalize data, never execute tools."""
from __future__ import annotations

import copy
import json
import re

from . import protocol


ANNOTATION_TOOL_NAME = "submit_annotation"
CANDIDATE_TOOL_NAME = "propose_candidates"
FINISH_TOOL_NAME = "finish_reading"
STAGED_WIRE_VERSION = "snapshot-v2"
MULTI_STAGED_WIRE_VERSION = "candidate-serial-snapshot-v2"
PROMPT_REVISION = "snapshot-guidance-v85"
RECOMMENDED_REASON_CHARS = 300
FINISH_REASONS = ("enough_evidence", "no_further_useful_read", "reserve_annotation_budget")
MAX_ENTRIES = 4
MAX_READ_CALLS = 4
ANNOTATION_FIELDS = ("commit", "vuln_title", "vuln_category_l1", "vuln_category_l2",
                     "entry_point", "critical_operation", "trace", "vuln_ids")
_STAGES = ("read", "candidate_selection", "annotation", "followup")
_FOLLOWUP_TOOLS = ("inspect_commit", "search_history", "read_file", "search_code", "read_diff")
_TOOL_DESCRIPTIONS = {
    "inspect_commit": "Resolve a local revision and read its commit metadata/parents. A resolved SHA is not proof of affected behavior.",
    "list_refs": "List available local refs and their revisions. Use when HEAD or a history start is unknown; a tag is only a clue.",
    "search_history": "Search literal text in local commit messages from the explicit commit start. Not source search or all remote history. Use list_refs first when HEAD is unavailable.",
    "list_files": "List repository-relative files at the commit, optionally by prefix; use offset and limit for bounded paging.",
    "read_file": "Read numbered source lines at the commit. Choose a path actually seen in saved repository evidence; a symbol name does not imply a filename. For an unobserved path, use list_files first. Its successful saved evidence ID and actually shown lines can support annotation locations.",
    "search_code": "Search a literal query in source at the commit, optionally within paths. Follow matches with read_file; hits alone cannot establish locations.",
    "read_diff": "Read a bounded change from before to after, optionally at one path. Use for navigation; read the selected revision's file to establish locations.",
    ANNOTATION_TOOL_NAME: "Submit all eight typed field decisions from saved evidence. Every decision requires value, including uncertain or missing locations. Use exact schema enums and short reasons that retain necessary uncertainty. This does not execute a repository tool.",
    CANDIDATE_TOOL_NAME: "Propose candidate scopes and saved evidence references only. The controller selects candidates and owns all entry identities and budgets.",
    FINISH_TOOL_NAME: "Finish this read stage without another read. This call must be alone, never mixed with reads. Select exactly one reason: enough_evidence, no_further_useful_read, or reserve_annotation_budget. No free-form explanation; field judgments belong in annotation.",
}
_REASONS = protocol._PROTOCOL_REASONS | {"location_placeholder_invalid"}
_EMPTY_LOCATION = {"evidence_ref": "", "start_line": 0, "end_line": 0, "desc": ""}
_NORMALIZATION_CODE = "redundant_properties_removed"
_MAX_NORMALIZATIONS = len(ANNOTATION_FIELDS) + 2 + 32
_DECISION_LOCATION_KEYS = frozenset(_EMPTY_LOCATION)
_LOCATION_DECISION_KEYS = frozenset({"status", "reason", "evidence_refs"})
_KNOWN_SHAPE_KEYS = frozenset(ANNOTATION_FIELDS) | frozenset({
    "value", "status", "reason", "evidence_refs", "revision_basis", "evidence_ref",
    "start_line", "end_line", "desc", "file", "line", "code", "description", "source_id",
    "name", "has_value", "summary", "slot", "entry_id", "report_id", "source_link",
    "origin", "project", "repo_url", "verify", "tool", "arguments", "calls",
    "records", "action", "plan", "entries", "fields", "field_reviews", "candidates", "scope",
    "affected_range_and_source", "behavior_at_revision", "selected_commit", "location",
    # Fixed schema vocabulary only; never retain arbitrary model property names
    # or their values. These are diagnostics, NOT additional accepted fields.
    "type", "kind", "note", "confidence", "source", "source_ref", "evidence_id",
    "range", "citation", "source_range", "start", "end", "revision", "code_span",
    "line_start", "line_end", "file_path", "line_range", "is_unknown", "value_type",
    "commit_id", "suggested_value", "basis", "additionalProperties", "properties", "required",
    "path", "source_path", "startLine", "endLine", "sourceId", "evidenceRef", "id",
    "evidence", "line_number", "schema", "$schema",
})
_DIAGNOSTIC_PATH = re.compile(
    r"\$(?:\.(?:tool|arguments|reason|summary|commit|vuln_title|vuln_category_l1|"
    r"vuln_category_l2|entry_point|critical_operation|trace|vuln_ids|value|status|"
    r"evidence_refs|revision_basis|evidence_ref|source_id|start_line|end_line|desc|prefix|"
    r"limit|query|path|offset|paths|before|after|calls|records|name|has_value|"
    r"action|plan|candidates|scope)|\[[0-9]{1,5}\])*")


def is_safe_diagnostic_item(name, value):
    if not isinstance(value, str):
        return False
    if name == "protocol_reason":
        return value in _REASONS
    if name == "protocol_path":
        return len(value) <= 200 and _DIAGNOSTIC_PATH.fullmatch(value) is not None
    return False


class ProtocolError(ValueError):
    error_code = "deepseek_staged_protocol_invalid"

    def __init__(self, reason="schema_mismatch", path="$"):
        super().__init__(self.error_code)
        self.diagnostic = {
            "phase": "validate_staged_step",
            "protocol_reason": reason if is_safe_diagnostic_item("protocol_reason", reason) else "schema_mismatch",
            "protocol_path": path if is_safe_diagnostic_item("protocol_path", path) else "$",
        }


def _stage(stage):
    if stage == "annotation_multi":
        raise ValueError("staged_annotation_multi_unsupported")
    if not isinstance(stage, str) or stage not in _STAGES:
        raise ValueError("staged_stage_invalid")
    return stage


def _annotation_schema(location_key="evidence_ref"):
    if location_key not in ("evidence_ref", "source_id"):
        raise ValueError("location_reference_key_invalid")
    from .annotation_rules import (REVISION_DECISION_GUIDANCE, LOCAL_OPERATION_GUIDANCE,
                                   ENTRY_DECISION_GUIDANCE, CATEGORY_DECISION_GUIDANCE,
                                   COARSE_CATEGORY_DECISION_GUIDANCE,
                                   TRACE_DECISION_GUIDANCE)
    properties = {}
    for field in ANNOTATION_FIELDS:
        if field == "commit":
            value = protocol._string(pattern=r"^(?:[0-9a-f]{40})?$")
        elif field in ("entry_point", "critical_operation"):
            # A fixed object prevents multiple EP/CO candidates on the wire.
            # Cross-property placeholder consistency is checked locally below.
            value = protocol._object({
                location_key: protocol._string(pattern=r"^(?:E[0-9]{4,8})?$"),
                "start_line": protocol._integer(0), "end_line": protocol._integer(0),
                "desc": protocol._string(),
            })
        elif field == "trace":
            location = protocol._location()
            if location_key != "evidence_ref":
                location["properties"][location_key] = location["properties"].pop("evidence_ref")
                location["required"] = [location_key if key == "evidence_ref" else key for key in location["required"]]
            value = protocol._array(location)
        elif field == "vuln_ids":
            value = protocol._array(protocol._string())
        else:
            value = protocol._string()
        decision = {"value": value, "status": protocol._string(enum=protocol.STATUSES),
                    "reason": protocol._string(), "evidence_refs": protocol._array(protocol._string(pattern=r"^E[0-9]{4,8}$"))}
        if field == "commit":
            decision["revision_basis"] = protocol._string(enum=protocol.REVISION_BASES)
        properties[field] = protocol._object(decision)
        if field == "commit":
            properties[field]["description"] = REVISION_DECISION_GUIDANCE
        elif field == "critical_operation":
            properties[field]["description"] = LOCAL_OPERATION_GUIDANCE
        elif field == "entry_point":
            properties[field]["description"] = ENTRY_DECISION_GUIDANCE
        elif field == "vuln_category_l1":
            properties[field]["description"] = COARSE_CATEGORY_DECISION_GUIDANCE
        elif field == "vuln_category_l2":
            properties[field]["description"] = CATEGORY_DECISION_GUIDANCE
        elif field == "trace":
            properties[field]["description"] = TRACE_DECISION_GUIDANCE
    return protocol._object(properties)


def _schemas(stage):
    if _stage(stage) == "annotation":
        return {ANNOTATION_TOOL_NAME: _annotation_schema()}
    if stage == "candidate_selection":
        return {CANDIDATE_TOOL_NAME: protocol._object({
            "candidates": protocol._array(protocol._object({
                "scope": protocol._string(),
                "evidence_refs": protocol._array(protocol._string(pattern=r"^E[0-9]{4,8}$")),
            })),
        })}
    # Reuse only the existing argument shapes, not its union answer container.
    choices = protocol._schema()["properties"]["calls"]["items"]["anyOf"]
    schemas = {choice["properties"]["tool"]["enum"][0]: copy.deepcopy(choice["properties"]["arguments"])
               for choice in choices}
    if stage == "followup":
        schemas = {name: schemas[name] for name in _FOLLOWUP_TOOLS}
    schemas[FINISH_TOOL_NAME] = protocol._object({"reason": protocol._string(enum=FINISH_REASONS)})
    return schemas


def tool_definitions(stage, *, location_key="evidence_ref", read_format="native_tool"):
    """Fresh native schemas, or an explicitly selected closed read-plan union."""
    if read_format not in ("native_tool", "plan_tool"):
        raise ValueError("provider_read_format_invalid")
    if read_format == "plan_tool":
        if location_key != "evidence_ref":
            raise ValueError("location_reference_key_invalid")
        from .read_plan_protocol import definition
        return [definition(stage)]
    schemas = _schemas(stage)
    if stage == "annotation":
        schemas[ANNOTATION_TOOL_NAME] = _annotation_schema(location_key)
    elif location_key != "evidence_ref":
        raise ValueError("location_reference_key_invalid")
    return [{"type": "function", "function": {
        "name": name, "strict": True,
        "description": _TOOL_DESCRIPTIONS[name],
        "parameters": schema,
    }} for name, schema in schemas.items()]


def instruction(stage, *, location_key="evidence_ref", read_format="native_tool"):
    if read_format not in ("native_tool", "plan_tool"):
        raise ValueError("provider_read_format_invalid")
    if read_format == "plan_tool":
        if location_key != "evidence_ref":
            raise ValueError("location_reference_key_invalid")
        from .read_plan_protocol import instruction as plan_instruction
        return plan_instruction(stage)
    text = _instruction(stage)
    if location_key == "source_id" and stage == "annotation":
        text = text.replace("at most one subsequent targeted field review",
                            "at most one targeted field review per initial/final snapshot")
        return re.sub(r"\bevidence_ref\b", "source_id", text)
    if location_key != "evidence_ref":
        raise ValueError("location_reference_key_invalid")
    return text


def _instruction(stage):
    _stage(stage)
    if stage == "candidate_selection":
        example = json.dumps({"candidates": [{"scope": "Brief distinct entry-to-operation scope",
                                              "evidence_refs": ["E0001"]}]}, separators=(",", ":"))
        return ("Staged wire " + MULTI_STAGED_WIRE_VERSION + "; prompt " + PROMPT_REVISION + ". "
                "Call propose_candidates exactly once. The example is shape only: its scope and E0001 "
                "are not supplied facts. An empty candidates list is valid; invent nothing. Cite saved evidence. "
                "Propose scopes, not finished fields, source text, IDs or slots. The controller selects at most "
                "four within its budget; more than four proposals are allowed, up to 64 array items. "
                "Describe each entry-to-operation branch and distinguishing premise; shared files or sinks "
                "alone do not prove distinctness. Scopes are proposals, not facts. Later snapshots receive "
                "bounded previous-candidate context: keep an unproven branch uncertain, never substitute "
                "a previously covered branch. No reads in this stage.\n"
                "Candidate arguments example (JSON):\n" + example)
    if stage == "annotation":
        schema = _annotation_schema()["properties"]
        statuses = schema["commit"]["properties"]["status"]["enum"]
        bases = schema["commit"]["properties"]["revision_basis"]["enum"]
        return ("Staged wire " + STAGED_WIRE_VERSION + "; prompt " + PROMPT_REVISION + ". "
                "Call submit_annotation exactly once with all eight "
                "fields as direct decision objects containing value, status, reason and evidence_refs; "
                "commit also requires revision_basis. Draft and self-review replace the entire snapshot. "
                "There are no outer decision arrays or no-update markers. "
                "Do not supply summary, slot, entry IDs, controller metadata or source text. "
                "value is required in EVERY decision, even when status is uncertain, missing or conflicting. "
                "For unknown text use the empty string; for unknown EP/CO use the complete empty location "
                "object shown in the template. These placeholders cannot be supported. "
                "Do not omit value or use null. A known but uncertain candidate location keeps its "
                "evidence-reference object with an uncertain status. Each EP/CO value is one object, never an array. "
                "A real location requires an E evidence_ref and positive start/end lines; desc may be empty. "
                "Mixed or partial placeholders are rejected. Empty trace/vuln_ids arrays are valid values. "
                "Use exactly one allowed status; no combinations, translations or aliases. "
                "Category labels belong in value, not status; only commit carries revision_basis.\n"
                "Allowed status values (JSON array): " + json.dumps(statuses) + "\n"
                "Allowed commit revision_basis values (JSON array): " + json.dumps(bases) + "\n"
                "Use only typed values, never serialized JSON strings. Put assessment reasons in each field's reason. "
                "Prefer one or two short sentences, usually reason <=" + str(RECOMMENDED_REASON_CHARS) +
                " characters; retain necessary uncertainty conditions and evidence limitations even if longer. "
                "The local hard limits remain reason <=2000 characters, evidence_refs <=24 IDs per decision "
                "and trace <=32 locations. Evidence IDs are E followed by 4 to 8 digits, for example E0001; "
                "cite only IDs actually present in saved evidence, not the example ID unless it exists. "
                "Use an empty evidence_refs array when no supporting citation is established. "
                "Output only declared schema properties; do not add extra properties, even duplicates. "
                "Cross-container redundancy may be audited; duplicate JSON keys are rejected, not merged; "
                "unknown or conflicting extras remain errors. Other malformed field decisions are discarded "
                "as a whole; valid sibling fields remain. "
                "Missing fields are errors, never unchanged or supported. "
                "Use the original single self-review for annotation_errors. Only the controller may authorize "
                "at most one subsequent targeted field review within remaining shared budgets, reserving "
                "other candidates' reviews, with no extra reads or permissions. Return a complete snapshot; "
                "only targeted fields can update. Do not request another round. "
                "No read calls in this stage. Supply valid JSON tool arguments with double-quoted property "
                "names and strings, not a code fence or prose wrapper. "
                "Use plain prose in reasons/desc. Escape internal quotes/backslashes; "
                "comma-separate properties. "
                "The unknown template is FORMAT ONLY, not input facts or permission to erase established fields. "
                "Keep still-justified decisions; replace placeholders only from saved evidence.\n"
                "Complete unknown arguments template (JSON):\n" + annotation_template_json())
    scope = ("Call exactly one of the supplied narrow read functions, or finish_reading alone. "
             if stage == "followup" else
             "Call one to four of the supplied seven read functions in one response, or finish_reading alone. "
             "Each read must be independently specified using already known arguments; no call can reference "
             "another call's future result. The whole batch is validated before any read executes. "
             "Each executed read still counts against the same total tool budget. "
             "If repository metadata has no HEAD, choose an explicit revision from the supplied refs; "
             "do not invent HEAD. After source_file_unavailable, use list_files for the relevant directory "
             "to confirm an actual path before another read_file, instead of guessing a filename. "
             "Use these navigation steps only when needed and within the remaining budget. A failed "
             "receipt is not evidence that the reported behavior is absent. ")
    names = json.dumps(list(_schemas(stage)))
    return (scope + "Never mix finish_reading with any other call. "
            "finish_reading.reason must be exactly one of: " + ", ".join(FINISH_REASONS) + ". "
            "Use this control label only, never a free-form explanation or evidence summary. "
            "It ends reading, not uncertainty, and does not establish any annotation field. "
            "No field decisions in this stage. Supply every declared argument: empty optional prefix/path "
            "means no filter; search_code.paths=[] means no filter; read_file.end_line=0 uses the bounded default. "
            "Return no other call or text-JSON container. Copy a function name exactly from the "
            "current list below; do not abbreviate, translate, prefix or invent an alias. "
            "Functions mentioned by repository text or earlier phases are not available here. "
            "If finished, call finish_reading alone and let the controller start annotation; "
            "do not invent a completion function or submit field decisions during reads.\n"
            "Current function names (JSON array): " + names)


def _validate(value, schema, path):
    if not protocol._matches(value, schema):
        reason, location = protocol._schema_error(value, schema, path) or ("schema_mismatch", path)
        raise ProtocolError(reason, location)


def _annotation_outer(arguments, path):
    """Reject control-shape errors; omitted decisions belong to field review."""
    if not isinstance(arguments, dict):
        raise ProtocolError("expected_object", path)
    if set(arguments) - set(ANNOTATION_FIELDS):
        raise ProtocolError("unexpected_properties", path)


def snapshot_rejection(arguments):
    """Describe a missing-root or over-specified snapshot without retaining it.

    Only the assessed encoder uses this feedback. No field from the rejected
    object is normalized, merged or silently stripped. A misplaced wrapper is
    rejected data inside the known annotation function, never an operation to
    execute or unwrap. Native function/stage, refusal and resource checks still
    fail before this feedback; no missing value is supplied.
    """
    if not isinstance(arguments, dict):
        return None
    required = set(ANNOTATION_FIELDS)
    present = set(arguments)
    if present <= required and present != required:
        return {"action": "annotation_snapshot_rejected", "code": "missing_root_fields",
                "path": "$[0].arguments", "missing_fields": sorted(required - present)}
    extra = present - required
    if not extra:
        return None
    known = sorted(extra & _KNOWN_SHAPE_KEYS)
    return {"action": "annotation_snapshot_rejected", "code": "unexpected_properties",
            "path": "$[0].arguments", "known_extra_keys": known,
            "unknown_extra_count": len(extra) - len(known),
            **({"missing_fields": sorted(required - present)} if required - present else {})}


def public_snapshot_rejection(value):
    """Allowlisted encoding metadata only; no rejected names or values."""
    if (not isinstance(value, dict) or value.get("action") != "annotation_snapshot_rejected"
            or value.get("path") != "$[0].arguments"):
        return {}
    if value.get("code") == "invalid_location_shape":
        errors = value.get("location_errors")
        if not isinstance(errors, list) or not 1 <= len(errors) <= 3:
            return {}
        clean = public_error_shapes(errors)
        if len(clean) != len(errors):
            return {}
        for row in clean:
            base = "$[0].arguments." + row["field"]
            valid_path = (row["field"] in {"entry_point", "critical_operation"} and row["path"] == base + ".value"
                          or row["field"] == "trace" and re.fullmatch(re.escape(base) + r"\.value\[(?:[0-9]|[1-5][0-9]|6[0-3])\]", row["path"]))
            if row.get("location_reference_key") != "source_id" or not valid_path:
                return {}
        return {"action": value["action"], "code": value["code"], "path": value["path"],
                "location_errors": clean}
    if value.get("code") == "missing_root_fields":
        fields = value.get("missing_fields")
        if (not isinstance(fields, list) or not 1 <= len(fields) <= len(ANNOTATION_FIELDS)
                or any(not isinstance(field, str) or field not in ANNOTATION_FIELDS for field in fields)
                or len(fields) != len(set(fields))):
            return {}
        return {"action": value["action"], "code": value["code"], "path": value["path"],
                "missing_fields": sorted(fields)}
    if value.get("code") == "invalid_annotation_json":
        length = value.get("answer_characters")
        if type(length) is not int or not 1 <= length <= 262_144:
            return {}
        return {"action": value["action"], "code": value["code"], "path": value["path"],
                "answer_characters": length}
    if value.get("code") in {"duplicate_location_key", "duplicate_reference_key"}:
        reference_rejection = value["code"] == "duplicate_reference_key"
        allowed_fields = set(ANNOTATION_FIELDS) if reference_rejection else {"entry_point", "critical_operation", "trace"}
        allowed_keys = {"source_id", "start_line", "end_line", "desc"}
        if reference_rejection:
            allowed_keys.add("evidence_refs")
        fields, keys, count = (value.get("duplicate_fields"), value.get("known_duplicate_keys"),
                               value.get("duplicate_key_count"))
        if (not isinstance(fields, list) or not 1 <= len(fields) <= len(allowed_fields)
                or any(not isinstance(field, str) or field not in allowed_fields
                       for field in fields)
                or not isinstance(keys, list) or not 1 <= len(keys) <= len(allowed_keys)
                or any(not isinstance(key, str) or key not in allowed_keys
                       for key in keys)
                or (reference_rejection and "evidence_refs" not in keys)
                or type(count) is not int or not 1 <= count <= 128):
            return {}
        return {"action": value["action"], "code": value["code"], "path": value["path"],
                "duplicate_fields": sorted(set(fields)), "known_duplicate_keys": sorted(set(keys)),
                "duplicate_key_count": count}
    if value.get("code") != "unexpected_properties":
        return {}
    keys, count = value.get("known_extra_keys"), value.get("unknown_extra_count")
    if (not isinstance(keys, list) or len(keys) > 64
            or any(not isinstance(key, str) or key not in _KNOWN_SHAPE_KEYS for key in keys)
            or type(count) is not int or not 0 <= count <= 256):
        return {}
    missing = value.get("missing_fields", [])
    if (not isinstance(missing, list) or len(missing) > len(ANNOTATION_FIELDS)
            or any(not isinstance(field, str) or field not in ANNOTATION_FIELDS for field in missing)
            or len(missing) != len(set(missing))):
        return {}
    return {"action": value["action"], "code": value["code"], "path": value["path"],
            "known_extra_keys": sorted(set(keys)), "unknown_extra_count": count,
            **({"missing_fields": sorted(missing)} if missing else {})}


def location_snapshot_rejection(reply):
    """Re-encode a known malformed location, never strip or apply its siblings.

    The ordinary decoder keeps its field-level diagnostics and legacy behavior.
    Only the assessed production session opts into one same-assessment encoding
    correction before any value from this snapshot is merged.
    """
    if not isinstance(reply, dict) or reply.get("action") != "draft":
        return None
    errors = reply.get("annotation_errors")
    shapes = public_error_shapes(reply.get("annotation_error_shapes"))
    if not isinstance(errors, list) or not shapes:
        return None
    matched = [shape for shape in shapes if any(isinstance(error, dict) and
               all(error.get(key) == shape[key] for key in ("field", "code", "path")) for error in errors)]
    rejection = public_snapshot_rejection({"action": "annotation_snapshot_rejected",
        "code": "invalid_location_shape", "path": "$[0].arguments", "location_errors": matched})
    return rejection or None


def _normalization_keys(field, path):
    """Only known redundant containers; root/control objects are never adapted."""
    base = "$[0].arguments." + field
    if path == base:
        return {"name"} | (_DECISION_LOCATION_KEYS if field in ("entry_point", "critical_operation") else set())
    if field in ("entry_point", "critical_operation") and path == base + ".value":
        return _LOCATION_DECISION_KEYS
    if field == "trace" and re.fullmatch(re.escape(base) + r"\.value\[(?:[0-9]|[12][0-9]|3[01])\]", path):
        return _LOCATION_DECISION_KEYS
    return frozenset()


def public_normalizations(value):
    """Filter audit records without retaining unknown property names or values."""
    if not isinstance(value, list) or len(value) > _MAX_NORMALIZATIONS:
        return []
    output = []
    for item in value:
        if not isinstance(item, dict) or set(item) != {"field", "code", "path", "removed_keys"}:
            continue
        field, path, keys = item["field"], item["path"], item["removed_keys"]
        if (not isinstance(field, str) or field not in ANNOTATION_FIELDS
                or item["code"] != _NORMALIZATION_CODE or not isinstance(path, str)
                or not isinstance(keys, list) or not 1 <= len(keys) <= 5
                or not all(isinstance(key, str) for key in keys) or len(set(keys)) != len(keys)):
            continue
        if not set(keys) <= _normalization_keys(field, path):
            continue
        output.append({"field": field, "code": _NORMALIZATION_CODE, "path": path,
                       "removed_keys": list(keys)})
    return output


def _error_object_schema(field, path, location_key="evidence_ref"):
    """Locate only declared annotation objects, never a model-chosen property."""
    if (not isinstance(field, str) or field not in ANNOTATION_FIELDS or not isinstance(path, str)
            or location_key not in ("evidence_ref", "source_id")):
        return None
    base = "$[0].arguments." + field
    schema = _annotation_schema(location_key)["properties"][field]
    if path == base:
        return schema
    if field in ("entry_point", "critical_operation") and path == base + ".value":
        return schema["properties"]["value"]
    if field == "trace" and re.fullmatch(re.escape(base) + r"\.value\[(?:[0-9]|[1-5][0-9]|6[0-3])\]", path):
        return schema["properties"]["value"]["items"]
    return None


def public_error_shapes(value):
    """Bound extra-key diagnostics to fixed names and counts, never raw values."""
    if not isinstance(value, list) or len(value) > len(ANNOTATION_FIELDS):
        return []
    output, seen = [], set()
    required = {"field", "code", "path", "known_extra_keys", "unknown_extra_count"}
    for item in value:
        if (not isinstance(item, dict) or not required <= set(item)
                or set(item) - required - {"location_reference_key"}):
            continue
        field, path = item["field"], item["path"]
        location_key = item.get("location_reference_key", "evidence_ref")
        schema = _error_object_schema(field, path, location_key)
        keys, unknown = item["known_extra_keys"], item["unknown_extra_count"]
        if (schema is None or field in seen or item["code"] != "unexpected_properties"
                or not isinstance(keys, list) or len(keys) > len(_KNOWN_SHAPE_KEYS)
                or not all(isinstance(key, str) for key in keys) or len(set(keys)) != len(keys)
                or not set(keys) <= _KNOWN_SHAPE_KEYS - set(schema["properties"])
                or type(unknown) is not int or not 0 <= unknown <= 10_000
                or not keys and unknown == 0):
            continue
        output.append({"field": field, "code": "unexpected_properties", "path": path,
                       "known_extra_keys": sorted(keys), "unknown_extra_count": unknown,
                       **({"location_reference_key": "source_id"} if location_key == "source_id" else {})})
        seen.add(field)
    return output


def _extra_property_shape(field, decision, path, location_key="evidence_ref"):
    """Describe the rejected object only; unknown nested content is not inspected."""
    schema = _error_object_schema(field, path, location_key)
    if schema is None or not isinstance(decision, dict):
        return []
    base = "$[0].arguments." + field
    value = decision
    if path != base:
        value = decision.get("value")
        if field == "trace":
            index = int(path.rsplit("[", 1)[1][:-1])
            if not isinstance(value, list) or index >= len(value):
                return []
            value = value[index]
    if not isinstance(value, dict):
        return []
    extras = set(value) - set(schema["properties"])
    return public_error_shapes([{
        "field": field, "code": "unexpected_properties", "path": path,
        "known_extra_keys": sorted(extras & _KNOWN_SHAPE_KEYS),
        "unknown_extra_count": len(extras - _KNOWN_SHAPE_KEYS),
        **({"location_reference_key": "source_id"} if location_key == "source_id" else {}),
    }])


def _same_typed_value(left, right):
    # Python equates True/1 and 1.0/1. Those are not lossless JSON duplicates.
    if type(left) is not type(right):
        return False
    if isinstance(left, list):
        return len(left) == len(right) and all(_same_typed_value(a, b) for a, b in zip(left, right))
    if isinstance(left, dict):
        return set(left) == set(right) and all(_same_typed_value(left[key], right[key]) for key in left)
    return left == right


def _normalize_redundant_decision(field, decision, schema):
    """Project provisionally, then prove a valid core and redundant extras.

    No required value is filled or inferred. Unknown extras may contain a
    qualification, so they cannot be ignored. Nothing is removed unless the
    whole field passes both its strict schema and existing semantic/resource
    checks, and every extra is an exact duplicate at an allowed position.
    """
    if not isinstance(decision, dict):
        return None
    base = "$[0].arguments." + field
    candidate = {key: copy.deepcopy(decision[key]) for key in schema["properties"] if key in decision}
    objects = [(base, decision, schema["properties"], "decision")]
    value = decision.get("value")
    if field in ("entry_point", "critical_operation") and isinstance(value, dict):
        location_schema = schema["properties"]["value"]
        candidate["value"] = {key: copy.deepcopy(value[key]) for key in location_schema["properties"] if key in value}
        objects.append((base + ".value", value, location_schema["properties"], "location"))
    elif field == "trace" and isinstance(value, list):
        location_schema = schema["properties"]["value"]["items"]
        for index, location in enumerate(value):
            if isinstance(location, dict):
                candidate["value"][index] = {key: copy.deepcopy(location[key])
                    for key in location_schema["properties"] if key in location}
                objects.append((f"{base}.value[{index}]", location, location_schema["properties"], "location"))
    try:
        _validate(candidate, schema, base)
        normalized = _normalize_decision(field, candidate)
    except ProtocolError:
        return None
    removals = []
    for path, original, properties, kind in objects:
        extras = sorted(set(original) - set(properties))
        if not extras:
            continue
        targets = {"name": field} if kind == "decision" else {
            key: candidate[key] for key in _LOCATION_DECISION_KEYS}
        if kind == "decision" and field in ("entry_point", "critical_operation"):
            targets.update(candidate["value"])
        if any(key not in targets or not _same_typed_value(original[key], targets[key]) for key in extras):
            return None
        removals.append({"field": field, "code": _NORMALIZATION_CODE, "path": path, "removed_keys": extras})
    return (normalized, removals) if removals else None


def annotation_shape_feedback(annotation_errors, *, location_key="evidence_ref"):
    """Return at most eight fixed schema hints, never rejected values/keys.

    The nearest declared object supplies allowed_keys and expected_shape. This
    is repair guidance for the existing review, not a fabricated field value.
    Full output is bounded to 12000 characters; a field's hint is below 1400.
    """
    if not isinstance(annotation_errors, list):
        return []
    schemas = _annotation_schema(location_key)["properties"]
    output, seen = [], set()
    for error in annotation_errors[:8]:
        if not isinstance(error, dict):
            continue
        field, code, path = (error.get(key) for key in ("field", "code", "path"))
        if (not isinstance(field, str) or field not in ANNOTATION_FIELDS or field in seen
                or not is_safe_diagnostic_item("protocol_reason", code)
                or not is_safe_diagnostic_item("protocol_path", path)):
            continue
        base = "$[0].arguments." + field
        if path != base and not path.startswith(base + "."):
            continue
        schema, nearest = schemas[field], schemas[field]
        valid_path = True
        for token in re.findall(r"\.[a-z_]+|\[[0-9]+\]", path[len(base):]):
            if token.startswith(".") and token[1:] in schema.get("properties", {}):
                schema = schema["properties"][token[1:]]
            elif token.startswith("[") and schema.get("type") == "array":
                schema = schema["items"]
            else:
                valid_path = False
                break
            if schema.get("type") == "object":
                nearest = schema
        if not valid_path:
            continue
        expected_shape = copy.deepcopy(nearest)
        # Semantic descriptions already accompany the actual function schema.
        # This compact packet is only the rejected object's structural shape.
        expected_shape.pop("description", None)
        hint = {"field": field, "code": code, "path": path,
                "allowed_keys": list(nearest["properties"]), "expected_shape": expected_shape}
        if (len(json.dumps(hint, ensure_ascii=False, separators=(",", ":"))) > 1400
                or len(json.dumps(output + [hint], ensure_ascii=False, separators=(",", ":"))) > 12000):
            continue
        output.append(hint)
        seen.add(field)
    return output


def _normalize_annotation(arguments, location_key="evidence_ref"):
    """Keep valid siblings; only audited, demonstrably redundant extras adapt."""
    result = {"action": "draft", "fields": {}, "field_reviews": {}, "summary": ""}
    errors, normalizations, error_shapes = [], [], []
    schemas = _annotation_schema(location_key)["properties"]
    for field in ANNOTATION_FIELDS:
        field_path = "$[0].arguments." + field
        try:
            if field not in arguments:
                raise ProtocolError("missing_property", field_path)
            _validate(arguments[field], schemas[field], field_path)
            normalized = _normalize_decision(field, arguments[field], location_key=location_key)
        except ProtocolError as error:
            adapted = (_normalize_redundant_decision(field, arguments.get(field), schemas[field])
                       if location_key == "evidence_ref" and error.diagnostic["protocol_reason"] == "unexpected_properties" else None)
            if adapted is None:
                errors.append({"field": field, "code": error.diagnostic["protocol_reason"],
                               "path": error.diagnostic["protocol_path"]})
                if error.diagnostic["protocol_reason"] == "unexpected_properties":
                    error_shapes.extend(_extra_property_shape(
                        field, arguments.get(field), error.diagnostic["protocol_path"], location_key))
                continue
            normalized, removals = adapted
            normalizations.extend(removals)
        result["fields"].update(normalized["fields"])
        result["field_reviews"].update(normalized["field_reviews"])
    if errors:
        result["annotation_errors"] = errors
    if normalizations:
        result["annotation_normalizations"] = public_normalizations(normalizations)
    if error_shapes:
        result["annotation_error_shapes"] = public_error_shapes(error_shapes)
    return result


def _legacy_error(error, record_fields=()):
    reason = error.diagnostic.get("protocol_reason", "schema_mismatch")
    path = error.diagnostic.get("protocol_path", "$")
    match = re.match(r"^\$\.records\[([0-9]+)\](.*)$", path)
    if match and int(match[1]) < len(record_fields):
        field, suffix = record_fields[int(match[1])], match[2]
        if suffix == ".has_value":
            suffix = ".value"  # has_value exists only in the internal normal form.
        path = "$[0].arguments." + field + suffix
    elif path.startswith("$.calls["):
        path = path.replace("$.calls[", "$[", 1)
    elif path == "$.summary":
        path = "$[0].arguments.summary"
    return ProtocolError(reason, path)


def normalize_calls(calls, stage, *, location_key="evidence_ref"):
    """Validate a stage-bounded native call batch before returning any actions.

    ``calls`` contains exactly ``{tool: name, arguments: object}`` records.
    The transport, not this module, validates the provider envelope and JSON.
    Annotation is a complete snapshot; unknown decisions never emit empty facts.
    """
    schemas = {item["function"]["name"]: item["function"]["parameters"]
               for item in tool_definitions(stage, location_key=location_key)}
    try:
        protocol._bounded(calls, allow_json_scalars=stage == "annotation")
    except protocol.ProtocolError as error:
        raise _legacy_error(error) from None
    # Resource ceilings apply to the complete batch even for direct callers.
    # Schema/type errors in bounded annotation fields are isolated below.
    if not isinstance(calls, list):
        raise ProtocolError("expected_array")
    if not 1 <= len(calls) <= (MAX_READ_CALLS if stage == "read" else 1):
        raise ProtocolError("calls_limit" if calls else "tools_calls_required")
    rejected_arguments = []
    conflicting_finish = None
    for index, call in enumerate(calls):
        path = f"$[{index}]"
        if not isinstance(call, dict):
            raise ProtocolError("expected_object", path)
        for key in ("tool", "arguments"):
            if key not in call:
                raise ProtocolError("missing_property", path + "." + key)
        if set(call) != {"tool", "arguments"}:
            raise ProtocolError("unexpected_properties", path)
        tool, arguments = call["tool"], call["arguments"]
        _validate(tool, protocol._string(enum=schemas), path + ".tool")
        if stage == "annotation":
            if location_key == "source_id" and (rejected := snapshot_rejection(arguments)):
                return rejected
            _annotation_outer(arguments, path + ".arguments")
        else:
            try:
                _validate(arguments, schemas[tool], path + ".arguments")
            except ProtocolError as error:
                # Missing named arguments and out-of-range coordinates for a
                # known read are tool-input feedback, not a network retry.
                # Reject the whole batch; never fill defaults or clamp values.
                # Unknown/control functions and other schema failures stop.
                detail = error.diagnostic
                field = detail.get("protocol_path", "").removeprefix(path + ".arguments.")
                reason = detail.get("protocol_reason")
                numeric = reason == "numeric_range" and field in {"start_line", "end_line", "limit", "offset"}
                missing = reason == "missing_property" and field in schemas[tool].get("properties", {})
                if stage != "read" or tool == FINISH_TOOL_NAME or not (numeric or missing):
                    raise
                constraint = schemas[tool]["properties"][field]
                rejected_arguments.append({"tool": tool, "path": detail["protocol_path"], "code": reason,
                    **({key: constraint[key] for key in ("minimum", "maximum") if key in constraint} if numeric else
                       {"property_schema": copy.deepcopy(constraint), "required_keys": list(schemas[tool]["required"])})})
                continue
        if tool == FINISH_TOOL_NAME and len(calls) != 1:
            # A bounded read plan can contradict itself without being a
            # transport failure. Validate every sibling before returning
            # feedback; execute neither the reads nor the finish instruction.
            # Follow-up/annotation still allow exactly one call, checked above.
            conflicting_finish = path + ".tool"
        if tool == "read_file" and not arguments["path"].strip():
            raise ProtocolError("blank_argument", path + ".arguments.path")
    if conflicting_finish is not None:
        rejected_arguments.append({"tool": FINISH_TOOL_NAME, "path": conflicting_finish,
            "code": "finish_must_be_alone", "required_choice": "read_functions_or_finish_alone"})
    if rejected_arguments:
        return {"action": "read_request_rejected", "errors": rejected_arguments, "requested_calls": len(calls)}
    tool, arguments = calls[0]["tool"], calls[0]["arguments"]
    if tool == FINISH_TOOL_NAME:
        return {"action": "finish_reading", "reason": arguments["reason"]}
    if stage == "candidate_selection":
        return {"action": "candidates", "candidates": copy.deepcopy(arguments["candidates"])}
    if stage != "annotation":
        try:
            return protocol.normalize_step({"action": "tools", "plan": "", "calls": copy.deepcopy(calls),
                                            "records": [], "summary": ""})
        except protocol.ProtocolError as error:
            raise _legacy_error(error) from None
    return _normalize_annotation(arguments, location_key)


def _normalize_decision(field, decision, *, location_key="evidence_ref"):
    """Adapt the same direct decision shape to the existing strict record checks."""
    value = copy.deepcopy(decision["value"])
    if location_key == "source_id":
        locations = [value] if field in ("entry_point", "critical_operation") else value if field == "trace" else []
        for location in locations:
            location["evidence_ref"] = location.pop("source_id")
    if field in ("entry_point", "critical_operation"):
        has_value = value != _EMPTY_LOCATION
        if has_value and (not value["evidence_ref"] or value["start_line"] == 0 or value["end_line"] == 0):
            raise ProtocolError("location_placeholder_invalid", "$[0].arguments." + field + ".value")
        if not has_value:
            value = ""
    else:
        has_value = not isinstance(value, str) or value != ""
    record = {"name": field, "has_value": has_value, "value": value,
              "status": decision["status"], "reason": decision["reason"],
              "evidence_refs": copy.deepcopy(decision["evidence_refs"]),
              "revision_basis": decision["revision_basis"] if field == "commit" else "unknown"}
    try:
        return protocol.normalize_step({"action": "draft", "plan": "", "calls": [],
                                        "records": [record], "summary": ""})
    except protocol.ProtocolError as error:
        raise _legacy_error(error, (field,)) from None


def _unknown_value(field):
    if field in ("entry_point", "critical_operation"):
        return copy.deepcopy(_EMPTY_LOCATION)
    return [] if field in ("trace", "vuln_ids") else ""


def source_id_snapshot(snapshot):
    """Explicit lossless wire encoding; never applied to arbitrary JSON or evidence."""
    result = copy.deepcopy(snapshot)
    for field in ("entry_point", "critical_operation", "trace"):
        value = result[field]["value"]
        locations = value if field == "trace" else [value]
        for location in locations:
            location["source_id"] = location.pop("evidence_ref")
    return result


def annotation_template_json():
    """Render format guidance from the same serializer used for draft history.

    The template establishes no facts and is never merged into candidate state.
    """
    return json.dumps(snapshot_from_state({}, {}), ensure_ascii=False)


def snapshot_from_state(fields, field_reviews):
    """Serialize all eight decisions without inventing missing source provenance.

    Locations must already be compact evidence references. Invalid/partial
    expanded or suggested locations become typed unknowns, never guessed refs.
    This only serializes current state; it cannot establish a supported claim.
    """
    fields = fields if isinstance(fields, dict) else {}
    field_reviews = field_reviews if isinstance(field_reviews, dict) else {}
    schemas = _annotation_schema()["properties"]
    snapshot = {}
    for field in ANNOTATION_FIELDS:
        review = field_reviews.get(field)
        review = review if isinstance(review, dict) else {}
        status = review.get("status")
        status = status if isinstance(status, str) and status in protocol.STATUSES else "missing"
        value = (fields.get(field) if status == "supported" else
                 review.get("suggested_value", fields.get(field)))
        reason = review.get("reason")
        reason = reason[:2000] if isinstance(reason, str) else "Not established from the current state."
        refs = review.get("evidence_refs")
        refs = list(dict.fromkeys(ref for ref in refs if isinstance(ref, str)
                    and re.fullmatch(r"E[0-9]{4,8}", ref)))[:24] if isinstance(refs, list) else []
        decision = {"value": copy.deepcopy(value), "status": status, "reason": reason, "evidence_refs": refs}
        if field == "commit":
            basis = review.get("revision_basis")
            decision["revision_basis"] = basis if isinstance(basis, str) and basis in protocol.REVISION_BASES else "unknown"
        try:
            protocol._bounded(decision)
            _validate(decision, schemas[field], "$[0].arguments." + field)
            _normalize_decision(field, decision)
        except (ProtocolError, protocol.ProtocolError):
            decision["value"] = _unknown_value(field)
            if decision["status"] == "supported":
                decision["status"] = "uncertain"
        snapshot[field] = decision
    return snapshot
