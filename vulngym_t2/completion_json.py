"""Explicit, value-preserving completion-JSON punctuation compatibility.

The caller owns byte/UTF-8 limits, a strict decoder (duplicate keys and
non-finite numbers), object/domain validation, and stage authorization. This
module performs no I/O and never supplies a missing JSON character or value.
"""
from __future__ import annotations

import json
from typing import Any


_JSON_WHITESPACE = " \t\r\n"
_NORMALIZATION_CODE = "redundant_object_close_removed"
_SEPARATOR_CODE = "trailing_separator_removed"


def extra_data_diagnostics(text: str, error: Exception) -> dict[str, Any]:
    """Describe only an Extra data tail, excluding JSON whitespace at its ends."""
    if (not isinstance(text, str) or not isinstance(error, json.JSONDecodeError)
            or error.msg != "Extra data" or error.doc != text
            or type(error.pos) is not int or not 0 <= error.pos <= len(text)):
        return {}
    tail = text[error.pos:].strip(_JSON_WHITESPACE)
    return {"tail_length": len(tail),
            "tail_kind": "single_object_close" if tail == "}" else "other"}


def public_normalizations(value: Any) -> list[dict[str, Any]]:
    """Accept one fixed punctuation audit, never text or caller-chosen labels."""
    if not isinstance(value, list) or len(value) != 1:
        return []
    item = value[0]
    if (not isinstance(item, dict) or set(item) != {"code", "count"}
            or item["code"] not in {_NORMALIZATION_CODE, _SEPARATOR_CODE}
            or type(item["count"]) is not int or item["count"] != 1):
        return []
    return [{"code": item["code"], "count": 1}]


def parse_completion_json(text: str, *, decoder: json.JSONDecoder,
                          allowed: bool = False) -> tuple[Any, dict[str, Any] | None]:
    """Decode unchanged JSON or remove one provably redundant delimiter.

    Normal JSON values are returned unchanged for the caller's existing object
    check. Compatibility is opt-in and applies only to dictionaries. The same
    caller-supplied strict decoder parses the whole input and any candidate
    prefix. All unhandled syntax errors retain the original parser exception;
    the caller must still apply its unchanged bounded-domain/schema checks.
    """
    try:
        return decoder.decode(text), None
    except json.JSONDecodeError as error:
        if allowed is not True:
            raise
        closing = error.pos
        if error.msg in {"Illegal trailing comma before end of object", "Illegal trailing comma before end of array"}:
            # Python 3.14 points at the comma or its following whitespace;
            # earlier decoders report the closing bracket instead.
            if closing < len(text) and text[closing] == ",":
                closing += 1
            while closing < len(text) and text[closing] in _JSON_WHITESPACE:
                closing += 1
        if (error.msg in {"Expecting value", "Expecting property name enclosed in double quotes",
                          "Illegal trailing comma before end of object", "Illegal trailing comma before end of array"}
                and closing < len(text) and text[closing] in "}]"
                and text[:closing].rstrip(_JSON_WHITESPACE).endswith(",")):
            comma = len(text[:closing].rstrip(_JSON_WHITESPACE)) - 1
            # Delete exactly this separator, not a value or quote. A missing
            # value, doubled comma, malformed string, duplicate key, nonfinite
            # number, second syntax error or non-object root still fails the
            # same strict decoder. Never apply this recursively.
            try:
                value = decoder.decode(text[:comma] + text[comma + 1:])
            except (ValueError, UnicodeError, RecursionError):
                pass
            else:
                if isinstance(value, dict):
                    return value, {"code": _SEPARATOR_CODE, "count": 1}
            raise
        if extra_data_diagnostics(text, error).get("tail_kind") != "single_object_close":
            raise
        # Extra data identifies a fully parsed first value. Re-decoding its
        # exact prefix uses the original strict hooks; no fields are rewritten.
        try:
            value = decoder.decode(text[:error.pos])
        except (ValueError, UnicodeError, RecursionError):
            pass
        else:
            if isinstance(value, dict):
                return value, {"code": _NORMALIZATION_CODE, "count": 1}
        raise
