"""Controller-owned, run-local IDs for bounded multi-entry annotations."""
from __future__ import annotations

from collections.abc import Mapping, Sequence
import re


MAX_ENTRIES = 4
COUNTING_VERSION = "input-review-v2"
_ENTRY_ID = re.compile(r"entry-[0-9]{5}\Z")


def validate_entry_ids(base_id, entry_ids):
    """Validate an already allocated slot map without changing its identities."""
    if not isinstance(entry_ids, Mapping) or not 1 <= len(entry_ids) <= MAX_ENTRIES:
        raise ValueError("entry_ids_invalid")
    if (any(type(slot) is not int for slot in entry_ids)
            or set(entry_ids) != set(range(1, len(entry_ids) + 1))):
        raise ValueError("entry_slots_invalid")
    values = list(entry_ids.values())
    if any(not isinstance(value, str) or not _ENTRY_ID.fullmatch(value) for value in values):
        raise ValueError("entry_id_invalid")
    if len(set(values)) != len(values):
        raise ValueError("duplicate_entry_id")
    if entry_ids[1] != base_id:
        raise ValueError("base_entry_id_mismatch")
    return dict(sorted(entry_ids.items()))


def allocate_entry_ids(jobs, *, max_entries=MAX_ENTRIES):
    """Return slot maps aligned with jobs, reserving every supplied base ID.

    Slot 1 preserves the existing input ID. Additional IDs use unused numbers
    in sorted base-ID order, making allocation repeatable for the same job set.
    This is not a persistent cross-run catalogue or a semantic identity claim.
    No model-supplied identifier or location participates in allocation.
    """
    if type(max_entries) is not int or not 1 <= max_entries <= MAX_ENTRIES:
        raise ValueError("max_entries_invalid")
    if not isinstance(jobs, Sequence) or isinstance(jobs, (str, bytes)) or len(jobs) > 500:
        raise ValueError("jobs_invalid")
    bases = []
    for job in jobs:
        base = job.get("entry_id") if isinstance(job, Mapping) else None
        if not isinstance(base, str) or not _ENTRY_ID.fullmatch(base):
            raise ValueError("entry_id_invalid")
        bases.append(base)
    if len(set(bases)) != len(bases):
        raise ValueError("duplicate_input_entry_id")
    allocated = {base: {1: base} for base in bases}
    reserved = set(bases)
    number = 0
    for base in sorted(bases):
        for slot in range(2, max_entries + 1):
            while number < 100_000 and f"entry-{number:05d}" in reserved:
                number += 1
            if number >= 100_000:
                raise ValueError("entry_id_space_exhausted")
            selected = f"entry-{number:05d}"
            allocated[base][slot] = selected
            reserved.add(selected)
            number += 1
    return [allocated[base] for base in bases]
