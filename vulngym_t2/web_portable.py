"""Automatic local usage for the portable GUI; no keys or model calls at startup.

Existing fixed authorizations are reused unchanged. For a new installation,
only an explicitly confirmed batch can create/extend the cumulative counter;
the child still independently enforces both cumulative and per-batch limits.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from .intake import _input_json
from .llm import MAX_AUTHORIZED_REQUESTS, MAX_RUN_REQUESTS, RequestLedger
from .web_runtime import RunManager, budget_snapshot, local_path, read_bytes


def profile_directory() -> Path:
    base = os.environ.get("LOCALAPPDATA") if os.name == "nt" else os.environ.get("XDG_STATE_HOME")
    return (Path(base) if base else Path.home() / ".local" / "state") / "VulnGymT2"


def recorded_limit(path: Path) -> int:
    """Read bounded accounting metadata, never guess missing/corrupt usage as zero."""
    raw = read_bytes(path, 2_000_000)
    if not raw.endswith(b"\n"):
        raise ValueError("managed_usage_unavailable")
    rows = [_input_json(line) for line in raw.splitlines()]
    if not rows or not isinstance(rows[0], dict) or rows[0].get("event") != "authorization":
        raise ValueError("managed_usage_unavailable")
    limit = rows[0].get("request_limit")
    for row in rows[1:]:
        if not isinstance(row, dict):
            raise ValueError("managed_usage_unavailable")
        if row.get("event") == "authorization_extended":
            limit = row.get("request_limit")
    if type(limit) is not int or not 1 <= limit <= MAX_AUTHORIZED_REQUESTS:
        raise ValueError("managed_usage_unavailable")
    return limit


class PortableRunManager(RunManager):
    """Allow free preparation before the user's first paid-batch confirmation."""

    def __init__(self, root: Path, counter: Path, *, settings_path: Path | None = None, **kwargs):
        # Reuse the base's side-effect-free initialization. The actual GUI is
        # writable, but a billing file is deliberately not created at startup.
        super().__init__(root, read_only=True, **kwargs)
        self.read_only = False
        self.ledger = counter.resolve()
        self.settings_path = settings_path
        self._counter_seen = self.ledger.exists()
        self.root.mkdir(parents=True, exist_ok=True)

    def budget(self):
        try:
            if self.ledger.exists():
                self._counter_seen = True
                limit = recorded_limit(self.ledger)
                result = budget_snapshot(self.ledger, limit, 0)
                if not result["available"]:
                    raise ValueError("managed_usage_unavailable")
            else:
                if self._counter_seen or (self.settings_path is not None and self.settings_path.exists()):
                    raise ValueError("managed_usage_unavailable")
                limit = 0
                result = {"available": True, "used": 0, "generation_used": 0,
                          "pending": 0, "reported_tokens": 0, "unknown_usage": 0,
                          "currency_cost_measured": False}
            # This is technical headroom, not permission to spend it. The GUI
            # shows cumulative use only; each batch needs its own confirmation.
            return {**result, "managed": True, "limit": MAX_AUTHORIZED_REQUESTS,
                    "authorization_limit": limit,
                    "remaining": max(0, MAX_AUTHORIZED_REQUESTS - result["generation_used"])}
        except (OSError, ValueError, TypeError):
            return {"available": False, "managed": True, "remaining": None,
                    "code": "managed_usage_unavailable"}

    def start(self, run_id, key, cap, confirmed):
        # Validate before writing even an authorization header. No key is ever
        # sent to this module's persistence layer or included in any exception.
        if confirmed is not True:
            raise ValueError("explicit_run_confirmation_required")
        if not isinstance(key, str) or not 1 <= len(key) <= 500 or not all(33 <= ord(c) <= 126 for c in key):
            raise ValueError("api_key_missing_or_invalid")
        with self.lock:
            self._idle()
            if self.get(run_id).state != "prepared":
                raise ValueError("prepare_successfully_before_start")
            budget = self.budget()
            if not budget["available"] or budget["pending"]:
                raise ValueError("managed_usage_unavailable")
            if type(cap) is not int or not 1 <= cap <= min(MAX_RUN_REQUESTS, budget["remaining"]):
                raise ValueError("request_cap_exceeds_remaining")
            limit = max(budget["authorization_limit"], budget["generation_used"] + cap)
            self.ledger.parent.mkdir(parents=True, exist_ok=True)
            # Append only. RequestLedger owns cross-process locking and full
            # validation; corrupt or pending histories are never replaced.
            ledger = RequestLedger(self.ledger, limit=limit, model="deepseek-flash",
                                   extend_authorization=self.ledger.exists())
            ledger.close()
            if self.settings_path is not None:
                settings = {"version": 1, "mode": "managed", "ledger": str(self.ledger)}
                try:
                    with self.settings_path.open("x", encoding="utf-8") as stream:
                        json.dump(settings, stream)
                except FileExistsError:
                    if _input_json(read_bytes(self.settings_path, 16_384)) != settings:
                        raise ValueError("managed_budget_account_conflict") from None
            self.limit = limit
            return super().start(run_id, key, cap, confirmed)


def portable_manager(root: Path, *, profile: Path | None = None, **kwargs) -> RunManager:
    """Use machine-local settings, never a developer path embedded in the ZIP."""
    profile = profile_directory() if profile is None else profile.resolve()
    settings_path = profile / "workbench.json"
    if settings_path.exists():
        settings = _input_json(read_bytes(settings_path, 16_384))
        if not isinstance(settings, dict) or settings.get("version") != 1:
            raise ValueError("managed_budget_account_conflict")
        path = local_path(settings.get("ledger"), required=True)
        if not path.is_file():
            raise ValueError("managed_usage_unavailable")
        if settings.get("mode") == "managed":
            return PortableRunManager(root / "data" / "runs", path, **kwargs)
        if settings.get("mode") != "existing":
            raise ValueError("managed_budget_account_conflict")
        limit, historical = settings.get("limit"), settings.get("historical_requests", 0)
        if (type(limit) is not int or not 1 <= limit <= MAX_AUTHORIZED_REQUESTS
                or type(historical) is not int or not 0 <= historical <= MAX_AUTHORIZED_REQUESTS):
            raise ValueError("managed_budget_account_conflict")
        return RunManager(root / "data" / "runs", path, limit, historical,
                          effective_limit=settings.get("effective_limit"), **kwargs)

    counter = profile / "requests.jsonl"
    previous = root / "data" / "own-requests.jsonl"
    if previous.exists():
        # v2's explicit new-account setup used a package-local counter. Preserve
        # it and remember its location, so a later unzip cannot silently reset it.
        if counter.exists():
            raise ValueError("managed_budget_account_conflict")
        limit = recorded_limit(previous)
        if not budget_snapshot(previous, limit, 0)["available"]:
            raise ValueError("managed_usage_unavailable")
        profile.mkdir(parents=True, exist_ok=True)
        with settings_path.open("x", encoding="utf-8") as stream:
            json.dump({"version": 1, "mode": "managed", "ledger": str(previous.resolve())}, stream)
        counter = previous
    return PortableRunManager(root / "data" / "runs", counter, settings_path=settings_path, **kwargs)
