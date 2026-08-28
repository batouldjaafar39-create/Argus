from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any
from datetime import datetime, timezone

from src.C3.context import truncate_tool_result
from src.C3.tools import ToolDispatchError, dispatch_tool_call


def _normalize_timestamp_args(args: Any) -> dict[str, Any]:
    """Normalize ISO-8601 start/end timestamps to epoch floats for Zeek tools."""
    if not isinstance(args, dict):
        return args
    normalized = dict(args)
    for field in ("start_ts", "end_ts"):
        value = normalized.get(field)
        if isinstance(value, str):
            candidate = value.strip()
            if candidate.endswith("Z"):
                candidate = candidate[:-1] + "+00:00"
            try:
                dt = datetime.fromisoformat(candidate)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                normalized[field] = dt.timestamp()
            except ValueError:
                pass
    return normalized


@dataclass
class EvidenceEntry:
    evidence_id: str
    tool: str
    args: dict[str, Any]
    status: str
    result: dict[str, Any] | None = None
    error: str | None = None
    matched_before_limit: int | None = None
    context_kept_count: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "tool": self.tool,
            "args": self.args,
            "status": self.status,
            "result": self.result,
            "error": self.error,
            "matched_before_limit": self.matched_before_limit,
            "context_kept_count": self.context_kept_count,
        }


@dataclass
class EvidenceLedger:
    """Authoritative, deterministic record of evidence retrieved by Argus."""

    log_paths: dict[str, str]
    max_records: int = 20
    max_chars: int = 6000
    entries: list[EvidenceEntry] = field(default_factory=list)

    def execute(self, tool_name: Any, args: Any) -> EvidenceEntry:
        evidence_id = f"E{len(self.entries) + 1:03d}"
        args = _normalize_timestamp_args(args)
        try:
            result = dispatch_tool_call(tool_name, args, self.log_paths)
            bounded, trunc_event = truncate_tool_result(
                tool_name,
                result,
                max_records=self.max_records,
                max_chars=self.max_chars,
            )
            entry = EvidenceEntry(
                evidence_id=evidence_id,
                tool=str(tool_name),
                args=args if isinstance(args, dict) else {},
                status="success",
                result=bounded,
                matched_before_limit=result.get("matched_before_limit"),
                context_kept_count=bounded.get("context_kept_count"),
            )
            if trunc_event.reason != "none":
                # Preserve the fact that the ledger is bounded without
                # changing the underlying Zeek implementation.
                entry.result = dict(entry.result or {})
                entry.result["_argus_truncated"] = {
                    "reason": trunc_event.reason,
                    "original_record_count": trunc_event.original_record_count,
                    "kept_record_count": trunc_event.kept_record_count,
                }
        except ToolDispatchError as exc:
            entry = EvidenceEntry(
                evidence_id=evidence_id,
                tool=str(tool_name),
                args=args if isinstance(args, dict) else {},
                status="failed",
                error=str(exc),
            )

        self.entries.append(entry)
        return entry

    def successful_ids(self) -> set[str]:
        return {e.evidence_id for e in self.entries if e.status == "success"}

    def get(self, evidence_id: str) -> EvidenceEntry | None:
        return next((e for e in self.entries if e.evidence_id == evidence_id), None)

    def to_dict(self, max_chars: int | None = None) -> list[dict[str, Any]]:
        payload = [e.to_dict() for e in self.entries]
        if max_chars is None:
            return payload

        # Keep the ledger metadata and remove the least recent records when
        # the serialized prompt budget is exceeded.
        while len(json.dumps(payload)) > max_chars:
            candidates = [
                entry["result"]["records"]
                for entry in payload
                if isinstance(entry.get("result"), dict)
                and entry["result"].get("records")
            ]
            if not candidates:
                break
            largest = max(candidates, key=len)
            largest.pop()
        return payload
