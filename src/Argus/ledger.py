from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from src.C3.context import truncate_tool_result
from src.C3.tools import ToolDispatchError, dispatch_tool_call


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
        """
        Full authoritative representation of this evidence entry.

        This representation is used by verification and trace-related logic.
        It must not be confused with the compact representation sent to the LLM.
        """
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
    """
    Authoritative, deterministic record of evidence retrieved by Argus.

    IMPORTANT:
    - entries contains the complete bounded evidence used by Argus.
    - max_records/max_chars control how much evidence is retained per tool.
    - compact_to_dict() creates a smaller deterministic representation for Qwen.
    - compacting never modifies entries, so verification still sees all evidence.
    """

    log_paths: dict[str, str]
    max_records: int = 20
    max_chars: int = 6000
    entries: list[EvidenceEntry] = field(default_factory=list)

    def execute(self, tool_name: Any, args: Any) -> EvidenceEntry:
        evidence_id = f"E{len(self.entries) + 1:03d}"

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
                # Preserve truncation metadata inside the authoritative evidence.
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
        return {
            e.evidence_id
            for e in self.entries
            if e.status == "success"
        }

    def get(self, evidence_id: str) -> EvidenceEntry | None:
        return next(
            (e for e in self.entries if e.evidence_id == evidence_id),
            None,
        )

    def to_dict(self, max_chars: int | None = None) -> list[dict[str, Any]]:
        """
        Return the FULL authoritative ledger.

        This method intentionally preserves the previous behavior because
        verification depends on access to all bounded evidence.

        max_chars is retained for compatibility with existing callers.
        """
        payload = [e.to_dict() for e in self.entries]

        if max_chars is None:
            return payload

        # Compatibility behavior:
        # Return a bounded serialized representation without modifying
        # self.entries or the authoritative EvidenceEntry objects.
        while len(json.dumps(payload)) > max_chars:
            candidates = [
                entry["result"]["records"]
                for entry in payload
                if isinstance(entry.get("result"), dict)
                and isinstance(entry["result"].get("records"), list)
                and entry["result"]["records"]
            ]

            if not candidates:
                break

            largest = max(candidates, key=len)
            largest.pop()

        return payload

    def compact_to_dict(
        self,
        max_chars: int = 12000,
        records_per_entry: int = 6,
    ) -> list[dict[str, Any]]:
        """
        Return a SMALL deterministic representation for the LLM.

        IMPORTANT:
        This does NOT modify self.entries.

        The authoritative ledger may contain up to 40 records / 16000 chars
        per tool result, but Qwen does not need all of those raw records in
        every planning/analysis prompt.

        Selection is deterministic:
        - entries remain in chronological insertion order
        - successful evidence keeps the first N and last N records
        - metadata is always preserved
        - failed entries are always preserved
        - no random sampling
        """

        compact_payload: list[dict[str, Any]] = []

        for entry in self.entries:
            base: dict[str, Any] = {
                "evidence_id": entry.evidence_id,
                "tool": entry.tool,
                "args": entry.args,
                "status": entry.status,
                "matched_before_limit": entry.matched_before_limit,
                "context_kept_count": entry.context_kept_count,
            }

            if entry.status == "failed":
                base["error"] = entry.error
                compact_payload.append(base)
                continue

            result = entry.result or {}

            compact_result: dict[str, Any] = {}

            # Preserve useful result-level metadata.
            for key, value in result.items():
                if key != "records":
                    compact_result[key] = value

            records = result.get("records")

            if isinstance(records, list):
                compact_result["records"] = self._select_records(
                    records,
                    records_per_entry,
                )

                original_count = len(records)
                selected_count = len(compact_result["records"])

                if selected_count < original_count:
                    compact_result["_argus_compacted"] = {
                        "original_context_records": original_count,
                        "records_shown_to_llm": selected_count,
                        "selection": (
                            "first_and_last_records"
                            if selected_count > 1
                            else "first_records"
                        ),
                    }

            base["result"] = compact_result
            compact_payload.append(base)

        return self._fit_compact_budget(
            compact_payload,
            max_chars=max_chars,
        )

    @staticmethod
    def _select_records(
        records: list[Any],
        records_per_entry: int,
    ) -> list[Any]:
        """
        Deterministically select representative records.

        For N >= 4:
            first half + last half

        This gives Qwen visibility into both the beginning and end
        of the evidence without sending all records.

        The original records remain untouched in self.entries.
        """

        if not records:
            return []

        n = max(1, records_per_entry)

        if len(records) <= n:
            return list(records)

        if n == 1:
            return [records[0]]

        if n == 2:
            return [records[0], records[-1]]

        first_count = (n + 1) // 2
        last_count = n - first_count

        selected = list(records[:first_count])

        if last_count > 0:
            selected.extend(records[-last_count:])

        return selected

    @staticmethod
    def _fit_compact_budget(
        payload: list[dict[str, Any]],
        max_chars: int,
    ) -> list[dict[str, Any]]:
        """
        Ensure the compact LLM representation stays under max_chars.

        Evidence entries themselves are NEVER modified.

        If the initial compact representation is still too large,
        records are removed deterministically from the middle of the
        largest record list.

        Metadata and evidence IDs are retained.
        """

        if max_chars <= 0:
            return payload

        while len(json.dumps(payload, separators=(",", ":"))) > max_chars:
            candidates: list[tuple[int, list[Any]]] = []

            for index, entry in enumerate(payload):
                result = entry.get("result")

                if not isinstance(result, dict):
                    continue

                records = result.get("records")

                if isinstance(records, list) and len(records) > 1:
                    candidates.append((index, records))

            if not candidates:
                break

            # Deterministically choose the largest record collection.
            index, records = max(
                candidates,
                key=lambda item: (len(item[1]), -item[0]),
            )

            # Remove from the middle so the first/last evidence remains.
            remove_index = len(records) // 2
            records.pop(remove_index)

            payload[index]["result"]["_argus_compacted"] = {
                "reason": "prompt_budget",
                "records_currently_shown": len(records),
            }

        return payload

