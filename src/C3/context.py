import json
from dataclasses import dataclass


@dataclass
class TruncationEvent:
    tool: str
    original_record_count: int
    kept_record_count: int
    reason: str  # "record_count_cap" | "char_budget_cap" | "none"


def truncate_tool_result(
    tool_name: str,
    result: dict,
    max_records: int,
    max_chars: int,
) -> tuple[dict, TruncationEvent]:
    """
    Apply deterministic record-count and character-budget caps to a
    Zeek tool result before it is placed into the LLM context.

    Returns:
        (possibly-truncated result dict, TruncationEvent). The returned
        dict always carries explicit "context_truncated" /
        "context_kept_count" / "context_original_count" fields, so the
        model is told in-band when it is not seeing everything query_*
        already found.
    """
    records = result.get("records", [])
    original_count = len(records)

    kept = records[:max_records]
    reason = "record_count_cap" if len(kept) < original_count else "none"

    # Further shrink by serialized character budget, deterministically
    # dropping from the end until it fits (or nothing is left).
    while kept and len(json.dumps(kept)) > max_chars:
        kept = kept[:-1]
        reason = "char_budget_cap"

    truncated = len(kept) < original_count

    truncated_result = dict(result)
    truncated_result["records"] = kept
    truncated_result["context_truncated"] = truncated
    truncated_result["context_kept_count"] = len(kept)
    truncated_result["context_original_count"] = original_count

    event = TruncationEvent(
        tool=tool_name,
        original_record_count=original_count,
        kept_record_count=len(kept),
        reason=reason if truncated else "none",
    )
    return truncated_result, event