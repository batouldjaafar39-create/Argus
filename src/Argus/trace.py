from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional


@dataclass
class ArgusTrace:
    case_id: str
    condition: str = "Argus"
    start_time: float = field(default_factory=time.time)
    end_time: Optional[float] = None
    events: list[dict[str, Any]] = field(default_factory=list)
    final_report: Optional[dict[str, Any]] = None
    terminated_reason: Optional[str] = None

    def log_event(self, event_type: str, **payload: Any) -> None:
        self.events.append({"event": event_type, "ts": time.time(), **payload})

    def finish(self, final_report: Optional[dict[str, Any]], terminated_reason: Optional[str] = None) -> None:
        self.end_time = time.time()
        self.final_report = final_report
        self.terminated_reason = terminated_reason

    @property
    def duration_seconds(self) -> Optional[float]:
        return None if self.end_time is None else self.end_time - self.start_time

    @property
    def planning_round_count(self) -> int:
        return sum(1 for e in self.events if e["event"] == "planning_round_start")

    @property
    def revision_count(self) -> int:
        return sum(1 for e in self.events if e["event"] == "analyst_revision")

    @property
    def zeek_query_count(self) -> int:
        return sum(1 for e in self.events if e["event"] == "ledger_result")

    @property
    def tools_queried(self) -> list[str]:
        seen: list[str] = []
        for e in self.events:
            tool = e.get("tool")
            if e["event"] == "ledger_result" and isinstance(tool, str) and tool not in seen:
                seen.append(tool)
        return seen

    @property
    def json_retry_count(self) -> int:
        return sum(1 for e in self.events if e["event"] == "json_retry")

    @property
    def tool_call_failure_count(self) -> int:
        return sum(1 for e in self.events if e["event"] == "ledger_result" and e.get("status") == "failed")

    def summary(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "condition": self.condition,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_seconds": self.duration_seconds,
            "planning_rounds": self.planning_round_count,
            "analyst_revisions": self.revision_count,
            "zeek_queries": self.zeek_query_count,
            "tools_queried": self.tools_queried,
            "json_retries": self.json_retry_count,
            "tool_call_failures": self.tool_call_failure_count,
            "terminated_reason": self.terminated_reason,
        }

    def to_dict(self) -> dict[str, Any]:
        return {"summary": self.summary(), "events": self.events, "final_report": self.final_report}

    def save(self, path: Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2, default=str)
