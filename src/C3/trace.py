import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional


@dataclass
class C3Trace:
    case_id: str
    condition: str = "C3"
    start_time: float = field(default_factory=time.time)
    end_time: Optional[float] = None
    events: list = field(default_factory=list)
    final_report: Optional[dict] = None
    terminated_reason: Optional[str] = None  # None if completed via final_report

    def log_event(self, event_type: str, **payload: Any) -> None:
        self.events.append({"event": event_type, "ts": time.time(), **payload})

    def finish(self, final_report: Optional[dict], terminated_reason: Optional[str] = None) -> None:
        self.end_time = time.time()
        self.final_report = final_report
        self.terminated_reason = terminated_reason

    @property
    def duration_seconds(self) -> Optional[float]:
        if self.end_time is None:
            return None
        return self.end_time - self.start_time

    @property
    def iteration_count(self) -> int:
        return sum(1 for e in self.events if e["event"] == "iteration_start")

    @property
    def zeek_query_count(self) -> int:
        return sum(1 for e in self.events if e["event"] == "tool_result")

    @property
    def tools_queried(self) -> list:
        seen = []
        for e in self.events:
            if e["event"] == "tool_call" and e.get("tool") not in seen:
                seen.append(e.get("tool"))
        return seen

    @property
    def json_retry_count(self) -> int:
        return sum(1 for e in self.events if e["event"] == "json_retry")

    @property
    def tool_call_failure_count(self) -> int:
        return sum(1 for e in self.events if e["event"] == "tool_call_failed")

    @property
    def truncation_event_count(self) -> int:
        return sum(1 for e in self.events if e["event"] == "context_truncated")

    def summary(self) -> dict:
        return {
            "case_id": self.case_id,
            "condition": self.condition,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_seconds": self.duration_seconds,
            "iteration_count": self.iteration_count,
            "zeek_query_count": self.zeek_query_count,
            "tools_queried": self.tools_queried,
            "json_retry_count": self.json_retry_count,
            "tool_call_failure_count": self.tool_call_failure_count,
            "truncation_event_count": self.truncation_event_count,
            "terminated_reason": self.terminated_reason,
        }

    def to_dict(self) -> dict:
        return {
            "summary": self.summary(),
            "events": self.events,
            "final_report": self.final_report,
        }

    def save(self, path: Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2, default=str)