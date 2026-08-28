import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional


@dataclass
class C1Trace:
    """Trace shape mirrors C2Trace/C3Trace/ArgusTrace ({"summary",
    "events", "final_report"}) for a uniform evaluation pipeline across
    C1-C4. C1 has no LLM-specific counters (no json_retry, no
    correction_round) -- its distinctive counters are queries_executed
    and rules_fired, since those fully determine its (deterministic)
    behavior.
    """

    case_id: str
    condition: str = "C1"
    start_time: float = field(default_factory=time.time)
    end_time: Optional[float] = None
    events: list = field(default_factory=list)
    final_report: Optional[dict] = None
    terminated_reason: Optional[str] = None  # None if completed normally

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
    def queries_executed(self) -> list:
        return [e.get("tool") for e in self.events if e["event"] == "query_executed"]

    @property
    def branches_triggered(self) -> list:
        return [e.get("branch") for e in self.events if e["event"] == "branch_triggered"]

    @property
    def rules_fired(self) -> list:
        return [e.get("rule_id") for e in self.events if e["event"] == "rule_fired"]

    def summary(self) -> dict:
        return {
            "case_id": self.case_id,
            "condition": self.condition,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_seconds": self.duration_seconds,
            "queries_executed": self.queries_executed,
            "branches_triggered": self.branches_triggered,
            "rules_fired": self.rules_fired,
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
