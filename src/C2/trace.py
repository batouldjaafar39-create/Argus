import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional


@dataclass
class C2Trace:
    """Trace shape deliberately mirrors C3Trace/ArgusTrace ({"summary",
    "events", "final_report"}) so the eventual evaluation pipeline
    (Section 7.10-7.11) can process C1-C4 traces generically. Zeek/tool
    counters from C3Trace are dropped since C2 never touches Zeek --
    their absence here IS the signal that this condition had no evidence
    access, not an oversight.
    """

    case_id: str
    condition: str = "C2"
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
    def correction_round_count(self) -> int:
        return sum(1 for e in self.events if e["event"] == "correction_round_start")

    @property
    def json_retry_count(self) -> int:
        return sum(1 for e in self.events if e["event"] == "json_retry")

    def summary(self) -> dict:
        return {
            "case_id": self.case_id,
            "condition": self.condition,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_seconds": self.duration_seconds,
            "correction_round_count": self.correction_round_count,
            "json_retry_count": self.json_retry_count,
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
