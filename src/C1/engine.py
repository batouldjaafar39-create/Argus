from datetime import datetime, timedelta, timezone
from typing import Optional

from src.C3.report import FinalReport
from src.zeek.queries import (
    query_conn,
    query_dce_rpc,
    query_dns,
    query_kerberos,
    query_smb_files,
    query_smb_mapping,
)

from .config import C1Config
from .rules import (
    confidence_from_findings,
    evaluate_dce_rpc,
    evaluate_kerberos,
    evaluate_remote_access_ports,
    evaluate_smb_files,
    triggered_lateral_movement_ports,
)
from .trace import C1Trace


_MAX_EVIDENCE_REFS_PER_FINDING = 5


# ---------------------------------------------------------------------
# Timestamp helpers
# ---------------------------------------------------------------------

def _parse_alert_timestamp(alert: dict) -> Optional[datetime]:
    """Parse the alert timestamp into an aware UTC datetime.

    Returns None if the alert does not contain a timestamp.

    Supported example:
        2020-04-30T00:06:38Z
    """

    timestamp = alert.get("timestamp")

    if not timestamp:
        return None

    if not isinstance(timestamp, str):
        raise ValueError(
            f"Alert timestamp must be a string, got {type(timestamp).__name__}"
        )

    value = timestamp.strip()

    # ISO-8601 'Z' means UTC.
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"

    parsed = datetime.fromisoformat(value)

    # Make naive timestamps explicitly UTC rather than silently using
    # the machine's local timezone.
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed.astimezone(timezone.utc)


def _build_investigation_window(
    alert: dict,
    config: C1Config,
) -> tuple[Optional[float], Optional[float]]:
    """Return the fixed Zeek timestamp window for this investigation.

    If the alert has a timestamp:

        start = alert timestamp
        end   = start + configured investigation window

    If no timestamp exists, both values are None and the old
    unbounded-query behavior is preserved.
    """

    alert_dt = _parse_alert_timestamp(alert)

    if alert_dt is None:
        return None, None

    if config.investigation_window_seconds <= 0:
        raise ValueError(
            "investigation_window_seconds must be greater than zero"
        )

    end_dt = alert_dt + timedelta(
        seconds=config.investigation_window_seconds
    )

    return alert_dt.timestamp(), end_dt.timestamp()


# ---------------------------------------------------------------------
# Query execution
# ---------------------------------------------------------------------

def _run_query(
    tool_name: str,
    log_paths: dict,
    trace: C1Trace,
    **kwargs,
) -> list:
    """Run one Zeek query and record the complete query lifecycle."""

    query_fns = {
        "query_conn": query_conn,
        "query_dns": query_dns,
        "query_dce_rpc": query_dce_rpc,
        "query_smb_files": query_smb_files,
        "query_smb_mapping": query_smb_mapping,
        "query_kerberos": query_kerberos,
    }

    if tool_name not in log_paths:
        trace.log_event(
            "query_skipped",
            tool=tool_name,
            reason="no_log_for_host",
        )
        return []

    trace.log_event(
        "query_executed",
        tool=tool_name,
        args=kwargs,
    )

    result = query_fns[tool_name](
        log_path=log_paths[tool_name],
        **kwargs,
    )

    trace.log_event(
        "query_result",
        tool=tool_name,
        count=result["count"],
        matched_before_limit=result["matched_before_limit"],
        errors_skipped=result["errors_skipped"],
    )

    return result["records"]


# ---------------------------------------------------------------------
# Report construction
# ---------------------------------------------------------------------

def _findings_to_report(alert: dict, findings: list) -> dict:
    evidence = []
    technique_ids: set = set()

    for finding in findings:
        technique_ids.update(
            t.strip()
            for t in finding.attack_technique.split(",")
            if t.strip()
        )

        for ref in finding.evidence_refs[:_MAX_EVIDENCE_REFS_PER_FINDING]:
            evidence.append(
                f"[{finding.rule_id}] {ref}"
            )

    if findings:
        finding_text = " ".join(
            f"{f.rule_id}: {f.description}"
            for f in findings
        )
    else:
        finding_text = (
            "No fixed detection rule fired for this host's Zeek evidence. "
            "This does not rule out compromise -- C1's rule set only "
            "covers a fixed list of structural lateral-movement/Kerberos "
            "abuse indicators, not the full range of possible activity."
        )

    return FinalReport(
        finding=finding_text,
        affected_entities=[
            alert.get("host", "unknown")
        ],
        evidence=evidence,
        interpretation=(
            "This report was produced by a fixed rule set applied "
            "mechanically to Zeek evidence. No adaptive reasoning or "
            "LLM-generated investigation decisions were used."
        ),
        attack_technique_mapping=sorted(technique_ids),
        confidence=confidence_from_findings(findings),
        limitations=(
            "C1 is a non-adaptive deterministic baseline. Zeek evidence "
            "is restricted to a fixed investigation window beginning at "
            "the initial alert timestamp. C1 only checks the predefined "
            "rules in src/C1/rules.py and cannot adapt its investigation "
            "strategy to new evidence."
        ),
    ).model_dump()


# ---------------------------------------------------------------------
# Main C1 investigation
# ---------------------------------------------------------------------

def run_c1_investigation(
    alert: dict,
    log_paths: dict,
    config: Optional[C1Config] = None,
    case_id: str = "unknown_case",
) -> C1Trace:
    """Run the deterministic C1 investigation.

    Procedure:

        Alert
          |
          v
        Fixed time window
          |
          v
        Stage 1 Zeek sweep
          |
          v
        Fixed branch rules
          |
          v
        Stage 2 follow-up queries
          |
          v
        Fixed detection rules
          |
          v
        Final report

    No LLM or free-form reasoning is used.
    """

    config = config or C1Config()

    trace = C1Trace(
        case_id=case_id,
        condition="C1",
    )

    # ------------------------------------------------------------------
    # Determine investigation window
    # ------------------------------------------------------------------

    start_ts, end_ts = _build_investigation_window(
        alert,
        config,
    )

    if start_ts is not None and end_ts is not None:
        start_dt = datetime.fromtimestamp(
            start_ts,
            tz=timezone.utc,
        )
        end_dt = datetime.fromtimestamp(
            end_ts,
            tz=timezone.utc,
        )

        trace.log_event(
            "investigation_window",
            start_ts=start_ts,
            end_ts=end_ts,
            start_iso=start_dt.isoformat().replace("+00:00", "Z"),
            end_iso=end_dt.isoformat().replace("+00:00", "Z"),
            duration_seconds=config.investigation_window_seconds,
        )
    else:
        trace.log_event(
            "investigation_window",
            start_ts=None,
            end_ts=None,
            reason="alert_has_no_timestamp",
        )

    # These two values are deliberately passed to EVERY query.
    #
    # This is the key fix:
    #
    #     C1 does not search the entire day's logs.
    #
    # Every tool sees the exact same temporal investigation scope.
    query_time_filter = {
        "start_ts": start_ts,
        "end_ts": end_ts,
    }

    # Remove None values when there is no alert timestamp. This keeps
    # compatibility with older alerts/tests that contain no timestamp.
    query_time_filter = {
        key: value
        for key, value in query_time_filter.items()
        if value is not None
    }

    # ------------------------------------------------------------------
    # Stage 1: baseline sweep
    # ------------------------------------------------------------------

    conn_records = _run_query(
        "query_conn",
        log_paths,
        trace,
        **query_time_filter,
        limit=config.baseline_query_limit,
    )

    dns_records = _run_query(
        "query_dns",
        log_paths,
        trace,
        **query_time_filter,
        limit=config.baseline_query_limit,
    )

    kerberos_records = _run_query(
        "query_kerberos",
        log_paths,
        trace,
        **query_time_filter,
        limit=config.baseline_query_limit,
    )

    # ------------------------------------------------------------------
    # Stage 2: fixed branching from conn.log
    # ------------------------------------------------------------------

    triggered = triggered_lateral_movement_ports(
        conn_records,
        config,
    )

    for branch in sorted(triggered):
        trace.log_event(
            "branch_triggered",
            branch=branch,
        )

    dce_rpc_records: list = []
    smb_files_records: list = []
    smb_mapping_records: list = []

    # Follow-up queries use THE SAME time window.
    if "dce_rpc" in triggered:
        dce_rpc_records = _run_query(
            "query_dce_rpc",
            log_paths,
            trace,
            **query_time_filter,
            limit=config.baseline_query_limit,
        )

    if "smb" in triggered:
        smb_files_records = _run_query(
            "query_smb_files",
            log_paths,
            trace,
            **query_time_filter,
            limit=config.baseline_query_limit,
        )

        smb_mapping_records = _run_query(
            "query_smb_mapping",
            log_paths,
            trace,
            **query_time_filter,
            limit=config.baseline_query_limit,
        )

    # ------------------------------------------------------------------
    # Stage 3: fixed detection rules
    # ------------------------------------------------------------------

    findings = []

    findings += evaluate_remote_access_ports(
        conn_records,
        config,
    )

    findings += evaluate_kerberos(
        kerberos_records,
        config,
    )

    findings += evaluate_dce_rpc(
        dce_rpc_records,
        config,
    )

    findings += evaluate_smb_files(
        smb_files_records,
        config,
    )

    # ------------------------------------------------------------------
    # Log rule firings
    # ------------------------------------------------------------------

    for finding in findings:
        trace.log_event(
            "rule_fired",
            rule_id=finding.rule_id,
            description=finding.description,
            attack_technique=finding.attack_technique,
            evidence_count=len(finding.evidence_refs),
        )

    # DNS and SMB mapping are collected for evidentiary completeness.
    trace.log_event(
        "dns_reviewed",
        count=len(dns_records),
    )

    trace.log_event(
        "smb_mapping_reviewed",
        count=len(smb_mapping_records),
    )

    # ------------------------------------------------------------------
    # Final report
    # ------------------------------------------------------------------

    report = _findings_to_report(
        alert,
        findings,
    )

    trace.finish(
        final_report=report,
        terminated_reason=None,
    )

    return trace