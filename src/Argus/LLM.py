from __future__ import annotations

import json
from typing import Any, Callable, Optional, cast
from datetime import datetime, timedelta, timezone

from pydantic import ValidationError

from src.C3.LLM import ASSISTANT_TAG, IM_END, LlamaCliError, _extract_json, _format_message, _run_llama_cli
from src.C3.tools import tool_schemas_for_prompt

from .config import ArgusConfig
from .grounding import sanitize_unsupported_report, verify_report
from .ledger import EvidenceLedger
from .report import ArgusReport
from .trace import ArgusTrace


LLMCallable = Callable[[str, ArgusConfig], str]


def build_planner_prompt() -> str:
    return (
        "/no_think\n"
        "You are the Argus investigation planner in a reproducible SOC research prototype. "
        "You receive an alert and an evidence ledger. Plan the next bounded evidence-retrieval step. "
        "Do not invent Zeek evidence or ground truth.\n\n"
        "Return EXACTLY ONE JSON object:\n"
        '{"action":"plan","hypotheses":[{"id":"H1","statement":"..."}],'
        '"tool_calls":[{"tool":"<tool>","args":{...}}],"follow_up_required":true|false,'
        '"follow_up_reason":"..."}\n\n'
        "You may request multiple tool calls in one plan. The execution layer will run every call through the real dispatcher. "
        "Use only these tools and their arguments:\n"
        f"{json.dumps(tool_schemas_for_prompt(), indent=2)}\n"
        "Do not include log_path. Do not include more calls than the system budget. "
        "The log files are already scoped to the alerted host. Do not use the alert hostname "
        "as src_ip or dst_ip; those filters accept IP addresses only. Omit host filters unless "
        "the alert contains an actual IP address. "
        "If the alert contains a timestamp, use that timestamp to constrain the first query to the "
        "investigation window supplied in the alert/context. Do not invent timestamps or IPs. "
        "If existing evidence is sufficient, return an empty tool_calls list and follow_up_required=false."
    )


def build_analyst_prompt() -> str:
    return (
        "/no_think\n"
        "You are the Argus SOC analyst. Produce an evidence-grounded "
        "investigation report from the alert and Ledger. "
        "Never invent Zeek records, IPs, domains, timestamps, commands, "
        "or ATT&CK mappings. "

        "Every factual statement in finding, interpretation, "
        "affected_entities, and attack_technique_mapping MUST contain "
        "at least one citation in the exact form [E###]. "

        "The evidence field MUST contain the same Ledger evidence IDs "
        "used to support the report. "

        "Only assign an ATT&CK technique when the Ledger evidence "
        "directly supports it. Do not infer an ATT&CK technique merely "
        "from a port, protocol, hostname, or generic suspicious behavior. "

        "If the evidence is insufficient to support an ATT&CK technique, "
        "return an empty attack_technique_mapping list.\n\n"

        "Return EXACTLY ONE JSON object:\n"

        '{"action":"final_report","report":{'
        '"finding":"... [E001]",'
        '"affected_entities":["... [E001]"],'
        '"evidence":["E001"],'
        '"interpretation":"... [E001]",'
        '"attack_technique_mapping":["TXXXX - description [E001]"],'
        '"confidence":"low|medium|high",'
        '"limitations":"..."}}'
    )


def _planner_user_message(
    alert: dict[str, Any], ledger: EvidenceLedger, round_number: int, max_chars: int
) -> str:
    window_note = "No alert timestamp window available."
    timestamp = alert.get("timestamp") if isinstance(alert, dict) else None
    if isinstance(timestamp, str):
        try:
            candidate = timestamp[:-1] + "+00:00" if timestamp.endswith("Z") else timestamp
            start = datetime.fromisoformat(candidate)
            if start.tzinfo is None:
                start = start.replace(tzinfo=timezone.utc)
            end = start + timedelta(seconds=3600)
            window_note = (
                "Investigation window: "
                + start.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
                + " through "
                + end.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
                + ". If using start_ts/end_ts, provide these values; the execution layer accepts ISO timestamps and converts them to epoch seconds."
            )
        except ValueError:
            pass
    return (
        f"Planning round {round_number}.\n\nALERT:\n{json.dumps(alert, indent=2)}\n\n"
        f"{window_note}\n\nLEDGER:\n{json.dumps(ledger.to_dict(max_chars), indent=2)}\n\n"
        "Return one plan JSON object."
    )


def _analyst_user_message(alert: dict[str, Any], ledger: EvidenceLedger, max_chars: int) -> str:
    return (
        "Prepare the final report.\n\nALERT:\n"
        + json.dumps(alert, indent=2)
        + "\n\nLEDGER:\n"
        + json.dumps(ledger.to_dict(max_chars), indent=2)
        + "\n\nReturn one final_report JSON object."
    )


def _revision_user_message(
    violations: list[str], report: dict[str, Any], ledger: EvidenceLedger, max_chars: int
) -> str:
    return (
        "Your report failed deterministic evidence verification. Revise ONLY the report. "
        "Specific violations:\n"
        + json.dumps(violations, indent=2)
        + "\n\nCURRENT REPORT:\n"
        + json.dumps(report, indent=2)
        + "\n\nLEDGER:\n"
        + json.dumps(ledger.to_dict(max_chars), indent=2)
        + "\n\nReturn one corrected final_report JSON object."
    )


def _remove_hostname_filters(args: Any, alert: dict[str, Any]) -> dict[str, Any]:
    """Drop host-name values from IP-only query filters."""
    if not isinstance(args, dict):
        return {}

    host = alert.get("host")
    if not isinstance(host, str):
        return dict(args)

    cleaned = dict(args)
    for field in ("src_ip", "dst_ip"):
        if isinstance(cleaned.get(field), str) and cleaned[field].casefold() == host.casefold():
            cleaned.pop(field)
    return cleaned


def _generate_json(
    prompt: str,
    config: ArgusConfig,
    trace: ArgusTrace,
    phase: str,
    round_number: int,
    generate: LLMCallable,
) -> tuple[Optional[dict[str, Any]], Optional[str]]:
    attempt_prompt = prompt
    for attempt in range(config.max_json_retries + 1):
        trace.log_event("llm_request", phase=phase, round=round_number, attempt=attempt, prompt_chars=len(attempt_prompt))
        try:
            raw = generate(attempt_prompt, config)
        except LlamaCliError as exc:
            trace.log_event("llm_request_failed", phase=phase, round=round_number, attempt=attempt, error=str(exc))
            return None, "llm_call_failure"
        trace.log_event("llm_response_raw", phase=phase, round=round_number, attempt=attempt, raw_text=raw)
        try:
            return _extract_json(raw), None
        except json.JSONDecodeError as exc:
            if attempt < config.max_json_retries:
                trace.log_event("json_retry", phase=phase, round=round_number, attempt=attempt, error=str(exc))
                attempt_prompt = (
                    prompt + raw + IM_END + "\n"
                    + _format_message("user", f"Your response was invalid JSON ({exc}). Return exactly one valid JSON object.")
                    + ASSISTANT_TAG + "\n"
                )
            else:
                trace.log_event("json_parse_failed_final", phase=phase, round=round_number, attempt=attempt, error=str(exc))
                return None, "json_parse_failure"
    return None, "json_parse_failure"


def _fallback_report(reason: str) -> dict[str, Any]:
    return ArgusReport(
        finding="Investigation did not complete normally.",
        affected_entities=[],
        evidence=[],
        interpretation="No evidence-grounded interpretation was finalized.",
        attack_technique_mapping=[],
        confidence="low",
        limitations=reason,
    ).model_dump()


def run_argus_investigation(
    alert: dict[str, Any],
    log_paths: dict[str, str],
    config: Optional[ArgusConfig] = None,
    case_id: str = "unknown_case",
    generate: Optional[LLMCallable] = None,
) -> ArgusTrace:
    config = config or ArgusConfig()
    generate = generate or cast(LLMCallable, _run_llama_cli)
    trace = ArgusTrace(case_id=case_id)
    ledger = EvidenceLedger(log_paths, config.context_max_records, config.context_max_chars)

    planner_history = ""
    for planning_round in range(1, config.max_planning_rounds + 1):
        trace.log_event("planning_round_start", round=planning_round)
        prompt = (
            _format_message("system", build_planner_prompt())
            + _format_message(
                "user",
                _planner_user_message(alert, ledger, planning_round, config.prompt_max_chars),
            )
            + planner_history
            + ASSISTANT_TAG + "\n"
        )
        parsed, failure = _generate_json(prompt, config, trace, "planner", planning_round, generate)
        if parsed is None:
            trace.finish(_fallback_report(f"Planner failed: {failure}"), failure)
            return trace
        if parsed.get("action") != "plan":
            trace.log_event("invalid_planner_action", round=planning_round, parsed=parsed)
            planner_history = prompt + json.dumps(parsed) + IM_END + "\n" + _format_message("user", 'The action must be "plan". Return a valid plan.')
            continue

        hypotheses = parsed.get("hypotheses") or []
        calls = parsed.get("tool_calls") or []
        if len(calls) > config.max_tool_calls_per_plan:
            trace.log_event("plan_tool_call_limit", round=planning_round, requested=len(calls), allowed=config.max_tool_calls_per_plan)
            calls = calls[:config.max_tool_calls_per_plan]

        trace.log_event("plan_created", round=planning_round, hypotheses=hypotheses, tool_call_count=len(calls))
        for index, call in enumerate(calls, start=1):
            tool = call.get("tool") if isinstance(call, dict) else None
            args = call.get("args") if isinstance(call, dict) else None
            args = _remove_hostname_filters(args, alert)
            entry = ledger.execute(tool, args or {})
            trace.log_event("ledger_result", round=planning_round, index=index, evidence_id=entry.evidence_id, tool=entry.tool, status=entry.status, error=entry.error, matched_before_limit=entry.matched_before_limit, context_kept_count=entry.context_kept_count)

        follow_up = bool(parsed.get("follow_up_required"))
        trace.log_event("planning_round_end", round=planning_round, follow_up_required=follow_up)
        if not follow_up or planning_round >= config.max_planning_rounds:
            break
        planner_history = (
            _format_message("user", "The Ledger now contains the retrieved evidence. Re-plan only if additional evidence is genuinely needed.")
        )

    # Analyst phase.
    analyst_prompt = (
        _format_message("system", build_analyst_prompt())
        + _format_message("user", _analyst_user_message(alert, ledger, config.prompt_max_chars))
        + ASSISTANT_TAG
        + "\n"
    )
    parsed, failure = _generate_json(analyst_prompt, config, trace, "analyst", 0, generate)
    if parsed is None:
        trace.finish(_fallback_report(f"Analyst failed: {failure}"), failure)
        return trace

    if parsed.get("action") != "final_report":
        trace.log_event("invalid_analyst_action", parsed=parsed)
        trace.finish(_fallback_report("Analyst did not return a final_report action."), "invalid_analyst_action")
        return trace

    report_raw = parsed.get("report")
    try:
        report = ArgusReport.model_validate(report_raw)
    except ValidationError as exc:
        trace.log_event("analyst_report_invalid", error=str(exc), raw_report=report_raw)
        trace.finish(_fallback_report(f"Analyst report schema validation failed: {exc}"), "report_validation_failure")
        return trace

    for revision in range(config.max_revisions + 1):
        verification = verify_report(report, ledger)
        trace.log_event("verification", revision=revision, clean=verification.clean, violations=verification.violations)
        if verification.clean:
            trace.finish(report.model_dump(), None)
            return trace
        if revision >= config.max_revisions:
            sanitized = sanitize_unsupported_report(report, ledger, verification.violations)
            trace.log_event("unsupported_claims_stripped", revision=revision, violations=verification.violations)
            trace.finish(sanitized.model_dump(), "verification_budget_exhausted")
            return trace

        trace.log_event("analyst_revision", revision=revision + 1, violations=verification.violations)
        revision_prompt = (
            _format_message("system", build_analyst_prompt())
            + _format_message(
                "user",
                _revision_user_message(
                    verification.violations,
                    report.model_dump(),
                    ledger,
                    config.prompt_max_chars,
                ),
            )
            + ASSISTANT_TAG + "\n"
        )
        parsed, failure = _generate_json(revision_prompt, config, trace, "analyst_revision", revision + 1, generate)
        if parsed is None:
            trace.finish(_fallback_report(f"Analyst revision failed: {failure}"), failure)
            return trace
        if parsed.get("action") != "final_report":
            trace.log_event("invalid_revision_action", revision=revision + 1, parsed=parsed)
            continue
        try:
            report = ArgusReport.model_validate(parsed.get("report"))
        except ValidationError as exc:
            trace.log_event("revision_report_invalid", revision=revision + 1, error=str(exc))
            continue

    trace.finish(_fallback_report("Unexpected Argus termination."), "unexpected_termination")
    return trace
