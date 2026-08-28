from __future__ import annotations

import json
from typing import Optional

from pydantic import ValidationError

from src.C3.LLM import ASSISTANT_TAG, IM_END, LlamaCliError, _extract_json, _format_message, _run_llama_cli
from src.C3.report import FinalReport

from .config import C2Config
from .trace import C2Trace


def build_system_prompt() -> str:
    return (
        "/no_think\n"
        "You are a SOC investigation assistant analyzing a single security "
        "alert. You are a research baseline (condition C2): you have NO "
        "access to Zeek or any other evidence-retrieval tool. You must "
        "reason using only the information given in the alert itself.\n\n"
        "You do NOT have ground truth, and you cannot request additional "
        "evidence. You must not invent Zeek records, IP addresses, "
        "timestamps, domains, commands, or ATT&CK techniques. If you "
        "cannot support a claim from the alert alone, say so explicitly "
        "in interpretation/limitations rather than inventing detail.\n\n"
        "Respond with EXACTLY ONE JSON object and nothing else -- no "
        "prose outside the JSON, no markdown code fences -- with exactly "
        "this shape:\n\n"
        '{"action": "final_report", "report": {\n'
        '  "finding": "...",\n'
        '  "affected_entities": ["..."],\n'
        '  "evidence": ["..."],\n'
        '  "interpretation": "...",\n'
        '  "attack_technique_mapping": ["..." or empty list if not supported],\n'
        '  "confidence": "low" | "medium" | "high",\n'
        '  "limitations": "..."\n'
        "}}\n\n"
        "Rules:\n"
        "- The \"evidence\" field may only contain direct quotes/paraphrases "
        "of the alert itself -- you have no other evidence source.\n"
        "- If the alert does not support an ATT&CK mapping, leave "
        "attack_technique_mapping empty rather than guessing.\n"
        "- Clearly separate what the alert states (evidence field) from "
        "your own interpretation (interpretation field).\n"
        "- Because you have no tool access, your confidence should "
        "usually be \"low\" unless the alert alone is unusually conclusive.\n"
    )


def build_initial_user_message(alert: dict) -> str:
    return (
        "Initial alert (this is ALL the information you have; you have "
        "no Zeek access and no other context):\n\n"
        f"{json.dumps(alert, indent=2)}\n\n"
        "Respond with exactly one final_report JSON object as instructed."
    )


def _fallback_report(reason: str) -> dict:
    return FinalReport(
        finding="Investigation did not complete normally.",
        affected_entities=[],
        evidence=[],
        interpretation="No interpretation produced.",
        attack_technique_mapping=[],
        confidence="low",
        limitations=reason,
    ).model_dump()


def _get_llm_json_with_retries(
    conversation_with_prompt: str,
    config: C2Config,
    trace: C2Trace,
    round_number: int,
) -> tuple[Optional[dict], Optional[str]]:
    """Safeguard 1: JSON retry wrapper. Same semantics as C3's version --
    see src/C3/LLM.py for the full rationale. Duplicated rather than
    imported because it is tied to C2Trace's event log, not C3Trace's."""
    attempt_prompt = conversation_with_prompt
    for attempt in range(config.max_json_retries + 1):
        trace.log_event(
            "llm_request", round=round_number, attempt=attempt,
            prompt_chars=len(attempt_prompt),
        )
        try:
            raw = _run_llama_cli(attempt_prompt, config)
        except LlamaCliError as exc:
            trace.log_event(
                "llm_request_failed", round=round_number, attempt=attempt,
                error=str(exc),
            )
            return None, "llm_call_failure"

        trace.log_event(
            "llm_response_raw", round=round_number, attempt=attempt, raw_text=raw,
        )

        try:
            return _extract_json(raw), None
        except json.JSONDecodeError as exc:
            if attempt < config.max_json_retries:
                trace.log_event(
                    "json_retry", round=round_number, attempt=attempt, error=str(exc),
                )
                attempt_prompt = (
                    conversation_with_prompt
                    + raw + IM_END + "\n"
                    + _format_message(
                        "user",
                        "Your last response was not valid JSON "
                        f"(error: {exc}). Respond again with EXACTLY ONE "
                        "valid JSON object as instructed, and nothing else.",
                    )
                    + ASSISTANT_TAG + "\n"
                )
            else:
                trace.log_event(
                    "json_parse_failed_final", round=round_number, attempt=attempt,
                    error=str(exc), raw_text=raw,
                )
                return None, "json_parse_failure"
    return None, "json_parse_failure"  # unreachable, satisfies type checkers


def run_c2_investigation(
    alert: dict,
    config: Optional[C2Config] = None,
    case_id: str = "unknown_case",
) -> C2Trace:
    """
    Run the C2 (LLM-only, no Zeek) baseline investigation for one case.

    Unlike C3/Argus, this is intentionally single-shot in spirit: the
    model gets one alert and must produce a final_report from it alone.
    The only reason multiple "rounds" can happen at all is to bound
    correcting a structurally-invalid final_report or a hallucinated
    non-final_report action (e.g. the model attempting a tool_call it
    doesn't have) -- never to let the model gather more information,
    since none exists for this condition.

    Args:
        alert: initial alert dict shown to the model. Must NOT contain
            ground truth. No log_paths argument exists for this
            condition -- C2 has no Zeek access by design.
        config: C2Config; defaults to C2Config() if not given.
        case_id: identifier recorded in the trace.

    Returns:
        A C2Trace with the full event log and final_report populated.
    """
    config = config or C2Config()
    trace = C2Trace(case_id=case_id, condition="C2")

    conversation = _format_message("system", build_system_prompt()) + _format_message(
        "user", build_initial_user_message(alert)
    )

    for round_number in range(1, config.max_correction_rounds + 1):
        trace.log_event("correction_round_start", round=round_number)
        conversation_with_prompt = conversation + ASSISTANT_TAG + "\n"

        parsed, failure_reason = _get_llm_json_with_retries(
            conversation_with_prompt, config, trace, round_number
        )

        if parsed is None:
            if failure_reason == "llm_call_failure":
                reason_text = (
                    "The LLM backend call itself failed (timeout, missing "
                    "binary, or process error) -- the model never produced "
                    "output to judge. See the llm_request_failed event for "
                    "details."
                )
            else:
                reason_text = (
                    "LLM responded but its output could not be parsed as "
                    "valid JSON after retries."
                )
            trace.finish(
                final_report=_fallback_report(reason_text),
                terminated_reason=failure_reason,
            )
            trace.log_event("round_end", round=round_number, outcome=failure_reason)
            return trace

        action = parsed.get("action")

        if action == "final_report":
            report_raw = parsed.get("report")
            try:
                validated = FinalReport.model_validate(report_raw)
            except ValidationError as exc:
                trace.log_event(
                    "final_report_invalid", round=round_number,
                    error=str(exc), raw_report=report_raw,
                )
                conversation = (
                    conversation_with_prompt
                    + json.dumps(parsed) + IM_END + "\n"
                    + _format_message(
                        "user",
                        "Your final_report did not match the required "
                        f"structure (error: {exc}). Respond again with a "
                        "corrected final_report JSON object containing "
                        "exactly: finding, affected_entities, evidence, "
                        "interpretation, attack_technique_mapping, "
                        'confidence ("low"/"medium"/"high"), limitations.',
                    )
                )
                trace.log_event("round_end", round=round_number, outcome="final_report_invalid")
                continue

            trace.finish(final_report=validated.model_dump(), terminated_reason=None)
            trace.log_event("round_end", round=round_number, outcome="final_report")
            return trace

        # Any other action (including a hallucinated "tool_call") is
        # invalid for C2 -- it has no tools. Reject and ask again, bounded
        # by max_correction_rounds like any other correction.
        trace.log_event("invalid_action", round=round_number, parsed=parsed)
        conversation = (
            conversation_with_prompt
            + json.dumps(parsed) + IM_END + "\n"
            + _format_message(
                "user",
                'Invalid "action" value. You have no tools available in '
                'this condition; the only valid action is "final_report". '
                "Respond again with one valid final_report JSON object.",
            )
        )
        trace.log_event("round_end", round=round_number, outcome="invalid_action")

    trace.finish(
        final_report=_fallback_report(
            f"Correction-round limit ({config.max_correction_rounds}) "
            "reached before the model produced a valid final_report."
        ),
        terminated_reason="iteration_limit",
    )
    trace.log_event("round_end_forced", outcome="iteration_limit")
    return trace
