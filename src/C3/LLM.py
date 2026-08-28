from __future__ import annotations

import json
import subprocess
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Optional

from pydantic import ValidationError

from .config import C3Config
from .context import truncate_tool_result
from .report import FinalReport
from .tools import (
    ToolDispatchError,
    dispatch_tool_call,
    tool_schemas_for_prompt,
)
from .trace import C3Trace


ASSISTANT_TAG = "<|im_start|>assistant"
IM_END = "<|im_end|>"


class LlamaCliError(Exception):
    """Raised when the LLM backend fails."""


_servers_confirmed_up: set[tuple[str, int]] = set()


# ---------------------------------------------------------------------
# Prompt helpers
# ---------------------------------------------------------------------

def _format_message(role: str, content: str) -> str:
    return f"<|im_start|>{role}\n{content}{IM_END}\n"


def _normalize_timestamp_args(args: object) -> dict:
    """Normalize model-generated scalar arguments to Zeek tool types."""
    if not isinstance(args, dict):
        return args
    normalized = dict(args)
    for field in ("start_ts", "end_ts"):
        value = normalized.get(field)
        if isinstance(value, str):
            parsed = value.strip()
            if parsed.endswith("Z"):
                parsed = parsed[:-1] + "+00:00"
            try:
                dt = datetime.fromisoformat(parsed)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                normalized[field] = dt.timestamp()
            except ValueError:
                pass
    # DNS query type names are semantically equivalent to their numeric
    # IANA values, but the Zeek query function requires qtype: int.
    qtype_names = {
        "A": 1,
        "NS": 2,
        "MD": 3,
        "MF": 4,
        "CNAME": 5,
        "SOA": 6,
        "PTR": 12,
        "MX": 15,
        "TXT": 16,
        "AAAA": 28,
        "SRV": 33,
    }

    qtype = normalized.get("qtype")
    if isinstance(qtype, str):
        normalized_name = qtype.strip().upper()
        if normalized_name in qtype_names:
            normalized["qtype"] = qtype_names[normalized_name]

    for field in ("rcode",):
        value = normalized.get(field)
        if isinstance(value, str) and value.strip().isdigit():
            normalized[field] = int(value.strip())

    return normalized


def _parse_alert_timestamp(alert: dict) -> Optional[datetime]:
    """Parse alert timestamp as UTC."""

    timestamp = alert.get("timestamp")

    if not timestamp:
        return None

    if not isinstance(timestamp, str):
        return None

    value = timestamp.strip()

    if value.endswith("Z"):
        value = value[:-1] + "+00:00"

    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed.astimezone(timezone.utc)


def _alert_window(alert: dict, config: C3Config) -> tuple[Optional[float], Optional[float]]:
    """Return deterministic start/end timestamps derived from the alert."""

    start = _parse_alert_timestamp(alert)

    if start is None:
        return None, None

    end = start + timedelta(
        seconds=config.investigation_window_seconds
    )

    return start.timestamp(), end.timestamp()


def build_system_prompt() -> str:
    tools_json = json.dumps(
        tool_schemas_for_prompt(),
        indent=2,
    )

    return (
        "/no_think\n"
        "You are a SOC investigation assistant analyzing ONE security "
        "alert using Zeek network evidence.\n\n"

        "You are condition C3: a single local LLM interacting with "
        "deterministic Zeek query tools.\n\n"

        "CRITICAL EVIDENCE RULES:\n"
        "1. You must NEVER invent IP addresses, domains, timestamps, "
        "ports, UIDs, commands, usernames, hosts, or Zeek records.\n"
        "2. You may ONLY use values that appear in the initial alert or "
        "in a previous tool result.\n"
        "3. If the alert does not contain an IP address, DO NOT invent "
        "an IP address for a tool argument.\n"
        "4. If you need connection evidence but do not know an IP, call "
        "query_conn without src_ip or dst_ip.\n"
        "5. If you know only the alert timestamp, use the investigation "
        "window supplied by the system. Do not invent another timestamp.\n"
        "6. Never invent an ATT&CK technique. Only map a technique when "
        "the evidence supports it.\n\n"

        "OUTPUT RULES:\n"
        "On every turn output EXACTLY ONE JSON object.\n"
        "Do not output reasoning.\n"
        "Do not output <think>.\n"
        "Do not output markdown.\n"
        "Do not output code fences.\n"
        "Do not output explanations outside JSON.\n\n"

        "Valid tool call:\n"
        '{"action":"tool_call","tool":"<tool name>","args":{...}}\n\n'

        "Valid final report:\n"
        '{"action":"final_report","report":{'
        '"finding":"...",'
        '"affected_entities":["..."],'
        '"evidence":["..."],'
        '"interpretation":"...",'
        '"attack_technique_mapping":[],'
        '"confidence":"low",'
        '"limitations":"..."'
        '}}\n\n'

        "IMPORTANT:\n"
        "If the alert contains only a host and timestamp, your FIRST "
        "query should normally be an unfiltered query such as:\n"
        '{"action":"tool_call","tool":"query_conn","args":{}}\n\n'

        "Do not guess filters merely to make a query more specific.\n\n"

        "Available tools:\n"
        f"{tools_json}\n\n"

        "Investigation procedure:\n"
        "1. Start from the alert only.\n"
        "2. Query Zeek when evidence is needed.\n"
        "3. Use values discovered from Zeek results for follow-up queries.\n"
        "4. Produce a final report only when enough evidence exists or "
        "when further evidence is unnecessary.\n"
    )
def build_final_report_prompt(
    alert: dict,
    evidence_summary: str,
) -> str:
    return (
        "/no_think\n"
        "You are the final SOC analyst for a C3 investigation.\n\n"

        "Return ONLY one valid JSON object.\n"
        "Do NOT explain your reasoning.\n"
        "Do NOT output <think>.\n"
        "Do NOT call tools.\n"
        "Do NOT invent evidence IDs.\n\n"

        "IMPORTANT EVIDENCE RULES:\n"
        "- You may cite ONLY evidence IDs explicitly listed below.\n"
        "- Do not use E001, E002, etc. unless that exact ID exists below.\n"
        "- The evidence field MUST contain only IDs from the supplied evidence.\n"
        "- Do not call network activity suspicious merely because connections "
        "exist.\n"
        "- Only describe activity as suspicious/malicious if the evidence "
        "actually supports that conclusion.\n"
        "- If the evidence is insufficient to establish malicious activity, "
        "say so explicitly.\n"
        "- Do not invent IPs, hosts, ports, domains, users, timestamps, "
        "or ATT&CK techniques.\n"
        "- Do not reproduce full Zeek records.\n\n"

        f"ALERT:\n{json.dumps(alert, ensure_ascii=False)}\n\n"

        f"AVAILABLE EVIDENCE:\n{evidence_summary}\n\n"

        "Return exactly this structure:\n"
        "{"
        "\"action\":\"final_report\","
        "\"report\":{"
        "\"finding\":\"short evidence-grounded finding\","
        "\"affected_entities\":[],"
        "\"evidence\":[],"
        "\"interpretation\":\"short evidence-grounded interpretation\","
        "\"attack_technique_mapping\":[],"
        "\"confidence\":\"low\","
        "\"limitations\":\"short limitation\""
        "}"
        "}"
    )
def _build_final_evidence_summary(events: list) -> str:
    """Build the evidence available to the final analyst."""

    lines = []

    for event in events:
        if event.get("event") != "tool_result":
            continue

        evidence_id = event.get("evidence_id")

        if not evidence_id:
            continue

        tool = event.get("tool", "unknown")
        matched = event.get("matched_before_limit", 0)
        kept = event.get("kept_count", 0)
        evidence = event.get("evidence", {})

        lines.append(
            f"{evidence_id}:\n"
            f"tool={tool}\n"
            f"matched_before_limit={matched}\n"
            f"records_available_to_model={kept}\n"
            f"records={json.dumps(evidence, ensure_ascii=False)}"
        )

    if not lines:
        return "NO_EVIDENCE"

    return "\n\n".join(lines)

def build_initial_user_message(
    alert: dict,
    start_ts: Optional[float],
    end_ts: Optional[float],
) -> str:

    window_text = "No timestamp window is available."

    if start_ts is not None and end_ts is not None:
        start_dt = datetime.fromtimestamp(
            start_ts,
            tz=timezone.utc,
        )
        end_dt = datetime.fromtimestamp(
            end_ts,
            tz=timezone.utc,
        )

        window_text = (
            f"Investigation window: "
            f"{start_dt.isoformat().replace('+00:00', 'Z')} "
            f"through "
            f"{end_dt.isoformat().replace('+00:00', 'Z')}"
        )

    return (
        "Initial alert. This is ALL information initially available "
        "to you:\n\n"
        f"{json.dumps(alert, indent=2)}\n\n"
        f"{window_text}\n\n"
        "Do not invent missing values.\n"
        "If you need Zeek evidence, choose a tool and use only "
        "arguments supported by the information you actually have.\n\n"
        "Respond with EXACTLY ONE JSON object."
    )


# ---------------------------------------------------------------------
# Conversation bounding
# ---------------------------------------------------------------------

def _bound_conversation(
    conversation: str,
    seed: str,
    max_chars: int,
) -> str:

    if max_chars <= len(seed) or len(conversation) <= max_chars:
        return conversation

    marker = _format_message(
        "user",
        "Earlier tool transcript was compacted. "
        "Use the retained evidence and query again if needed.",
    )

    available = max_chars - len(seed) - len(marker)

    if available <= 0:
        return seed[:max_chars]

    recent = conversation[-available:]

    message_start = recent.find("<|im_start|>")

    if message_start > 0:
        recent = recent[message_start:]

    return seed + marker + recent


# ---------------------------------------------------------------------
# LLM backend
# ---------------------------------------------------------------------

def _run_llama_cli(prompt: str, config: C3Config) -> str:

    if config.use_server:
        return _run_via_server(prompt, config)

    return _run_via_subprocess(prompt, config)


def _run_via_server(prompt: str, config: C3Config) -> str:

    _ensure_server(config)

    url = (
        f"http://{config.server_host}:"
        f"{config.server_port}/completion"
    )

    body = json.dumps({
        "prompt": prompt,
        "n_predict": config.max_tokens,
        "temperature": config.temperature,
        "top_p": config.top_p,
        "top_k": config.top_k,
        "seed": config.seed,
        "stop": [IM_END],
    }).encode("utf-8")

    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(
            req,
            timeout=config.generation_timeout_s,
        ) as resp:
            payload = json.loads(
                resp.read().decode("utf-8")
            )

    except urllib.error.URLError as exc:
        raise LlamaCliError(
            f"llama-server request failed: {exc}"
        ) from exc

    except TimeoutError as exc:
        raise LlamaCliError(
            f"llama-server generation timed out after "
            f"{config.generation_timeout_s}s"
        ) from exc

    generated = payload.get("content", "")

    idx = generated.rfind(ASSISTANT_TAG)

    if idx != -1:
        generated = generated[
            idx + len(ASSISTANT_TAG):
        ].lstrip("\n")

    end_idx = generated.find(IM_END)

    if end_idx != -1:
        generated = generated[:end_idx]

    return generated.strip()


def _server_is_up(config: C3Config) -> bool:

    url = (
        f"http://{config.server_host}:"
        f"{config.server_port}/health"
    )

    try:
        with urllib.request.urlopen(
            url,
            timeout=3,
        ) as resp:
            return resp.status == 200

    except (
        urllib.error.URLError,
        TimeoutError,
        ConnectionError,
    ):
        return False


def _ensure_server(config: C3Config) -> None:

    key = (
        config.server_host,
        config.server_port,
    )

    if key in _servers_confirmed_up or _server_is_up(config):
        _servers_confirmed_up.add(key)
        return

    cmd = [
        config.llama_server_path,
        "-hf",
        config.model_hf_repo,
        "-c",
        str(config.context_size),
        "--host",
        config.server_host,
        "--port",
        str(config.server_port),
    ]

    if config.threads is not None:
        cmd += [
            "-t",
            str(config.threads),
        ]

    try:
        subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            start_new_session=config.keep_server_running,
        )

    except FileNotFoundError as exc:
        raise LlamaCliError(
            f"llama-server binary not found at "
            f"'{config.llama_server_path}'."
        ) from exc

    deadline = (
        time.monotonic()
        + config.server_startup_timeout_s
    )

    while time.monotonic() < deadline:

        if _server_is_up(config):
            _servers_confirmed_up.add(key)
            return

        time.sleep(
            config.server_health_poll_interval_s
        )

    raise LlamaCliError(
        f"llama-server did not become healthy within "
        f"{config.server_startup_timeout_s}s."
    )


def _run_via_subprocess(
    prompt: str,
    config: C3Config,
) -> str:

    cmd = [
        config.llama_cli_path,
        "-hf",
        config.model_hf_repo,
        "-p",
        prompt,
        "-n",
        str(config.max_tokens),
        "-c",
        str(config.context_size),
        "--temp",
        str(config.temperature),
        "--top-p",
        str(config.top_p),
        "--top-k",
        str(config.top_k),
        "--seed",
        str(config.seed),
        "-no-cnv",
        "--simple-io",
        "-r",
        IM_END,
    ]

    if config.threads is not None:
        cmd += [
            "-t",
            str(config.threads),
        ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=config.generation_timeout_s,
        )

    except FileNotFoundError as exc:
        raise LlamaCliError(
            f"llama-cli binary not found at "
            f"'{config.llama_cli_path}'."
        ) from exc

    except subprocess.TimeoutExpired as exc:
        partial = (
            (exc.stdout or "")[-1000:]
            if exc.stdout
            else "(no output captured)"
        )

        raise LlamaCliError(
            f"llama-cli timed out after "
            f"{config.generation_timeout_s}s. "
            f"Partial stdout tail: {partial!r}"
        ) from exc

    if result.returncode != 0:
        raise LlamaCliError(
            f"llama-cli exited with code "
            f"{result.returncode}. "
            f"stderr: {result.stderr[-2000:]}"
        )

    stdout = result.stdout

    idx = stdout.rfind(ASSISTANT_TAG)

    if idx == -1:
        generated = stdout
    else:
        generated = stdout[
            idx + len(ASSISTANT_TAG):
        ].lstrip("\n")

    end_idx = generated.find(IM_END)

    if end_idx != -1:
        generated = generated[:end_idx]

    return generated.strip()


# ---------------------------------------------------------------------
# JSON parsing
# ---------------------------------------------------------------------

def _extract_json(raw_text: str) -> dict:

    text = raw_text.strip()

    if not text:
        raise json.JSONDecodeError(
            "Empty model response",
            text,
            0,
        )

    # Direct parse first.
    try:
        value = json.loads(text)

        if isinstance(value, dict):
            return value

    except json.JSONDecodeError:
        pass

    # Try JSON inside markdown fences.
    if "```" in text:

        fenced_parts = text.split("```")

        for part in fenced_parts:

            candidate = part.strip()

            if candidate.startswith("json"):
                candidate = candidate[4:].strip()

            try:
                value = json.loads(candidate)

                if isinstance(value, dict):
                    return value

            except json.JSONDecodeError:
                continue

    # Finally scan for a complete JSON object.
    decoder = json.JSONDecoder()

    candidates = []

    for start, character in enumerate(text):

        if character != "{":
            continue

        try:
            value, _end = decoder.raw_decode(
                text[start:]
            )

        except json.JSONDecodeError:
            continue

        if isinstance(value, dict):
            candidates.append(value)

    action_candidates = [
        candidate
        for candidate in candidates
        if candidate.get("action")
        in {"plan", "tool_call", "final_report"}
    ]

    if action_candidates:
        return action_candidates[-1]

    if candidates:
        return candidates[-1]

    raise json.JSONDecodeError(
        "No valid JSON object found",
        text,
        0,
    )


# ---------------------------------------------------------------------
# Deterministic tool-argument safety
# ---------------------------------------------------------------------

def _alert_values(alert: dict) -> set[str]:
    """Collect values explicitly present in the initial alert."""

    values: set[str] = set()

    def collect(value):

        if isinstance(value, str):
            values.add(value)

        elif isinstance(value, dict):
            for child in value.values():
                collect(child)

        elif isinstance(value, list):
            for child in value:
                collect(child)

    collect(alert)

    return values


def _sanitize_initial_tool_args(
    parsed: dict,
    alert: dict,
) -> tuple[dict, list[str]]:

    """
    Prevent the first LLM turn from inventing entity filters.

    If the initial alert does not contain an IP, a first-turn src_ip
    or dst_ip is removed.

    If the initial alert does not contain a timestamp, timestamp
    filters are not allowed either.

    This is a deterministic safety boundary around the model, not
    additional intelligence.
    """

    cleaned = json.loads(
        json.dumps(parsed)
    )

    removed: list[str] = []

    if cleaned.get("action") != "tool_call":
        return cleaned, removed

    args = cleaned.get("args")

    if not isinstance(args, dict):
        return cleaned, removed

    alert_values = _alert_values(alert)

    for key in (
        "src_ip",
        "dst_ip",
        "id_orig_h",
        "id_resp_h",
        "domain",
        "query",
    ):

        if key not in args:
            continue

        value = args[key]

        # Do not allow an IP/entity filter unless the value was
        # explicitly present in the initial alert.
        if isinstance(value, str) and value not in alert_values:

            if key in {
                "src_ip",
                "dst_ip",
                "id_orig_h",
                "id_resp_h",
            }:

                removed.append(key)
                args.pop(key)

    return cleaned, removed


def _validate_initial_tool_args(
    parsed: dict,
    alert: dict,
) -> None:

    if parsed.get("action") != "tool_call":
        return

    args = parsed.get("args")

    if not isinstance(args, dict):
        return

    alert_values = _alert_values(alert)

    for key in (
        "src_ip",
        "dst_ip",
        "id_orig_h",
        "id_resp_h",
    ):

        value = args.get(key)

        if value is None:
            continue

        if value not in alert_values:
            raise ToolDispatchError(
                f"Initial-turn argument '{key}={value}' "
                "was not present in the initial alert. "
                "The model is not allowed to invent entity filters."
            )


# ---------------------------------------------------------------------
# JSON generation with safe retries
# ---------------------------------------------------------------------

def _get_llm_json_with_retries(
    conversation_with_prompt: str,
    config: C3Config,
    trace: C3Trace,
    iteration: int,
    alert: dict,
) -> tuple[Optional[dict], Optional[str]]:

    """
    Generate one JSON action.

    IMPORTANT:
    A malformed model response is NOT appended to the conversation.

    The old implementation did this:

        conversation
        + malformed response
        + "please fix it"

    That caused the 4B model to reason about its previous response
    instead of simply producing JSON.

    Each retry therefore starts from the original clean conversation
    and receives a short deterministic correction instruction.
    """

    base_prompt = conversation_with_prompt

    for attempt in range(
        config.max_json_retries + 1
    ):

        if attempt == 0:

            attempt_prompt = base_prompt

        else:

            attempt_prompt = (
                base_prompt
                + _format_message(
                    "user",
                    "OUTPUT FORMAT ERROR.\n"
                    "Your previous response was not valid JSON.\n\n"
                    "Do not explain the error.\n"
                    "Do not reason.\n"
                    "Do not use <think>.\n"
                    "Output exactly ONE JSON object.\n\n"
                    "If querying Zeek, prefer an unfiltered query "
                    "rather than inventing IP addresses.\n"
                )
                + ASSISTANT_TAG
                + "\n"
            )

        trace.log_event(
            "llm_request",
            iteration=iteration,
            attempt=attempt,
            prompt_chars=len(attempt_prompt),
        )

        try:

            raw = _run_llama_cli(
                attempt_prompt,
                config,
            )

        except LlamaCliError as exc:

            trace.log_event(
                "llm_request_failed",
                iteration=iteration,
                attempt=attempt,
                error=str(exc),
            )

            return None, "llm_call_failure"

        trace.log_event(
            "llm_response_raw",
            iteration=iteration,
            attempt=attempt,
            raw_text=raw,
        )

        try:

            parsed = _extract_json(raw)

        except json.JSONDecodeError as exc:

            if attempt < config.max_json_retries:

                trace.log_event(
                    "json_retry",
                    iteration=iteration,
                    attempt=attempt,
                    error=str(exc),
                )

                continue

            trace.log_event(
                "json_parse_failed_final",
                iteration=iteration,
                attempt=attempt,
                error=str(exc),
                raw_text=raw,
            )

            return None, "json_parse_failure"

        # -------------------------------------------------------------
        # Initial-turn hallucination protection
        # -------------------------------------------------------------

        if iteration == 1:

            cleaned, removed = _sanitize_initial_tool_args(
                parsed,
                alert,
            )

            if removed:

                trace.log_event(
                    "initial_tool_args_sanitized",
                    iteration=iteration,
                    removed_arguments=removed,
                    original=parsed,
                    sanitized=cleaned,
                )

                parsed = cleaned

            try:

                _validate_initial_tool_args(
                    parsed,
                    alert,
                )

            except ToolDispatchError as exc:

                trace.log_event(
                    "initial_tool_args_invalid",
                    iteration=iteration,
                    error=str(exc),
                    parsed=parsed,
                )

                if attempt < config.max_json_retries:
                    continue

                return None, "invalid_initial_tool_args"

        return parsed, None

    return None, "json_parse_failure"


# ---------------------------------------------------------------------
# Fallback
# ---------------------------------------------------------------------

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


# ---------------------------------------------------------------------
# Main C3 investigation
# ---------------------------------------------------------------------

def run_c3_investigation(
    alert: dict,
    log_paths: dict,
    config: Optional[C3Config] = None,
    case_id: str = "unknown_case",
) -> C3Trace:

    config = config or C3Config()

    trace = C3Trace(
        case_id=case_id,
        condition="C3",
    )

    # -------------------------------------------------------------
    # Deterministic investigation window
    # -------------------------------------------------------------

    start_ts, end_ts = _alert_window(
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
            start_iso=start_dt.isoformat().replace(
                "+00:00",
                "Z",
            ),
            end_iso=end_dt.isoformat().replace(
                "+00:00",
                "Z",
            ),
            duration_seconds=config.investigation_window_seconds,
        )

    else:

        trace.log_event(
            "investigation_window",
            start_ts=None,
            end_ts=None,
            reason="alert_timestamp_unavailable",
        )

    # -------------------------------------------------------------
    # Conversation
    # -------------------------------------------------------------

    conversation = (
        _format_message(
            "system",
            build_system_prompt(),
        )
        + _format_message(
            "user",
            build_initial_user_message(
                alert,
                start_ts,
                end_ts,
            ),
        )
    )

    conversation_seed = conversation

    # -------------------------------------------------------------
    # Investigation loop
    # -------------------------------------------------------------

    for iteration in range(
        1,
        config.max_iterations + 1,
    ):

        trace.log_event(
            "iteration_start",
            iteration=iteration,
        )

        # ---------------------------------------------------------
        # Final-report turn for the normal 3-iteration C3 baseline
        # ---------------------------------------------------------
        # With the default max_iterations=3, after two successful
        # Zeek queries the third turn is dedicated to finalization.
        # Explicit larger limits remain available for tests and
        # controlled experiments.

        final_turn = (
            config.max_iterations <= 3
            and trace.zeek_query_count >= 2
        ) or (
            config.max_iterations <= 3
            and iteration == config.max_iterations
        )

        if final_turn:
            evidence_summary = _build_final_evidence_summary(
                trace.events
            )

            final_prompt = build_final_report_prompt(
                alert=alert,
                evidence_summary=evidence_summary,
            )

            conversation_with_prompt = (
                _format_message(
                    "system",
                    final_prompt,
                )
                + ASSISTANT_TAG
                + "\n"
            )

        else:
            conversation_with_prompt = (
                conversation
                + ASSISTANT_TAG
                + "\n"
            )

        parsed, failure_reason = _get_llm_json_with_retries(
            conversation_with_prompt,
            config,
            trace,
            iteration,
            alert,
        )

        if parsed is None:

            if failure_reason == "llm_call_failure":
                reason_text = (
                    "The backend call itself failed before producing a usable "
                    "response. See llm_request_failed for details."
                )

            elif failure_reason == "invalid_initial_tool_args":
                reason_text = (
                    "The LLM repeatedly attempted to use entity "
                    "filters that were not present in the initial alert. "
                    "The investigation was terminated rather than "
                    "allowing invented evidence filters."
                )

            else:
                reason_text = (
                    "The LLM responded, but its output could not be "
                    "parsed as valid JSON after the configured retries."
                )

            trace.finish(
                final_report=_fallback_report(reason_text),
                terminated_reason=failure_reason,
            )

            trace.log_event(
                "iteration_end",
                iteration=iteration,
                outcome=failure_reason,
            )

            return trace

        action = parsed.get("action")

        # -------------------------------------------------------------
        # Final report
        # -------------------------------------------------------------

        if action == "final_report":

            report_raw = parsed.get("report")

            try:
                validated = FinalReport.model_validate(
                    report_raw
                )

            except ValidationError as exc:

                trace.log_event(
                    "final_report_invalid",
                    iteration=iteration,
                    error=str(exc),
                    raw_report=report_raw,
                )

                # Keep the correction prompt compact, especially on
                # the dedicated final-report turn.
                conversation = (
                    conversation_with_prompt
                    + json.dumps(parsed)
                    + IM_END
                    + "\n"
                    + _format_message(
                        "user",
                        "FINAL REPORT FORMAT ERROR.\n"
                        "Return ONLY one compact final_report JSON object.\n"
                        "Do not explain. Do not output <think>.\n"
                        "The evidence field must contain evidence IDs or "
                        "short evidence descriptions only, never full Zeek records.\n"
                        "Required fields: finding, affected_entities, evidence, "
                        "interpretation, attack_technique_mapping, confidence, limitations.",
                    )
                )

                trace.log_event(
                    "iteration_end",
                    iteration=iteration,
                    outcome="final_report_invalid",
                )

                # If this was the final allowed turn, do not fall through
                # into an invalid extra iteration.
                if iteration >= config.max_iterations:
                    trace.finish(
                        final_report=_fallback_report(
                            f"Iteration limit ({config.max_iterations}) "
                            "was reached before the model produced a valid final_report."
                        ),
                        terminated_reason="iteration_limit",
                    )
                    return trace

                continue

            trace.finish(
                final_report=validated.model_dump(),
                terminated_reason=None,
            )

            trace.log_event(
                "iteration_end",
                iteration=iteration,
                outcome="final_report",
            )

            return trace

        # -------------------------------------------------------------
        # Tool call
        # -------------------------------------------------------------

        if action == "tool_call":

            tool_name = parsed.get("tool")
            raw_args = parsed.get("args") or {}
            args = _normalize_timestamp_args(raw_args)

            # The alert-derived window is deterministic. If the model
            # supplies timestamp filters, normalize them and constrain
            # them to the authoritative investigation window.
            if (
                isinstance(args, dict)
                and start_ts is not None
                and end_ts is not None
                and ("start_ts" in args or "end_ts" in args)
            ):
                args["start_ts"] = float(start_ts)
                args["end_ts"] = float(end_ts)

            if args != raw_args:
                parsed = dict(parsed)
                parsed["args"] = args

            trace.log_event(
                "tool_call",
                iteration=iteration,
                tool=tool_name,
                args=args,
            )

            try:
                result = dispatch_tool_call(
                    tool_name,
                    args,
                    log_paths,
                )

            except ToolDispatchError as exc:

                trace.log_event(
                    "tool_call_failed",
                    iteration=iteration,
                    tool=tool_name,
                    args=args,
                    error=str(exc),
                )

                conversation = (
                    conversation_with_prompt
                    + json.dumps(parsed)
                    + IM_END
                    + "\n"
                    + _format_message(
                        "user",
                        "Tool call failed.\n"
                        f"Error: {str(exc)}\n\n"
                        "Do not invent missing values. Choose a valid "
                        "tool call or finish with a final_report using "
                        "only available evidence.",
                    )
                )

                trace.log_event(
                    "iteration_end",
                    iteration=iteration,
                    outcome="tool_call_failed",
                )

                continue

            # ---------------------------------------------------------
            # Deterministic evidence truncation
            # ---------------------------------------------------------

            truncated_result, trunc_event = truncate_tool_result(
                tool_name,
                result,
                max_records=config.context_max_records,
                max_chars=config.context_max_chars,
            )
            successful_query_count = trace.zeek_query_count + 1
            evidence_id = f"E{successful_query_count:03d}"
            trace.log_event(
                "tool_result",
                iteration=iteration,
                tool=tool_name,
                evidence_id=evidence_id,
                matched_before_limit=result.get(
                    "matched_before_limit"
                ),
                errors_skipped=result.get(
                    "errors_skipped"
                ),
                kept_count=truncated_result.get(
                    "context_kept_count"
                ),
                 evidence=truncated_result,
            )

            if trunc_event.reason != "none":
                trace.log_event(
                    "context_truncated",
                    iteration=iteration,
                    tool=tool_name,
                    original_record_count=(
                        trunc_event.original_record_count
                    ),
                    kept_record_count=(
                        trunc_event.kept_record_count
                    ),
                    reason=trunc_event.reason,
                )

            # ---------------------------------------------------------
            # Add tool result to conversation
            # ---------------------------------------------------------

            conversation = (
                conversation_with_prompt
                + json.dumps(parsed)
                + IM_END
                + "\n"
                + _format_message(
                    "user",
                    "Tool result:\n"
                    + json.dumps(
                        truncated_result,
                        indent=2,
                    ),
                )
            )

            conversation = _bound_conversation(
                conversation,
                conversation_seed,
                config.conversation_max_chars,
            )

            # C3 baseline policy: after two successful Zeek queries,
            # require the next turn to produce the final report.
            if (
                config.max_iterations <= 3
                and trace.zeek_query_count >= 2
                and iteration < config.max_iterations
            ):
                conversation += _format_message(
                    "user",
                    "FINALIZATION REQUIRED. Two Zeek queries have now "
                    "completed successfully. Do not call another tool. "
                    "On your next turn return ONLY a compact final_report "
                    "JSON object. The evidence field must contain only "
                    "evidence IDs or short evidence descriptions, never "
                    "full Zeek records.",
                )

            trace.log_event(
                "iteration_end",
                iteration=iteration,
                outcome="tool_call",
            )

            continue

        # -------------------------------------------------------------
        # Unknown action
        # -------------------------------------------------------------

        trace.log_event(
            "invalid_action",
            iteration=iteration,
            parsed=parsed,
        )

        conversation = (
            conversation_with_prompt
            + json.dumps(parsed)
            + IM_END
            + "\n"
            + _format_message(
                "user",
                'Invalid "action". '
                'Use exactly "tool_call" or "final_report". '
                "Output JSON only.",
            )
        )

        trace.log_event(
            "iteration_end",
            iteration=iteration,
            outcome="invalid_action",
        )

    # -------------------------------------------------------------
    # Iteration limit
    # -------------------------------------------------------------

    trace.finish(
        final_report=_fallback_report(
            f"Iteration limit ({config.max_iterations}) "
            "was reached before the model produced a final_report."
        ),
        terminated_reason="iteration_limit",
    )

    trace.log_event(
        "iteration_end_forced",
        outcome="iteration_limit",
    )

    return trace
