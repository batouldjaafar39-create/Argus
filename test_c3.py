import json

import pytest

from src.C3 import C3Config, run_c3_investigation
from src.C3 import LLM as c3_llm
from src.C3.config import C3Config

ALERT = {"alert_id": "A1", "summary": "Unusual Kerberos activity observed", "source": "IDS"}


def _script(responses):
    """Fake _run_llama_cli returning each item in `responses` in order,
    one per call, ignoring the prompt entirely."""
    calls = {"n": 0}

    def fake(prompt, config):
        i = calls["n"]
        calls["n"] += 1
        if i >= len(responses):
            raise AssertionError("llama-cli called more times than scripted")
        return responses[i]

    return fake


def _final_report_json(finding="Test finding", **overrides):
    report = {
        "finding": finding,
        "affected_entities": ["10.0.0.1"],
        "evidence": ["conn.log uid=C1"],
        "interpretation": "Test interpretation",
        "attack_technique_mapping": [],
        "confidence": "low",
        "limitations": "test",
    }
    report.update(overrides)
    return json.dumps({"action": "final_report", "report": report})


# ---------------------------------------------------------------------
# Happy paths
# ---------------------------------------------------------------------

def test_immediate_final_report(monkeypatch, all_log_paths):
    monkeypatch.setattr(c3_llm, "_run_llama_cli", _script([_final_report_json("done immediately")]))
    trace = run_c3_investigation(ALERT, all_log_paths, case_id="t1")
    assert trace.terminated_reason is None
    assert trace.final_report["finding"] == "done immediately"
    assert trace.iteration_count == 1
    assert trace.zeek_query_count == 0


def test_one_tool_call_then_final_report(monkeypatch, all_log_paths):
    tool_call = json.dumps({"action": "tool_call", "tool": "query_conn", "args": {"service": "dns"}})
    monkeypatch.setattr(c3_llm, "_run_llama_cli", _script([tool_call, _final_report_json("used evidence")]))
    trace = run_c3_investigation(ALERT, all_log_paths, case_id="t2")
    assert trace.terminated_reason is None
    assert trace.iteration_count == 2
    assert trace.zeek_query_count == 1
    assert trace.tools_queried == ["query_conn"]


def test_multiple_tools_across_iterations(monkeypatch, all_log_paths):
    calls = [
        json.dumps({"action": "tool_call", "tool": "query_conn", "args": {}}),
        json.dumps({"action": "tool_call", "tool": "query_kerberos", "args": {"success": False}}),
        _final_report_json("used two tools"),
    ]
    monkeypatch.setattr(c3_llm, "_run_llama_cli", _script(calls))
    trace = run_c3_investigation(ALERT, all_log_paths, case_id="t3")
    assert trace.zeek_query_count == 2
    assert trace.tools_queried == ["query_conn", "query_kerberos"]


def test_all_six_tools_reachable_in_one_investigation(monkeypatch, all_log_paths):
    tool_names = ["query_conn", "query_dns", "query_dce_rpc", "query_smb_files", "query_smb_mapping", "query_kerberos"]
    calls = [json.dumps({"action": "tool_call", "tool": t, "args": {}}) for t in tool_names]
    calls.append(_final_report_json("toured all tools"))
    config = C3Config(max_iterations=10)
    monkeypatch.setattr(c3_llm, "_run_llama_cli", _script(calls))
    trace = run_c3_investigation(ALERT, all_log_paths, config=config, case_id="t3b")
    assert trace.tools_queried == tool_names
    assert trace.terminated_reason is None


# ---------------------------------------------------------------------
# Safeguard 1: JSON retry wrapper
# ---------------------------------------------------------------------

def test_json_retry_succeeds_on_second_attempt(monkeypatch, all_log_paths):
    monkeypatch.setattr(
        c3_llm, "_run_llama_cli",
        _script(["not json at all", _final_report_json("recovered")]),
    )
    trace = run_c3_investigation(ALERT, all_log_paths, case_id="t4")
    assert trace.terminated_reason is None
    assert trace.json_retry_count == 1
    assert trace.final_report["finding"] == "recovered"


def test_json_retry_exhausted_terminates_gracefully(monkeypatch, all_log_paths):
    config = C3Config(max_json_retries=2)
    monkeypatch.setattr(
        c3_llm, "_run_llama_cli",
        _script(["garbage 1", "garbage 2", "garbage 3"]),  # 1 initial + 2 retries
    )
    trace = run_c3_investigation(ALERT, all_log_paths, config=config, case_id="t5")
    assert trace.terminated_reason == "json_parse_failure"
    assert trace.json_retry_count == 2
    assert trace.final_report["confidence"] == "low"
    assert "did not complete normally" in trace.final_report["finding"]


def test_json_extraction_handles_markdown_fence():
    fenced = '```json\n{"action": "final_report", "report": {}}\n```'
    parsed = c3_llm._extract_json(fenced)
    assert parsed["action"] == "final_report"


def test_json_extraction_recovers_extra_closing_brace():
    raw = '{"action": "tool_call", "tool": "query_conn", "args": {}}}'
    parsed = c3_llm._extract_json(raw)
    assert parsed["action"] == "tool_call"


def test_json_extraction_uses_last_object_after_reasoning():
    raw = 'I corrected it: {"action": "tool_call", "tool": "query_conn", "args": {}}'
    parsed = c3_llm._extract_json(raw)
    assert parsed["tool"] == "query_conn"


def test_malformed_tool_call_args_triggers_recovery_not_crash(monkeypatch, all_log_paths):
    # Valid JSON, but "args" is a list instead of an object -- dispatcher
    # rejects it; loop must feed the error back, not crash.
    bad_call = json.dumps({"action": "tool_call", "tool": "query_conn", "args": ["service", "dns"]})
    monkeypatch.setattr(c3_llm, "_run_llama_cli", _script([bad_call, _final_report_json("recovered from bad args")]))
    trace = run_c3_investigation(ALERT, all_log_paths, case_id="t5b")
    assert trace.terminated_reason is None
    assert trace.tool_call_failure_count == 1
    assert trace.final_report["finding"] == "recovered from bad args"


# ---------------------------------------------------------------------
# Safeguard 2: iteration limit
# ---------------------------------------------------------------------

def test_iteration_limit_enforced(monkeypatch, all_log_paths):
    config = C3Config(max_iterations=3)
    infinite_tool_call = json.dumps({"action": "tool_call", "tool": "query_conn", "args": {}})
    monkeypatch.setattr(c3_llm, "_run_llama_cli", lambda prompt, cfg: infinite_tool_call)
    trace = run_c3_investigation(ALERT, all_log_paths, config=config, case_id="t6")
    assert trace.terminated_reason == "iteration_limit"
    assert trace.iteration_count == 3
    assert trace.zeek_query_count == 3


# ---------------------------------------------------------------------
# Safeguard 3: context truncation
# ---------------------------------------------------------------------

def test_truncation_event_logged_in_trace(monkeypatch, all_log_paths):
    tool_call = json.dumps({"action": "tool_call", "tool": "query_conn", "args": {"limit": 100}})
    monkeypatch.setattr(c3_llm, "_run_llama_cli", _script([tool_call, _final_report_json()]))
    config = C3Config(context_max_records=1)  # fixture has 3 conn records
    trace = run_c3_investigation(ALERT, all_log_paths, config=config, case_id="t7")
    assert trace.truncation_event_count == 1


def test_no_truncation_when_under_cap(monkeypatch, all_log_paths):
    tool_call = json.dumps({
        "action": "tool_call",
        "tool": "query_conn",
        "args": {"limit": 10},
    })

    monkeypatch.setattr(
        c3_llm,
        "_run_llama_cli",
        _script([tool_call, _final_report_json()]),
    )

    config = C3Config(
    context_max_records=1000,
    context_max_chars=1_000_000,
)

    trace = run_c3_investigation(
        ALERT,
        all_log_paths,
        config=config,
        case_id="t7b",
    )

    assert trace.truncation_event_count == 0


def test_conversation_prompt_is_bounded():
    seed = "<|im_start|>system\nbase<|im_end|>\n"
    conversation = seed + "x" * 1000
    bounded = c3_llm._bound_conversation(conversation, seed, 100)
    assert len(bounded) <= 100
    assert bounded.startswith(seed)
    assert C3Config().conversation_max_chars > 0


# ---------------------------------------------------------------------
# Final report validation
# ---------------------------------------------------------------------

def test_invalid_final_report_fed_back_and_corrected(monkeypatch, all_log_paths):
    bad_report = json.dumps({
        "action": "final_report",
        "report": {"finding": "x", "confidence": "extremely_sure"},  # invalid enum, missing fields
    })
    monkeypatch.setattr(c3_llm, "_run_llama_cli", _script([bad_report, _final_report_json("corrected")]))
    trace = run_c3_investigation(ALERT, all_log_paths, case_id="t10")
    assert trace.terminated_reason is None
    assert trace.final_report["finding"] == "corrected"
    invalid_events = [e for e in trace.events if e["event"] == "final_report_invalid"]
    assert len(invalid_events) == 1


def test_final_report_missing_required_field_rejected(monkeypatch, all_log_paths):
    bad_report = json.dumps({"action": "final_report", "report": {"confidence": "low"}})
    monkeypatch.setattr(c3_llm, "_run_llama_cli", _script([bad_report, _final_report_json("fixed")]))
    trace = run_c3_investigation(ALERT, all_log_paths, case_id="t11")
    assert trace.final_report["finding"] == "fixed"


def test_persistently_invalid_final_report_hits_iteration_limit(monkeypatch, all_log_paths):
    bad_report = json.dumps({"action": "final_report", "report": {"confidence": "not_a_real_level"}})
    config = C3Config(max_iterations=2)
    monkeypatch.setattr(c3_llm, "_run_llama_cli", lambda prompt, cfg: bad_report)
    trace = run_c3_investigation(ALERT, all_log_paths, config=config, case_id="t12")
    assert trace.terminated_reason == "iteration_limit"
    assert trace.final_report["confidence"] == "low"


def test_fallback_report_itself_is_schema_valid():
    from src.C3.LLM import _fallback_report
    from src.C3.report import FinalReport
    report = _fallback_report("some reason")
    FinalReport.model_validate(report)  # must not raise


# ---------------------------------------------------------------------
# Invalid action / semantic errors that aren't JSON-syntax errors
# ---------------------------------------------------------------------

def test_invalid_action_value_recovered(monkeypatch, all_log_paths):
    bad_action = json.dumps({"action": "do_something_else", "foo": "bar"})
    monkeypatch.setattr(c3_llm, "_run_llama_cli", _script([bad_action, _final_report_json("recovered")]))
    trace = run_c3_investigation(ALERT, all_log_paths, case_id="t13")
    assert trace.terminated_reason is None
    assert trace.final_report["finding"] == "recovered"
    assert any(e["event"] == "invalid_action" for e in trace.events)


# ---------------------------------------------------------------------
# Tool dispatch failures inside the loop (not the dispatcher unit tests)
# ---------------------------------------------------------------------

def test_tool_call_failure_fed_back_not_fatal(monkeypatch, all_log_paths):
    bad_call = json.dumps({"action": "tool_call", "tool": "query_kerberos", "args": {"success": "not-a-bool"}})
    monkeypatch.setattr(c3_llm, "_run_llama_cli", _script([bad_call, _final_report_json("recovered from bad tool")]))
    trace = run_c3_investigation(ALERT, all_log_paths, case_id="t8")
    assert trace.terminated_reason is None
    assert trace.tool_call_failure_count == 1
    assert trace.final_report["finding"] == "recovered from bad tool"


# ---------------------------------------------------------------------
# Trace export
# ---------------------------------------------------------------------

def test_trace_save_writes_valid_json(tmp_path, monkeypatch, all_log_paths):
    monkeypatch.setattr(c3_llm, "_run_llama_cli", _script([_final_report_json()]))
    trace = run_c3_investigation(ALERT, all_log_paths, case_id="t9")
    out = tmp_path / "t9_trace.json"
    trace.save(out)
    loaded = json.loads(out.read_text())
    assert loaded["summary"]["case_id"] == "t9"
    assert "final_report" in loaded
    assert isinstance(loaded["events"], list) and len(loaded["events"]) > 0


def test_llm_call_failure_distinct_from_json_parse_failure(monkeypatch, all_log_paths):
    """A backend failure (timeout / missing binary / process error) must
    not be reported under the same terminated_reason as a genuine
    malformed-JSON response -- they have different root causes and need
    different fixes."""
    def raise_backend_error(prompt, config):
        raise c3_llm.LlamaCliError("llama-cli timed out after 300s")

    monkeypatch.setattr(c3_llm, "_run_llama_cli", raise_backend_error)
    trace = run_c3_investigation(ALERT, all_log_paths, case_id="t15")
    assert trace.terminated_reason == "llm_call_failure"
    assert "backend call itself failed" in trace.final_report["limitations"]
    # must NOT be attempted config.max_json_retries+1 times -- a broken
    # backend call isn't a JSON-parsing problem, so retrying it is pointless
    assert trace.json_retry_count == 0


def test_subprocess_backend_passes_stop_sequence(monkeypatch):
    """Regression test for the root cause of the original hang: without
    a stop sequence, llama-cli always generates the full max_tokens
    budget even after emitting a complete JSON object. The subprocess
    fallback must pass -r <IM_END> so generation halts as soon as the
    assistant turn ends."""
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        class FakeResult:
            returncode = 0
            stdout = c3_llm.ASSISTANT_TAG + '\n{"action": "final_report", "report": {}}' + c3_llm.IM_END
            stderr = ""
        return FakeResult()

    monkeypatch.setattr(c3_llm.subprocess, "run", fake_run)
    from src.C3.config import C3Config
    config = C3Config(use_server=False)
    c3_llm._run_via_subprocess("some prompt", config)

    cmd = captured["cmd"]
    assert "-r" in cmd
    assert cmd[cmd.index("-r") + 1] == c3_llm.IM_END


def test_trace_summary_counts_match_events(monkeypatch, all_log_paths):
    tool_call = json.dumps({"action": "tool_call", "tool": "query_conn", "args": {}})
    monkeypatch.setattr(c3_llm, "_run_llama_cli", _script([tool_call, _final_report_json()]))
    trace = run_c3_investigation(ALERT, all_log_paths, case_id="t14")
    summary = trace.summary()
    assert summary["iteration_count"] == 2
    assert summary["zeek_query_count"] == 1
    assert summary["tools_queried"] == ["query_conn"]
    assert summary["terminated_reason"] is None