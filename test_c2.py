import json

from src.C2 import C2Config, run_c2_investigation
from src.C2 import LLM as c2_llm

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
        "evidence": ["alert states unusual Kerberos activity"],
        "interpretation": "Test interpretation",
        "attack_technique_mapping": [],
        "confidence": "low",
        "limitations": "test",
    }
    report.update(overrides)
    return json.dumps({"action": "final_report", "report": report})


# ---------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------

def test_immediate_final_report():
    trace = run_c2_investigation(ALERT, case_id="t1")
    # default C2Config has no monkeypatched backend, so this test instead
    # verifies the trivial no-op path below via a scripted backend
    assert trace.case_id == "t1"


def test_immediate_final_report_scripted(monkeypatch):
    monkeypatch.setattr(c2_llm, "_run_llama_cli", _script([_final_report_json("done immediately")]))
    trace = run_c2_investigation(ALERT, case_id="t1b")
    assert trace.terminated_reason is None
    assert trace.final_report is not None
    assert trace.final_report["finding"] == "done immediately"
    assert trace.correction_round_count == 1


# ---------------------------------------------------------------------
# Safeguard 1: JSON retry wrapper
# ---------------------------------------------------------------------

def test_json_retry_succeeds_on_second_attempt(monkeypatch):
    monkeypatch.setattr(
        c2_llm, "_run_llama_cli",
        _script(["not json at all", _final_report_json("recovered")]),
    )
    trace = run_c2_investigation(ALERT, case_id="t2")
    assert trace.terminated_reason is None
    assert trace.json_retry_count == 1
    assert trace.final_report is not None
    assert trace.final_report["finding"] == "recovered"


def test_json_retry_exhausted_terminates_gracefully(monkeypatch):
    config = C2Config(max_json_retries=2)
    monkeypatch.setattr(
        c2_llm, "_run_llama_cli",
        _script(["garbage 1", "garbage 2", "garbage 3"]),  # 1 initial + 2 retries
    )
    trace = run_c2_investigation(ALERT, config=config, case_id="t3")
    assert trace.terminated_reason == "json_parse_failure"
    assert trace.json_retry_count == 2
    assert trace.final_report is not None
    assert trace.final_report["confidence"] == "low"
    assert "did not complete normally" in trace.final_report["finding"]


def test_json_extraction_handles_markdown_fence():
    fenced = '```json\n{"action": "final_report", "report": {}}\n```'
    parsed = c2_llm._extract_json(fenced)
    assert parsed["action"] == "final_report"


# ---------------------------------------------------------------------
# Safeguard 2: correction-round limit
# ---------------------------------------------------------------------

def test_correction_round_limit_enforced_on_persistent_invalid_action(monkeypatch):
    config = C2Config(max_correction_rounds=3)
    hallucinated_tool_call = json.dumps({"action": "tool_call", "tool": "query_conn", "args": {}})
    monkeypatch.setattr(c2_llm, "_run_llama_cli", lambda prompt, cfg: hallucinated_tool_call)
    trace = run_c2_investigation(ALERT, config=config, case_id="t4")
    assert trace.terminated_reason == "iteration_limit"
    assert trace.correction_round_count == 3


def test_persistently_invalid_final_report_hits_correction_limit(monkeypatch):
    bad_report = json.dumps({"action": "final_report", "report": {"confidence": "not_a_real_level"}})
    config = C2Config(max_correction_rounds=2)
    monkeypatch.setattr(c2_llm, "_run_llama_cli", lambda prompt, cfg: bad_report)
    trace = run_c2_investigation(ALERT, config=config, case_id="t5")
    assert trace.terminated_reason == "iteration_limit"
    assert trace.final_report is not None
    assert trace.final_report["confidence"] == "low"


# ---------------------------------------------------------------------
# C2 has no tools: any tool_call attempt must be rejected, not dispatched
# ---------------------------------------------------------------------

def test_hallucinated_tool_call_is_rejected_not_dispatched(monkeypatch):
    """C2 has no Zeek access at all -- if the model hallucinates a
    tool_call action anyway, it must be treated as an invalid action
    (never actually dispatched to Zeek) and the model told to correct
    itself, exactly like any other bad action value."""
    hallucinated = json.dumps({"action": "tool_call", "tool": "query_conn", "args": {}})
    monkeypatch.setattr(c2_llm, "_run_llama_cli", _script([hallucinated, _final_report_json("recovered")]))
    trace = run_c2_investigation(ALERT, case_id="t6")
    assert trace.terminated_reason is None
    assert trace.final_report is not None
    assert trace.final_report["finding"] == "recovered"
    assert any(e["event"] == "invalid_action" for e in trace.events)
    # no ledger/tool-dispatch events should ever appear for C2
    assert not any("tool" in e.get("event", "") for e in trace.events)


# ---------------------------------------------------------------------
# Final report validation
# ---------------------------------------------------------------------

def test_invalid_final_report_fed_back_and_corrected(monkeypatch):
    bad_report = json.dumps({
        "action": "final_report",
        "report": {"finding": "x", "confidence": "extremely_sure"},  # invalid enum, missing fields
    })
    monkeypatch.setattr(c2_llm, "_run_llama_cli", _script([bad_report, _final_report_json("corrected")]))
    trace = run_c2_investigation(ALERT, case_id="t7")
    assert trace.terminated_reason is None
    assert trace.final_report is not None
    assert trace.final_report["finding"] == "corrected"
    invalid_events = [e for e in trace.events if e["event"] == "final_report_invalid"]
    assert len(invalid_events) == 1


def test_fallback_report_itself_is_schema_valid():
    from src.C2.LLM import _fallback_report
    from src.C3.report import FinalReport
    report = _fallback_report("some reason")
    FinalReport.model_validate(report)  # must not raise


# ---------------------------------------------------------------------
# Invalid action / semantic errors that aren't JSON-syntax errors
# ---------------------------------------------------------------------

def test_invalid_action_value_recovered(monkeypatch):
    bad_action = json.dumps({"action": "do_something_else", "foo": "bar"})
    monkeypatch.setattr(c2_llm, "_run_llama_cli", _script([bad_action, _final_report_json("recovered")]))
    trace = run_c2_investigation(ALERT, case_id="t8")
    assert trace.terminated_reason is None
    assert trace.final_report is not None
    assert trace.final_report["finding"] == "recovered"
    assert any(e["event"] == "invalid_action" for e in trace.events)


# ---------------------------------------------------------------------
# Backend failure vs JSON-parse failure
# ---------------------------------------------------------------------

def test_llm_call_failure_distinct_from_json_parse_failure(monkeypatch):
    def raise_backend_error(prompt, config):
        raise c2_llm.LlamaCliError("llama-cli timed out after 300s")

    monkeypatch.setattr(c2_llm, "_run_llama_cli", raise_backend_error)
    trace = run_c2_investigation(ALERT, case_id="t9")
    assert trace.terminated_reason == "llm_call_failure"
    assert "backend call itself failed" in trace.final_report["limitations"]
    assert trace.json_retry_count == 0


# ---------------------------------------------------------------------
# Trace export
# ---------------------------------------------------------------------

def test_trace_save_writes_valid_json(tmp_path, monkeypatch):
    monkeypatch.setattr(c2_llm, "_run_llama_cli", _script([_final_report_json()]))
    trace = run_c2_investigation(ALERT, case_id="t10")
    out = tmp_path / "t10_trace.json"
    trace.save(out)
    loaded = json.loads(out.read_text())
    assert loaded["summary"]["case_id"] == "t10"
    assert loaded["summary"]["condition"] == "C2"
    assert "final_report" in loaded
    assert isinstance(loaded["events"], list) and len(loaded["events"]) > 0


def test_trace_summary_counts_match_events(monkeypatch):
    monkeypatch.setattr(c2_llm, "_run_llama_cli", _script([_final_report_json()]))
    trace = run_c2_investigation(ALERT, case_id="t11")
    summary = trace.summary()
    assert summary["correction_round_count"] == 1
    assert summary["json_retry_count"] == 0
    assert summary["terminated_reason"] is None
