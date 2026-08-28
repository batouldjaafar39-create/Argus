import json
from typing import Any

from src.Argus.LLM import run_argus_investigation
from src.Argus.config import ArgusConfig
from src.Argus.grounding import verify_report
from src.Argus.ledger import EvidenceLedger
from src.Argus.report import ArgusReport
from src.Argus.LLM import _remove_hostname_filters


def small_config(**overrides):
    values: dict[str, Any] = dict(
        max_json_retries=0,
        max_planning_rounds=1,
        max_revisions=1,
        max_tool_calls_per_plan=3,
        context_max_records=5,
        context_max_chars=2000,
    )
    values.update(overrides)
    return ArgusConfig(**values)


def test_ledger_assigns_ids_and_records_dispatch_result(monkeypatch):
    def fake_dispatch(tool_name, args, log_paths):
        assert tool_name == "query_dns"
        assert log_paths["query_dns"] == "dns.log"
        return {"records": [{"query": "example.com"}], "matched_before_limit": 1}

    monkeypatch.setattr("src.Argus.ledger.dispatch_tool_call", fake_dispatch)
    ledger = EvidenceLedger({"query_dns": "dns.log"})

    first = ledger.execute("query_dns", {"query": "example.com"})
    second = ledger.execute("query_dns", {"query": "example.org"})

    assert first.evidence_id == "E001"
    assert second.evidence_id == "E002"
    assert first.status == "success"
    assert ledger.successful_ids() == {"E001", "E002"}


def test_ledger_records_dispatch_failure(monkeypatch):
    def fake_dispatch(tool_name, args, log_paths):
        raise Exception("should be converted by test fake")

    # The real dispatcher exposes ToolDispatchError. Use it explicitly.
    from src.C3.tools import ToolDispatchError
    def failing_dispatch(tool_name, args, log_paths):
        raise ToolDispatchError("bad arguments")

    monkeypatch.setattr("src.Argus.ledger.dispatch_tool_call", failing_dispatch)
    ledger = EvidenceLedger({"query_dns": "dns.log"})
    entry = ledger.execute("query_dns", {})
    assert entry.evidence_id == "E001"
    assert entry.status == "failed"
    assert entry.error == "bad arguments"


def test_verifier_rejects_unknown_citation():
    report = ArgusReport(
        finding="Suspicious activity [E999]",
        affected_entities=[],
        evidence=["E999"],
        interpretation="The evidence indicates suspicious behavior [E999]",
        attack_technique_mapping=[],
        confidence="low",
        limitations="Limited evidence.",
    )
    ledger = EvidenceLedger({})
    result = verify_report(report, ledger)
    assert not result.clean
    assert any("E999" in v for v in result.violations)


def test_verifier_accepts_grounded_report():
    ledger = EvidenceLedger({})
    from src.Argus.ledger import EvidenceEntry
    ledger.entries.append(
        EvidenceEntry("E001", "query_dns", {}, "success", {"records": []})
    )
    report = ArgusReport(
        finding="The queried domain was observed in Zeek DNS evidence [E001]",
        affected_entities=["example.com [E001]"],
        evidence=["E001"],
        interpretation="The observation supports the finding [E001]",
        attack_technique_mapping=[],
        confidence="medium",
        limitations="The available evidence is limited.",
    )
    result = verify_report(report, ledger)
    assert result.clean


def test_hostname_is_not_used_as_ip_filter():
    args = {"src_ip": "SCRANTON", "limit": 100}
    assert _remove_hostname_filters(args, {"host": "SCRANTON"}) == {"limit": 100}


def test_argus_end_to_end_with_batched_plan_and_revision(monkeypatch):
    from src.C3.tools import ToolDispatchError

    def fake_dispatch(tool_name, args, log_paths):
        return {"records": [{"tool": tool_name, "args": args}], "matched_before_limit": 1}

    monkeypatch.setattr("src.Argus.ledger.dispatch_tool_call", fake_dispatch)

    responses = iter([
        {
            "action": "plan",
            "hypotheses": [{"id": "H1", "statement": "DNS activity needs review"}],
            "tool_calls": [
                {"tool": "query_dns", "args": {"query": "example.com"}},
                {"tool": "query_kerberos", "args": {"client": "10.0.0.5"}},
            ],
            "follow_up_required": False,
            "follow_up_reason": "",
        },
        {
            "action": "final_report",
            "report": {
                "finding": "Suspicious DNS activity [E001]",
                "affected_entities": ["example.com [E001]"],
                "evidence": ["E999"],
                "interpretation": "The activity warrants review [E001]",
                "attack_technique_mapping": [],
                "confidence": "medium",
                "limitations": "Limited evidence.",
            },
        },
        {
            "action": "final_report",
            "report": {
                "finding": "Suspicious DNS activity [E001]",
                "affected_entities": ["example.com [E001]"],
                "evidence": ["E001"],
                "interpretation": "The activity warrants review [E001]",
                "attack_technique_mapping": [],
                "confidence": "medium",
                "limitations": "Limited evidence.",
            },
        },
    ])

    def fake_generate(prompt, config):
        return json.dumps(next(responses))

    trace = run_argus_investigation(
        {"alert_id": "TEST-001", "summary": "test"},
        {"query_dns": "dns.log", "query_kerberos": "kerberos.log"},
        config=small_config(),
        case_id="TEST-001",
        generate=fake_generate,
    )

    assert trace.terminated_reason is None
    assert trace.zeek_query_count == 2
    assert trace.revision_count == 1
    report = trace.final_report
    assert report is not None
    assert report["evidence"] == ["E001"]
    assert report["finding"].endswith("[E001]")
