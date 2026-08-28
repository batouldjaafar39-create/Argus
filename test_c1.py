import json

import pytest

from src.C1 import C1Config, run_c1_investigation
from src.C1.rules import (
    confidence_from_findings,
    evaluate_dce_rpc,
    evaluate_kerberos,
    evaluate_remote_access_ports,
    evaluate_smb_files,
    triggered_lateral_movement_ports,
)

ALERT = {"alert_id": "A1", "host": "TESTHOST", "summary": "test alert"}


def _conn(id_resp_p=443, id_orig_h="10.0.1.5", id_resp_h="10.0.0.4", **overrides):
    r = {"uid": "C1", "ts": 100.0, "id_orig_h": id_orig_h, "id_orig_p": 1234,
         "id_resp_h": id_resp_h, "id_resp_p": id_resp_p, "proto": "tcp"}
    r.update(overrides)
    return r


def _kerberos(cipher="aes256-cts-hmac-sha1-96", success=True, **overrides):
    r = {"uid": "K1", "ts": 100.0, "id_orig_h": "10.0.1.5", "id_orig_p": 1234,
         "id_resp_h": "10.0.0.4", "id_resp_p": 88, "request_type": "TGS",
         "client": "HOST$/DOMAIN", "service": "krbtgt/DOMAIN",
         "success": success, "cipher": cipher}
    r.update(overrides)
    return r


def _dce_rpc(named_pipe="epmapper", **overrides):
    r = {"uid": "D1", "ts": 100.0, "id_orig_h": "10.0.1.5", "id_orig_p": 1234,
         "id_resp_h": "10.0.0.4", "id_resp_p": 135, "named_pipe": named_pipe,
         "endpoint": "epmapper", "operation": "ept_map"}
    r.update(overrides)
    return r


def _smb_file(path="\\\\host\\share", name="notes.txt", **overrides):
    r = {"uid": "S1", "ts": 100.0, "id_orig_h": "10.0.1.5", "id_orig_p": 1234,
         "id_resp_h": "10.0.0.4", "id_resp_p": 445, "action": "SMB::FILE_OPEN",
         "path": path, "name": name}
    r.update(overrides)
    return r


# ---------------------------------------------------------------------
# rules.py unit tests
# ---------------------------------------------------------------------

def test_no_branch_triggered_on_ordinary_traffic():
    triggered = triggered_lateral_movement_ports([_conn(id_resp_p=443)], C1Config())
    assert triggered == set()


def test_smb_branch_triggered_by_port_445():
    triggered = triggered_lateral_movement_ports([_conn(id_resp_p=445)], C1Config())
    assert triggered == {"smb"}


def test_dce_rpc_branch_triggered_by_port_135():
    triggered = triggered_lateral_movement_ports([_conn(id_resp_p=135)], C1Config())
    assert triggered == {"dce_rpc"}


def test_both_branches_can_trigger_together():
    triggered = triggered_lateral_movement_ports(
        [_conn(id_resp_p=445), _conn(id_resp_p=135, uid="C2")], C1Config()
    )
    assert triggered == {"smb", "dce_rpc"}


def test_remote_access_port_flagged():
    findings = evaluate_remote_access_ports([_conn(id_resp_p=3389)], C1Config())
    assert len(findings) == 1
    assert findings[0].rule_id == "conn-remote-access"
    assert findings[0].attack_technique == "T1021"


def test_remote_access_not_flagged_on_ordinary_port():
    findings = evaluate_remote_access_ports([_conn(id_resp_p=443)], C1Config())
    assert findings == []


def test_dce_rpc_sensitive_pipe_flagged():
    findings = evaluate_dce_rpc([_dce_rpc(named_pipe="svcctl")], C1Config())
    assert len(findings) == 1
    assert findings[0].rule_id == "dce-rpc-sensitive-pipe"
    assert "T1021.002" in findings[0].attack_technique


def test_dce_rpc_non_sensitive_pipe_not_flagged():
    # matches real observed data: epmapper/endpoint mapping is routine,
    # not a lateral-movement pipe
    findings = evaluate_dce_rpc([_dce_rpc(named_pipe="epmapper")], C1Config())
    assert findings == []


def test_kerberos_weak_cipher_flagged():
    findings = evaluate_kerberos([_kerberos(cipher="rc4-hmac")], C1Config())
    rule_ids = {f.rule_id for f in findings}
    assert "kerberos-weak-cipher" in rule_ids


def test_kerberos_strong_cipher_not_flagged():
    findings = evaluate_kerberos([_kerberos(cipher="aes256-cts-hmac-sha1-96", success=True)], C1Config())
    assert findings == []


def test_kerberos_auth_failure_flagged():
    findings = evaluate_kerberos([_kerberos(success=False)], C1Config())
    rule_ids = {f.rule_id for f in findings}
    assert "kerberos-auth-failure" in rule_ids


def test_smb_admin_share_executable_flagged():
    findings = evaluate_smb_files(
        [_smb_file(path="\\\\host\\ADMIN$", name="tool.exe")], C1Config()
    )
    assert len(findings) == 1
    assert findings[0].rule_id == "smb-admin-share-executable"


def test_smb_non_admin_share_not_flagged():
    findings = evaluate_smb_files(
        [_smb_file(path="\\\\host\\public", name="tool.exe")], C1Config()
    )
    assert findings == []


def test_smb_admin_share_non_executable_not_flagged():
    findings = evaluate_smb_files(
        [_smb_file(path="\\\\host\\ADMIN$", name="notes.txt")], C1Config()
    )
    assert findings == []


def test_confidence_mapping():
    from src.C1.rules import Finding
    assert confidence_from_findings([]) == "low"
    one = [Finding("r1", "d", "T1", [])]
    assert confidence_from_findings(one) == "medium"
    two = [Finding("r1", "d", "T1", []), Finding("r2", "d", "T2", [])]
    assert confidence_from_findings(two) == "high"
    # same rule_id twice still counts as one distinct rule
    dup = [Finding("r1", "d", "T1", []), Finding("r1", "d", "T1", [])]
    assert confidence_from_findings(dup) == "medium"


# ---------------------------------------------------------------------
# engine.py integration tests (real files on disk, no LLM to mock)
# ---------------------------------------------------------------------

def _write_ndjson(path, records):
    with open(path, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")


@pytest.fixture
def clean_log_paths(tmp_path):
    """A host with only ordinary traffic -- no branch should trigger,
    no rule should fire."""
    conn_path = tmp_path / "conn.log"
    dns_path = tmp_path / "dns.log"
    kerberos_path = tmp_path / "kerberos.log"
    _write_ndjson(conn_path, [_conn(id_resp_p=443), _conn(id_resp_p=80, uid="C2")])
    _write_ndjson(dns_path, [])
    _write_ndjson(kerberos_path, [_kerberos(cipher="aes256-cts-hmac-sha1-96")])
    return {
        "query_conn": str(conn_path),
        "query_dns": str(dns_path),
        "query_kerberos": str(kerberos_path),
    }


@pytest.fixture
def lateral_movement_log_paths(tmp_path):
    """A host with conn traffic to port 135 (triggers the dce_rpc
    branch) and a sensitive-named-pipe DCE/RPC call once queried."""
    conn_path = tmp_path / "conn.log"
    dce_rpc_path = tmp_path / "dce_rpc.log"
    kerberos_path = tmp_path / "kerberos.log"
    dns_path = tmp_path / "dns.log"
    _write_ndjson(conn_path, [_conn(id_resp_p=135)])
    _write_ndjson(dce_rpc_path, [_dce_rpc(named_pipe="svcctl")])
    _write_ndjson(kerberos_path, [_kerberos(cipher="aes256-cts-hmac-sha1-96")])
    _write_ndjson(dns_path, [])
    return {
        "query_conn": str(conn_path),
        "query_dce_rpc": str(dce_rpc_path),
        "query_kerberos": str(kerberos_path),
        "query_dns": str(dns_path),
    }


def test_no_branch_no_findings_on_clean_data(clean_log_paths):
    trace = run_c1_investigation(ALERT, clean_log_paths, case_id="t1")
    assert trace.branches_triggered == []
    assert trace.rules_fired == []
    assert trace.final_report["confidence"] == "low"
    assert "No fixed detection rule fired" in trace.final_report["finding"]
    # dce_rpc/smb tools were never queried since no branch triggered
    assert "query_dce_rpc" not in trace.queries_executed
    assert "query_smb_files" not in trace.queries_executed


def test_branch_triggers_follow_up_query_and_rule_fires(lateral_movement_log_paths):
    trace = run_c1_investigation(ALERT, lateral_movement_log_paths, case_id="t2")
    assert "dce_rpc" in trace.branches_triggered
    assert "query_dce_rpc" in trace.queries_executed
    assert "dce-rpc-sensitive-pipe" in trace.rules_fired
    assert trace.final_report["confidence"] == "medium"
    assert "T1021.002" in trace.final_report["attack_technique_mapping"]
    assert trace.final_report["affected_entities"] == ["TESTHOST"]


def test_missing_tool_skipped_gracefully(clean_log_paths):
    # no query_dns key at all, and query_kerberos removed too
    log_paths = {"query_conn": clean_log_paths["query_conn"]}
    trace = run_c1_investigation(ALERT, log_paths, case_id="t3")
    assert any(e["event"] == "query_skipped" and e["tool"] == "query_dns" for e in trace.events)
    assert any(e["event"] == "query_skipped" and e["tool"] == "query_kerberos" for e in trace.events)
    assert trace.final_report is not None  # never crashes on missing tools


def test_deterministic_repeat_runs_produce_identical_report(lateral_movement_log_paths):
    trace1 = run_c1_investigation(ALERT, lateral_movement_log_paths, case_id="t4")
    trace2 = run_c1_investigation(ALERT, lateral_movement_log_paths, case_id="t4")
    assert trace1.final_report == trace2.final_report
    assert trace1.rules_fired == trace2.rules_fired


def test_trace_save_writes_valid_json(tmp_path, clean_log_paths):
    trace = run_c1_investigation(ALERT, clean_log_paths, case_id="t5")
    out = tmp_path / "t5_trace.json"
    trace.save(out)
    loaded = json.loads(out.read_text())
    assert loaded["summary"]["case_id"] == "t5"
    assert loaded["summary"]["condition"] == "C1"
    assert "final_report" in loaded
    assert isinstance(loaded["events"], list) and len(loaded["events"]) > 0


def test_report_schema_matches_other_conditions(clean_log_paths):
    """C1's report must validate against the same FinalReport schema
    C2/C3/Argus use, so evaluation (Section 7.9-7.11) can treat all
    four conditions' outputs uniformly."""
    from src.C3.report import FinalReport
    trace = run_c1_investigation(ALERT, clean_log_paths, case_id="t6")
    FinalReport.model_validate(trace.final_report)  # must not raise
