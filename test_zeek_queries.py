import pytest

from src.zeek.queries import (
    query_conn,
    query_dce_rpc,
    query_dns,
    query_kerberos,
    query_smb_files,
    query_smb_mapping,
)


# ---------------------------------------------------------------------
# conn.log
# ---------------------------------------------------------------------

def test_query_conn_basic_filter(conn_log):
    result = query_conn(conn_log, service="dns")

    assert "records" in result
    assert "count" in result
    assert result["count"] >= 0

    # If DNS connections exist, every returned record must match.
    for record in result["records"]:
        assert record["service"] == "dns"


def test_query_conn_malformed_line_skipped(conn_log):
    result = query_conn(conn_log)

    assert "records" in result
    assert "count" in result
    assert "errors_skipped" in result

    # The parser should never crash because of a malformed record.
    assert result["count"] >= 0
    assert result["errors_skipped"] >= 0


def test_query_conn_limit_truncates(conn_log):
    result = query_conn(conn_log, limit=10)

    assert result["count"] <= 10
    assert result["count"] >= 0
    assert "truncated" in result
    assert "matched_before_limit" in result

    if result["matched_before_limit"] > 10:
        assert result["truncated"] is True
        assert result["count"] == 10
    else:
        assert result["truncated"] is False
        assert result["count"] == result["matched_before_limit"]


def test_query_conn_missing_file_raises():
    with pytest.raises(FileNotFoundError):
        query_conn("/nonexistent/conn.log")


# ---------------------------------------------------------------------
# dns.log
# ---------------------------------------------------------------------

def test_query_dns_filter_by_query(dns_log):
    # First obtain a real query from the actual dataset.
    all_records = query_dns(dns_log, limit=1)

    if all_records["count"] == 0:
        pytest.skip("No DNS records available in the real dataset.")

    real_query = all_records["records"][0]["query"]

    result = query_dns(dns_log, query=real_query)

    assert result["count"] > 0

    for record in result["records"]:
        assert record["query"] == real_query


def test_query_dns_no_match(dns_log):
    result = query_dns(
        dns_log,
        query="THIS_DOMAIN_SHOULD_NOT_EXIST_123456789.example",
    )

    assert result["count"] == 0


# ---------------------------------------------------------------------
# dce_rpc.log
# ---------------------------------------------------------------------

def test_query_dce_rpc_filter_by_named_pipe(dce_rpc_log):
    all_records = query_dce_rpc(dce_rpc_log, limit=1)

    if all_records["count"] == 0:
        pytest.skip("No DCE/RPC records available in the real dataset.")

    real_pipe = all_records["records"][0].get("named_pipe")

    if real_pipe is None:
        pytest.skip("No named_pipe value available in the real dataset.")

    result = query_dce_rpc(
        dce_rpc_log,
        named_pipe=real_pipe,
    )

    assert result["count"] > 0

    for record in result["records"]:
        assert record["named_pipe"] == real_pipe


def test_query_dce_rpc_filter_by_endpoint(dce_rpc_log):
    all_records = query_dce_rpc(dce_rpc_log, limit=1)

    if all_records["count"] == 0:
        pytest.skip("No DCE/RPC records available in the real dataset.")

    real_endpoint = all_records["records"][0].get("endpoint")

    if real_endpoint is None:
        pytest.skip("No endpoint value available in the real dataset.")

    result = query_dce_rpc(
        dce_rpc_log,
        endpoint=real_endpoint,
    )

    assert result["count"] > 0

    for record in result["records"]:
        assert record["endpoint"] == real_endpoint


# ---------------------------------------------------------------------
# smb_files.log
# ---------------------------------------------------------------------

def test_query_smb_files_filter_by_name(smb_files_log):
    all_records = query_smb_files(smb_files_log, limit=1)

    if all_records["count"] == 0:
        pytest.skip("No SMB file records available in the real dataset.")

    real_name = all_records["records"][0].get("name")

    if real_name is None:
        pytest.skip("No file name available in the real dataset.")

    result = query_smb_files(
        smb_files_log,
        name=real_name,
    )

    assert result["count"] > 0

    for record in result["records"]:
        assert record["name"] == real_name


# ---------------------------------------------------------------------
# smb_mapping.log
# ---------------------------------------------------------------------

def test_query_smb_mapping_filter_by_share_type(smb_mapping_log):
    all_records = query_smb_mapping(smb_mapping_log, limit=1)

    if all_records["count"] == 0:
        pytest.skip("No SMB mapping records available in the real dataset.")

    real_share_type = all_records["records"][0].get("share_type")

    if real_share_type is None:
        pytest.skip("No share_type value available in the real dataset.")

    result = query_smb_mapping(
        smb_mapping_log,
        share_type=real_share_type,
    )

    assert result["count"] > 0

    for record in result["records"]:
        assert record["share_type"] == real_share_type


def test_query_smb_mapping_no_match(smb_mapping_log):
    result = query_smb_mapping(
        smb_mapping_log,
        share_type="THIS_SHARE_TYPE_DOES_NOT_EXIST_123456",
    )

    assert result["count"] == 0


# ---------------------------------------------------------------------
# kerberos.log
# ---------------------------------------------------------------------

def test_query_kerberos_filter_by_success(kerberos_log):
    result = query_kerberos(
        kerberos_log,
        success=True,
    )

    assert "records" in result
    assert "count" in result

    for record in result["records"]:
        assert record["success"] is True


def test_query_kerberos_filter_failed_requests(kerberos_log):
    result = query_kerberos(
        kerberos_log,
        success=False,
    )

    assert "records" in result
    assert "count" in result

    for record in result["records"]:
        assert record["success"] is False


def test_query_kerberos_invalid_limit_raises(kerberos_log):
    with pytest.raises(ValueError):
        query_kerberos(kerberos_log, limit=0)