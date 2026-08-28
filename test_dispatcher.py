import pytest

from src.C3.tools import TOOL_FUNCTIONS, ToolDispatchError, dispatch_tool_call


# ---------------------------------------------------------------------
# All six tools reachable through the dispatcher
# ---------------------------------------------------------------------

@pytest.mark.parametrize(
    "tool_name,kwargs",
    [
        ("query_conn", {}),
        ("query_dns", {}),
        ("query_dce_rpc", {}),
        ("query_smb_files", {}),
        ("query_smb_mapping", {}),
        ("query_kerberos", {}),
    ],
)
def test_all_six_tools_dispatch_successfully(tool_name, kwargs, all_log_paths):
    result = dispatch_tool_call(tool_name, kwargs, all_log_paths)
    assert "records" in result
    assert "count" in result
    assert "truncated" in result


def test_tool_registry_has_exactly_six_tools():
    assert set(TOOL_FUNCTIONS) == {
        "query_conn", "query_dns", "query_dce_rpc",
        "query_smb_files", "query_smb_mapping", "query_kerberos",
    }


# ---------------------------------------------------------------------
# 1. Unknown tool name
# ---------------------------------------------------------------------

def test_unknown_tool_name_rejected(all_log_paths):
    with pytest.raises(ToolDispatchError, match="Unknown tool"):
        dispatch_tool_call("query_nonexistent", {}, all_log_paths)


def test_tool_name_not_a_string_rejected(all_log_paths):
    with pytest.raises(ToolDispatchError, match="must be a string"):
        dispatch_tool_call(123, {}, all_log_paths)


def test_tool_name_none_rejected(all_log_paths):
    with pytest.raises(ToolDispatchError):
        dispatch_tool_call(None, {}, all_log_paths)


# ---------------------------------------------------------------------
# 2. args is not a JSON object
# ---------------------------------------------------------------------

def test_args_as_list_rejected(all_log_paths):
    with pytest.raises(ToolDispatchError, match="'args' must be a JSON object"):
        dispatch_tool_call("query_conn", ["service", "dns"], all_log_paths)


def test_args_as_string_rejected(all_log_paths):
    with pytest.raises(ToolDispatchError, match="'args' must be a JSON object"):
        dispatch_tool_call("query_conn", "service=dns", all_log_paths)


def test_args_as_none_rejected(all_log_paths):
    with pytest.raises(ToolDispatchError):
        dispatch_tool_call("query_conn", None, all_log_paths)


# ---------------------------------------------------------------------
# 3. log_path override attempt
# ---------------------------------------------------------------------

def test_log_path_override_rejected(all_log_paths):
    with pytest.raises(ToolDispatchError, match="log_path"):
        dispatch_tool_call("query_conn", {"log_path": "/etc/passwd"}, all_log_paths)


# ---------------------------------------------------------------------
# 4. Unknown argument name
# ---------------------------------------------------------------------

def test_unknown_argument_name_rejected(all_log_paths):
    with pytest.raises(ToolDispatchError, match="Unknown argument"):
        dispatch_tool_call("query_conn", {"not_a_real_filter": "x"}, all_log_paths)


# ---------------------------------------------------------------------
# 5. Invalid argument types
# ---------------------------------------------------------------------

def test_wrong_type_int_expected_got_string(all_log_paths):
    with pytest.raises(ToolDispatchError, match="wrong type"):
        dispatch_tool_call("query_conn", {"src_port": "not-a-port"}, all_log_paths)


def test_wrong_type_str_expected_got_int(all_log_paths):
    with pytest.raises(ToolDispatchError, match="wrong type"):
        dispatch_tool_call("query_conn", {"src_ip": 12345}, all_log_paths)


def test_wrong_type_bool_expected_got_int(all_log_paths):
    with pytest.raises(ToolDispatchError, match="wrong type"):
        dispatch_tool_call("query_kerberos", {"success": 1}, all_log_paths)


def test_bool_not_accepted_where_int_expected(all_log_paths):
    # bool is a subclass of int in Python; must not silently pass as a port number.
    with pytest.raises(ToolDispatchError, match="wrong type"):
        dispatch_tool_call("query_conn", {"src_port": True}, all_log_paths)


def test_correct_types_accepted(all_log_paths):
    result = dispatch_tool_call(
        "query_conn",
        {
            "src_ip": "10.0.0.1",
            "src_port": 1111,
            "limit": 5,
        },
        all_log_paths,
    )

    assert "records" in result
    assert "count" in result
    assert result["count"] >= 0


def test_none_value_always_accepted_for_optional_arg(all_log_paths):
    result = dispatch_tool_call("query_conn", {"src_ip": None}, all_log_paths)
    assert "records" in result


# ---------------------------------------------------------------------
# 6. Underlying query function's own validation still surfaces cleanly
# ---------------------------------------------------------------------

def test_underlying_invalid_limit_becomes_dispatch_error(all_log_paths):
    with pytest.raises(ToolDispatchError, match="rejected arguments"):
        dispatch_tool_call("query_conn", {"limit": 0}, all_log_paths)


def test_no_log_path_configured_for_case_rejected(conn_log):
    with pytest.raises(ToolDispatchError, match="No log path configured"):
        dispatch_tool_call("query_dns", {}, {"query_conn": str(conn_log)})


# ---------------------------------------------------------------------
# Nothing here ever raises anything except ToolDispatchError
# ---------------------------------------------------------------------

@pytest.mark.parametrize(
    "tool_name,args",
    [
        ("query_nonexistent", {}),
        (123, {}),
        ("query_conn", "not a dict"),
        ("query_conn", {"log_path": "x"}),
        ("query_conn", {"bogus": 1}),
        ("query_conn", {"src_port": "abc"}),
        ("query_conn", {"limit": -1}),
    ],
)
def test_every_failure_mode_raises_only_tool_dispatch_error(tool_name, args, all_log_paths):
    with pytest.raises(ToolDispatchError):
        dispatch_tool_call(tool_name, args, all_log_paths)