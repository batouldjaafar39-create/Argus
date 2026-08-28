import json
from pathlib import Path
from typing import Optional

# tool name -> Zeek log filename suffix
TOOL_LOG_SUFFIXES: dict[str, str] = {
    "query_conn": "conn.log",
    "query_dns": "dns.log",
    "query_dce_rpc": "dce_rpc.log",
    "query_smb_files": "smb_files.log",
    "query_smb_mapping": "smb_mapping.log",
    "query_kerberos": "kerberos.log",
}


class CaseLoadError(Exception):
    """Raised when a case file is missing, malformed, or its host has no data."""


def load_case(
    case_id: str,
    cases_dir: Path = Path("scenarios/cases"),
    data_dir: Path = Path("data"),
) -> tuple[dict, dict[str, str]]:
    """
    Load one scenario case and resolve it to a ready-to-run
    (alert, log_paths) pair.

    Args:
        case_id: e.g. "D1-C1", must match scenarios/cases/<case_id>.json.
        cases_dir: directory containing the case JSON files.
        data_dir: directory containing day1/ and day2/ Zeek logs.

    Returns:
        (alert, log_paths):
            alert: the case's "initial_alert" dict, passed straight to
                run_c3_investigation. Ground truth is never in here.
            log_paths: {tool_name: path} for every one of the six Zeek
                tools that actually has a log file for this host. Tools
                with no matching file for this host are simply omitted
                (dispatch_tool_call already reports that cleanly if the
                model tries to use one), never silently pointed at the
                wrong host's file.

    Raises:
        CaseLoadError: case file missing/malformed, unresolved
            "<CAPTURE_TIMESTAMP>" placeholder, unknown dataset, or zero
            log files found for the case's host.
    """
    case_path = cases_dir / f"{case_id}.json"
    if not case_path.is_file():
        raise CaseLoadError(f"No case file at {case_path}")

    try:
        case = json.loads(case_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise CaseLoadError(f"{case_path} is not valid JSON: {exc}") from exc

    dataset = case.get("dataset")
    if dataset not in ("day1", "day2"):
        raise CaseLoadError(
            f"{case_path}: 'dataset' must be 'day1' or 'day2', got {dataset!r}"
        )

    alert = case.get("initial_alert")
    if not isinstance(alert, dict):
        raise CaseLoadError(f"{case_path}: missing/invalid 'initial_alert'")

    host = alert.get("host")
    if not host:
        raise CaseLoadError(f"{case_path}: 'initial_alert.host' is required")

    if alert.get("timestamp") == "<CAPTURE_TIMESTAMP>":
        raise CaseLoadError(
            f"{case_path}: 'initial_alert.timestamp' is still the "
            f"'<CAPTURE_TIMESTAMP>' placeholder and needs to be filled in "
            f"with a real timestamp before this case can be run."
        )

    host_dir = data_dir / dataset
    log_paths: dict[str, str] = {}
    for tool_name, suffix in TOOL_LOG_SUFFIXES.items():
        candidate = host_dir / f"{host}_{suffix}"
        if candidate.is_file():
            log_paths[tool_name] = str(candidate)

    if not log_paths:
        raise CaseLoadError(
            f"No Zeek log files found for host '{host}' under {host_dir} "
            f"(expected files like '{host}_conn.log')."
        )

    return alert, log_paths


def list_case_ids(cases_dir: Path = Path("scenarios/cases")) -> list[str]:
    """Return all case_ids found in cases_dir, sorted (e.g. D1-C1, D1-C2, ...)."""
    return sorted(p.stem for p in cases_dir.glob("*.json"))
