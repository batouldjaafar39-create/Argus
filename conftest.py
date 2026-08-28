from pathlib import Path

import pytest


DATA_DIR = Path(__file__).parent / "data" / "day2"
# Test fixtures use NEWYORK's real Zeek logs as a fixed, known-good
# single-host dataset. NEWYORK has all six log types, unlike the other
# day2 hosts (e.g. UTICA-C has no dce_rpc/smb_files, SCRANTON has no
# smb_files). Do not point these at generic "conn.log"-style filenames
# -- those don't exist on disk; every real log is host-prefixed
# (NEWYORK_conn.log, SCRANTON_conn.log, UTICA-A_conn.log, ...). Case
# investigations resolve their own host's files via src/C3/cases.py;
# these fixtures are only for unit tests that need *some* valid file.
TEST_HOST = "NEWYORK"


@pytest.fixture
def conn_log():
    return str(DATA_DIR / f"{TEST_HOST}_conn.log")


@pytest.fixture
def dns_log():
    return str(DATA_DIR / f"{TEST_HOST}_dns.log")


@pytest.fixture
def dce_rpc_log():
    return str(DATA_DIR / f"{TEST_HOST}_dce_rpc.log")


@pytest.fixture
def smb_files_log():
    return str(DATA_DIR / f"{TEST_HOST}_smb_files.log")


@pytest.fixture
def smb_mapping_log():
    return str(DATA_DIR / f"{TEST_HOST}_smb_mapping.log")


@pytest.fixture
def kerberos_log():
    return str(DATA_DIR / f"{TEST_HOST}_kerberos.log")


@pytest.fixture
def all_log_paths():
    return {
        "query_conn": str(DATA_DIR / f"{TEST_HOST}_conn.log"),
        "query_dns": str(DATA_DIR / f"{TEST_HOST}_dns.log"),
        "query_dce_rpc": str(DATA_DIR / f"{TEST_HOST}_dce_rpc.log"),
        "query_smb_files": str(DATA_DIR / f"{TEST_HOST}_smb_files.log"),
        "query_smb_mapping": str(DATA_DIR / f"{TEST_HOST}_smb_mapping.log"),
        "query_kerberos": str(DATA_DIR / f"{TEST_HOST}_kerberos.log"),
    }