from pathlib import Path
from typing import Optional, Union

from .parser import ParseError, parse_conn_log, parse_dns_log, parse_dce_rpc_log,parse_smb_files_log, parse_smb_mapping_log, parse_kerberos_log
from .schemas import ConnRecord, DnsRecord, DceRpcRecord, SmbFilesRecord, SmbMappingRecord, KerberosRecord


def _record_to_dict(record: ConnRecord) -> dict:
    return record.model_dump(by_alias=True, exclude_none=True)


def query_conn(
    log_path: Union[str, Path],
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    src_port: Optional[int] = None,
    dst_port: Optional[int] = None,
    proto: Optional[str] = None,
    service: Optional[str] = None,
    uid: Optional[str] = None,
    start_ts: Optional[float] = None,
    end_ts: Optional[float] = None,
    limit: int = 100,
) -> dict:
    """
    Query a Zeek conn.log file, filtering ONLY on fields that actually
    exist in conn.log.

    Args:
        log_path: path to a conn.log (NDJSON) file.
        src_ip: exact match against id_orig_h.
        dst_ip: exact match against id_resp_h.
        src_port: exact match against id_orig_p.
        dst_port: exact match against id_resp_p.
        proto: exact match against proto (e.g. "tcp", "udp").
        service: exact match against service (e.g. "dns", "krb_tcp").
        uid: exact match against uid.
        start_ts: inclusive lower bound on ts.
        end_ts: inclusive upper bound on ts.
        limit: maximum number of records to return (must be > 0).

    Returns:
        {
            "records": [dict, ...],       # matching records (<= limit)
            "count": int,                  # len(records)
            "truncated": bool,             # True if more matches existed than `limit`
            "matched_before_limit": int,   # total matches found, before truncation
            "errors_skipped": int,         # malformed lines skipped during the scan
        }

    Raises:
        FileNotFoundError: if log_path does not exist.
        ValueError: if limit <= 0, or start_ts > end_ts.
    """
    if limit <= 0:
        raise ValueError("limit must be a positive integer")
    if start_ts is not None and end_ts is not None and start_ts > end_ts:
        raise ValueError("start_ts must be <= end_ts")

    results = []
    matched_before_limit = 0
    errors_skipped = 0

    for item in parse_conn_log(log_path):
        if isinstance(item, ParseError):
            errors_skipped += 1
            continue

        record: ConnRecord = item

        if src_ip is not None and record.id_orig_h != src_ip:
            continue
        if dst_ip is not None and record.id_resp_h != dst_ip:
            continue
        if src_port is not None and record.id_orig_p != src_port:
            continue
        if dst_port is not None and record.id_resp_p != dst_port:
            continue
        if proto is not None and record.proto != proto:
            continue
        if service is not None and record.service != service:
            continue
        if uid is not None and record.uid != uid:
            continue
        if start_ts is not None and record.ts < start_ts:
            continue
        if end_ts is not None and record.ts > end_ts:
            continue

        matched_before_limit += 1
        if len(results) < limit:
            results.append(_record_to_dict(record))

    return {
        "records": results,
        "count": len(results),
        "truncated": matched_before_limit > limit,
        "matched_before_limit": matched_before_limit,
        "errors_skipped": errors_skipped,
    }
def query_dns(
    log_path: Union[str, Path],
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    query: Optional[str] = None,
    qtype: Optional[int] = None,
    qtype_name: Optional[str] = None,
    rcode: Optional[int] = None,
    rcode_name: Optional[str] = None,
    uid: Optional[str] = None,
    start_ts: Optional[float] = None,
    end_ts: Optional[float] = None,
    limit: int = 100,
) -> dict:
    """
    Query a Zeek dns.log file.

    Filters only use fields that actually exist in the DNS records.

    Args:
        log_path: Path to dns.log.
        src_ip: Exact match against id_orig_h.
        dst_ip: Exact match against id_resp_h.
        query: Exact match against DNS query name.
        qtype: Exact numeric DNS query type.
        qtype_name: Exact DNS query type name, e.g. "A".
        rcode: Exact numeric DNS response code.
        rcode_name: Exact DNS response code name, e.g. "NOERROR".
        uid: Exact Zeek UID.
        start_ts: Inclusive lower bound on timestamp.
        end_ts: Inclusive upper bound on timestamp.
        limit: Maximum number of records returned.

    Returns:
        {
            "records": [...],
            "count": int,
            "truncated": bool,
            "matched_before_limit": int,
            "errors_skipped": int,
        }
    """

    if limit <= 0:
        raise ValueError("limit must be a positive integer")

    if (
        start_ts is not None
        and end_ts is not None
        and start_ts > end_ts
    ):
        raise ValueError("start_ts must be <= end_ts")

    results = []
    matched_before_limit = 0
    errors_skipped = 0

    for item in parse_dns_log(log_path):

        if isinstance(item, ParseError):
            errors_skipped += 1
            continue

        record: DnsRecord = item

        # Source IP
        if (
            src_ip is not None
            and record.id_orig_h != src_ip
        ):
            continue

        # Destination IP
        if (
            dst_ip is not None
            and record.id_resp_h != dst_ip
        ):
            continue

        # DNS query name
        if (
            query is not None
            and record.query != query
        ):
            continue

        # DNS query type
        if (
            qtype is not None
            and record.qtype != qtype
        ):
            continue

        # DNS query type name
        if (
            qtype_name is not None
            and record.qtype_name != qtype_name
        ):
            continue

        # DNS response code
        if (
            rcode is not None
            and record.rcode != rcode
        ):
            continue

        # DNS response code name
        if (
            rcode_name is not None
            and record.rcode_name != rcode_name
        ):
            continue

        # Zeek UID
        if (
            uid is not None
            and record.uid != uid
        ):
            continue

        # Timestamp range
        if (
            start_ts is not None
            and record.ts < start_ts
        ):
            continue

        if (
            end_ts is not None
            and record.ts > end_ts
        ):
            continue

        matched_before_limit += 1

        if len(results) < limit:
            results.append(
                record.model_dump(
                    by_alias=True,
                    exclude_none=True,
                )
            )

    return {
        "records": results,
        "count": len(results),
        "truncated": matched_before_limit > limit,
        "matched_before_limit": matched_before_limit,
        "errors_skipped": errors_skipped,
    }
def _dce_rpc_record_to_dict(
    record: DceRpcRecord,
) -> dict:
    return record.model_dump(
        by_alias=True,
        exclude_none=True,
    )


def query_dce_rpc(
    log_path: Union[str, Path],
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    src_port: Optional[int] = None,
    dst_port: Optional[int] = None,
    uid: Optional[str] = None,
    named_pipe: Optional[str] = None,
    endpoint: Optional[str] = None,
    operation: Optional[str] = None,
    start_ts: Optional[float] = None,
    end_ts: Optional[float] = None,
    limit: int = 100,
) -> dict:
    """
    Query a Zeek dce_rpc.log file.

    Filters only use fields actually present in the
    observed dce_rpc.log records.

    Returns a JSON-serializable dictionary.
    """

    if limit <= 0:
        raise ValueError(
            "limit must be a positive integer"
        )

    if (
        start_ts is not None
        and end_ts is not None
        and start_ts > end_ts
    ):
        raise ValueError(
            "start_ts must be <= end_ts"
        )

    results = []
    matched_before_limit = 0
    errors_skipped = 0

    for item in parse_dce_rpc_log(log_path):

        if isinstance(item, ParseError):
            errors_skipped += 1
            continue

        record: DceRpcRecord = item

        # Source IP
        if (
            src_ip is not None
            and record.id_orig_h != src_ip
        ):
            continue

        # Destination IP
        if (
            dst_ip is not None
            and record.id_resp_h != dst_ip
        ):
            continue

        # Source port
        if (
            src_port is not None
            and record.id_orig_p != src_port
        ):
            continue

        # Destination port
        if (
            dst_port is not None
            and record.id_resp_p != dst_port
        ):
            continue

        # UID
        if (
            uid is not None
            and record.uid != uid
        ):
            continue

        # Named pipe
        if (
            named_pipe is not None
            and record.named_pipe != named_pipe
        ):
            continue

        # Endpoint
        if (
            endpoint is not None
            and record.endpoint != endpoint
        ):
            continue

        # Operation
        if (
            operation is not None
            and record.operation != operation
        ):
            continue

        # Timestamp range
        if (
            start_ts is not None
            and record.ts < start_ts
        ):
            continue

        if (
            end_ts is not None
            and record.ts > end_ts
        ):
            continue

        matched_before_limit += 1

        if len(results) < limit:
            results.append(
                _dce_rpc_record_to_dict(record)
            )

    return {
        "records": results,
        "count": len(results),
        "truncated": matched_before_limit > limit,
        "matched_before_limit": matched_before_limit,
        "errors_skipped": errors_skipped,
    }
def query_smb_files(
    log_path: Union[str, Path],
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    src_port: Optional[int] = None,
    dst_port: Optional[int] = None,
    uid: Optional[str] = None,
    action: Optional[str] = None,
    path: Optional[str] = None,
    name: Optional[str] = None,
    start_ts: Optional[float] = None,
    end_ts: Optional[float] = None,
    limit: int = 100,
) -> dict:
    """
    Query a Zeek smb_files.log file.

    Filters only use fields present in the observed SMB file records.
    """

    if limit <= 0:
        raise ValueError("limit must be a positive integer")

    if (
        start_ts is not None
        and end_ts is not None
        and start_ts > end_ts
    ):
        raise ValueError("start_ts must be <= end_ts")

    results = []
    matched_before_limit = 0
    errors_skipped = 0

    for item in parse_smb_files_log(log_path):

        if isinstance(item, ParseError):
            errors_skipped += 1
            continue

        record: SmbFilesRecord = item

        if (
            src_ip is not None
            and record.id_orig_h != src_ip
        ):
            continue

        if (
            dst_ip is not None
            and record.id_resp_h != dst_ip
        ):
            continue

        if (
            src_port is not None
            and record.id_orig_p != src_port
        ):
            continue

        if (
            dst_port is not None
            and record.id_resp_p != dst_port
        ):
            continue

        if (
            uid is not None
            and record.uid != uid
        ):
            continue

        if (
            action is not None
            and record.action != action
        ):
            continue

        if (
            path is not None
            and record.path != path
        ):
            continue

        if (
            name is not None
            and record.name != name
        ):
            continue

        if (
            start_ts is not None
            and record.ts < start_ts
        ):
            continue

        if (
            end_ts is not None
            and record.ts > end_ts
        ):
            continue

        matched_before_limit += 1

        if len(results) < limit:
            results.append(
                record.model_dump(
                    by_alias=True,
                    exclude_none=True,
                )
            )

    return {
        "records": results,
        "count": len(results),
        "truncated": matched_before_limit > limit,
        "matched_before_limit": matched_before_limit,
        "errors_skipped": errors_skipped,
    }
def query_smb_mapping(
    log_path: Union[str, Path],
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    src_port: Optional[int] = None,
    dst_port: Optional[int] = None,
    uid: Optional[str] = None,
    path: Optional[str] = None,
    share_type: Optional[str] = None,
    start_ts: Optional[float] = None,
    end_ts: Optional[float] = None,
    limit: int = 100,
) -> dict:
    """
    Query a Zeek smb_mapping.log file.

    Filters only use fields actually present in the
    observed SMB mapping records.
    """

    if limit <= 0:
        raise ValueError("limit must be a positive integer")

    if (
        start_ts is not None
        and end_ts is not None
        and start_ts > end_ts
    ):
        raise ValueError("start_ts must be <= end_ts")

    results = []
    matched_before_limit = 0
    errors_skipped = 0

    for item in parse_smb_mapping_log(log_path):

        if isinstance(item, ParseError):
            errors_skipped += 1
            continue

        record: SmbMappingRecord = item

        # Source IP
        if (
            src_ip is not None
            and record.id_orig_h != src_ip
        ):
            continue

        # Destination IP
        if (
            dst_ip is not None
            and record.id_resp_h != dst_ip
        ):
            continue

        # Source port
        if (
            src_port is not None
            and record.id_orig_p != src_port
        ):
            continue

        # Destination port
        if (
            dst_port is not None
            and record.id_resp_p != dst_port
        ):
            continue

        # UID
        if (
            uid is not None
            and record.uid != uid
        ):
            continue

        # SMB path
        if (
            path is not None
            and record.path != path
        ):
            continue

        # Share type
        if (
            share_type is not None
            and record.share_type != share_type
        ):
            continue

        # Timestamp range
        if (
            start_ts is not None
            and record.ts < start_ts
        ):
            continue

        if (
            end_ts is not None
            and record.ts > end_ts
        ):
            continue

        matched_before_limit += 1

        if len(results) < limit:
            results.append(
                record.model_dump(
                    by_alias=True,
                    exclude_none=True,
                )
            )

    return {
        "records": results,
        "count": len(results),
        "truncated": matched_before_limit > limit,
        "matched_before_limit": matched_before_limit,
        "errors_skipped": errors_skipped,
    }
def _kerberos_record_to_dict(
    record: KerberosRecord,
) -> dict:
    return record.model_dump(
        by_alias=True,
        exclude_none=True,
    )


def query_kerberos(
    log_path: Union[str, Path],
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    src_port: Optional[int] = None,
    dst_port: Optional[int] = None,
    request_type: Optional[str] = None,
    client: Optional[str] = None,
    service: Optional[str] = None,
    success: Optional[bool] = None,
    cipher: Optional[str] = None,
    error_msg: Optional[str] = None,
    uid: Optional[str] = None,
    start_ts: Optional[float] = None,
    end_ts: Optional[float] = None,
    limit: int = 100,
) -> dict:
    """
    Query a Zeek kerberos.log file.

    Filters only use fields actually present in the
    observed Kerberos records.
    """

    if limit <= 0:
        raise ValueError(
            "limit must be a positive integer"
        )

    if (
        start_ts is not None
        and end_ts is not None
        and start_ts > end_ts
    ):
        raise ValueError(
            "start_ts must be <= end_ts"
        )

    results = []
    matched_before_limit = 0
    errors_skipped = 0

    for item in parse_kerberos_log(log_path):

        if isinstance(item, ParseError):
            errors_skipped += 1
            continue

        record: KerberosRecord = item

        if (
            src_ip is not None
            and record.id_orig_h != src_ip
        ):
            continue

        if (
            dst_ip is not None
            and record.id_resp_h != dst_ip
        ):
            continue

        if (
            src_port is not None
            and record.id_orig_p != src_port
        ):
            continue

        if (
            dst_port is not None
            and record.id_resp_p != dst_port
        ):
            continue

        if (
            request_type is not None
            and record.request_type != request_type
        ):
            continue

        if (
            client is not None
            and record.client != client
        ):
            continue

        if (
            service is not None
            and record.service != service
        ):
            continue

        if (
            success is not None
            and record.success != success
        ):
            continue

        if (
            cipher is not None
            and record.cipher != cipher
        ):
            continue

        if (
            error_msg is not None
            and record.error_msg != error_msg
        ):
            continue

        if (
            uid is not None
            and record.uid != uid
        ):
            continue

        if (
            start_ts is not None
            and record.ts < start_ts
        ):
            continue

        if (
            end_ts is not None
            and record.ts > end_ts
        ):
            continue

        matched_before_limit += 1

        if len(results) < limit:
            results.append(
                _kerberos_record_to_dict(record)
            )

    return {
        "records": results,
        "count": len(results),
        "truncated": matched_before_limit > limit,
        "matched_before_limit": matched_before_limit,
        "errors_skipped": errors_skipped,
    }