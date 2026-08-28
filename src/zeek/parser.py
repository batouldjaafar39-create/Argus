from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Union

from pydantic import ValidationError

from .schemas import ConnRecord, DnsRecord, DceRpcRecord, SmbFilesRecord, SmbMappingRecord, KerberosRecord


@dataclass
class ParseError:
    """Represents one line that could not be parsed into a ConnRecord."""

    line_number: int
    raw_line: str
    error: str


def parse_conn_log(path: Union[str, Path]) -> Iterator[Union[ConnRecord, ParseError]]:
    """
    Stream-parse a Zeek conn.log (NDJSON) file.

    Yields ConnRecord for each valid line, ParseError for each line that
    could not be parsed/validated. Does not raise on malformed lines.

    Raises:
        FileNotFoundError: if `path` does not exist.
        ValueError: if `path` exists but is not a regular file.
    """
    log_path = Path(path)

    if not log_path.exists():
        raise FileNotFoundError(f"conn.log file not found: {log_path}")
    if not log_path.is_file():
        raise ValueError(f"Path exists but is not a file: {log_path}")

    with log_path.open("r", encoding="utf-8") as f:
        for line_number, raw_line in enumerate(f, start=1):
            line = raw_line.strip()
            if not line:
                continue  # blank line: skip silently, not an error

            try:
                record = ConnRecord.model_validate_json(line)
            except (ValidationError, ValueError) as exc:
                # ValueError also catches json.JSONDecodeError, which
                # Pydantic's model_validate_json raises for invalid JSON.
                yield ParseError(line_number=line_number, raw_line=line, error=str(exc))
                continue

            yield record
def parse_dns_log(
    path: Union[str, Path],
) -> Iterator[Union[DnsRecord, ParseError]]:
    """
    Stream-parse a Zeek dns.log (NDJSON) file.

    Valid DNS records are yielded as DnsRecord objects.
    Malformed or invalid records are yielded as ParseError objects.
    Blank lines are skipped silently.
    """

    log_path = Path(path)

    if not log_path.exists():
        raise FileNotFoundError(f"dns.log file not found: {log_path}")

    if not log_path.is_file():
        raise ValueError(f"Path exists but is not a file: {log_path}")

    with log_path.open("r", encoding="utf-8") as f:
        for line_number, raw_line in enumerate(f, start=1):
            line = raw_line.strip()

            if not line:
                continue

            try:
                record = DnsRecord.model_validate_json(line)
            except (ValidationError, ValueError) as exc:
                yield ParseError(
                    line_number=line_number,
                    raw_line=line,
                    error=str(exc),
                )
                continue

            yield record
def parse_dce_rpc_log(
    path: Union[str, Path],
) -> Iterator[Union[DceRpcRecord, ParseError]]:
    """
    Stream-parse a Zeek dce_rpc.log NDJSON file.

    Valid records are yielded as DceRpcRecord objects.
    Malformed or invalid lines are yielded as ParseError objects.
    Blank lines are skipped.
    """

    log_path = Path(path)

    if not log_path.exists():
        raise FileNotFoundError(
            f"dce_rpc.log file not found: {log_path}"
        )

    if not log_path.is_file():
        raise ValueError(
            f"Path exists but is not a file: {log_path}"
        )

    with log_path.open("r", encoding="utf-8") as f:
        for line_number, raw_line in enumerate(f, start=1):
            line = raw_line.strip()

            if not line:
                continue

            try:
                record = DceRpcRecord.model_validate_json(line)

            except (ValidationError, ValueError) as exc:
                yield ParseError(
                    line_number=line_number,
                    raw_line=line,
                    error=str(exc),
                )
                continue

            yield record
def parse_smb_files_log(
    path: Union[str, Path],
) -> Iterator[Union[SmbFilesRecord, ParseError]]:
    """
    Stream-parse a Zeek smb_files.log NDJSON file.

    Valid records are yielded as SmbFilesRecord objects.
    Malformed or invalid lines are yielded as ParseError objects.
    Blank lines are skipped.
    """

    log_path = Path(path)

    if not log_path.exists():
        raise FileNotFoundError(
            f"smb_files.log file not found: {log_path}"
        )

    if not log_path.is_file():
        raise ValueError(
            f"Path exists but is not a file: {log_path}"
        )

    with log_path.open("r", encoding="utf-8") as f:
        for line_number, raw_line in enumerate(f, start=1):
            line = raw_line.strip()

            if not line:
                continue

            try:
                record = SmbFilesRecord.model_validate_json(line)

            except (ValidationError, ValueError) as exc:
                yield ParseError(
                    line_number=line_number,
                    raw_line=line,
                    error=str(exc),
                )
                continue

            yield record
def parse_smb_mapping_log(
    path: Union[str, Path],
) -> Iterator[Union[SmbMappingRecord, ParseError]]:
    """
    Stream-parse a Zeek smb_mapping.log NDJSON file.

    Valid records are yielded as SmbMappingRecord objects.
    Malformed or invalid lines are yielded as ParseError objects.
    Blank lines are skipped.
    """

    log_path = Path(path)

    if not log_path.exists():
        raise FileNotFoundError(
            f"smb_mapping.log file not found: {log_path}"
        )

    if not log_path.is_file():
        raise ValueError(
            f"Path exists but is not a file: {log_path}"
        )

    with log_path.open("r", encoding="utf-8") as f:
        for line_number, raw_line in enumerate(f, start=1):
            line = raw_line.strip()

            if not line:
                continue

            try:
                record = SmbMappingRecord.model_validate_json(line)

            except (ValidationError, ValueError) as exc:
                yield ParseError(
                    line_number=line_number,
                    raw_line=line,
                    error=str(exc),
                )
                continue

            yield record
def parse_kerberos_log(
    path: Union[str, Path],
) -> Iterator[Union[KerberosRecord, ParseError]]:
    """
    Stream-parse a Zeek kerberos.log NDJSON file.

    Valid records are yielded as KerberosRecord objects.
    Malformed or invalid lines are yielded as ParseError objects.
    Blank lines are skipped.
    """

    log_path = Path(path)

    if not log_path.exists():
        raise FileNotFoundError(
            f"kerberos.log file not found: {log_path}"
        )

    if not log_path.is_file():
        raise ValueError(
            f"Path exists but is not a file: {log_path}"
        )

    with log_path.open("r", encoding="utf-8") as f:
        for line_number, raw_line in enumerate(f, start=1):
            line = raw_line.strip()

            if not line:
                continue

            try:
                record = KerberosRecord.model_validate_json(line)

            except (ValidationError, ValueError) as exc:
                yield ParseError(
                    line_number=line_number,
                    raw_line=line,
                    error=str(exc),
                )
                continue

            yield record