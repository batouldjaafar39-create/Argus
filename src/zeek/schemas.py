from typing import Optional

from pydantic import BaseModel, ConfigDict, Field


class ConnRecord(BaseModel):
    """A single validated Zeek conn.log record."""

    model_config = ConfigDict(
        extra="ignore",        # tolerate unexpected/future fields without hard-failing
        populate_by_name=True,  # allow constructing via python names OR aliases
    )

    # --- Pipeline / ingestion metadata (present in all samples, but not
    # --- part of Zeek's own conn.log schema) ---
    stream: Optional[str] = Field(default=None, alias="@stream")
    system: Optional[str] = Field(default=None, alias="@system")
    proc: Optional[str] = Field(default=None, alias="@proc")

    # --- Core fields: always present in Zeek conn.log ---
    ts: float
    uid: str
    id_orig_h: str
    id_orig_p: int
    id_resp_h: str
    id_resp_p: int
    proto: str

    # --- Optional Zeek conn.log fields ---
    service: Optional[str] = None
    duration: Optional[float] = None
    orig_bytes: Optional[int] = None
    resp_bytes: Optional[int] = None
    conn_state: Optional[str] = None
    missed_bytes: Optional[int] = None
    history: Optional[str] = None
    orig_pkts: Optional[int] = None
    orig_ip_bytes: Optional[int] = None
    resp_pkts: Optional[int] = None
    resp_ip_bytes: Optional[int] = None
    orig_l2_addr: Optional[str] = None
    resp_l2_addr: Optional[str] = None
class DnsRecord(BaseModel):
    """A single validated Zeek dns.log record."""

    model_config = ConfigDict(
        extra="ignore",
        populate_by_name=True,
    )

    # Pipeline / ingestion metadata
    stream: Optional[str] = Field(default=None, alias="@stream")
    system: Optional[str] = Field(default=None, alias="@system")
    proc: Optional[str] = Field(default=None, alias="@proc")

    # Core DNS fields
    ts: float
    uid: str
    id_orig_h: str
    id_orig_p: int
    id_resp_h: str
    id_resp_p: int
    proto: str
    trans_id: int

    # Optional DNS fields
    rtt: Optional[float] = None

    query: Optional[str] = None

    qclass: Optional[int] = None
    qclass_name: Optional[str] = None

    qtype: Optional[int] = None
    qtype_name: Optional[str] = None

    rcode: Optional[int] = None
    rcode_name: Optional[str] = None

    AA: Optional[bool] = None
    TC: Optional[bool] = None
    RD: Optional[bool] = None
    RA: Optional[bool] = None

    Z: Optional[int] = None

    answers: Optional[list[str]] = None
    TTLs: Optional[list[float]] = None

    rejected: Optional[bool] = None
class DceRpcRecord(BaseModel):
    """A single validated Zeek dce_rpc.log record."""

    model_config = ConfigDict(
        extra="ignore",
        populate_by_name=True,
    )

    # Pipeline / ingestion metadata
    stream: Optional[str] = Field(default=None, alias="@stream")
    system: Optional[str] = Field(default=None, alias="@system")
    proc: Optional[str] = Field(default=None, alias="@proc")

    # Core connection identity
    ts: float
    uid: str
    id_orig_h: str
    id_orig_p: int
    id_resp_h: str
    id_resp_p: int

    # DCE/RPC-specific fields
    rtt: Optional[float] = None
    named_pipe: Optional[str] = None
    endpoint: Optional[str] = None
    operation: Optional[str] = None
class SmbFilesRecord(BaseModel):
    """A single validated Zeek smb_files.log record."""

    model_config = ConfigDict(
        extra="ignore",
        populate_by_name=True,
    )

    # Pipeline / ingestion metadata
    stream: Optional[str] = Field(default=None, alias="@stream")
    system: Optional[str] = Field(default=None, alias="@system")
    proc: Optional[str] = Field(default=None, alias="@proc")

    # Core connection identity
    ts: float
    uid: str
    id_orig_h: str
    id_orig_p: int
    id_resp_h: str
    id_resp_p: int

    # SMB file fields
    action: Optional[str] = None
    path: Optional[str] = None
    name: Optional[str] = None
    size: Optional[int] = None

    # File timestamps
    times_modified: Optional[float] = None
    times_accessed: Optional[float] = None
    times_created: Optional[float] = None
    times_changed: Optional[float] = None
class SmbMappingRecord(BaseModel):
    """A single validated Zeek smb_mapping.log record."""

    model_config = ConfigDict(
        extra="ignore",
        populate_by_name=True,
    )

    # Pipeline / ingestion metadata
    stream: Optional[str] = Field(default=None, alias="@stream")
    system: Optional[str] = Field(default=None, alias="@system")
    proc: Optional[str] = Field(default=None, alias="@proc")

    # Core connection identity
    ts: float
    uid: str
    id_orig_h: str
    id_orig_p: int
    id_resp_h: str
    id_resp_p: int

    # SMB mapping fields
    path: Optional[str] = None
    share_type: Optional[str] = None
class KerberosRecord(BaseModel):
    """A single validated Zeek kerberos.log record."""

    model_config = ConfigDict(
        extra="ignore",
        populate_by_name=True,
    )

    # Pipeline / ingestion metadata
    stream: Optional[str] = Field(default=None, alias="@stream")
    system: Optional[str] = Field(default=None, alias="@system")
    proc: Optional[str] = Field(default=None, alias="@proc")

    # Core connection identity
    ts: float
    uid: str
    id_orig_h: str
    id_orig_p: int
    id_resp_h: str
    id_resp_p: int

    # Kerberos-specific fields
    request_type: Optional[str] = None
    client: Optional[str] = None
    service: Optional[str] = None
    success: Optional[bool] = None
    till: Optional[float] = None
    cipher: Optional[str] = None
    forwardable: Optional[bool] = None
    renewable: Optional[bool] = None
    error_msg: Optional[str] = None