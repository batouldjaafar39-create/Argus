from dataclasses import dataclass, field
from typing import FrozenSet


@dataclass(frozen=True)
class C1Config:
    """Fixed configuration for the C1 deterministic baseline.

    C1 has no LLM and no free-form reasoning. It applies the same
    predefined investigation procedure to every case.

    The investigation is scoped to a fixed time window beginning at
    the initial alert timestamp. This prevents C1 from searching an
    entire day's logs and accidentally attributing unrelated activity
    to the alert.
    """

    # ------------------------------------------------------------------
    # Investigation time window
    # ------------------------------------------------------------------

    # Number of seconds after the alert timestamp that C1 investigates.
    #
    # 3600 seconds = 1 hour.
    #
    # Example:
    #   alert = 2020-04-30T00:06:38Z
    #
    #   C1 window =
    #   2020-04-30T00:06:38Z
    #   through
    #   2020-04-30T01:06:38Z
    #
    # This is fixed for every case so the baseline remains deterministic.
    investigation_window_seconds: int = 3600

    # ------------------------------------------------------------------
    # Query volume
    # ------------------------------------------------------------------

    baseline_query_limit: int = 200

    # ------------------------------------------------------------------
    # Stage 2 branch triggers
    # ------------------------------------------------------------------

    smb_ports: FrozenSet[int] = field(
        default_factory=lambda: frozenset({445})
    )

    dce_rpc_ports: FrozenSet[int] = field(
        default_factory=lambda: frozenset({135})
    )

    remote_access_ports: FrozenSet[int] = field(
        default_factory=lambda: frozenset({3389, 5985, 5986})
    )

    # ------------------------------------------------------------------
    # Stage 3 fixed detection rules
    # ------------------------------------------------------------------

    sensitive_named_pipes: FrozenSet[str] = field(
        default_factory=lambda: frozenset({
            "svcctl",
            "atsvc",
            "winreg",
            "srvsvc",
        })
    )

    weak_kerberos_ciphers: FrozenSet[str] = field(
        default_factory=lambda: frozenset({
            "rc4-hmac",
            "des-cbc-md5",
            "des-cbc-crc",
        })
    )

    sensitive_share_markers: FrozenSet[str] = field(
        default_factory=lambda: frozenset({
            "admin$",
            "c$",
            "ipc$",
        })
    )

    executable_extensions: FrozenSet[str] = field(
        default_factory=lambda: frozenset({
            ".exe",
            ".dll",
            ".ps1",
            ".bat",
            ".vbs",
        })
    )