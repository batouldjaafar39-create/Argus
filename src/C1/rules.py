"""
Fixed detection rules for C1. Every function here is a pure function of
(records, config) -> list[Finding] -- no state, no randomness, no LLM.
This is deliberate: C1 exists as the non-LLM baseline, so its detection
logic must be auditable and exactly reproducible by inspection of this
file alone, unlike C2/C3/C4 whose behavior depends on model output.

Each rule maps directly to a fixed ATT&CK technique. This mapping is
part of the fixed procedure (not inferred at investigation time), so it
lives here as a constant rather than being "decided" per case.
"""

from dataclasses import dataclass
from typing import Optional

from .config import C1Config


@dataclass
class Finding:
    rule_id: str
    description: str
    attack_technique: str  # e.g. "T1021.002" or "" if no clean mapping
    evidence_refs: list  # list of small dicts identifying the triggering record(s)


def _conn_evidence_ref(record: dict) -> dict:
    return {
        "uid": record.get("uid"),
        "ts": record.get("ts"),
        "id_orig_h": record.get("id_orig_h"),
        "id_resp_h": record.get("id_resp_h"),
        "id_resp_p": record.get("id_resp_p"),
        "proto": record.get("proto"),
        "service": record.get("service"),
    }


def triggered_lateral_movement_ports(conn_records: list, config: C1Config) -> set:
    """Returns the set of {"smb", "dce_rpc", "remote_access"} branch
    categories triggered by any conn record's destination port. This is
    Stage 2's branch decision -- pure, no side effects, no queries."""
    triggered = set()
    for r in conn_records:
        port = r.get("id_resp_p")
        if port in config.smb_ports:
            triggered.add("smb")
        if port in config.dce_rpc_ports:
            triggered.add("dce_rpc")
        if port in config.remote_access_ports:
            triggered.add("remote_access")
    return triggered


def evaluate_remote_access_ports(conn_records: list, config: C1Config) -> list:
    """Detect connections to predefined remote-access services.

    ATT&CK mapping:
      3389 -> T1021.001 Remote Services: RDP
      5985 -> T1021.006 Remote Services: Windows Remote Management
      5986 -> T1021.006 Remote Services: Windows Remote Management

    The mapping is fixed and deterministic.
    """

    findings = []

    rdp_hits = [
        r for r in conn_records
        if r.get("id_resp_p") == 3389
    ]

    winrm_hits = [
        r for r in conn_records
        if r.get("id_resp_p") in {5985, 5986}
    ]

    if rdp_hits:
        findings.append(
            Finding(
                rule_id="conn-remote-access",
                description=(
                    f"{len(rdp_hits)} connection(s) observed to "
                    "RDP (TCP/3389)."
                ),
                attack_technique="T1021",
                evidence_refs=[
                    _conn_evidence_ref(r)
                    for r in rdp_hits
                ],
            )
        )

    if winrm_hits:
        ports = sorted({
            r.get("id_resp_p")
            for r in winrm_hits
        })

        findings.append(
            Finding(
                rule_id="conn-winrm",
                description=(
                    f"{len(winrm_hits)} connection(s) observed to "
                    f"Windows Remote Management (WinRM), "
                    f"TCP port(s) {ports}."
                ),
                attack_technique="T1021.006",
                evidence_refs=[
                    _conn_evidence_ref(r)
                    for r in winrm_hits
                ],
            )
        )

    return findings


def evaluate_dce_rpc(dce_rpc_records: list, config: C1Config) -> list:
    """RULE dce-rpc-sensitive-pipe: any DCE/RPC call over a named pipe
    associated with remote service control, scheduled tasks, registry
    access, or server service -- classic PsExec-style remote execution.
    ATT&CK T1021.002 (SMB/Windows Admin Shares) + T1569.002 (Service
    Execution)."""
    findings = []
    hits = [r for r in dce_rpc_records if r.get("named_pipe") in config.sensitive_named_pipes]
    if hits:
        pipes = sorted({r.get("named_pipe") for r in hits})
        findings.append(Finding(
            rule_id="dce-rpc-sensitive-pipe",
            description=(
                f"{len(hits)} DCE/RPC call(s) observed over sensitive named "
                f"pipe(s) {pipes}, consistent with remote service control or "
                "remote execution."
            ),
            attack_technique="T1021.002, T1569.002",
            evidence_refs=[
                {"uid": r.get("uid"), "ts": r.get("ts"), "named_pipe": r.get("named_pipe"),
                 "endpoint": r.get("endpoint"), "operation": r.get("operation")}
                for r in hits
            ],
        ))
    return findings


def evaluate_kerberos(kerberos_records: list, config: C1Config) -> list:
    """RULE kerberos-weak-cipher: TGS/TGT requests using a weak cipher
    -- classic Kerberoasting/overpass-the-hash indicator. ATT&CK T1558
    (Steal or Forge Kerberos Tickets).
    RULE kerberos-auth-failure: a failed Kerberos exchange whose error
    is NOT KDC_ERR_PREAUTH_REQUIRED -- ATT&CK T1558 (left as T1558
    rather than splitting out T1110 Brute Force, since that
    distinction needs a volume/rate threshold this baseline doesn't
    compute).

    KDC_ERR_PREAUTH_REQUIRED is explicitly excluded: RFC 4120 requires
    every KDC to reject a client's first AS-REQ (sent without pre-auth
    data) with exactly this error, so the client can retry with a
    pre-auth timestamp encrypted under its password hash. Every normal
    Kerberos logon produces one of these as a matter of protocol, not
    as a sign of anything wrong -- counting it as a "failure" makes
    this rule fire on ordinary domain traffic. A genuine authentication
    problem (bad password, disabled account, clock skew, ticket
    tampering) surfaces as a different error_msg."""
    findings = []

    weak_cipher_hits = [r for r in kerberos_records if r.get("cipher") in config.weak_kerberos_ciphers]
    if weak_cipher_hits:
        ciphers = sorted({r.get("cipher") for r in weak_cipher_hits})
        findings.append(Finding(
            rule_id="kerberos-weak-cipher",
            description=(
                f"{len(weak_cipher_hits)} Kerberos exchange(s) used a weak "
                f"cipher {ciphers}, consistent with Kerberoasting or "
                "overpass-the-hash activity."
            ),
            attack_technique="T1558",
            evidence_refs=[
                {"uid": r.get("uid"), "ts": r.get("ts"), "client": r.get("client"),
                 "service": r.get("service"), "cipher": r.get("cipher")}
                for r in weak_cipher_hits
            ],
        ))

    failure_hits = [
        r for r in kerberos_records
        if r.get("success") is False and r.get("error_msg") != "KDC_ERR_PREAUTH_REQUIRED"
    ]
    if failure_hits:
        findings.append(Finding(
            rule_id="kerberos-auth-failure",
            description=f"{len(failure_hits)} failed Kerberos authentication exchange(s) observed.",
            attack_technique="T1558",
            evidence_refs=[
                {"uid": r.get("uid"), "ts": r.get("ts"), "client": r.get("client"),
                 "service": r.get("service"), "error_msg": r.get("error_msg")}
                for r in failure_hits
            ],
        ))

    return findings


def evaluate_smb_files(smb_files_records: list, config: C1Config) -> list:
    """RULE smb-admin-share-executable: an executable-extension file
    touched on an administrative share (ADMIN$/C$/IPC$) -- classic
    lateral tool transfer. ATT&CK T1570 (Lateral Tool Transfer) +
    T1021.002 (SMB/Windows Admin Shares)."""
    findings = []
    hits = []
    for r in smb_files_records:
        path = (r.get("path") or "").lower()
        name = (r.get("name") or "").lower()
        on_sensitive_share = any(marker in path for marker in config.sensitive_share_markers)
        is_executable = any(name.endswith(ext) for ext in config.executable_extensions)
        if on_sensitive_share and is_executable:
            hits.append(r)

    if hits:
        findings.append(Finding(
            rule_id="smb-admin-share-executable",
            description=(
                f"{len(hits)} executable file(s) observed on an "
                "administrative SMB share, consistent with lateral tool "
                "transfer."
            ),
            attack_technique="T1570, T1021.002",
            evidence_refs=[
                {"uid": r.get("uid"), "ts": r.get("ts"), "path": r.get("path"),
                 "name": r.get("name"), "action": r.get("action")}
                for r in hits
            ],
        ))
    return findings


def confidence_from_findings(findings: list) -> str:
    """Fixed mapping from finding count to a confidence label -- part of
    the deterministic procedure, not a judgment call made per case."""
    distinct_rules = len({f.rule_id for f in findings})
    if distinct_rules >= 2:
        return "high"
    if distinct_rules == 1:
        return "medium"
    return "low"
