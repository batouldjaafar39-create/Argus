from __future__ import annotations

import re
from dataclasses import dataclass

from .ledger import EvidenceLedger
from .report import ArgusReport


# Matches:
#   [E001]
#   [E002]
#   [E123]
#
# It intentionally does not care what comes before or after the citation.
_EVIDENCE_REF_RE = re.compile(r"\[E\d{3}\]")


@dataclass(frozen=True)
class VerificationResult:
    clean: bool
    violations: list[str]


def _extract_citations(text: str) -> set[str]:
    """
    Extract machine-checkable evidence IDs from arbitrary report text.

    Examples:
        "Observed traffic [E001]"
            -> {"E001"}

        "T1011 [E001]"
            -> {"E001"}

        "E001 [T1011]"
            -> {"E001"}

        "Possible SMB activity [E001] [E002]"
            -> {"E001", "E002"}
    """
    if not isinstance(text, str):
        return set()

    return {
        match.group(0)[1:-1]
        for match in _EVIDENCE_REF_RE.finditer(text)
    }


def referenced_ids(report: ArgusReport) -> set[str]:
    """
    Return every evidence ID referenced anywhere in the report.
    """
    refs = set(report.evidence)

    texts = [
        report.finding,
        report.interpretation,
        *report.affected_entities,
        *report.attack_technique_mapping,
    ]

    for text in texts:
        refs.update(_extract_citations(text))

    return refs


def verify_report(
    report: ArgusReport,
    ledger: EvidenceLedger,
) -> VerificationResult:

    violations: list[str] = []

    successful = ledger.successful_ids()

    # -------------------------------------------------------------
    # 1. Validate explicit evidence[] IDs
    # -------------------------------------------------------------

    explicit = set(report.evidence)

    bad_explicit = sorted(
        explicit - successful
    )

    if bad_explicit:
        violations.append(
            "Evidence field contains unavailable or failed "
            f"evidence IDs: {bad_explicit}"
        )

    # -------------------------------------------------------------
    # 2. Validate every citation appearing in the report
    # -------------------------------------------------------------

    refs = referenced_ids(report)

    bad_refs = sorted(
        refs - successful
    )

    if bad_refs:
        violations.append(
            "Report contains citations to unavailable or failed "
            f"evidence IDs: {bad_refs}"
        )

    # -------------------------------------------------------------
    # 3. Every factual field must contain an evidence citation
    # -------------------------------------------------------------

    factual_fields = (
        ("finding", [report.finding]),
        ("interpretation", [report.interpretation]),
        ("affected_entities", report.affected_entities),
        ("attack_technique_mapping", report.attack_technique_mapping),
    )

    for field_name, values in factual_fields:

        for value in values:

            if not value:
                continue

            citations = _extract_citations(value)

            if not citations:
                violations.append(
                    f"Field '{field_name}' contains a factual "
                    f"statement without an [E###] citation: "
                    f"{value!r}"
                )

    # -------------------------------------------------------------
    # 4. A substantive report must declare its evidence
    # -------------------------------------------------------------

    if not report.evidence and (
        report.finding
        or report.interpretation
    ):
        violations.append(
            "Report has substantive findings but no evidence "
            "IDs in the evidence field."
        )

    return VerificationResult(
        clean=not violations,
        violations=violations,
    )


def sanitize_unsupported_report(
    report: ArgusReport,
    ledger: EvidenceLedger,
    violations: list[str],
) -> ArgusReport:
    """
    Produce a conservative fallback after the revision budget
    is exhausted.

    We do not attempt semantic rewriting deterministically.
    Unsupported claims are removed rather than invented.
    """

    valid = sorted(
        set(report.evidence)
        & ledger.successful_ids()
    )

    return ArgusReport(
        finding="No fully evidence-grounded finding could be finalized.",
        affected_entities=[],
        evidence=valid,
        interpretation=(
            "The analyst report contained claims that could not "
            "be deterministically verified against the retrieved "
            "evidence."
        ),
        attack_technique_mapping=[],
        confidence="low",
        limitations=(
            "Argus removed the unsupported final claims after "
            "the revision budget was exhausted. "
            "Verification violations: "
            + "; ".join(violations)
        ),
    )