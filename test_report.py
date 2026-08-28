import pytest
from pydantic import ValidationError

from src.C3.report import FinalReport


def _valid_report(**overrides):
    base = dict(
        finding="Suspicious Kerberos ticket request observed.",
        affected_entities=["10.0.0.1"],
        evidence=["kerberos.log uid=K1, success=false"],
        interpretation="Possible kerberoasting attempt.",
        attack_technique_mapping=["T1558.003"],
        confidence="medium",
        limitations="Single log source only.",
    )
    base.update(overrides)
    return base


def test_valid_report_passes():
    report = FinalReport.model_validate(_valid_report())
    assert report.confidence == "medium"
    assert report.affected_entities == ["10.0.0.1"]


def test_defaults_applied_for_missing_optional_lists():
    report = FinalReport.model_validate(
        {
            "finding": "x",
            "interpretation": "y",
            "confidence": "low",
            "limitations": "z",
        }
    )
    assert report.affected_entities == []
    assert report.evidence == []
    assert report.attack_technique_mapping == []


def test_missing_finding_rejected():
    with pytest.raises(ValidationError):
        FinalReport.model_validate(_valid_report(finding=None))


def test_empty_finding_rejected():
    with pytest.raises(ValidationError):
        FinalReport.model_validate(_valid_report(finding=""))


def test_missing_confidence_rejected():
    bad = _valid_report()
    del bad["confidence"]
    with pytest.raises(ValidationError):
        FinalReport.model_validate(bad)


def test_invalid_confidence_value_rejected():
    with pytest.raises(ValidationError):
        FinalReport.model_validate(_valid_report(confidence="extremely_sure"))


def test_missing_interpretation_rejected():
    bad = _valid_report()
    del bad["interpretation"]
    with pytest.raises(ValidationError):
        FinalReport.model_validate(bad)


def test_missing_limitations_rejected():
    bad = _valid_report()
    del bad["limitations"]
    with pytest.raises(ValidationError):
        FinalReport.model_validate(bad)


def test_extra_fields_ignored_not_rejected():
    report = FinalReport.model_validate(_valid_report(unexpected_field="should be dropped"))
    assert not hasattr(report, "unexpected_field")


def test_empty_technique_mapping_allowed():
    report = FinalReport.model_validate(_valid_report(attack_technique_mapping=[]))
    assert report.attack_technique_mapping == []


def test_non_list_evidence_rejected():
    with pytest.raises(ValidationError):
        FinalReport.model_validate(_valid_report(evidence="just a string, not a list"))