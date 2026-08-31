"""Matches docs/risk-scoring.md's worked examples exactly — if you change
the formula, update both.
"""

import pytest

from app.core.enums import FindingSeverity, RiskSeverityBand
from app.models.finding import Finding
from app.services.risk_engine import band_for_score, compute_finding_risk_score, compute_scan_risk


def _finding(severity, exposure, exploitability, confidence) -> Finding:
    return Finding(
        module="test",
        title="t",
        severity=severity,
        exposure=exposure,
        exploitability=exploitability,
        confidence=confidence,
    )


def test_weights_sum_to_one():
    from app.services.risk_engine import WEIGHT_EXPLOITABILITY, WEIGHT_EXPOSURE, WEIGHT_SEVERITY

    assert WEIGHT_SEVERITY + WEIGHT_EXPOSURE + WEIGHT_EXPLOITABILITY == pytest.approx(1.0)


def test_missing_hsts_example():
    f = _finding(FindingSeverity.medium, 1.0, 0.3, 0.9)
    assert compute_finding_risk_score(f) == pytest.approx(48.6)
    assert band_for_score(48.6) == RiskSeverityBand.medium


def test_expired_tls_certificate_example():
    f = _finding(FindingSeverity.critical, 1.0, 0.5, 1.0)
    assert compute_finding_risk_score(f) == pytest.approx(85.0)
    assert band_for_score(85.0) == RiskSeverityBand.critical


def test_missing_csp_example():
    f = _finding(FindingSeverity.low, 1.0, 0.2, 0.8)
    assert compute_finding_risk_score(f) == pytest.approx(30.8)
    assert band_for_score(30.8) == RiskSeverityBand.low


def test_confidence_dampens_score_heavily():
    f = _finding(FindingSeverity.critical, 1.0, 1.0, 0.1)
    assert compute_finding_risk_score(f) == pytest.approx(10.0)
    assert band_for_score(10.0) == RiskSeverityBand.minimal


def test_maximum_possible_score():
    f = _finding(FindingSeverity.critical, 1.0, 1.0, 1.0)
    assert compute_finding_risk_score(f) == 100.0
    assert band_for_score(100.0) == RiskSeverityBand.critical


def test_zero_confidence_always_zeroes_score_regardless_of_severity():
    f = _finding(FindingSeverity.critical, 1.0, 1.0, 0.0)
    assert compute_finding_risk_score(f) == 0.0


def test_score_never_exceeds_bounds_even_with_out_of_range_inputs():
    f = _finding(FindingSeverity.critical, 5.0, -3.0, 2.0)  # deliberately out of [0,1]
    score = compute_finding_risk_score(f)
    assert 0.0 <= score <= 100.0


def test_info_severity_findings_excluded_from_scan_aggregate():
    findings = [
        _finding(FindingSeverity.info, 1.0, 0.0, 1.0),
        _finding(FindingSeverity.info, 1.0, 0.0, 1.0),
    ]
    score, band = compute_scan_risk(findings)
    assert score == 0.0
    assert band == RiskSeverityBand.minimal


def test_scan_aggregate_is_max_of_relevant_findings():
    findings = [
        _finding(FindingSeverity.info, 1.0, 0.0, 1.0),
        _finding(FindingSeverity.low, 1.0, 0.2, 0.8),  # 30.8
        _finding(FindingSeverity.critical, 1.0, 0.5, 1.0),  # 85.0
        _finding(FindingSeverity.medium, 1.0, 0.3, 0.9),  # 48.6
    ]
    score, band = compute_scan_risk(findings)
    assert score == pytest.approx(85.0)
    assert band == RiskSeverityBand.critical


def test_empty_findings_list_yields_minimal():
    score, band = compute_scan_risk([])
    assert score == 0.0
    assert band == RiskSeverityBand.minimal


@pytest.mark.parametrize(
    "score,expected_band",
    [
        (0.0, RiskSeverityBand.minimal),
        (19.99, RiskSeverityBand.minimal),
        (20.0, RiskSeverityBand.low),
        (39.99, RiskSeverityBand.low),
        (40.0, RiskSeverityBand.medium),
        (59.99, RiskSeverityBand.medium),
        (60.0, RiskSeverityBand.high),
        (79.99, RiskSeverityBand.high),
        (80.0, RiskSeverityBand.critical),
        (100.0, RiskSeverityBand.critical),
    ],
)
def test_band_boundaries(score, expected_band):
    assert band_for_score(score) == expected_band


def test_finding_severity_and_risk_severity_band_are_distinct_enums():
    assert FindingSeverity is not RiskSeverityBand
    assert "info" in {s.value for s in FindingSeverity}
    assert "info" not in {b.value for b in RiskSeverityBand}
    assert "minimal" in {b.value for b in RiskSeverityBand}
    assert "minimal" not in {s.value for s in FindingSeverity}
