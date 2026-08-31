"""Deterministic risk scoring. See docs/risk-scoring.md for the full
specification with worked examples — this module must match that document
exactly; if you change one, change the other.
"""

from app.core.enums import FindingSeverity, RiskSeverityBand
from app.models.finding import Finding

SEVERITY_SCORES: dict[FindingSeverity, float] = {
    FindingSeverity.info: 0.0,
    FindingSeverity.low: 0.25,
    FindingSeverity.medium: 0.5,
    FindingSeverity.high: 0.75,
    FindingSeverity.critical: 1.0,
}

WEIGHT_SEVERITY = 0.5
WEIGHT_EXPOSURE = 0.2
WEIGHT_EXPLOITABILITY = 0.3
assert abs((WEIGHT_SEVERITY + WEIGHT_EXPOSURE + WEIGHT_EXPLOITABILITY) - 1.0) < 1e-9

_BAND_THRESHOLDS: list[tuple[float, RiskSeverityBand]] = [
    (80.0, RiskSeverityBand.critical),
    (60.0, RiskSeverityBand.high),
    (40.0, RiskSeverityBand.medium),
    (20.0, RiskSeverityBand.low),
    (0.0, RiskSeverityBand.minimal),
]


def _clamp01(value: float) -> float:
    return max(0.0, min(1.0, value))


def band_for_score(score: float) -> RiskSeverityBand:
    for threshold, band in _BAND_THRESHOLDS:
        if score >= threshold:
            return band
    return RiskSeverityBand.minimal


def compute_finding_risk_score(finding: Finding) -> float:
    """Bounded to [0, 100] by construction: WEIGHT_* sum to 1.0, each norm
    is clamped to [0, 1], and confidence (also clamped) is applied as a
    final multiplicative scale — so this can never exceed 100 regardless
    of input, and confidence=0 always yields exactly 0.
    """
    severity_norm = SEVERITY_SCORES[finding.severity]
    exposure_norm = _clamp01(finding.exposure)
    exploitability_norm = _clamp01(finding.exploitability)
    confidence = _clamp01(finding.confidence)

    base_score = (
        WEIGHT_SEVERITY * severity_norm
        + WEIGHT_EXPOSURE * exposure_norm
        + WEIGHT_EXPLOITABILITY * exploitability_norm
    ) * 100

    return round(base_score * confidence, 2)


def compute_scan_risk(findings: list[Finding]) -> tuple[float, RiskSeverityBand]:
    """Aggregates a scan's findings into one (score, band) pair.

    Informational findings (severity=info — e.g. "N DNS records
    enumerated", "technology fingerprint completed") are excluded from
    the aggregate: they represent module bookkeeping/observations, not
    issues, and including them would put a floor under every scan's score
    purely from exposure weighting even when nothing was actually wrong.
    They still get an individual score if computed directly via
    compute_finding_risk_score for transparency in a report's technical
    appendix — they just don't move the scan-level needle.

    Aggregation is max() over the remaining findings: a scan's risk is at
    least as bad as its single worst finding. This is a deliberately
    simple v1 choice — it doesn't yet account for volume (e.g. ten medium
    findings vs. one) — documented as a known limitation in
    docs/risk-scoring.md rather than solved with an untested heuristic.
    """
    relevant = [f for f in findings if f.severity != FindingSeverity.info]
    if not relevant:
        return 0.0, RiskSeverityBand.minimal

    score = max(compute_finding_risk_score(f) for f in relevant)
    return score, band_for_score(score)
