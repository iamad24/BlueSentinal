
"""Unit tests for the BlueSentinel Risk Scoring Engine."""

import pytest

from Engine.risk_scoring.risk_engine import RiskEngine, RiskAssessment


@pytest.fixture
def engine():
    return RiskEngine()


@pytest.fixture
def high_alert():
    return {
        "alert_id": "alert-001",
        "severity": "high",
        "host": "WIN-01",
    }


def test_returns_risk_assessment(engine, high_alert):
    result = engine.assess(high_alert)

    assert isinstance(result, RiskAssessment)


def test_high_severity_base_score(engine, high_alert):
    result = engine.assess(high_alert)

    assert result.risk_score == 65
    assert result.risk_level == "high"


def test_critical_severity_score(engine):
    result = engine.assess({"severity": "critical"})

    assert result.risk_score == 80
    assert result.risk_level == "critical"


def test_low_severity_score(engine):
    result = engine.assess({"severity": "low"})

    assert result.risk_score == 20
    assert result.risk_level == "low"


def test_correlation_increases_score(engine, high_alert):
    result = engine.assess(high_alert, correlated=True)

    assert result.risk_score == 75
    assert result.risk_level == "high"


def test_malicious_intelligence_increases_score(engine, high_alert):
    result = engine.assess(
        high_alert,
        threat_intel={"malicious": True},
    )

    assert result.risk_score == 75


def test_missing_intelligence_does_not_block_scoring(
    engine, high_alert
):
    result = engine.assess(high_alert, threat_intel=None)

    assert result.risk_score == 65
    assert any("unavailable" in f for f in result.factors)


def test_clean_intelligence_adds_no_bonus(engine, high_alert):
    result = engine.assess(
        high_alert,
        threat_intel={"malicious": False, "malicious_count": 0},
    )

    assert result.risk_score == 65


def test_score_never_exceeds_100(engine):
    result = engine.assess(
        {"alert_id": "alert-002", "severity": "critical"},
        correlated=True,
        threat_intel={"malicious": True},
    )

    assert result.risk_score == 100
    assert result.risk_level == "critical"


def test_unknown_severity_uses_safe_default(engine):
    result = engine.assess({"severity": "unexpected"})

    assert result.risk_score == 5
    assert result.risk_level == "low"


def test_batch_assessment(engine):
    results = engine.assess_batch([
        {"alert_id": "A1", "severity": "low"},
        {"alert_id": "A2", "severity": "critical"},
    ])

    assert len(results) == 2
    assert results[0].alert_id == "A1"
    assert results[1].alert_id == "A2"
    assert results[0].risk_score < results[1].risk_score


def test_result_serializes_to_dictionary(engine, high_alert):
    result = engine.assess(high_alert)
    data = result.to_dict()

    assert data["alert_id"] == "alert-001"
    assert isinstance(data["risk_score"], int)
    assert isinstance(data["factors"], list)


def test_invalid_threat_intelligence_type_raises_error(
    engine, high_alert
):
    with pytest.raises(TypeError):
        engine.assess(high_alert, threat_intel="unknown")


def test_negative_malicious_count_raises_error(engine, high_alert):
    with pytest.raises(ValueError):
        engine.assess(
            high_alert,
            threat_intel={"malicious_count": -1},
        )
