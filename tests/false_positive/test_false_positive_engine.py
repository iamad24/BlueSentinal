
"""Tests for the BlueSentinel False Positive Engine."""

import pytest

from Engine.false_positive.false_positive_engine import (
    FalsePositiveEngine,
    FalsePositiveResult,
)


@pytest.fixture
def engine():
    return FalsePositiveEngine()


def make_alert(
    alert_id="A1",
    timestamp="2026-10-14T10:00:00Z",
    severity="medium",
    rule_id="RULE-001",
    host="WIN-01",
    user="alice",
    event_type="process_creation",
    source_ip="10.0.0.5",
):
    return {
        "alert_id": alert_id,
        "timestamp": timestamp,
        "severity": severity,
        "rule_id": rule_id,
        "title": "Test detection",
        "host": host,
        "user": user,
        "event_type": event_type,
        "source_ip": source_ip,
    }


def test_returns_result_object(engine):
    result = engine.evaluate(make_alert())

    assert isinstance(result, FalsePositiveResult)


def test_normal_alert_is_retained(engine):
    result = engine.evaluate(make_alert())

    assert result.suppressed is False
    assert result.is_false_positive is False


def test_matching_allowlist_rule_suppresses_alert():
    engine = FalsePositiveEngine(
        allowlist=[{"rule_id": "RULE-001", "host": "WIN-01"}]
    )

    result = engine.evaluate(make_alert())

    assert result.suppressed is True
    assert result.is_false_positive is True
    assert result.matched_rule == "allowlist-1"


def test_nonmatching_allowlist_does_not_suppress():
    engine = FalsePositiveEngine(
        allowlist=[{"host": "WIN-OTHER"}]
    )

    result = engine.evaluate(make_alert())

    assert result.suppressed is False


def test_repeated_alert_is_suppressed(engine):
    first = make_alert(alert_id="A1")
    second = make_alert(
        alert_id="A2",
        timestamp="2026-10-14T10:05:00Z",
    )

    assert engine.evaluate(first).suppressed is False

    result = engine.evaluate(second)

    assert result.suppressed is True
    assert result.matched_rule == "duplicate-window"


def test_different_host_is_not_duplicate(engine):
    engine.evaluate(make_alert())

    result = engine.evaluate(
        make_alert(
            alert_id="A2",
            host="WIN-02",
            timestamp="2026-10-14T10:05:00Z",
        )
    )

    assert result.suppressed is False


def test_alert_outside_duplicate_window_is_retained(engine):
    engine.evaluate(make_alert())

    result = engine.evaluate(
        make_alert(
            alert_id="A2",
            timestamp="2026-10-14T10:20:00Z",
        )
    )

    assert result.suppressed is False


def test_critical_alert_bypasses_allowlist():
    engine = FalsePositiveEngine(
        allowlist=[{"rule_id": "RULE-001"}]
    )

    result = engine.evaluate(
        make_alert(severity="critical")
    )

    assert result.suppressed is False
    assert result.is_false_positive is False
    assert "Critical" in result.reason


def test_invalid_timestamp_skips_duplicate_suppression(engine):
    result = engine.evaluate(
        make_alert(timestamp="not-a-timestamp")
    )

    assert result.suppressed is False


def test_zero_window_disables_duplicate_suppression():
    engine = FalsePositiveEngine(duplicate_window_minutes=0)

    engine.evaluate(make_alert())

    result = engine.evaluate(
        make_alert(
            alert_id="A2",
            timestamp="2026-10-14T10:01:00Z",
        )
    )

    assert result.suppressed is False


def test_negative_window_is_rejected():
    with pytest.raises(ValueError):
        FalsePositiveEngine(duplicate_window_minutes=-1)


def test_batch_evaluation():
    engine = FalsePositiveEngine()
    results = engine.evaluate_batch([
        make_alert(alert_id="A1"),
        make_alert(
            alert_id="A2",
            timestamp="2026-10-14T10:01:00Z",
        ),
    ])

    assert len(results) == 2
    assert results[0].suppressed is False
    assert results[1].suppressed is True


def test_result_serializes_to_dictionary(engine):
    result = engine.evaluate(make_alert())
    data = result.to_dict()

    assert data["alert_id"] == "A1"
    assert isinstance(data["factors"], list)
    assert "suppressed" in data


def test_unknown_allowlist_field_is_ignored():
    engine = FalsePositiveEngine(
        allowlist=[{"unknown_field": "value"}]
    )

    result = engine.evaluate(make_alert())

    assert result.suppressed is False
