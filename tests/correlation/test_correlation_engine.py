
"""Unit tests for the BlueSentinel Correlation Engine."""

import pytest

from Engine.correlation.correlation_engine import (
    CorrelationEngine,
    CorrelationGroup,
)


@pytest.fixture
def engine():
    return CorrelationEngine(window_minutes=30)


def make_alert(
    alert_id,
    timestamp,
    host="WIN-01",
    user="analyst",
    severity="medium",
    evidence=None,
    source_ip=None,
):
    return {
        "alert_id": alert_id,
        "timestamp": timestamp,
        "host": host,
        "user": user,
        "severity": severity,
        "evidence": evidence or {},
        "source_ip": source_ip,
    }


def test_same_host_alerts_are_correlated(engine):
    alerts = [
        make_alert("A1", "2026-10-09T10:00:00Z"),
        make_alert("A2", "2026-10-09T10:10:00Z"),
    ]

    groups = engine.correlate(alerts)

    assert len(groups) == 1
    assert set(groups[0].alert_ids) == {"A1", "A2"}
    assert "Shared host: WIN-01" in groups[0].reasons


def test_different_hosts_and_users_are_not_correlated(engine):
    alerts = [
        make_alert(
            "A1",
            "2026-10-09T10:00:00Z",
            host="WIN-01",
            user="alice",
        ),
        make_alert(
            "A2",
            "2026-10-09T10:10:00Z",
            host="WIN-02",
            user="bob",
        ),
    ]

    assert engine.correlate(alerts) == []


def test_alerts_outside_window_are_not_correlated(engine):
    alerts = [
        make_alert("A1", "2026-10-09T10:00:00Z"),
        make_alert("A2", "2026-10-09T10:45:00Z"),
    ]

    assert engine.correlate(alerts) == []


def test_shared_indicator_correlates_alerts(engine):
    alerts = [
        make_alert(
            "A1",
            "2026-10-09T10:00:00Z",
            host="WIN-01",
            user="alice",
            evidence={"domains": ["suspicious.example"]},
        ),
        make_alert(
            "A2",
            "2026-10-09T10:05:00Z",
            host="WIN-02",
            user="bob",
            evidence={"domains": ["suspicious.example"]},
        ),
    ]

    groups = engine.correlate(alerts)

    assert len(groups) == 1
    assert any(
        "suspicious.example" in reason
        for reason in groups[0].reasons
    )


def test_group_uses_highest_severity(engine):
    alerts = [
        make_alert(
            "A1", "2026-10-09T10:00:00Z", severity="low"
        ),
        make_alert(
            "A2", "2026-10-09T10:05:00Z", severity="critical"
        ),
    ]

    groups = engine.correlate(alerts)

    assert len(groups) == 1
    assert groups[0].severity == "critical"


def test_invalid_timestamps_are_skipped(engine):
    alerts = [
        make_alert("A1", "not-a-timestamp"),
        make_alert("A2", "2026-10-09T10:05:00Z"),
    ]

    assert engine.correlate(alerts) == []


def test_empty_input_returns_empty_list(engine):
    assert engine.correlate([]) == []


def test_single_alert_does_not_create_group(engine):
    alerts = [
        make_alert("A1", "2026-10-09T10:00:00Z"),
    ]

    assert engine.correlate(alerts) == []


def test_invalid_window_raises_error():
    with pytest.raises(ValueError):
        CorrelationEngine(window_minutes=0)


def test_correlation_group_serializes_to_dict():
    group = CorrelationGroup(
        alert_ids=["A1", "A2"],
        hosts=["WIN-01"],
        users=["alice"],
        severity="high",
        reasons=["Shared host: WIN-01"],
    )

    result = group.to_dict()

    assert result["alert_ids"] == ["A1", "A2"]
    assert result["severity"] == "high"
    assert result["correlation_id"]
