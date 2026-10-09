
"""Tests for the BlueSentinel XDR Alert Builder."""

import pytest

from Engine.detection.models import (
    SecurityEvent,
    DetectionResult,
)
from Engine.detection.alert_builder import AlertBuilder


@pytest.fixture
def builder():
    return AlertBuilder()


@pytest.fixture
def event():
    return SecurityEvent(
        timestamp="2026-10-09T10:00:00Z",
        host="WIN-TEST01",
        os="windows",
        event_type="process_creation",
        user="testuser",
        process="powershell.exe",
        process_id=1234,
        command_line="powershell.exe -enc suspicious_command",
        log_source="Sysmon",
    )


@pytest.fixture
def matched_detection():
    return DetectionResult(
        matched=True,
        rule_id="test-rule-001",
        rule_title="Suspicious PowerShell Execution",
        severity="high",
        description="Suspicious PowerShell command detected.",
        mitre_techniques=["T1059.001"],
        evidence={"command_line": "powershell.exe -enc suspicious_command"},
    )


def test_matched_detection_creates_alert(
    builder, event, matched_detection
):
    alert = builder.build(event, matched_detection)

    assert alert is not None
    assert alert.rule_id == "test-rule-001"
    assert alert.title == "Suspicious PowerShell Execution"
    assert alert.severity == "high"


def test_alert_has_unique_id(builder, event, matched_detection):
    first = builder.build(event, matched_detection)
    second = builder.build(event, matched_detection)

    assert first.alert_id != second.alert_id


def test_alert_contains_event_context(
    builder, event, matched_detection
):
    alert = builder.build(event, matched_detection)

    assert alert.host == event.host
    assert alert.user == event.user
    assert alert.event_type == event.event_type


def test_alert_contains_mitre_techniques(
    builder, event, matched_detection
):
    alert = builder.build(event, matched_detection)

    assert alert.mitre_techniques == ["T1059.001"]


def test_alert_contains_evidence(
    builder, event, matched_detection
):
    alert = builder.build(event, matched_detection)

    assert (
        alert.evidence["command_line"]
        == "powershell.exe -enc suspicious_command"
    )
    assert alert.evidence["log_source"] == "Sysmon"


def test_unmatched_detection_returns_none(builder, event):
    detection = DetectionResult(matched=False)

    assert builder.build(event, detection) is None


def test_invalid_severity_defaults_to_medium(builder, event):
    detection = DetectionResult(
        matched=True,
        rule_id="test-rule-002",
        rule_title="Test Detection",
        severity="unknown",
    )

    alert = builder.build(event, detection)

    assert alert.severity == "medium"


def test_build_batch_returns_only_matched_alerts(
    builder, event, matched_detection
):
    unmatched = DetectionResult(matched=False)

    alerts = builder.build_batch(
        event,
        [matched_detection, unmatched, matched_detection],
    )

    assert len(alerts) == 2
    assert all(alert.rule_id == "test-rule-001" for alert in alerts)


def test_missing_rule_id_raises_error(builder, event):
    detection = DetectionResult(
        matched=True,
        rule_title="Test Detection",
    )

    with pytest.raises(ValueError, match="rule_id"):
        builder.build(event, detection)


def test_missing_rule_title_raises_error(builder, event):
    detection = DetectionResult(
        matched=True,
        rule_id="test-rule-003",
    )

    with pytest.raises(ValueError, match="rule_title"):
        builder.build(event, detection)
