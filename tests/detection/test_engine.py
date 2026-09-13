from datetime import datetime, timezone

from Engine.detection.engine import DetectionEngine
from Engine.detection.models import SecurityEvent


def test_engine_detects_aad_internals():
    """
    Verify that the DetectionEngine detects
    AADInternals PowerShell activity.
    """

    event = SecurityEvent(
        timestamp=datetime.now(timezone.utc),
        host="TEST-PC",
        os="windows",
        event_type="powershell_script",
        log_source="windows",
        raw_event={
            "ScriptBlockText": "Get-AADIntTenantDetails"
        },
    )

    engine = DetectionEngine()

    results = engine.detect(event)

    assert results, "Expected at least one detection."

    rule_titles = [
        result.rule_title
        for result in results
    ]

    assert (
        "AADInternals PowerShell Cmdlets Execution - PsScript"
        in rule_titles
    )


def test_engine_does_not_detect_benign_powershell():
    """
    Verify that a benign PowerShell command
    does not trigger the AADInternals rule.
    """

    event = SecurityEvent(
        timestamp=datetime.now(timezone.utc),
        host="TEST-PC",
        os="windows",
        event_type="powershell_script",
        log_source="windows",
        raw_event={
            "ScriptBlockText": "Get-Process"
        },
    )

    engine = DetectionEngine()

    results = engine.detect(event)

    rule_titles = [
        result.rule_title
        for result in results
    ]

    assert (
        "AADInternals PowerShell Cmdlets Execution - PsScript"
        not in rule_titles
    )


def test_engine_filters_inapplicable_rules():
    """
    Verify that rules belonging to unrelated
    telemetry sources are not evaluated as matches.

    A Windows PowerShell event should not trigger
    a Zeek RDP rule merely because of a NOT condition.
    """

    event = SecurityEvent(
        timestamp=datetime.now(timezone.utc),
        host="TEST-PC",
        os="windows",
        event_type="powershell_script",
        log_source="windows",
        raw_event={
            "ScriptBlockText": "Get-AADIntTenantDetails"
        },
    )

    engine = DetectionEngine()

    results = engine.detect(event)

    rule_titles = [
        result.rule_title
        for result in results
    ]

    assert (
        "Publicly Accessible RDP Service"
        not in rule_titles
    )


def test_engine_returns_detection_results():
    """
    Verify that every returned result is a
    DetectionResult and represents a matched detection.
    """

    event = SecurityEvent(
        timestamp=datetime.now(timezone.utc),
        host="TEST-PC",
        os="windows",
        event_type="powershell_script",
        log_source="windows",
        raw_event={
            "ScriptBlockText": "Get-AADIntTenantDetails"
        },
    )

    engine = DetectionEngine()

    results = engine.detect(event)

    assert results

    for result in results:
        assert result.matched is True
        assert result.rule_id
        assert result.rule_title