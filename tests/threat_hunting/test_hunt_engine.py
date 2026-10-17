
"""Unit tests for the threat hunting module."""

import pytest

from ThreatHunting.finding_store import FindingStore
from ThreatHunting.hunt_engine import HuntEngine
from ThreatHunting.hunt_library import (
    get_builtin_hunts,
    get_hunt_by_id,
)


@pytest.fixture
def store():
    return FindingStore()


@pytest.fixture
def engine(store):
    return HuntEngine(finding_store=store)


def test_builtin_hunts_are_available():
    hunts = get_builtin_hunts()
    assert len(hunts) >= 5
    assert all(hunt.get("id") for hunt in hunts)


def test_get_hunt_by_id():
    hunt = get_hunt_by_id("TH-001")
    assert hunt is not None
    assert hunt["name"] == "Suspicious PowerShell Execution"


def test_unknown_hunt_id_returns_none():
    assert get_hunt_by_id("TH-999") is None


def test_detects_suspicious_powershell(engine):
    events = [{
        "event_id": "evt-1",
        "process": "powershell.exe",
        "command_line": "powershell.exe -EncodedCommand QUJD",
        "hostname": "workstation-01",
    }]

    findings = engine.run_hunt(events, "TH-001")

    assert findings
    assert findings[0]["hunt_id"] == "TH-001"
    assert "encodedcommand" in findings[0]["matched_keywords"]
    assert findings[0]["disposition"] == "requires_investigation"


def test_clean_event_does_not_match(engine):
    events = [{
        "event_id": "evt-2",
        "process": "notepad.exe",
        "command_line": "notepad.exe document.txt",
    }]

    assert engine.run_all(events) == []


def test_detects_registry_autorun_path(engine):
    events = [{
        "event_id": "evt-3",
        "registry_path": (
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
        ),
    }]

    findings = engine.run_hunt(events, "TH-004")

    assert len(findings) == 1
    assert findings[0]["hunt_id"] == "TH-004"


def test_unknown_hunt_raises_error(engine):
    with pytest.raises(ValueError):
        engine.run_hunt([], "TH-999")


def test_invalid_events_argument_raises_error(engine):
    with pytest.raises(TypeError):
        engine.run_hunt("not a list")


def test_finding_store_add_get_and_delete(store):
    finding = {
        "finding_id": "finding-1",
        "severity": "high",
        "status": "new",
    }

    store.add(finding)
    assert store.get("finding-1")["severity"] == "high"
    assert store.delete("finding-1") is True
    assert store.get("finding-1") is None


def test_finding_store_rejects_missing_id(store):
    with pytest.raises(ValueError):
        store.add({"severity": "high"})


def test_finding_store_status_update(store):
    store.add({
        "finding_id": "finding-2",
        "status": "new",
    })

    updated = store.update_status("finding-2", "investigating")

    assert updated["status"] == "investigating"
    assert store.update_status("missing", "closed") is None


def test_finding_store_severity_filter(store):
    store.add({"finding_id": "f1", "severity": "high"})
    store.add({"finding_id": "f2", "severity": "low"})

    results = store.list_by_severity("HIGH")

    assert len(results) == 1
    assert results[0]["finding_id"] == "f1"


def test_finding_does_not_expose_mutable_internal_data(store):
    finding = {"finding_id": "f3", "evidence": {"host": "pc-01"}}
    store.add(finding)

    returned = store.get("f3")
    returned["evidence"]["host"] = "modified"

    assert store.get("f3")["evidence"]["host"] == "pc-01"


def test_multiple_events_create_separate_findings(engine):
    events = [
        {
            "event_id": "evt-a",
            "command_line": "powershell.exe -EncodedCommand ABC",
        },
        {
            "event_id": "evt-b",
            "command_line": "powershell.exe -EncodedCommand XYZ",
        },
    ]

    findings = engine.run_hunt(events, "TH-001")

    assert len(findings) == 2
    assert findings[0]["finding_id"] != findings[1]["finding_id"]
