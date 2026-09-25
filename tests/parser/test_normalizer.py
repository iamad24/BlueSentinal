from datetime import datetime, timezone

from Parser.normalizer import LogNormalizer


def test_normalize_powershell_event():
    """
    Verify that a Windows PowerShell event is normalized
    correctly.
    """

    raw_event = {
        "TimeCreated": "2026-09-25T12:00:00Z",
        "Computer": "WIN-PC01",
        "EventID": 4104,
        "UserName": "TEST\\admin",
        "Image": (
            "C:\\Windows\\System32\\"
            "WindowsPowerShell\\v1.0\\powershell.exe"
        ),
        "ProcessId": 1234,
        "CommandLine": (
            'powershell.exe -Command '
            '"Get-AADIntTenantDetails"'
        ),
        "ScriptBlockText": "Get-AADIntTenantDetails",
    }

    normalizer = LogNormalizer()

    event = normalizer.normalize(raw_event)

    assert event.host == "WIN-PC01"
    assert event.os == "windows"
    assert event.event_type == "powershell_script"
    assert event.log_source == "windows"

    assert event.user == "TEST\\admin"
    assert event.process.endswith("powershell.exe")
    assert event.process_id == 1234

    assert (
        event.script_block_text
        == "Get-AADIntTenantDetails"
    )

    assert (
        event.command_line
        == 'powershell.exe -Command '
        '"Get-AADIntTenantDetails"'
    )

    assert event.raw_event == raw_event


def test_normalize_network_event():
    """
    Verify that network-specific fields are normalized
    when they are actually present.
    """

    raw_event = {
        "timestamp": "2026-09-25T12:05:00Z",
        "host": "WIN-PC01",
        "os": "windows",
        "event_type": "network_connection",
        "log_source": "windows",

        "SourceIp": "192.168.1.10",
        "SourcePort": 49152,
        "DestinationIp": "8.8.8.8",
        "DestinationPort": 443,
        "Protocol": "TCP",
    }

    normalizer = LogNormalizer()

    event = normalizer.normalize(raw_event)

    assert event.host == "WIN-PC01"
    assert event.os == "windows"
    assert event.event_type == "network_connection"

    assert event.source_ip == "192.168.1.10"
    assert event.source_port == 49152

    assert event.destination_ip == "8.8.8.8"
    assert event.destination_port == 443

    assert event.protocol == "TCP"


def test_event_without_network_fields():
    """
    Verify that events without network information
    are still normalized correctly.
    """

    raw_event = {
        "timestamp": "2026-09-25T12:10:00Z",
        "Computer": "WIN-PC01",
        "EventID": 4104,
        "ScriptBlockText": "Get-Process",
    }

    normalizer = LogNormalizer()

    event = normalizer.normalize(raw_event)

    assert event.host == "WIN-PC01"
    assert event.os == "windows"
    assert event.event_type == "powershell_script"

    assert event.source_ip is None
    assert event.destination_ip is None


def test_timestamp_is_normalized():
    """
    Verify that an ISO timestamp is converted into
    a timezone-aware datetime.
    """

    raw_event = {
        "timestamp": "2026-09-25T12:15:00Z",
        "host": "TEST-PC",
        "event_type": "powershell_script",
        "ScriptBlockText": "Get-Process",
    }

    normalizer = LogNormalizer()

    event = normalizer.normalize(raw_event)

    assert isinstance(
        event.timestamp,
        datetime,
    )

    assert event.timestamp.tzinfo is not None