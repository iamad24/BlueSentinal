from Parser.normalizer import LogNormalizer
from Parser.parser import LogParser


def test_parser_normalizer_powershell_flow():
    """
    Verify the complete raw-event parsing and normalization
    flow for a PowerShell event.
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

    parser = LogParser()
    normalizer = LogNormalizer()

    # Step 1: Parse raw telemetry
    parsed_event = parser.parse(raw_event)

    # Step 2: Normalize raw telemetry
    event = normalizer.normalize(
        parsed_event.raw_event
    )

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

    assert event.raw_event == raw_event


def test_parser_normalizer_network_flow():
    """
    Verify the complete parsing and normalization flow
    for a network event.
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

    parser = LogParser()
    normalizer = LogNormalizer()

    parsed_event = parser.parse(raw_event)

    event = normalizer.normalize(
        parsed_event.raw_event
    )

    assert event.host == "WIN-PC01"
    assert event.os == "windows"
    assert event.event_type == "network_connection"

    assert event.source_ip == "192.168.1.10"
    assert event.source_port == 49152

    assert event.destination_ip == "8.8.8.8"
    assert event.destination_port == 443

    assert event.protocol == "TCP"


def test_parser_normalizer_preserves_raw_event():
    """
    Verify that the original telemetry is preserved
    after parsing and normalization.
    """

    raw_event = {
        "timestamp": "2026-09-25T12:10:00Z",
        "Computer": "WIN-PC01",
        "EventID": 4104,
        "ScriptBlockText": "Get-Process",
    }

    parser = LogParser()
    normalizer = LogNormalizer()

    parsed_event = parser.parse(raw_event)

    normalized_event = normalizer.normalize(
        parsed_event.raw_event
    )

    assert normalized_event.raw_event == raw_event