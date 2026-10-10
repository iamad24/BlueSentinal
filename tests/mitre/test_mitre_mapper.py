
"""Unit tests for the BlueSentinel MITRE ATT&CK Mapper."""

import pytest

from Engine.mitre.mitre_mapper import (
    MitreAttackMapper,
    MitreMapping,
)


@pytest.fixture
def mapper():
    return MitreAttackMapper()


def test_known_technique_is_mapped(mapper):
    result = mapper.map_technique("T1059.001")

    assert isinstance(result, MitreMapping)
    assert result.technique_id == "T1059.001"
    assert result.technique_name == "PowerShell"
    assert "Execution" in result.tactics
    assert result.known is True


def test_technique_id_is_normalized(mapper):
    result = mapper.map_technique("  t1059.001  ")

    assert result.technique_id == "T1059.001"
    assert result.known is True


def test_unknown_technique_is_preserved(mapper):
    result = mapper.map_technique("T9999")

    assert result.technique_id == "T9999"
    assert result.technique_name == "Unknown technique"
    assert result.tactics == []
    assert result.known is False
    assert result.url is None


def test_multiple_techniques_are_mapped(mapper):
    results = mapper.map_techniques(
        ["T1059.001", "T1003.001"]
    )

    assert len(results) == 2
    assert results[0].technique_name == "PowerShell"
    assert results[1].technique_name == "LSASS Memory"


def test_duplicate_techniques_are_removed(mapper):
    results = mapper.map_techniques(
        ["T1059.001", "T1059.001", "t1059.001"]
    )

    assert len(results) == 1


def test_detection_dictionary_is_mapped(mapper):
    detection = {
        "rule_id": "test-rule",
        "mitre_techniques": ["T1059.001"],
    }

    results = mapper.map_detection(detection)

    assert len(results) == 1
    assert results[0].technique_name == "PowerShell"


def test_alert_dictionary_is_mapped(mapper):
    alert = {
        "alert_id": "alert-001",
        "mitre_techniques": ["T1547.001"],
    }

    results = mapper.map_alert(alert)

    assert len(results) == 1
    assert (
        results[0].technique_name
        == "Registry Run Keys / Startup Folder"
    )


def test_empty_technique_list_returns_empty_list(mapper):
    assert mapper.map_techniques([]) == []


def test_empty_technique_id_raises_error(mapper):
    with pytest.raises(ValueError):
        mapper.map_technique("")


def test_non_string_technique_id_raises_error(mapper):
    with pytest.raises(TypeError):
        mapper.map_technique(123)


def test_custom_catalogue_can_be_used():
    custom_catalogue = {
        "T1234": {
            "name": "Example Technique",
            "tactics": ["Discovery"],
            "url": "https://example.com/technique",
        }
    }

    mapper = MitreAttackMapper(catalogue=custom_catalogue)
    result = mapper.map_technique("T1234")

    assert result.technique_name == "Example Technique"
    assert result.tactics == ["Discovery"]


def test_mapping_serializes_to_dictionary(mapper):
    result = mapper.map_technique("T1082")
    data = result.to_dict()

    assert data["technique_id"] == "T1082"
    assert data["technique_name"] == "System Information Discovery"
    assert isinstance(data["tactics"], list)
