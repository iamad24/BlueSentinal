
import pytest

from Engine.ai_assistant import AIAssistant, PromptBuilder, ResponseFormatter


@pytest.fixture
def assistant():
    return AIAssistant()


@pytest.fixture
def sample_alert():
    return {
        "title": "Suspicious PowerShell execution",
        "description": "Encoded PowerShell command detected",
        "severity": "high",
        "host": "WIN-TEST",
        "user": "testuser",
        "process": "powershell.exe",
        "command_line": "powershell.exe -enc example",
        "mitre_techniques": ["T1059.001"],
    }


def test_analyze_alert_returns_required_fields(assistant, sample_alert):
    result = assistant.analyze_alert(sample_alert)

    assert result["summary"]
    assert result["severity"] == "high"
    assert isinstance(result["findings"], list)
    assert isinstance(result["recommended_actions"], list)
    assert isinstance(result["limitations"], list)


def test_alert_evidence_appears_in_findings(assistant, sample_alert):
    result = assistant.analyze_alert(sample_alert)

    assert any("WIN-TEST" in item for item in result["findings"])
    assert any("powershell.exe" in item for item in result["findings"])


def test_high_severity_prioritizes_review(assistant, sample_alert):
    result = assistant.analyze_alert(sample_alert)

    assert "Prioritize analyst review and follow your incident response procedure." \
        in result["recommended_actions"][0]


def test_low_severity_does_not_get_high_priority_action(assistant, sample_alert):
    sample_alert["severity"] = "low"

    result = assistant.analyze_alert(sample_alert)

    assert not result["recommended_actions"][0].startswith(
        "Prioritize analyst review"
    )


def test_mitre_techniques_are_preserved(assistant, sample_alert):
    result = assistant.analyze_alert(sample_alert)

    assert result["mitre_techniques"] == ["T1059.001"]


def test_unknown_severity_is_handled(assistant):
    result = assistant.analyze_alert({"title": "Test alert"})

    assert result["severity"] == "unknown"


def test_prepare_investigation_builds_messages(assistant, sample_alert):
    result = assistant.prepare_investigation(sample_alert)

    assert "context" in result
    assert "messages" in result
    assert result["messages"][0]["role"] == "system"
    assert result["messages"][1]["role"] == "user"


def test_prompt_builder_rejects_unrecognized_alert():
    builder = PromptBuilder()

    with pytest.raises(ValueError):
        builder.build_context({"unrelated_field": "test"})


def test_response_formatter_normalizes_severity():
    formatter = ResponseFormatter()

    result = formatter.format_response({
        "summary": "Test",
        "severity": "HIGH",
        "confidence": "medium",
    })

    assert result["severity"] == "high"
    assert result["confidence"] == "medium"


def test_response_formatter_handles_invalid_severity():
    formatter = ResponseFormatter()

    result = formatter.format_response({
        "summary": "Test",
        "severity": "extreme",
    })

    assert result["severity"] == "unknown"
