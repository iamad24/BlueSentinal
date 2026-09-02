from datetime import datetime, timezone
from pathlib import Path

from Engine.detection.models import SecurityEvent
from Engine.detection.rule_loader import SigmaRuleLoader
from Engine.detection.evaluator import SigmaEvaluator


def create_event(script_text: str) -> SecurityEvent:
    return SecurityEvent(
        timestamp=datetime.now(timezone.utc),
        host="TEST-PC",
        os="windows",
        event_type="powershell_script",
        log_source="windows",
        raw_event={
            "ScriptBlockText": script_text
        }
    )


def load_aadinternals_rule():
    project_root = Path(__file__).resolve().parents[2]

    rule_path = (
        project_root
        / "Sigma_rules"
        / "sigma"
        / "rules"
        / "windows"
        / "powershell"
        / "powershell_script"
        / "posh_ps_aadinternals_cmdlets_execution.yml"
    )

    loader = SigmaRuleLoader()

    return loader.load_rule(rule_path)


def test_aadinternals_rule_matches_malicious_event():
    rule = load_aadinternals_rule()

    assert rule is not None

    event = create_event(
        "Get-AADIntTenantDetails"
    )

    evaluator = SigmaEvaluator(rule)
    result = evaluator.evaluate(event)

    assert result.matched is True
    assert result.rule_id == "91e69562-2426-42ce-a647-711b8152ced6"
    assert result.severity == "HIGH"


def test_aadinternals_rule_does_not_match_benign_event():
    rule = load_aadinternals_rule()

    assert rule is not None

    event = create_event(
        "Get-Process"
    )

    evaluator = SigmaEvaluator(rule)
    result = evaluator.evaluate(event)

    assert result.matched is False

def load_alternate_powershell_rule():
    project_root = Path(__file__).resolve().parents[2]

    rule_path = (
        project_root
        / "Sigma_rules"
        / "sigma"
        / "rules"
        / "windows"
        / "powershell"
        / "powershell_module"
        / "posh_pm_alternate_powershell_hosts.yml"
    )

    loader = SigmaRuleLoader()

    return loader.load_rule(rule_path)


def create_module_event(context_info: str, payload: str = "") -> SecurityEvent:
    return SecurityEvent(
        timestamp=datetime.now(timezone.utc),
        host="TEST-PC",
        os="windows",
        event_type="powershell_module",
        log_source="windows",
        raw_event={
            "ContextInfo": context_info,
            "Payload": payload
        }
    )


def test_alternate_powershell_rule_matches():
    rule = load_alternate_powershell_rule()

    assert rule is not None

    event = create_module_event(
        context_info="Microsoft.PowerShell profile loaded"
    )

    evaluator = SigmaEvaluator(rule)
    result = evaluator.evaluate(event)

    assert result.matched is True
    assert result.rule_id == "64e8e417-c19a-475a-8d19-98ea705394cc"


def test_alternate_powershell_rule_does_not_match_legitimate_powershell():
    rule = load_alternate_powershell_rule()

    assert rule is not None

    event = create_module_event(
        context_info="Command executed = powershell"
    )

    evaluator = SigmaEvaluator(rule)
    result = evaluator.evaluate(event)

    assert result.matched is False