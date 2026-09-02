from Engine.detection.rule_loader import SigmaRuleLoader
from Engine.detection.evaluator import SigmaEvaluator


def test_sigma_rules_load_successfully():
    loader = SigmaRuleLoader()

    rules = loader.load_community_rules()

    assert rules, "No Sigma community rules were loaded."

    print(f"\nLoaded Sigma rules: {len(rules)}")

    for rule in rules:
        assert isinstance(rule, dict)
        assert rule.get("title"), "Sigma rule is missing title."
        assert rule.get("id"), "Sigma rule is missing id."
        assert isinstance(
            rule.get("detection"),
            dict,
        )


def test_sigma_rules_can_be_processed():
    loader = SigmaRuleLoader()

    rules = loader.load_community_rules()

    assert rules, "No Sigma community rules were loaded."

    test_event = {
        "raw_event": {}
    }

    processed = 0

    for rule in rules:
        evaluator = SigmaEvaluator(rule)

        result = evaluator.evaluate(test_event)

        assert result is not None
        assert isinstance(result.matched, bool)

        processed += 1

    print(f"\nProcessed Sigma rules: {processed}")

    assert processed == len(rules)