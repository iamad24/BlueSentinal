from typing import Any

from .evaluator import SigmaEvaluator
from .models import SecurityEvent, DetectionResult
from .rule_loader import SigmaRuleLoader


class DetectionEngine:
    """
    Coordinates Sigma rule loading and event evaluation.

    The DetectionEngine receives a security event,
    evaluates it against the loaded Sigma rules,
    and returns the detections that matched.
    """

    def __init__(
        self,
        rule_loader: SigmaRuleLoader | None = None,
    ):
        self.rule_loader = rule_loader or SigmaRuleLoader()

        self.rules: list[dict[str, Any]] = []

        self.load_rules()

    # =========================================================
    # Rule management
    # =========================================================

    def load_rules(self) -> None:
        """
        Load all community and custom Sigma rules.
        """

        self.rules = self.rule_loader.load_all_rules()

    def reload_rules(self) -> None:
        """
        Reload Sigma rules from disk.
        """

        self.load_rules()

    def get_rule_count(self) -> int:
        """
        Return the number of loaded Sigma rules.
        """

        return len(self.rules)

    # =========================================================
    # Event detection
    # =========================================================

    def detect(
        self,
        event: SecurityEvent | dict[str, Any],
    ) -> list[DetectionResult]:
        """
        Evaluate one security event against all loaded rules.

        Only matched detections are returned.
        """

        detections: list[DetectionResult] = []

        for rule in self.rules:

            evaluator = SigmaEvaluator(rule)

            result = evaluator.evaluate(event)

            if result.matched:
                detections.append(result)

        return detections


if __name__ == "__main__":
    print("BlueSentinel Detection Engine")
    print("-" * 35)

    engine = DetectionEngine()

    print(f"Loaded Sigma rules: {engine.get_rule_count()}")