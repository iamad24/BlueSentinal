
"""
BlueSentinel XDR - Risk Scoring Engine

Calculates explainable risk scores for security alerts.
This is a prioritization score, not a probability of compromise.
"""

from dataclasses import asdict, dataclass, field
from typing import Any


SEVERITY_SCORES = {
    "informational": 5,
    "low": 20,
    "medium": 40,
    "high": 65,
    "critical": 80,
}

RISK_LEVELS = (
    (25, "low"),
    (50, "medium"),
    (75, "high"),
    (100, "critical"),
)


@dataclass
class RiskAssessment:
    """Explainable risk assessment for a security alert."""

    alert_id: str | None
    risk_score: int
    risk_level: str
    factors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Return a dictionary suitable for JSON serialization."""
        return asdict(self)


def _to_dict(item: Any) -> dict[str, Any]:
    """Accept dictionaries and common model types."""

    if isinstance(item, dict):
        return item

    if hasattr(item, "model_dump"):
        result = item.model_dump(mode="json")
        if isinstance(result, dict):
            return result

    if hasattr(item, "dict") and callable(item.dict):
        result = item.dict()
        if isinstance(result, dict):
            return result

    if hasattr(item, "__dataclass_fields__"):
        return asdict(item)

    raise TypeError(
        "Input must be a dictionary, Pydantic model, or dataclass"
    )


def _risk_level(score: int) -> str:
    """Convert a numeric score into a risk category."""

    if score <= 25:
        return "low"
    if score <= 50:
        return "medium"
    if score <= 75:
        return "high"
    return "critical"


class RiskEngine:
    """Calculate risk scores using transparent rules."""

    def __init__(
        self,
        severity_scores: dict[str, int] | None = None,
        correlation_bonus: int = 10,
        threat_intel_bonus: int = 10,
        max_score: int = 100,
    ):
        self.severity_scores = (
            dict(SEVERITY_SCORES)
            if severity_scores is None
            else dict(severity_scores)
        )

        if not 0 <= correlation_bonus <= max_score:
            raise ValueError("correlation_bonus is out of range")

        if not 0 <= threat_intel_bonus <= max_score:
            raise ValueError("threat_intel_bonus is out of range")

        if max_score < 1:
            raise ValueError("max_score must be positive")

        if any(
            not isinstance(value, int) or value < 0
            for value in self.severity_scores.values()
        ):
            raise ValueError("Severity scores must be non-negative integers")

        if any(value > max_score for value in self.severity_scores.values()):
            raise ValueError("Severity scores cannot exceed max_score")

        self.correlation_bonus = correlation_bonus
        self.threat_intel_bonus = threat_intel_bonus
        self.max_score = max_score

    def assess(
        self,
        alert: Any,
        correlated: bool = False,
        threat_intel: dict[str, Any] | None = None,
    ) -> RiskAssessment:
        """
        Score an alert.

        `correlated` should be True only when the alert is part
        of a meaningful correlated group.

        `threat_intel` may contain:
            {"malicious": True}
        or:
            {"malicious_count": 2}

        Missing reputation data adds no points and does not
        prevent an alert from being scored.
        """

        data = _to_dict(alert)

        severity = str(
            data.get("severity") or "informational"
        ).strip().lower()

        if severity not in self.severity_scores:
            severity = "informational"

        score = self.severity_scores[severity]
        factors = [f"Base severity: {severity} (+{score})"]

        if correlated:
            score += self.correlation_bonus
            factors.append(
                f"Related security activity (+{self.correlation_bonus})"
            )

        if threat_intel is not None:
            if not isinstance(threat_intel, dict):
                raise TypeError("threat_intel must be a dictionary")

            malicious = threat_intel.get("malicious") is True
            malicious_count = threat_intel.get("malicious_count", 0)

            if (
                not isinstance(malicious_count, int)
                or isinstance(malicious_count, bool)
                or malicious_count < 0
            ):
                raise ValueError(
                    "malicious_count must be a non-negative integer"
                )

            if malicious or malicious_count > 0:
                score += self.threat_intel_bonus
                factors.append(
                    "Threat intelligence reports malicious activity "
                    f"(+{self.threat_intel_bonus})"
                )
            else:
                factors.append(
                    "No positive malicious reputation evidence; "
                    "no reputation bonus applied"
                )
        else:
            factors.append(
                "Threat reputation unavailable; no reputation bonus applied"
            )

        score = min(score, self.max_score)

        return RiskAssessment(
            alert_id=data.get("alert_id"),
            risk_score=score,
            risk_level=_risk_level(score),
            factors=factors,
        )

    def assess_batch(
        self,
        alerts: list[Any],
    ) -> list[RiskAssessment]:
        """Assess multiple alerts independently."""

        return [self.assess(alert) for alert in alerts]
