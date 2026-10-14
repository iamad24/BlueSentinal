
"""
BlueSentinel XDR - False Positive Engine

Evaluates alerts against explicit suppression rules and a
configurable duplicate-alert window.

Critical alerts are retained by default, even when they match
an allowlist or duplicate signature.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any


CRITICAL_SEVERITIES = {"critical"}


@dataclass
class FalsePositiveResult:
    """Explainable result of false-positive analysis."""

    alert_id: str | None
    is_false_positive: bool
    suppressed: bool
    reason: str
    matched_rule: str | None = None
    factors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert the result into a dictionary."""
        return asdict(self)


def _to_dict(alert: Any) -> dict[str, Any]:
    """Accept dictionaries and common Python model types."""
    if isinstance(alert, dict):
        return alert

    if hasattr(alert, "model_dump"):
        result = alert.model_dump(mode="json")
        if isinstance(result, dict):
            return result

    if hasattr(alert, "dict") and callable(alert.dict):
        result = alert.dict()
        if isinstance(result, dict):
            return result

    if hasattr(alert, "__dataclass_fields__"):
        return asdict(alert)

    raise TypeError(
        "alert must be a dictionary, Pydantic model, or dataclass"
    )


def _parse_timestamp(value: Any) -> datetime | None:
    """Parse an ISO timestamp into UTC."""
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(
                value.strip().replace("Z", "+00:00")
            )
        except ValueError:
            return None
    else:
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed.astimezone(timezone.utc)


class FalsePositiveEngine:
    """Analyze alerts using explicit rules and duplicate detection."""

    def __init__(
        self,
        allowlist: list[dict[str, Any]] | None = None,
        duplicate_window_minutes: int = 10,
        protect_critical: bool = True,
    ):
        if duplicate_window_minutes < 0:
            raise ValueError(
                "duplicate_window_minutes cannot be negative"
            )

        self.allowlist = list(allowlist or [])
        self.duplicate_window = timedelta(
            minutes=duplicate_window_minutes
        )
        self.protect_critical = protect_critical

        # Maps alert fingerprints to the last observed timestamp.
        self._seen: dict[tuple[str, str, str, str], datetime] = {}

    @staticmethod
    def _fingerprint(
        alert: dict[str, Any],
    ) -> tuple[str, str, str, str]:
        """Build a stable signature for duplicate detection."""
        return (
            str(alert.get("rule_id") or alert.get("title") or "").lower(),
            str(alert.get("host") or "").lower(),
            str(alert.get("user") or "").lower(),
            str(alert.get("event_type") or "").lower(),
        )

    def _matches_allowlist(
        self,
        alert: dict[str, Any],
    ) -> str | None:
        """
        Match an explicit allowlist rule.

        Every field in a rule must match. Supported keys are
        rule_id, host, user, event_type, and source_ip.
        """
        supported = {
            "rule_id",
            "host",
            "user",
            "event_type",
            "source_ip",
        }

        for index, rule in enumerate(self.allowlist):
            if not isinstance(rule, dict) or not rule:
                continue

            if not set(rule).issubset(supported):
                continue

            if all(
                str(alert.get(key) or "").casefold()
                == str(value).casefold()
                for key, value in rule.items()
            ):
                return f"allowlist-{index + 1}"

        return None

    def evaluate(self, alert: Any) -> FalsePositiveResult:
        """
        Analyze one alert.

        The alert is suppressed only when an explicit allowlist
        rule matches or an identical fingerprint appears within
        the duplicate window. Critical alerts are protected by
        default.
        """
        data = _to_dict(alert)
        alert_id = data.get("alert_id")
        severity = str(
            data.get("severity") or "informational"
        ).strip().lower()

        if self.protect_critical and severity in CRITICAL_SEVERITIES:
            return FalsePositiveResult(
                alert_id=alert_id,
                is_false_positive=False,
                suppressed=False,
                reason="Critical alert retained by safety policy",
                factors=["Critical alerts are protected from suppression"],
            )

        matched_rule = self._matches_allowlist(data)

        if matched_rule:
            return FalsePositiveResult(
                alert_id=alert_id,
                is_false_positive=True,
                suppressed=True,
                reason="Alert matched an explicit allowlist rule",
                matched_rule=matched_rule,
                factors=[f"Matched {matched_rule}"],
            )

        timestamp = _parse_timestamp(data.get("timestamp"))

        # Without a usable timestamp, avoid making a temporal
        # duplicate decision.
        if timestamp is None or self.duplicate_window.total_seconds() == 0:
            return FalsePositiveResult(
                alert_id=alert_id,
                is_false_positive=False,
                suppressed=False,
                reason="No suppression rule matched",
                factors=["Duplicate check requires a valid timestamp"],
            )

        fingerprint = self._fingerprint(data)

        # Remove stale entries to keep the cache bounded by active
        # fingerprints rather than retaining every historical alert.
        cutoff = timestamp - self.duplicate_window
        self._seen = {
            key: seen_at
            for key, seen_at in self._seen.items()
            if seen_at >= cutoff
        }

        previous = self._seen.get(fingerprint)

        if (
            previous is not None
            and timedelta(0) <= timestamp - previous <= self.duplicate_window
        ):
            return FalsePositiveResult(
                alert_id=alert_id,
                is_false_positive=True,
                suppressed=True,
                reason="Duplicate alert detected within the configured window",
                matched_rule="duplicate-window",
                factors=[
                    f"Duplicate window: {self.duplicate_window.total_seconds() / 60:g} minutes"
                ],
            )

        self._seen[fingerprint] = timestamp

        return FalsePositiveResult(
            alert_id=alert_id,
            is_false_positive=False,
            suppressed=False,
            reason="No suppression rule matched",
            factors=["Alert retained for investigation"],
        )

    def evaluate_batch(
        self,
        alerts: list[Any],
    ) -> list[FalsePositiveResult]:
        """Evaluate alerts in the order received."""
        return [self.evaluate(alert) for alert in alerts]
