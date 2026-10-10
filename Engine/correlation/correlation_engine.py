
"""
BlueSentinel XDR - Correlation Engine

Groups related security alerts into investigation cases.

Correlation is based on shared context within a configurable
time window. It does not independently determine maliciousness.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4


SEVERITY_RANK = {
    "informational": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


@dataclass
class CorrelationGroup:
    """A group of related alerts for investigation."""

    correlation_id: str = field(
        default_factory=lambda: str(uuid4())
    )
    alert_ids: list[str] = field(default_factory=list)
    hosts: list[str] = field(default_factory=list)
    users: list[str] = field(default_factory=list)
    severity: str = "informational"
    first_seen: str | None = None
    last_seen: str | None = None
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-friendly dictionary."""
        return asdict(self)


def _to_dict(alert: Any) -> dict[str, Any]:
    """Convert a dictionary, Pydantic model, or dataclass."""

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
    """Parse ISO timestamps into timezone-aware datetimes."""

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


def _unique(values: list[str]) -> list[str]:
    """Remove empty values and duplicates while preserving order."""

    result = []
    seen = set()

    for value in values:
        value = value.strip() if isinstance(value, str) else ""
        if value and value not in seen:
            seen.add(value)
            result.append(value)

    return result


def _extract_indicators(alert: dict[str, Any]) -> set[str]:
    """Extract comparable indicators from alert fields and evidence."""

    indicators: set[str] = set()

    for key in (
        "source_ip",
        "destination_ip",
        "domain",
        "url",
        "file_hash",
    ):
        value = alert.get(key)
        if isinstance(value, str) and value.strip():
            indicators.add(value.strip().lower())

    evidence = alert.get("evidence") or {}

    if isinstance(evidence, dict):
        indicator_fields = (
            "ips",
            "domains",
            "urls",
            "md5_hashes",
            "sha1_hashes",
            "sha256_hashes",
            "file_hashes",
        )

        for key in indicator_fields:
            values = evidence.get(key, [])
            if isinstance(values, str):
                values = [values]
            if isinstance(values, (list, tuple, set)):
                indicators.update(
                    value.strip().lower()
                    for value in values
                    if isinstance(value, str) and value.strip()
                )

    return indicators


class CorrelationEngine:
    """Correlate alerts using time and shared context."""

    def __init__(self, window_minutes: int = 30):
        if window_minutes < 1:
            raise ValueError("window_minutes must be at least 1")

        self.window = timedelta(minutes=window_minutes)

    def correlate(
        self,
        alerts: list[Any],
    ) -> list[CorrelationGroup]:
        """
        Group alerts that share a host, user, or indicator
        within the configured time window.

        Alerts without a valid timestamp are skipped because
        their temporal relationship cannot be established.
        """

        normalized = []

        for alert in alerts:
            item = _to_dict(alert)
            timestamp = _parse_timestamp(item.get("timestamp"))

            if timestamp is None:
                continue

            item["_parsed_timestamp"] = timestamp
            item["_indicators"] = _extract_indicators(item)
            normalized.append(item)

        normalized.sort(key=lambda item: item["_parsed_timestamp"])

        groups: list[CorrelationGroup] = []
        group_alerts: list[list[dict[str, Any]]] = []

        for alert in normalized:
            timestamp = alert["_parsed_timestamp"]
            host = alert.get("host")
            user = alert.get("user")
            indicators = alert["_indicators"]

            matching_indexes = []

            for index, members in enumerate(group_alerts):
                latest = max(
                    member["_parsed_timestamp"] for member in members
                )

                if timestamp - latest > self.window:
                    continue

                shared_host = bool(
                    host and any(member.get("host") == host for member in members)
                )
                shared_user = bool(
                    user and any(member.get("user") == user for member in members)
                )
                shared_indicators = any(
                    indicators & member["_indicators"]
                    for member in members
                )

                if shared_host or shared_user or shared_indicators:
                    matching_indexes.append(index)

            if not matching_indexes:
                group_alerts.append([alert])
                continue

            # Merge all matching groups to avoid duplicate cases.
            target_index = matching_indexes[0]
            group_alerts[target_index].append(alert)

            for index in reversed(matching_indexes[1:]):
                group_alerts[target_index].extend(group_alerts[index])
                del group_alerts[index]

        for members in group_alerts:
            # Singleton alerts are not considered correlated.
            if len(members) < 2:
                continue

            timestamps = [
                member["_parsed_timestamp"] for member in members
            ]

            hosts = _unique([
                member.get("host", "") for member in members
            ])
            users = _unique([
                member.get("user", "") for member in members
            ])
            alert_ids = _unique([
                member.get("alert_id", "") for member in members
            ])

            severities = [
                (member.get("severity") or "informational").lower()
                for member in members
            ]
            severity = max(
                severities,
                key=lambda value: SEVERITY_RANK.get(value, 0),
            )

            reasons = set()

            for left_index, left in enumerate(members):
                for right in members[left_index + 1:]:
                    if (
                        left.get("host")
                        and left.get("host") == right.get("host")
                    ):
                        reasons.add(
                            f"Shared host: {left['host']}"
                        )

                    if (
                        left.get("user")
                        and left.get("user") == right.get("user")
                    ):
                        reasons.add(
                            f"Shared user: {left['user']}"
                        )

                    shared = (
                        left["_indicators"] & right["_indicators"]
                    )
                    for indicator in sorted(shared):
                        reasons.add(
                            f"Shared indicator: {indicator}"
                        )

            groups.append(
                CorrelationGroup(
                    alert_ids=alert_ids,
                    hosts=hosts,
                    users=users,
                    severity=severity,
                    first_seen=min(timestamps).isoformat(),
                    last_seen=max(timestamps).isoformat(),
                    reasons=sorted(reasons),
                )
            )

        return groups
