
from typing import Any


class ResponseFormatter:
    """Normalize AI investigation responses into a consistent structure."""

    VALID_SEVERITIES = {
        "critical",
        "high",
        "medium",
        "low",
        "informational",
        "unknown",
    }

    VALID_CONFIDENCE = {
        "high",
        "medium",
        "low",
        "unknown",
    }

    @staticmethod
    def _text(value: Any, default: str = "") -> str:
        if value is None:
            return default

        return str(value).strip()

    @staticmethod
    def _string_list(value: Any) -> list[str]:
        if value is None:
            return []

        if isinstance(value, str):
            value = [value]

        if not isinstance(value, (list, tuple, set)):
            return []

        return [
            str(item).strip()
            for item in value
            if item is not None and str(item).strip()
        ]

    def format_response(self, response: dict) -> dict:
        """Validate and normalize a structured assistant response."""
        if not isinstance(response, dict):
            raise TypeError("Response must be a dictionary.")

        severity = self._text(
            response.get("severity"), "unknown"
        ).lower()

        confidence = self._text(
            response.get("confidence"), "unknown"
        ).lower()

        if severity not in self.VALID_SEVERITIES:
            severity = "unknown"

        if confidence not in self.VALID_CONFIDENCE:
            confidence = "unknown"

        return {
            "summary": self._text(
                response.get("summary"),
                "No investigation summary provided.",
            ),
            "severity": severity,
            "findings": self._string_list(
                response.get("findings")
            ),
            "recommended_actions": self._string_list(
                response.get("recommended_actions")
            ),
            "mitre_techniques": self._string_list(
                response.get("mitre_techniques")
            ),
            "confidence": confidence,
            "limitations": self._string_list(
                response.get("limitations")
            ),
        }
