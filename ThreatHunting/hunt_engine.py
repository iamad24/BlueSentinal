
"""Evidence-based threat hunting engine for BlueSentinel XDR."""

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from ThreatHunting.finding_store import FindingStore
from ThreatHunting.hunt_library import get_builtin_hunts


class HuntEngine:
    """Run built-in or custom hunts against normalized security events."""

    VALID_SEVERITIES = {"critical", "high", "medium", "low", "informational"}

    def __init__(
        self,
        finding_store: FindingStore | None = None,
        hunts: list[dict[str, Any]] | None = None,
    ) -> None:
        self.finding_store = finding_store or FindingStore()
        self.hunts = hunts if hunts is not None else get_builtin_hunts()

    @staticmethod
    def _to_dict(event: Any) -> dict[str, Any]:
        """Convert supported event objects to dictionaries."""
        if isinstance(event, dict):
            return event

        if hasattr(event, "model_dump"):
            return event.model_dump()

        if hasattr(event, "dict") and callable(event.dict):
            return event.dict()

        if hasattr(event, "__dict__"):
            return vars(event)

        raise TypeError("Event must be a dictionary or a model object")

    @staticmethod
    def _get_text(event: dict[str, Any], field: str) -> str:
        """Read a field using common normalized-event aliases."""
        aliases = {
            "process": (
                "process", "image", "process_name", "process_path",
                "executable", "Image",
            ),
            "command_line": (
                "command_line", "commandline", "cmdline", "CommandLine",
                "ScriptBlockText",
            ),
            "registry_path": (
                "registry_path", "registry_key", "target_object",
                "TargetObject", "registry_key_path",
            ),
        }

        for key in aliases.get(field, (field,)):
            value = event.get(key)
            if value is not None:
                if isinstance(value, (str, int, float)):
                    return str(value)
                if isinstance(value, list):
                    return " ".join(str(item) for item in value)

        # PowerShell script content may be recorded separately from the
        # process command line.
        if field == "command_line":
            return " ".join(
                str(event.get(key, ""))
                for key in ("process", "image", "ScriptBlockText")
                if event.get(key) is not None
            )

        return ""

    @staticmethod
    def _event_summary(event: dict[str, Any]) -> dict[str, Any]:
        """Keep a bounded, relevant event snapshot as finding evidence."""
        allowed_fields = (
            "timestamp", "TimeCreated", "host", "hostname", "Computer",
            "user", "username", "UserName", "event_id", "EventID",
            "process", "image", "process_name", "process_id", "ProcessId",
            "parent_process", "command_line", "CommandLine",
            "source_ip", "destination_ip", "registry_path", "TargetObject",
        )

        evidence = {}
        for field in allowed_fields:
            value = event.get(field)
            if isinstance(value, (str, int, float, bool)) or value is None:
                if value is not None and str(value).strip():
                    evidence[field] = str(value)[:1000]

        return evidence

    @staticmethod
    def _event_identifier(event: dict[str, Any]) -> str | None:
        for key in ("event_id", "event_uid", "id", "record_id"):
            value = event.get(key)
            if value is not None:
                return str(value)
        return None

    def run_hunt(
        self,
        events: list[Any],
        hunt_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """Run all hunts or one selected hunt over the supplied events."""
        if not isinstance(events, list):
            raise TypeError("events must be a list")

        selected_hunts = self.hunts
        if hunt_id is not None:
            selected_hunts = [
                hunt for hunt in self.hunts
                if hunt.get("id") == hunt_id
            ]
            if not selected_hunts:
                raise ValueError(f"Unknown hunt ID: {hunt_id}")

        findings = []

        for raw_event in events:
            event = self._to_dict(raw_event)

            for hunt in selected_hunts:
                field = hunt.get("field", "")
                keywords = hunt.get("keywords", [])

                if not field or not isinstance(keywords, list):
                    continue

                text_value = self._get_text(event, field)
                if not text_value:
                    continue

                lowered_text = text_value.lower()
                matched = [
                    keyword for keyword in keywords
                    if isinstance(keyword, str)
                    and keyword.strip()
                    and keyword.lower() in lowered_text
                ]

                if not matched:
                    continue

                severity = str(hunt.get("severity", "medium")).lower()
                if severity not in self.VALID_SEVERITIES:
                    severity = "medium"

                finding = {
                    "finding_id": str(uuid4()),
                    "hunt_id": hunt.get("id", "CUSTOM"),
                    "hunt_name": hunt.get("name", "Custom Hunt"),
                    "description": hunt.get("description", ""),
                    "severity": severity,
                    "status": "new",
                    "confidence": "medium",
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "event_id": self._event_identifier(event),
                    "matched_field": field,
                    "matched_keywords": matched,
                    "evidence": self._event_summary(event),
                    "mitre_techniques": list(
                        hunt.get("mitre_techniques", [])
                    ),
                    "source": "behavioral_hunt",
                    "disposition": "requires_investigation",
                }

                findings.append(self.finding_store.add(finding))

        return findings

    def run_all(self, events: list[Any]) -> list[dict[str, Any]]:
        """Convenience method to run every registered hunt."""
        return self.run_hunt(events)

    def get_findings(self) -> list[dict[str, Any]]:
        """Return findings saved by this engine's store."""
        return self.finding_store.list_all()
