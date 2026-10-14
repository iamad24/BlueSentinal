
from typing import Any

from Engine.ai_assistant.prompt_builder import PromptBuilder
from Engine.ai_assistant.response_formatter import ResponseFormatter


class BlueSentinelAIAssistant:
    """Assistant foundation for BlueSentinel XDR investigations."""

    def __init__(self):
        self.prompt_builder = PromptBuilder()
        self.response_formatter = ResponseFormatter()

    def prepare_investigation(self, alert: Any) -> dict:
        """Prepare alert context and messages for a future LLM."""
        context = self.prompt_builder.build_context(alert)
        messages = self.prompt_builder.build_messages(alert)

        return {
            "context": context,
            "messages": messages,
        }

    def analyze_alert(self, alert: Any) -> dict:
        """
        Generate a basic evidence-based investigation summary.

        This version does not call an LLM. It organizes existing
        alert evidence and provides general defensive recommendations.
        """
        context = self.prompt_builder.build_context(alert)

        title = context.get("title", "Security alert")
        description = context.get("description", "")
        severity = str(context.get("severity", "unknown")).lower()

        findings = []

        if description:
            findings.append(f"Alert description: {description}")

        for field, label in (
            ("host", "Host"),
            ("hostname", "Host"),
            ("user", "User"),
            ("process", "Process"),
            ("command_line", "Command line"),
            ("source_ip", "Source IP"),
            ("destination_ip", "Destination IP"),
            ("file_hash", "File hash"),
        ):
            value = context.get(field)
            if value is not None and value != "":
                finding = f"{label}: {value}"
                if finding not in findings:
                    findings.append(finding)

        if context.get("mitre_techniques"):
            findings.append(
                "MITRE techniques are mapped in the supplied alert; "
                "review them against the underlying evidence."
            )

        if context.get("iocs"):
            findings.append(
                "Indicator data is available for investigation. "
                "Validate its context and reputation before drawing "
                "conclusions."
            )

        if not findings:
            findings.append(
                "The alert contains limited investigation details. "
                "Collect additional logs and related events."
            )

        recommended_actions = [
            "Review the original event and detection rule.",
            "Examine related events and process ancestry.",
            "Validate indicators using available threat-intelligence sources.",
            "Document the evidence before taking containment actions.",
        ]

        if severity in {"high", "critical"}:
            recommended_actions.insert(
                0,
                "Prioritize analyst review and follow your incident "
                "response procedure.",
            )

        result = {
            "summary": (
                f"{title}. This is an evidence-organizing assessment, "
                "not an independent confirmation of malicious activity."
            ),
            "severity": severity,
            "findings": findings,
            "recommended_actions": recommended_actions,
            "mitre_techniques": self._as_list(
                context.get("mitre_techniques")
            ),
            "confidence": "unknown",
            "limitations": [
                "No LLM analysis is enabled in this version.",
                "Recommendations are general and must be validated "
                "by a security analyst.",
                "Threat-intelligence results and missing evidence "
                "may affect the investigation.",
            ],
        }

        return self.response_formatter.format_response(result)

    @staticmethod
    def _as_list(value: Any) -> list[str]:
        if value is None:
            return []
        if isinstance(value, str):
            return [value]
        if isinstance(value, (list, tuple, set)):
            return [str(item) for item in value]
        return []


# Convenient alias for simpler imports.
AIAssistant = BlueSentinelAIAssistant
