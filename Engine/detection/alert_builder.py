
"""
BlueSentinel XDR - Alert Builder

Converts matched detection results into structured security alerts.
"""

from datetime import datetime, timezone
from uuid import uuid4

from Engine.detection.models import (
    SecurityEvent,
    DetectionResult,
    SecurityAlert,
)


class AlertBuilder:
    """Build structured alerts from matched detection results."""

    ALLOWED_SEVERITIES = {
        "informational",
        "low",
        "medium",
        "high",
        "critical",
    }

    def build(
        self,
        event: SecurityEvent,
        detection: DetectionResult,
    ) -> SecurityAlert | None:
        """Create an alert when a detection rule matches."""

        # Do not create alerts for unmatched detections.
        if not detection.matched:
            return None

        if not detection.rule_id:
            raise ValueError(
                "A matched detection must have a rule_id."
            )

        if not detection.rule_title:
            raise ValueError(
                "A matched detection must have a rule_title."
            )

        # Normalize and validate severity.
        severity = (detection.severity or "medium").strip().lower()

        if severity not in self.ALLOWED_SEVERITIES:
            severity = "medium"

        # Use the rule description when available.
        description = (
            detection.description
            or f"Detection rule matched: {detection.rule_title}"
        )

        # Preserve detection evidence and add event context.
        evidence = dict(detection.evidence or {})
        evidence.setdefault("event_type", event.event_type)
        evidence.setdefault("log_source", event.log_source)
        evidence.setdefault("process", event.process)
        evidence.setdefault("command_line", event.command_line)

        return SecurityAlert(
            alert_id=str(uuid4()),
            timestamp=datetime.now(timezone.utc),
            rule_id=detection.rule_id,
            title=detection.rule_title,
            severity=severity,
            host=event.host,
            user=event.user,
            event_type=event.event_type,
            description=description,
            mitre_techniques=list(
                detection.mitre_techniques or []
            ),
            source_ip=event.source_ip,
            destination_ip=event.destination_ip,
            evidence=evidence,
        )

    def build_batch(
        self,
        event: SecurityEvent,
        detections: list[DetectionResult],
    ) -> list[SecurityAlert]:
        """Build alerts for all matched detections."""

        alerts = []

        for detection in detections:
            alert = self.build(event, detection)

            if alert is not None:
                alerts.append(alert)

        return alerts
